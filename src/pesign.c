// SPDX-License-Identifier: GPLv2
/*
 * pesign.c - a PE signing utility
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "fix_coverity.h"

#include <err.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <nss.h>

#include <popt.h>

#include <prerror.h>
#include <cert.h>
#include <pkcs7t.h>

#include "pesign.h"
#include "pesign_standalone.h"

static struct {
	int flag;
	const char *name;
} flag_names[] = {
	{DAEMONIZE, "daemonize"},
	{GENERATE_DIGEST, "hash"},
	{GENERATE_SIGNATURE, "sign"},
	{IMPORT_RAW_SIGNATURE, "import-raw-sig"},
	{IMPORT_SIGNATURE, "import-sig"},
	{IMPORT_SATTRS, "import-sattrs" },
	{EXPORT_SATTRS, "export-sattrs" },
	{EXPORT_SIGNATURE, "export-sig"},
	{EXPORT_PUBKEY, "export-pubkey"},
	{EXPORT_CERT, "export-cert"},
	{REMOVE_SIGNATURE, "remove"},
	{LIST_SIGNATURES, "list"},
	{FLAG_LIST_END, NULL},
};

void
print_flag_name(FILE *f, int flag)
{
	for (int i = 0; flag_names[i].flag != FLAG_LIST_END; i++) {
		if (flag_names[i].flag == flag)
			fprintf(f, "%s ", flag_names[i].name);
	}
}

static long *verbose;

long verbosity(void)
{
	if (!verbose)
		return 0;
	return *verbose;
}

enum {
	POPT_RET_PWDB = 0x40000001,
	POPT_RET_ENV = 0x40000002,
	POPT_RET_PINFD = 0x40000003,
	POPT_RET_PINFILE = 0x40000004,
};

int
main(int argc, char *argv[])
{
	int rc;

	pesign_context *ctxp;
	file_format fmt = FORMAT_PE_BINARY;

	int list = 0;
	int remove = 0;
	int daemon = 0;
	int fork = 1;
	int padding = 1;
	int need_db = 0;
	int check_vendor_cert = 1;

	char *digest_name = "sha256";
	char *orig_digest_name = digest_name;
	char *tokenname = "NSS Certificate DB";
	char *origtoken = tokenname;
	char *certname = NULL;
	char *certdir = "/etc/pki/pesign";
	char *orig_certdir = certdir;
	char *signum = NULL;

	secuPWData pwdata;

	memset(&pwdata, 0, sizeof(pwdata));
	pwdata.intdata = -1;

	setenv("NSS_DEFAULT_DB_TYPE", "sql", 0);

	rc = pesign_context_new(&ctxp);
	if (rc < 0) {
		fprintf(stderr, "Could not initialize context: %m\n");
		exit(1);
	}
	verbose = &ctxp->verbose;

	poptContext optCon;
	struct poptOption options[] = {
		{.argInfo = POPT_ARG_INTL_DOMAIN,
		 .arg = "pesign" },
		{.longName = "in",
		 .shortName = 'i',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &ctxp->infile,
		 .descrip = "specify input file",
		 .argDescrip = "<infile>"},
		{.longName = "out",
		 .shortName = 'o',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &ctxp->outfile,
		 .descrip = "specify output file",
		 .argDescrip = "<outfile>" },
		{.longName = "certificate",
		 .shortName = 'c',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &certname,
		 .descrip = "specify certificate nickname",
		 .argDescrip = "<certificate nickname>" },
		{.longName = "certdir",
		 .shortName = 'n',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
		 .arg = &certdir,
		 .descrip = "specify nss certificate database directory",
		 .argDescrip = "<certificate directory path>" },
		{.longName = "force",
		 .shortName = 'f',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &ctxp->force,
		 .val = 1,
		 .descrip = "force overwriting of output file" },
		{.longName = "sign",
		 .shortName = 's',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &ctxp->sign,
		 .val = 1,
		 .descrip = "create a new signature" },
		{.longName = "hash",
		 .shortName = 'h',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &ctxp->hash,
		 .val = 1,
		 .descrip = "hash binary" },
		{.longName = "digest-type",
		 .shortName = 'd',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
		 .arg = &digest_name,
		 .descrip = "digest type to use for pe hash" },
		{.longName = "digest_type",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &digest_name,
		 .descrip = "digest type to use for pe hash" },
		{.longName = "import-signature",
		 .shortName = 'm',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &ctxp->insig,
		 .descrip = "<insig>" },
		{.longName = "import-signed-certificate",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &ctxp->insig,
		 .descrip = "<insig>" },
		{.longName = "export-signed-attributes",
		 .shortName = 'E',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &ctxp->outsattrs,
		 .descrip = "export signed attributes to file",
		 .argDescrip = "<signed_attributes_file>" },
		{.longName = "import-signed-attributes",
		 .shortName = 'I',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &ctxp->insattrs,
		 .descrip = "import signed attributes from file",
		 .argDescrip = "<signed_attributes_file>" },
		{.longName = "import-raw-signature",
		 .shortName = 'R',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &ctxp->rawsig,
		 .descrip = "import raw signature from file",
		 .argDescrip = "<inraw>" },
		{.longName = "signature-number",
		 .shortName = 'u',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &signum,
		 .descrip = "specify which signature to operate on","<sig-number>"},
		{.longName = "list-signatures",
		 .shortName = 'l',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &list,
		 .val = 1,
		 .descrip = "list signatures" },
		{.longName = "token",
		 .shortName = 't',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
		 .arg = &tokenname,
		 .descrip = "NSS token holding signing key" },
		{.longName = "nss-token",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &tokenname,
		 .descrip = "NSS token holding signing key" },
		{.longName = "show-signature",
		 .shortName = 'S',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &list,
		 .val = 1,
		 .descrip = "show signature" },
		{.longName = "remove-signature",
		 .shortName = 'r',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &remove,
		 .val = 1,
		 .descrip = "remove signature" },
		{.longName = "export-signature",
		 .shortName = 'e',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &ctxp->outsig,
		 .descrip = "export signature to file",
		 .argDescrip = "<outsig>" },
		{.longName = "export-pubkey",
		 .shortName = 'K',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &ctxp->outkey,
		 .descrip = "export pubkey to file",
		 .argDescrip = "<outkey>" },
		{.longName = "export-cert",
		 .shortName = 'C',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &ctxp->outcert,
		 .descrip = "export signing cert to file",
		 .argDescrip = "<outcert>" },
		{.longName = "ascii-armor",
		 .shortName = 'a',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &ctxp->ascii,
		 .val = 1,
		 .descrip = "use ascii armoring" },
		{.longName = "daemonize",
		 .shortName = 'D',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &daemon,
		 .val = 1,
		 .descrip = "run as a daemon process" },
		{.longName = "nofork",
		 .shortName = 'N',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &fork,
		 .descrip = "don't fork when daemonizing" },
		{.longName = "verbose",
		 .shortName = 'v',
		 .argInfo = POPT_ARG_VAL|POPT_ARG_LONG|POPT_ARGFLAG_OPTIONAL,
		 .arg = &ctxp->verbose,
		 .val = 1,
		 .descrip = "be more verbose" },
		{.longName = "debug",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_VAL|POPT_ARG_LONG|POPT_ARGFLAG_OPTIONAL,
		 .arg = &ctxp->verbose,
		 .val = 2,
		 .descrip = "be very verbose" },
		{.longName = "pinfd",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_INT,
		 .arg = &pwdata.intdata,
		 .val = POPT_RET_PINFD,
		 .descrip = "read file descriptor for pin information",
		 .argDescrip = "<file descriptor>" },
		{.longName = "pinfile",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &pwdata.data,
		 .val = POPT_RET_PINFILE,
		 .descrip = "read named file for pin information",
		 .argDescrip = "<pin file name>" },
		{.longName = "pinenv",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &pwdata.data,
		 .val = POPT_RET_ENV,
		 .descrip = "read file descriptor for pin information",
		 .argDescrip = "<file descriptor>" },
		{.longName = "padding",
		 .shortName = 'P',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &padding,
		 .val = 1,
		 .descrip = "pad data section (default)" },
		{.longName = "nopadding",
		 .shortName = 'p',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &padding,
		 .val = 0,
		 .descrip = "do not pad the data section" },
		{.longName = "no-vendor-cert",
		 .shortName = 'V',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &check_vendor_cert,
		 .val = 0,
		 .descrip = "do not hash the .vendor_cert section." },
		{.longName = "pwfile",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &pwdata.data,
		 .val = POPT_RET_PWDB,
		 .descrip = "file to read passwords from.",
		 .argDescrip = "<pwfile>" },
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext("pesign", argc, (const char **)argv, options,0);

	rc = poptReadDefaultConfig(optCon, 0);
	if (rc < 0 && !(rc == POPT_ERROR_ERRNO && errno == ENOENT)) {
		fprintf(stderr, "pesign: poptReadDefaultConfig failed: %s\n",
		poptStrerror(rc));
		exit(1);
	}

	while ((rc = poptGetNextOpt(optCon)) > 0) {
		switch (rc) {
		case POPT_RET_PWDB:
			dprintf("POPT_RET_PWDB:\"%s\"", pwdata.data ? pwdata.data : "(null)");
			if (pwdata.source != PW_SOURCE_INVALID)
				errx(1, "only one password/pin method can be used at a time");
			if (pwdata.data == NULL)
				errx(1, "--pwfile requires a file name as an argument");
			pwdata.source = PW_FROMFILEDB;
			pwdata.data = strdup(pwdata.data);
			pwdata.intdata = -1;
			if (!pwdata.data)
				err(1, "could not allocate memory");
			continue;

		case POPT_RET_ENV:
			dprintf("POPT_RET_ENV:\"%s\"", pwdata.data ? pwdata.data : "(null)");
			if (pwdata.source != PW_SOURCE_INVALID)
				errx(1, "only one password/pin method can be used at a time");
			if (pwdata.data == NULL)
				errx(1, "--pinenv requires an environment variable name as an argument");
			pwdata.source = PW_FROMENV;
			pwdata.data = strdup(pwdata.data);
			pwdata.intdata = -1;
			if (!pwdata.data)
				err(1, "could not allocate memory");
			continue;

		case POPT_RET_PINFD:
			dprintf("POPT_RET_PINFD:\"%s\"", pwdata.data ? pwdata.data : "(null)");
			if (pwdata.source != PW_SOURCE_INVALID)
				errx(1, "only one password/pin method can be used at a time");
			if (pwdata.data == NULL)
				errx(1, "--pinfd requires a file descriptor as an argument");
			errno = 0;
			pwdata.source = PW_FROMFD;
			pwdata.intdata = strtol(pwdata.data, NULL, 0);
			if ((pwdata.intdata == LONG_MIN || pwdata.intdata == LONG_MAX) && errno != 0)
				err(1, "file descriptor needed, got \"%s\"", pwdata.data ? pwdata.data : "(null)");
			pwdata.data = NULL;
			continue;

		case POPT_RET_PINFILE:
			dprintf("POPT_RET_PINFILE:\"%s\"", pwdata.data ? pwdata.data : "(null)");
			if (pwdata.source != PW_SOURCE_INVALID)
				errx(1, "only one password/pin method can be used at a time");
			if (pwdata.data == NULL)
				errx(1, "--pinfile requires a file name as an argument");
			pwdata.source = PW_FROMFILE;
			pwdata.data = strdup(pwdata.data);
			pwdata.intdata = -1;
			if (!pwdata.data)
				err(1, "could not allocate memory");
			continue;
		}
	}

	dprintf("pwdata.source:%d %schecking for PESIGN_TOKEN_PIN",
		pwdata.source,
		pwdata.source == PW_SOURCE_INVALID ? "" : "not ");
	if (pwdata.source == PW_SOURCE_INVALID && secure_getenv("PESIGN_TOKEN_PIN")) {
		pwdata.source = PW_FROMENV;
		pwdata.data = strdup(secure_getenv("PESIGN_TOKEN_PIN"));
		if (!pwdata.data)
			err(1, "could not allocate memory");
	}
	pwdata.orig_source = pwdata.source;

	if (rc < -1) {
		fprintf(stderr, "pesign: Invalid argument: %s: %s\n",
			poptBadOption(optCon, 0), poptStrerror(rc));
		exit(1);
	}

	if (poptPeekArg(optCon)) {
		fprintf(stderr, "pesign: Invalid Argument: \"%s\"\n",
				poptPeekArg(optCon));
		exit(1);
	}

	poptFreeContext(optCon);

	if (signum) {
		errno = 0;
		ctxp->signum = strtol(signum, NULL, 0);
		if (errno != 0) {
			fprintf(stderr, "invalid signature number: %m\n");
			exit(1);
		}
		free(signum);
	}

	int action = 0;
	if (daemon)
		action |= DAEMONIZE;

	if (ctxp->rawsig) {
		action |= IMPORT_RAW_SIGNATURE;
		need_db = 1;
	}

	if (ctxp->insattrs)
		action |= IMPORT_SATTRS;

	if (ctxp->outsattrs)
		action |= EXPORT_SATTRS;

	if (ctxp->insig)
		action |= IMPORT_SIGNATURE;

	if (ctxp->outkey) {
		action |= EXPORT_PUBKEY;
		need_db = 1;
	}

	if (ctxp->outcert) {
		action |= EXPORT_CERT;
		need_db = 1;
	}

	if (ctxp->outsig)
		action |= EXPORT_SIGNATURE;

	if (remove != 0)
		action |= REMOVE_SIGNATURE;

	if (list != 0)
		action |= LIST_SIGNATURES;

	if (ctxp->sign) {
		action |= GENERATE_SIGNATURE;
		if (!(action & EXPORT_SIGNATURE))
			action |= IMPORT_SIGNATURE;
		need_db = 1;
	}

	if (ctxp->hash)
		action |= GENERATE_DIGEST|PRINT_DIGEST;

	if (!check_vendor_cert) {
		action |= OMIT_VENDOR_CERT;
	}

	if (!daemon) {
		SECStatus status;
		int error = 0;
		if (need_db) {
			status = NSS_Init(certdir);
			if (status != SECSuccess) {
				char *globpattern = NULL;
				error = errno;
				rc = asprintf(&globpattern, "%s/cert*.db",
					      certdir);
				if (rc > 0) {
					glob_t globbuf;
					memset(&globbuf, 0, sizeof(globbuf));
					rc = glob(globpattern, GLOB_ERR, NULL,
						  &globbuf);
					if (rc != 0) {
						err(1, "Could not open NSS database (\"%s\")",
						     PORT_ErrorToString(PORT_GetError()));
					}
				}
			}
		} else
			status = NSS_NoDB_Init(NULL);
		if (status != SECSuccess) {
			errno = error;
			errx(1, "Could not initialize nss.\n"
			        "NSS says \"%s\" errno says \"%m\"\n",
			     PORT_ErrorToString(PORT_GetError()));
		}

		status = register_oids(ctxp->cms_ctx);
		if (status != SECSuccess) {
			fprintf(stderr, "Could not register OIDs\n");
			exit(1);
		}
	}

	rc = set_digest_parameters(ctxp->cms_ctx, digest_name);
	int is_help  = strcmp(digest_name, "help") ? 0 : 1;
	if (rc < 0) {
		if (!is_help) {
			fprintf(stderr, "Digest \"%s\" not found.\n",
				digest_name);
		}
		exit(!is_help);
	}

	if (pwdata.source != PW_DEVICE)
		cms_set_pw_data(ctxp->cms_ctx, &pwdata);

	ctxp->cms_ctx->omit_vendor_cert = !check_vendor_cert;

	ctxp->cms_ctx->tokenname = tokenname ?
		PORT_ArenaStrdup(ctxp->cms_ctx->arena, tokenname) : NULL;
	if (tokenname && !ctxp->cms_ctx->tokenname) {
		fprintf(stderr, "could not allocate token name: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		exit(1);
	}
	if (tokenname != origtoken)
		free(tokenname);

	ctxp->cms_ctx->certname = certname ?
		PORT_ArenaStrdup(ctxp->cms_ctx->arena, certname) : NULL;
	if (certname && !ctxp->cms_ctx->certname) {
		fprintf(stderr, "could not allocate certificate name: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		exit(1);
	}
	if (certname)
		free(certname);
	if (digest_name && digest_name != orig_digest_name)
		free(digest_name);

	if (ctxp->sign) {
		if (!ctxp->cms_ctx->certname) {
			fprintf(stderr, "pesign: signing requested but no "
				"certificate nickname provided\n");
			exit(1);
		}
	}

	if (ctxp->infile) {
		char *ext = strrchr(ctxp->infile, '.');
		if (ext && strcmp(ext, ".ko") == 0)
			fmt = FORMAT_KERNEL_MODULE;
	}

	switch (action) {
		case NO_FLAGS:
			fprintf(stderr, "pesign: Nothing to do.\n");
			exit(0);
			break;
		case DAEMONIZE:
			rc = daemonize(ctxp->cms_ctx, certdir, fork);
			break;
		default:
			switch (fmt) {
				case FORMAT_PE_BINARY:
					pe_handle_action(ctxp, action, padding);
					break;
				case FORMAT_KERNEL_MODULE:
					kmod_handle_action(ctxp, action);
					break;
			}
	}
	if (certdir && certdir != orig_certdir)
		free(certdir);
	pesign_context_free(ctxp);

	if (!daemon) {
		SECStatus status = NSS_Shutdown();
		if (status != SECSuccess) {
			fprintf(stderr, "could not shut down NSS: %s",
				PORT_ErrorToString(PORT_GetError()));
			exit(1);
		}
	}

	return (rc < 0);
}

// vim:fenc=utf-8:tw=75:noet
