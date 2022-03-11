// SPDX-License-Identifier: GPLv2
/*
 * pesum.c - pesum command line tool
 * Copyright Peter Jones <pjones@redhat.com>
 */

#include "fix_coverity.h"

#include <err.h>
#include <popt.h>

#include <nss.h>
#include <prerror.h>

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

long
verbosity(void)
{
	if (!verbose)
		return 0;
	return *verbose;
}

int
main(int argc, char *argv[])
{
	int rc;
	SECStatus status;

	char *digest_name = "sha256";
	char *orig_digest_name = digest_name;
	int padding = 1;
	long verbose_cmd_line = 0;
	const char *infile;

	int action = GENERATE_DIGEST|PRINT_DIGEST;
	file_format fmt = FORMAT_PE_BINARY;

	setenv("NSS_DEFAULT_DB_TYPE", "sql", 0);

	verbose = &verbose_cmd_line;

	poptContext optCon;
	struct poptOption options[] = {
		{.argInfo = POPT_ARG_INTL_DOMAIN,
		 .arg = "pesum" },
		{.longName = "verbose",
		 .shortName = 'v',
		 .argInfo = POPT_ARG_VAL|POPT_ARG_LONG|POPT_ARGFLAG_OPTIONAL,
		 .arg = &verbose_cmd_line,
		 .val = 1,
		 .descrip = "be more verbose" },
		{.longName = "debug",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_VAL|POPT_ARG_LONG|POPT_ARGFLAG_OPTIONAL,
		 .arg = &verbose_cmd_line,
		 .val = 2,
		 .descrip = "be very verbose" },
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
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext("pesum", argc, (const char **)argv, options,0);

	rc = poptReadDefaultConfig(optCon, 0);
	if (rc < 0 && !(rc == POPT_ERROR_ERRNO && errno == ENOENT))
		errx(1, "poptReadDefaultConfig failed: %s", poptStrerror(rc));

	while ((rc = poptGetNextOpt(optCon)) > 0) {
		;
	}

	if (rc < -1)
		errx(1, "Invalid argument: %s: %s",
		     poptBadOption(optCon, 0), poptStrerror(rc));

	if (!poptPeekArg(optCon))
		errx(1, "nothing to do");

	status = NSS_NoDB_Init(NULL);
	if (status != SECSuccess)
		errx(1, "Could not initialize nss.\n"
		        "NSS says \"%s\" errno says \"%m\"\n",
			PORT_ErrorToString(PORT_GetError()));

	while ((infile = poptGetArg(optCon)) != NULL) {
		pesign_context *ctxp = NULL;

		char *ext = strrchr(infile, '.');
		if (ext && strcmp(ext, ".ko") == 0)
			fmt = FORMAT_KERNEL_MODULE;

		rc = pesign_context_new(&ctxp);
		if (rc < 0)
			err(1, "Could not initialize context");

		ctxp->verbose = verbose_cmd_line;

		ctxp->hash = 1;
		ctxp->infile = strdup(infile);
		if (!ctxp->infile)
			err(1, "Could not allocate memory");

		rc = set_digest_parameters(ctxp->cms_ctx, digest_name);
		int is_help = strcmp(digest_name, "help") ? 0 : 1;
		if (rc < 0) {
			if (!is_help) {
				fprintf(stderr, "Digest \"%s\" not found.\n",
					digest_name);
			}
			exit(!is_help);
		}

		errno = 0;
		switch (fmt) {
			case FORMAT_PE_BINARY:
				pe_handle_action(ctxp, action, padding);
				break;
			case FORMAT_KERNEL_MODULE:
				kmod_handle_action(ctxp, action);
				break;
		}

		pesign_context_free(ctxp);
	}

	poptFreeContext(optCon);

	if (digest_name && digest_name != orig_digest_name)
		free(digest_name);

	status = NSS_Shutdown();
	if (status != SECSuccess)
		errx(1, "could not shut down NSS: %s",
		     PORT_ErrorToString(PORT_GetError()));

	return 0;
}

// vim:fenc=utf-8:tw=75:noet
