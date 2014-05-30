/*
 * Copyright 2011-2012 Red Hat, Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author(s): Peter Jones <pjones@redhat.com>
 */

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <nss.h>

#include <popt.h>

#include <prerror.h>
#include <cert.h>
#include <pkcs7t.h>

#include "pesign.h"

#define NO_FLAGS		0x00
#define GENERATE_DIGEST		0x01
#define GENERATE_SIGNATURE	0x02
#define IMPORT_RAW_SIGNATURE	0x04
#define IMPORT_SIGNATURE	0x08
#define IMPORT_SATTRS		0x10
#define EXPORT_SATTRS		0x20
#define EXPORT_SIGNATURE	0x40
#define REMOVE_SIGNATURE	0x80
#define LIST_SIGNATURES		0x100
#define PRINT_DIGEST		0x200
#define EXPORT_PUBKEY		0x400
#define EXPORT_CERT		0x800
#define DAEMONIZE		0x1000
#define FLAG_LIST_END		0x2000

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

static void
print_flag_name(FILE *f, int flag)
{
	for (int i = 0; flag_names[i].flag != FLAG_LIST_END; i++) {
		if (flag_names[i].flag == flag)
			fprintf(f, "%s ", flag_names[i].name);
	}
}

static void
open_input_helper(char *name, int *fd, char *errtext)
{
	if (!name)
		errx(1, "No input %s specified", errtext);

	*fd = open(name, O_RDONLY|O_CLOEXEC);
	if (*fd < 0)
		err(1, "Could not open %s for input", errtext);
}

static void
open_output_helper(char *name, int *fd, mode_t mode, char *errtext, int force)
{
	if (!name)
		errx(1, "No output %s specified", errtext);

	if (access(name, F_OK) == 0 && force == 0)
		errx(1, "\"%s\" exists and --force was not given",
			name);

	*fd = open(name, O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, mode);
	if (*fd < 0)
		err(1, "Could not open %s for output", errtext);
}

static void
open_input(pesign_context *ctx)
{
	open_input_helper(ctx->infile, &ctx->infd, "PE file");

	struct stat statbuf;
	fstat(ctx->infd, &statbuf);
	ctx->outmode = statbuf.st_mode;

	ctx->insize = statbuf.st_size;
	ctx->inmap = mmap(NULL, ctx->insize, PROT_READ, MAP_SHARED,
				ctx->infd, 0);
	if (ctx->inmap == MAP_FAILED)
		err(1, "Could not mmap input");

	set_up_file_handlers(ctx, ctx->inmap, ctx->insize);

	if (ctx->file_handlers->setup)
		ctx->file_handlers->setup(ctx, ctx->inmap, ctx->insize);
}

#define close_helper(fd) ({close(fd); fd = -1;})

static void
close_input(pesign_context *ctx)
{
	if (ctx->file_handlers->teardown)
		ctx->file_handlers->teardown(ctx);

	close_helper(ctx->infd);
}

static void
close_output(pesign_context *ctx)
{
	Pe_Cmd cmd = ctx->outfd == STDOUT_FILENO ? PE_C_RDWR : PE_C_RDWR_MMAP;

	finalize_pe_signatures(ctx->cms_ctx->signatures,
				ctx->cms_ctx->num_signatures, ctx->outpe);
	pe_update(ctx->outpe, cmd);
	pe_end(ctx->outpe);
	ctx->outpe = NULL;

	close_helper(ctx->outfd);
}

static void
open_output(pesign_context *ctx)
{
	open_output_helper(ctx->outfile, &ctx->outfd, ctx->outmode,
				"PE file", ctx->force);

	size_t size;
	char *addr;

	addr = pe_rawfile(ctx->inpe, &size);

	ftruncate(ctx->outfd, size);
	lseek(ctx->outfd, 0, SEEK_SET);
	write(ctx->outfd, addr, size);

	Pe_Cmd cmd = ctx->outfd == STDOUT_FILENO ? PE_C_RDWR : PE_C_RDWR_MMAP;
	ctx->outpe = pe_begin(ctx->outfd, cmd, NULL);
	if (!ctx->outpe)
		errx(1, "could not load output file: %s",
			pe_errmsg(pe_errno()));

	pe_clearcert(ctx->outpe);
}

static void
check_inputs(pesign_context *ctx)
{
	if (!ctx->infile)
		errx(1, "No input PE file specified");

	if (!ctx->outfile)
		errx(1, "No output PE file specified");

	if (!strcmp(ctx->infile, ctx->outfile))
		errx(1, "In-place file editing is not yet supported");
}

static void
print_digest(pesign_context *pctx)
{
	if (!pctx)
		return;

	cms_context *ctx = pctx->cms_ctx;
	if (!ctx)
		return;

	printf("hash: ");
	int j = ctx->selected_digest;
	for (int i = 0; i < ctx->digests[j].pe_digest->len; i++)
		printf("%02x",
			(unsigned char)ctx->digests[j].pe_digest->data[i]);
	printf("\n");
}

int
main(int argc, char *argv[])
{
	int rc;

	pesign_context *ctxp;

	int list = 0;
	int remove = 0;
	int daemon = 0;
	int fork = 1;
	int padding = 0;
	int need_db = 0;

	char *digest_name = "sha256";
	char *tokenname = "NSS Certificate DB";
	char *origtoken = tokenname;
	char *certname = NULL;
	char *certdir = "/etc/pki/pesign";
	char *signum = NULL;

	rc = pesign_context_new(&ctxp);
	if (rc < 0)
		err(1, "Could not initialize context");

	poptContext optCon;
	struct poptOption options[] = {
		{NULL, '\0', POPT_ARG_INTL_DOMAIN, "pesign" },
		{"in", 'i', POPT_ARG_STRING, &ctxp->infile, 0,
			"specify input file", "<infile>"},
		{"out", 'o', POPT_ARG_STRING, &ctxp->outfile, 0,
			"specify output file", "<outfile>" },
		{"certficate", 'c', POPT_ARG_STRING, &certname, 0,
			"specify certificate nickname",
			"<certificate nickname>" },
		{"certdir", 'n', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
			&certdir, 0,
			"specify nss certificate database directory",
			"<certificate directory path>" },
		{"force", 'f', POPT_ARG_VAL, &ctxp->force,  1,
			"force overwriting of output file", NULL },
		{"sign", 's', POPT_ARG_VAL, &ctxp->sign, 1,
			"create a new signature", NULL },
		{"hash", 'h', POPT_ARG_VAL, &ctxp->hash, 1,
			"hash binary", NULL },
		{"digest_type", 'd', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
			&digest_name, 0, "digest type to use for pe hash" },
		{"import-signed-certificate", 'm',
			POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
			&ctxp->insig, 0,"import signature from file", "<insig>" },
		{"export-signed-attributes", 'E',
			POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
			&ctxp->outsattrs, 0, "export signed attributes to file",
			"<signed_attributes_file>" },
		{"import-signed-attributes", 'I',
			POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
			&ctxp->insattrs, 0,
			"import signed attributes from file",
			"<signed_attributes_file>" },
		{"import-raw-signature", 'R',
			POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN, &ctxp->rawsig,
			0, "import raw signature from file", "<inraw>" },
		{"signature-number", 'u', POPT_ARG_STRING, &signum, 0,
			"specify which signature to operate on","<sig-number>"},
		{"list-signatures", 'l',
			POPT_ARG_VAL|POPT_ARGFLAG_DOC_HIDDEN,
			&list, 1, "list signatures", NULL },
		{"nss-token", 't', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
			&tokenname, 0, "NSS token holding signing key" },
		{"show-signature", 'S', POPT_ARG_VAL, &list, 1,
			"show signature", NULL },
		{"remove-signature", 'r', POPT_ARG_VAL, &remove, 1,
			"remove signature" },
		{"export-signature", 'e',
			POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
			&ctxp->outsig, 0,
			"export signature to file", "<outsig>" },
		{"export-pubkey", 'K', POPT_ARG_STRING,
			&ctxp->outkey, 0, "export pubkey to file", "<outkey>" },
		{"export-cert", 'C', POPT_ARG_STRING,
			&ctxp->outcert, 0, "export signing cert to file",
			"<outcert>" },
		{"ascii-armor", 'a', POPT_ARG_VAL, &ctxp->ascii, 1,
			"use ascii armoring", NULL },
		{"daemonize", 'D', POPT_ARG_VAL, &daemon, 1,
			"run as a daemon process", NULL },
		{"nofork", 'N', POPT_ARG_VAL, &fork, 0,
			"don't fork when daemonizing", NULL },
		{"verbose", 'v', POPT_ARG_VAL, &ctxp->verbose, 1,
			"be very verbose", NULL },
		{"padding", 'P', POPT_ARG_VAL,
			&padding, 1, "pad data section", NULL },
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext("pesign", argc, (const char **)argv, options,0);

	rc = poptReadDefaultConfig(optCon, 0);
	if (rc < 0)
		errx(1, "poptReadDefaultConfig failed: %s", poptStrerror(rc));

	while ((rc = poptGetNextOpt(optCon)) > 0)
		;

	if (rc < -1)
		errx(1, "Invalid argument: %s: %s",
			poptBadOption(optCon, 0), poptStrerror(rc));

	if (poptPeekArg(optCon))
		errx(1, "Invalid argument: \"%s", poptPeekArg(optCon));

	poptFreeContext(optCon);

	if (signum) {
		errno = 0;
		ctxp->signum = strtol(signum, NULL, 0);
		if (errno != 0)
			err(1, "Invalid signature number");
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

	if (!daemon) {
		SECStatus status;
		if (need_db)
			status = NSS_Init(certdir);
		else
			status = NSS_NoDB_Init(NULL);
		if (status != SECSuccess)
			nsserr(1, "Could not initializes nss");

		status = register_oids(ctxp->cms_ctx);
		if (status != SECSuccess)
			errx(1, "Could not register OIDs");
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

	ctxp->cms_ctx->tokenname = tokenname ?
		PORT_ArenaStrdup(ctxp->cms_ctx->arena, tokenname) : NULL;
	if (tokenname && !ctxp->cms_ctx->tokenname)
		nsserr(1, "could not allocate token name");

	if (tokenname != origtoken)
		free(tokenname);

	ctxp->cms_ctx->certname = certname ?
		PORT_ArenaStrdup(ctxp->cms_ctx->arena, certname) : NULL;
	if (certname && !ctxp->cms_ctx->certname)
		nsserr(1, "could not allocate certificate name");
	if (certname)
		free(certname);


	if (ctxp->sign && !ctxp->cms_ctx->certname)
		errx(1, "signing requested but no certificate "
			"nickname provided");

	ssize_t sigspace = 0;

	switch (action) {
		case NO_FLAGS:
			errx(0, "Nothing to do");
			break;
		/* in this case we have the actual binary signature and the
		 * signing cert, but not the pkcs7ish certificate that goes
		 * with it.
		 */
		case IMPORT_RAW_SIGNATURE|IMPORT_SATTRS:
			check_inputs(ctxp);
			rc = find_certificate(ctxp->cms_ctx, 0);
			if (rc < 0)
				errx(1, "pesign: Could not find certificate %s",
					ctxp->cms_ctx->certname);
			open_input_helper(ctxp->rawsig, &ctxp->rawsigfd,
					"raw signature");
			open_input_helper(ctxp->insattrs, &ctxp->insattrsfd,
					"signed attributes");
			import_raw_signature(ctxp);
			close_helper(ctxp->insattrsfd);
			close_helper(ctxp->rawsigfd);
			open_input(ctxp);
			open_output(ctxp);
			close_input(ctxp);
			generate_digest(ctxp->cms_ctx, ctxp->outpe, 1);
			sigspace = calculate_pe_signature_space(ctxp->cms_ctx,
								ctxp->outpe);
			allocate_pe_signature_space(ctxp->outpe, sigspace);
			generate_signature(ctxp->cms_ctx);
			teardown_digests(ctxp->cms_ctx);
			insert_signature(ctxp->cms_ctx, ctxp->signum);
			close_output(ctxp);
			break;
		case EXPORT_SATTRS:
			open_input(ctxp);
			open_output_helper(ctxp->outsattrs, &ctxp->outsattrsfd,
					ctxp->outmode, "signed attributes",
					ctxp->force);
			generate_digest(ctxp->cms_ctx, ctxp->inpe, 1);
			generate_sattr_blob(ctxp);
			teardown_digests(ctxp->cms_ctx);
			close_helper(ctxp->outsattrsfd);
			close_input(ctxp);
			break;
		/* add a signature from a file */
		case IMPORT_SIGNATURE:
			check_inputs(ctxp);
			if (ctxp->signum > ctxp->cms_ctx->num_signatures + 1)
				errx(1, "Invalid signature number");
			open_input(ctxp);
			open_output(ctxp);
			close_input(ctxp);
			open_input_helper(ctxp->insig, &ctxp->insigfd,
					"signature");
			parse_signature(ctxp);
			sigspace =
				calculate_pe_signature_overhead(
					ctxp->cms_ctx->newsig.len) +
				ctxp->cms_ctx->newsig.len +
				get_reserved_pe_sig_space(ctxp->cms_ctx,
							ctxp->outpe);
			allocate_pe_signature_space(ctxp->outpe, sigspace);
			assert_signature_space(ctxp);
			insert_signature(ctxp->cms_ctx, ctxp->signum);
			close_helper(ctxp->insigfd);
			close_output(ctxp);
			break;
		case EXPORT_PUBKEY:
			rc = find_certificate(ctxp->cms_ctx, 1);
			if (rc < 0)
				errx(1, "Could not find certificate %s",
					ctxp->cms_ctx->certname);
			open_output_helper(ctxp->outkey, &ctxp->outkeyfd,
					ctxp->outmode, "public key",
					ctxp->force);
			export_pubkey(ctxp);
			close_helper(ctxp->outkeyfd);
			break;
		case EXPORT_CERT:
			rc = find_certificate(ctxp->cms_ctx, 0);
			if (rc < 0)
				errx(1, "Could not find certificate %s",
					ctxp->cms_ctx->certname);
			open_output_helper(ctxp->outcert, &ctxp->outcertfd,
					ctxp->outmode, "certificate",
					ctxp->force);
			export_cert(ctxp);
			close_helper(ctxp->outcertfd);
			break;
		/* find a signature in the binary and save it to a file */
		case EXPORT_SIGNATURE:
			open_input(ctxp);
			open_output_helper(ctxp->outsig, &ctxp->outsigfd,
					ctxp->outmode, "signature",
					ctxp->force);
			if (ctxp->signum > ctxp->cms_ctx->num_signatures)
				errx(1, "Invalid signature number");
			if (ctxp->signum < 0)
				ctxp->signum = 0;
			if (ctxp->signum >= ctxp->cms_ctx->num_signatures)
				errx(1, "No valid signature #%d",
					ctxp->signum);
			memcpy(&ctxp->cms_ctx->newsig,
				ctxp->cms_ctx->signatures[ctxp->signum],
				sizeof (ctxp->cms_ctx->newsig));
			export_signature(ctxp->cms_ctx, ctxp->outsigfd, ctxp->ascii);
			close_input(ctxp);
			close_helper(ctxp->outsigfd);
			break;
		/* remove a signature from the binary */
		case REMOVE_SIGNATURE:
			check_inputs(ctxp);
			open_input(ctxp);
			open_output(ctxp);
			close_input(ctxp);
			if (ctxp->signum < 0 ||
					ctxp->signum >=
					ctxp->cms_ctx->num_signatures)
				errx(1, "Invalid signature number %d.  "
					"Must be between 0 and %d",
					ctxp->signum,
					ctxp->cms_ctx->num_signatures - 1);
			remove_signature(ctxp);
			close_output(ctxp);
			break;
		/* list signatures in the binary */
		case LIST_SIGNATURES:
			open_input(ctxp);
			list_signatures(ctxp);
			break;
		case GENERATE_DIGEST|PRINT_DIGEST:
			open_input(ctxp);
			generate_digest(ctxp->cms_ctx, ctxp->inpe, padding);
			print_digest(ctxp);
			teardown_digests(ctxp->cms_ctx);
			break;
		/* generate a signature and save it in a separate file */
		case EXPORT_SIGNATURE|GENERATE_SIGNATURE:
			rc = find_certificate(ctxp->cms_ctx, 1);
			if (rc < 0)
				errx(1, "Could not find certificate %s",
					ctxp->cms_ctx->certname);
			open_input(ctxp);
			open_output_helper(ctxp->outsig, &ctxp->outsigfd,
					ctxp->outmode, "signature",
					ctxp->force);
			generate_digest(ctxp->cms_ctx, ctxp->inpe, 1);
			generate_signature(ctxp->cms_ctx);
			teardown_digests(ctxp->cms_ctx);
			export_signature(ctxp->cms_ctx, ctxp->outsigfd, ctxp->ascii);
			break;
		/* generate a signature and embed it in the binary */
		case IMPORT_SIGNATURE|GENERATE_SIGNATURE:
			check_inputs(ctxp);
			rc = find_certificate(ctxp->cms_ctx, 1);
			if (rc < 0)
				errx(1, "Could not find certificate %s",
					ctxp->cms_ctx->certname);
			if (ctxp->signum > ctxp->cms_ctx->num_signatures + 1)
				errx(1, "Invalid signature number");
			open_input(ctxp);
			open_output(ctxp);
			close_input(ctxp);
			generate_digest(ctxp->cms_ctx, ctxp->outpe, 1);
			sigspace = calculate_pe_signature_space(ctxp->cms_ctx,
							     ctxp->outpe);
			allocate_pe_signature_space(ctxp->outpe, sigspace);
			generate_digest(ctxp->cms_ctx, ctxp->outpe, 1);
			generate_signature(ctxp->cms_ctx);
			teardown_digests(ctxp->cms_ctx);
			insert_signature(ctxp->cms_ctx, ctxp->signum);
			close_output(ctxp);
			break;
		case DAEMONIZE:
			rc = daemonize(ctxp->cms_ctx, certdir, fork);
			break;
		default:
			fprintf(stderr, "Incompatible flags (0x%08x): ", action);
			for (int i = 1; i < FLAG_LIST_END; i <<= 1) {
				if (action & i)
					print_flag_name(stderr, i);
			}
			fprintf(stderr, "\n");
			exit(1);
	}
	pesign_context_free(ctxp);

	if (!daemon) {
		SECStatus status = NSS_Shutdown();
		if (status != SECSuccess)
			nsserr(1, "Could not shut down NSS");
	}

	return (rc < 0);
}
