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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <popt.h>

#include <nss3/cert.h>
#include <nss3/pkcs7t.h>

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
#define FLAG_LIST_END		0x1000

static struct {
	int flag;
	const char *name;
} flag_names[] = {
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
open_input(pesign_context *ctx)
{
	if (!ctx->infile) {
		fprintf(stderr, "pesign: No input file specified.\n");
		exit(1);
	}

	struct stat statbuf;
	ctx->infd = open(ctx->infile, O_RDONLY|O_CLOEXEC);
	stat(ctx->infile, &statbuf); 
	ctx->outmode = statbuf.st_mode;

	if (ctx->infd < 0) {
		fprintf(stderr, "pesign: Error opening input: %m\n");
		exit(1);
	}

	Pe_Cmd cmd = ctx->infd == STDIN_FILENO ? PE_C_READ : PE_C_READ_MMAP;
	ctx->inpe = pe_begin(ctx->infd, cmd, NULL);
	if (!ctx->inpe) {
		fprintf(stderr, "pesign: could not load input file: %s\n",
			pe_errmsg(pe_errno()));
		exit(1);
	}

	int rc = parse_signatures(&ctx->cms_ctx, ctx->inpe);
	if (rc < 0) {
		fprintf(stderr, "pesign: could not parse signature data\n");
		exit(1);
	}
}

static void
close_input(pesign_context *ctx)
{
	pe_end(ctx->inpe);
	ctx->inpe = NULL;

	close(ctx->infd);
	ctx->infd = -1;
}

static void
close_output(pesign_context *ctx)
{
	Pe_Cmd cmd = ctx->outfd == STDOUT_FILENO ? PE_C_RDWR : PE_C_RDWR_MMAP;

	finalize_signatures(&ctx->cms_ctx, ctx->outpe);
	pe_update(ctx->outpe, cmd);
	pe_end(ctx->outpe);
	ctx->outpe = NULL;

	close(ctx->outfd);
	ctx->outfd = -1;
}

static void
open_output(pesign_context *ctx)
{
	if (!ctx->outfile) {
		fprintf(stderr, "pesign: No output file specified.\n");
		exit(1);
	}

	if (access(ctx->outfile, F_OK) == 0 && ctx->force == 0) {
		fprintf(stderr, "pesign: \"%s\" exists and --force was "
				"not given.\n", ctx->outfile);
		exit(1);
	}

	ctx->outfd = open(ctx->outfile, O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC,
			ctx->outmode);
	if (ctx->outfd < 0) {
		fprintf(stderr, "pesign: Error opening output: %m\n");
		exit(1);
	}

	size_t size;
	char *addr;

	addr = pe_rawfile(ctx->inpe, &size);

	ftruncate(ctx->outfd, size);
	lseek(ctx->outfd, 0, SEEK_SET);
	write(ctx->outfd, addr, size);

	Pe_Cmd cmd = ctx->outfd == STDOUT_FILENO ? PE_C_RDWR : PE_C_RDWR_MMAP;
	ctx->outpe = pe_begin(ctx->outfd, cmd, NULL);
	if (!ctx->outpe) {
		fprintf(stderr, "pesign: could not load output file: %s\n",
			pe_errmsg(pe_errno()));
		exit(1);
	}

	pe_clearcert(ctx->outpe);
}

static void
open_rawsig_input(pesign_context *ctx)
{
	if (!ctx->rawsig) {
		fprintf(stderr, "pesign: No input file specified.\n");
		exit(1);
	}

	ctx->rawsigfd = open(ctx->rawsig, O_RDONLY|O_CLOEXEC);
	if (ctx->rawsigfd < 0) {
		fprintf(stderr, "pesign: Error opening raw signature for input:"
				" %m\n");
		exit(1);
	}
}

static void
close_rawsig_input(pesign_context *ctx)
{
	close(ctx->rawsigfd);
	ctx->rawsigfd = -1;
}

static void
open_sattr_input(pesign_context *ctx)
{
	if (!ctx->insattrs) {
		fprintf(stderr, "pesign: No input file specified.\n");
		exit(1);
	}

	ctx->insattrsfd = open(ctx->insattrs, O_RDONLY|O_CLOEXEC);
	if (ctx->insattrsfd < 0) {
		fprintf(stderr, "pesign: Error opening signed attributes "
				"for input: %m\n");
		exit(1);
	}
}

static void
close_sattr_input(pesign_context *ctx)
{
	close(ctx->insattrsfd);
	ctx->insattrsfd = -1;
}

static void
open_sattr_output(pesign_context *ctx)
{
	if (!ctx->outsattrs) {
		fprintf(stderr, "pesign: No output file specified.\n");
		exit(1);
	}

	if (access(ctx->outsattrs, F_OK) == 0 && ctx->force == 0) {
		fprintf(stderr, "pesign: \"%s\" exists and --force "
				"was not given.\n", ctx->outsattrs);
		exit(1);
	}

	ctx->outsattrsfd = open(ctx->outsattrs,
			O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC,
			ctx->outmode);
	if (ctx->outsattrsfd < 0) {
		fprintf(stderr, "pesign: Error opening signed attributes "
				"for output: %m\n");
		exit(1);
	}
}

static void
close_sattr_output(pesign_context *ctx)
{
	close(ctx->outsattrsfd);
	ctx->outsattrsfd = -1;
}

static void
open_sig_input(pesign_context *ctx)
{
	if (!ctx->insig) {
		fprintf(stderr, "pesign: No input file specified.\n");
		exit(1);
	}

	ctx->insigfd = open(ctx->insig, O_RDONLY|O_CLOEXEC);
	if (ctx->insigfd < 0) {
		fprintf(stderr, "pesign: Error opening signature for input: "
				"%m\n");
		exit(1);
	}
}

static void
close_sig_input(pesign_context *ctx)
{
	close(ctx->insigfd);
	ctx->insigfd = -1;
}

static void
open_sig_output(pesign_context *ctx)
{
	if (!ctx->outsig) {
		fprintf(stderr, "pesign: No output file specified.\n");
		exit(1);
	}

	if (access(ctx->outsig, F_OK) == 0 && ctx->force == 0) {
		fprintf(stderr, "pesign: \"%s\" exists and --force "
				"was not given.\n", ctx->outsig);
		exit(1);
	}

	ctx->outsigfd = open(ctx->outsig, O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC,
				ctx->outmode);
	if (ctx->outsigfd < 0) {
		fprintf(stderr, "pesign: Error opening signature for output: "
				"%m\n");
		exit(1);
	}
}

static void
close_sig_output(pesign_context *ctx)
{
	close(ctx->outsigfd);
	ctx->outsigfd = -1;
}

static void
open_pubkey_output(pesign_context *ctx)
{
	if (!ctx->outkey) {
		fprintf(stderr, "pesign: No output file specified.\n");
		exit(1);
	}

	if (access(ctx->outkey, F_OK) == 0 && ctx->force == 0) {
		fprintf(stderr, "pesign: \"%s\" exists and --force "
				"was not given.\n", ctx->outkey);
		exit(1);
	}

	ctx->outkeyfd = open(ctx->outkey, O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC,
				ctx->outmode);
	if (ctx->outkeyfd < 0) {
		fprintf(stderr, "pesign: Error opening pubkey for output: "
				"%m\n");
		exit(1);
	}
}

static void
open_cert_output(pesign_context *ctx)
{
	if (!ctx->outcert) {
		fprintf(stderr, "pesign: No output file specified.\n");
		exit(1);
	}

	if (access(ctx->outcert, F_OK) == 0 && ctx->force == 0) {
		fprintf(stderr, "pesign: \"%s\" exists and --force "
				"was not given.\n", ctx->outcert);
		exit(1);
	}

	ctx->outcertfd = open(ctx->outcert, O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC,
				ctx->outmode);
	if (ctx->outcertfd < 0) {
		fprintf(stderr, "pesign: Error opening certificate for output: "
				"%m\n");
		exit(1);
	}
}

static void
__attribute__ ((unused))
open_privkey(pesign_context *ctx)
{
	if (!ctx->privkeyfile) {
		fprintf(stderr, "pesign: No signing private key specified.\n");
		exit(1);
	}

	int pkfd = open(ctx->privkeyfile, O_RDONLY|O_CLOEXEC);

	if (pkfd < 0) {
		fprintf(stderr, "pesign: could not open private key "
				"\"%s\": %m\n", ctx->privkeyfile);
		exit(1);
	}

#if 0
	int rc;

	rc = read_privkey(pkfd, &ctx->privkey);
	if (rc < 0) {
		fprintf(stderr, "pesign: could not read private key\n");
		exit(1);
	}
#endif

	close(pkfd);
}


static void
check_inputs(pesign_context *ctx)
{
	if (!ctx->infile) {
		fprintf(stderr, "pesign: No input file specified.\n");
		exit(1);
	}

	if (!ctx->outfile) {
		fprintf(stderr, "pesign: No output file specified.\n");
		exit(1);
	}

	if (!strcmp(ctx->infile, ctx->outfile)) {
		fprintf(stderr, "pesign: in-place file editing "
				"is not yet supported\n");
		exit(1);
	}
}

static void
print_digest(pesign_context *pctx)
{
	if (!pctx)
		return;

	cms_context *ctx = &pctx->cms_ctx;
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

	pesign_context ctx, *ctxp = &ctx;

	int list = 0;
	int remove = 0;

	char *digest_name = "sha256";
	char *tokenname = "NSS Certificate DB";

	poptContext optCon;
	struct poptOption options[] = {
		{NULL, '\0', POPT_ARG_INTL_DOMAIN, "pesign" },
		{"in", 'i', POPT_ARG_STRING, &ctx.infile, 0,
			"specify input file", "<infile>"},
		{"out", 'o', POPT_ARG_STRING, &ctx.outfile, 0,
			"specify output file", "<outfile>" },
		{"certficate", 'c', POPT_ARG_STRING, &ctx.cms_ctx.certname, 0,
			"specify certificate nickname",
			"<certificate nickname>" },
		{"privkey", 'p', POPT_ARG_STRING, &ctx.privkeyfile, 0,
			"specify private key file", "<privkey>" },
		{"force", 'f', POPT_ARG_VAL, &ctx.force,  1,
			"force overwriting of output file", NULL },
		{"sign", 's', POPT_ARG_VAL, &ctx.sign, 1,
			"create a new signature", NULL },
		{"hash", 'h', POPT_ARG_VAL, &ctx.hash, 1, "hash binary", NULL },
		{"digest_type", 'd', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
			&digest_name, 0, "digest type to use for pe hash" },
		{"import-signed-certificate", 'm',
			POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
			&ctx.insig, 0,"import signature from file", "<insig>" },
		{"export-signed-attributes", 'E',
			POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
			&ctx.outsattrs, 0, "export signed attributes to file",
			"<signed_attributes_file>" },
		{"import-signed-attributes", 'I',
			POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
			&ctx.insattrs, 0, "import signed attributes from file",
			"<signed_attributes_file>" },
		{"import-raw-signature", 'R',
			POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN, &ctx.rawsig,
			0, "import raw signature from file", "<inraw>" },
		{"signature-number", 'u', POPT_ARG_INT, &ctx.signum, -1,
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
			&ctx.outsig, 0,"export signature to file", "<outsig>" },
		{"export-pubkey", 'K', POPT_ARG_STRING,
			&ctx.outkey, 0, "export pubkey to file", "<outkey>" },
		{"export-cert", 'C', POPT_ARG_STRING,
			&ctx.outcert, 0, "export signing cert to file",
			"<outcert>" },
		{"ascii-armor", 'a', POPT_ARG_VAL, &ctx.ascii, 1,
			"use ascii armoring", NULL },
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	rc = pesign_context_init(ctxp);
	if (rc < 0) {
		fprintf(stderr, "Could not initialize context: %m\n");
		exit(1);
	}

	optCon = poptGetContext("pesign", argc, (const char **)argv, options,0);

	while ((rc = poptGetNextOpt(optCon)) > 0)
		;

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

	rc = set_digest_parameters(&ctx.cms_ctx, digest_name);
	int is_help  = strcmp(digest_name, "help") ? 0 : 1;
	if (rc < 0) {
		if (!is_help) {
			fprintf(stderr, "Digest \"%s\" not found.\n",
				digest_name);
		}
		exit(!is_help);
	}

	ctx.cms_ctx.tokenname = tokenname;

	int action = 0;
	if (ctx.rawsig)
		action |= IMPORT_RAW_SIGNATURE;

	if (ctx.insattrs)
		action |= IMPORT_SATTRS;

	if (ctx.outsattrs)
		action |= EXPORT_SATTRS;
		
	if (ctx.insig)
		action |= IMPORT_SIGNATURE;

	if (ctx.outkey)
		action |= EXPORT_PUBKEY;

	if (ctx.outcert)
		action |= EXPORT_CERT;

	if (ctx.outsig)
		action |= EXPORT_SIGNATURE;

	if (remove != 0)
		action |= REMOVE_SIGNATURE;

	if (list != 0)
		action |= LIST_SIGNATURES;

	if (ctx.sign) {
		action |= GENERATE_SIGNATURE;
		if (!(action & EXPORT_SIGNATURE))
			action |= IMPORT_SIGNATURE;
	}

	if (ctx.hash)
		action |= GENERATE_DIGEST|PRINT_DIGEST;

	ssize_t sigspace = 0;

	switch (action) {
		case NO_FLAGS:
			fprintf(stderr, "pesign: Nothing to do.\n");
			exit(0);
			break;
		/* in this case we have the actual binary signature and the
		 * signing cert, but not the pkcs7ish certificate that goes
		 * with it.
		 */
		case IMPORT_RAW_SIGNATURE|IMPORT_SATTRS:
			check_inputs(ctxp);
			rc = find_certificate(&ctx.cms_ctx);
			if (rc < 0) {
				fprintf(stderr, "pesign: Could not find "
					"certificate %s\n",
					ctx.cms_ctx.certname);
				exit(1);
			}
			open_rawsig_input(ctxp);
			open_sattr_input(ctxp);
			import_raw_signature(ctxp);
			close_sattr_input(ctxp);
			close_rawsig_input(ctxp);

			open_input(ctxp);
			open_output(ctxp);
			close_input(ctxp);
			generate_digest(&ctx.cms_ctx, ctx.outpe);
			sigspace = calculate_signature_space(&ctx.cms_ctx,
								ctx.outpe);
			allocate_signature_space(ctxp, sigspace);
			generate_signature(ctxp);
			insert_signature(ctxp);
			finalize_signatures(&ctx.cms_ctx, ctx.outpe);
			close_output(ctxp);
			break;
		case EXPORT_SATTRS:
			open_input(ctxp);
			open_sattr_output(ctxp);
			generate_digest(&ctx.cms_ctx, ctx.inpe);
			generate_sattr_blob(ctxp);
			close_sattr_output(ctxp);
			close_input(ctxp);
			break;
		/* add a signature from a file */
		case IMPORT_SIGNATURE:
			check_inputs(ctxp);
			open_input(ctxp);
			open_output(ctxp);
			close_input(ctxp);
			open_sig_input(ctxp);
			check_signature_space(ctxp);
			import_signature(ctxp);
			close_sig_input(ctxp);
			close_output(ctxp);
			break;
		case EXPORT_PUBKEY:
			rc = find_certificate(&ctx.cms_ctx);
			if (rc < 0) {
				fprintf(stderr, "pesign: Could not find "
					"certificate %s\n",
					ctx.cms_ctx.certname);
				exit(1);
			}
			open_pubkey_output(ctxp);
			export_pubkey(ctxp);
			break;
		case EXPORT_CERT:
			rc = find_certificate(&ctx.cms_ctx);
			if (rc < 0) {
				fprintf(stderr, "pesign: Could not find "
					"certificate %s\n",
					ctx.cms_ctx.certname);
				exit(1);
			}
			open_cert_output(ctxp);
			export_cert(ctxp);
			break;
		/* find a signature in the binary and save it to a file */
		case EXPORT_SIGNATURE:
			open_input(ctxp);
			open_sig_output(ctxp);
			if (ctx.signum > ctx.cms_ctx.num_signatures) {
				fprintf(stderr, "Invalid signature number.\n");
				exit(1);
			}
			if (ctx.signum < 0)
				ctx.signum = 0;
			if (ctx.signum >= ctx.cms_ctx.num_signatures) {
				fprintf(stderr, "No valid signature #%d.\n",
					ctx.signum);
				exit(1);
			}
			memcpy(&ctx.cms_ctx.newsig,
				ctx.cms_ctx.signatures[ctx.signum],
				sizeof (ctx.cms_ctx.newsig));
			export_signature(ctxp);
			close_input(ctxp);
			close_sig_output(ctxp);
			break;
		/* remove a signature from the binary */
		case REMOVE_SIGNATURE:
			check_inputs(ctxp);
			open_input(ctxp);
			open_output(ctxp);
			close_input(ctxp);
			if (ctx.signum > ctx.cms_ctx.num_signatures) {
				fprintf(stderr, "Invalid signature number.\n");
				exit(1);
			}
			remove_signature(&ctx);
			close_output(ctxp);
			break;
		/* list signatures in the binary */
		case LIST_SIGNATURES:
			open_input(ctxp);
			list_signatures(ctxp);
			break;
		case GENERATE_DIGEST|PRINT_DIGEST:
			open_input(ctxp);
			generate_digest(&ctx.cms_ctx, ctx.inpe);
			print_digest(ctxp);
			break;
		/* generate a signature and save it in a separate file */
		case EXPORT_SIGNATURE|GENERATE_SIGNATURE:
			rc = find_certificate(&ctx.cms_ctx);
			if (rc < 0) {
				fprintf(stderr, "pesign: Could not find "
					"certificate %s\n",
					ctx.cms_ctx.certname);
				exit(1);
			}
			open_input(ctxp);
			open_sig_output(ctxp);
			generate_digest(&ctx.cms_ctx, ctx.inpe);
			generate_signature(ctxp);
			export_signature(ctxp);
			break;
		/* generate a signature and embed it in the binary */
		case IMPORT_SIGNATURE|GENERATE_SIGNATURE:
			check_inputs(ctxp);
			rc = find_certificate(&ctx.cms_ctx);
			if (rc < 0) {
				fprintf(stderr, "pesign: Could not find "
					"certificate %s\n",
					ctx.cms_ctx.certname);
				exit(1);
			}
			open_input(ctxp);
			open_output(ctxp);
			close_input(ctxp);
			generate_digest(&ctx.cms_ctx, ctx.outpe);
			sigspace = calculate_signature_space(&ctx.cms_ctx,
							     ctx.outpe);
			allocate_signature_space(ctxp, sigspace);
			generate_digest(&ctx.cms_ctx, ctx.outpe);
			generate_signature(ctxp);
			insert_signature(ctxp);
			finalize_signatures(&ctx.cms_ctx, ctx.outpe);
			close_output(ctxp);
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
	pesign_context_fini(&ctx);
	return (rc < 0);
}
