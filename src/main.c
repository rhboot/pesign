/*
 * Copyright 2011 Red Hat, Inc.
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
#define GENERATE_SIGNATURE	0x01
#define IMPORT_SIGNATURE	0x02
#define EXPORT_SIGNATURE	0x04
#define REMOVE_SIGNATURE	0x08
#define LIST_SIGNATURES		0x10
#define FLAG_LIST_END		0x20

static struct {
	int flag;
	const char *name;
} flag_names[] = {
	{GENERATE_SIGNATURE, "sign"},
	{IMPORT_SIGNATURE, "import"},
	{EXPORT_SIGNATURE, "export"},
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

	Pe_Cmd cmd = ctx->outfd == STDOUT_FILENO ? PE_C_WRITE : PE_C_WRITE_MMAP;
	ctx->outpe = pe_begin(ctx->outfd, cmd, ctx->inpe);
	if (!ctx->outpe) {
		fprintf(stderr, "pesign: could not load output file: %s\n",
			pe_errmsg(pe_errno()));
		exit(1);
	}
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
open_certificate(pesign_context *ctx)
{
	int rc;

	if (!ctx->certfile) {
		fprintf(stderr, "pesign: No signing certificate specified.\n");
		exit(1);
	}

	int certfd = open(ctx->certfile, O_RDONLY|O_CLOEXEC);

	if (certfd < 0) {
		fprintf(stderr, "pesign: could not open certificate "
				"\"%s\": %m\n", ctx->certfile);
		exit(1);
	}

	rc = read_cert(certfd, &ctx->cert);
	if (rc < 0) {
		fprintf(stderr, "pesign: could not read certificate\n");
		exit(1);
	}

	close(certfd);
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

int
main(int argc, char *argv[])
{
	int rc;

	pesign_context ctx, *ctxp = &ctx;

	int list = 0;
	int remove = -1;

	poptContext optCon;
	struct poptOption options[] = {
		{"in", 'i', POPT_ARG_STRING, &ctx.infile, 0,
			"specify input file", "<infile>"},
		{"out", 'o', POPT_ARG_STRING, &ctx.outfile, 0,
			"specify output file", "<outfile>" },
		{"certficate", 'c', POPT_ARG_STRING, &ctx.certfile, 0,
			"specify certificate file", "<certificate>" },
		{"force", 'f', POPT_ARG_NONE|POPT_ARG_VAL, &ctx.force,  1,
			"force overwriting of output file", NULL },
		{"nogaps", 'n', POPT_ARG_NONE|POPT_ARG_VAL, &ctx.hashgaps, 0,
			"skip gaps between sections when signing", NULL },
		{"sign", 's', POPT_ARG_VAL, &ctx.sign, 1,
			"create a new signature", NULL },
		{"import-signature", 'm', POPT_ARG_STRING, &ctx.insig, 0,
			"import signature from file", "<insig>" },
#if 0 /* there's not concensus that this is really a thing... */
		{"signature-number", 'u', POPT_ARG_INT, &ctx.signum, -1,
			"specify which signature to operate on","<sig-number>"},
#endif
		{"list-signatures", 'l', POPT_ARG_NONE|POPT_ARG_VAL, &list, 1,
			"list signatures", NULL },
		{"export-signature", 'e', POPT_ARG_STRING, &ctx.outsig, 0,
			"export signature to file", "<outsig>" },
		{"remove-signature", 'r', POPT_ARG_INT, &remove, -1,
			"remove signature", "<sig-number>" },
		{"ascii-armor", 'a', POPT_ARG_VAL, &ctx.ascii, 1,
			"use ascii armoring", NULL },
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	pesign_context_init(ctxp);

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

	int action = 0;
	if (ctx.insig)
		action |= IMPORT_SIGNATURE;

	if (ctx.outsig)
		action |= EXPORT_SIGNATURE;

	if (remove != -1)
		action |= REMOVE_SIGNATURE;

	if (list != 0)
		action |= LIST_SIGNATURES;

	if (ctx.sign) {
		action |= GENERATE_SIGNATURE;
		if (!(action & EXPORT_SIGNATURE))
			action |= IMPORT_SIGNATURE;
	}

	rc = crypto_init();
	if (rc < 0) {
		fprintf(stderr, "Could not initialize cryptographic library\n");
		exit(1);
	}

	switch (action) {
		case NO_FLAGS:
			fprintf(stderr, "pesign: Nothing to do.\n");
			exit(0);
			break;
		/* add a signature from a file */
		case IMPORT_SIGNATURE:
			check_inputs(ctxp);
			open_input(ctxp);
			open_output(ctxp);
			open_sig_input(ctxp);
			parse_signature(ctxp);
			import_signature(ctxp);
			break;
		/* find a signature in the binary and save it to a file */
		case EXPORT_SIGNATURE:
			open_input(ctxp);
			open_sig_output(ctxp);
			export_signature(ctxp);
			break;
		/* remove a signature from the binary */
		case REMOVE_SIGNATURE:
			check_inputs(ctxp);
			open_input(ctxp);
			open_output(ctxp);
			rc = remove_signature(&ctx, remove);
			break;
		/* list signatures in the binary */
		case LIST_SIGNATURES:
			open_input(ctxp);
			list_signatures(ctxp);
			break;
		/* generate a signature and save it in a separate file */
		case EXPORT_SIGNATURE|GENERATE_SIGNATURE:
			open_certificate(ctxp);
			open_input(ctxp);
			open_sig_output(ctxp);
			generate_signature(ctxp);
			export_signature(ctxp);
			break;
		/* generate a signature and embed it in the binary */
		case IMPORT_SIGNATURE|GENERATE_SIGNATURE:
			check_inputs(ctxp);
			open_certificate(ctxp);
			open_input(ctxp);
			open_output(ctxp);
			generate_signature(ctxp);
			import_signature(ctxp);
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
	crypto_fini();
	return (rc < 0);
}
