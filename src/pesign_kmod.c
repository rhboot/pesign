// SPDX-License-Identifier: GPLv2
/*
 * pesign_kmod.c - implement kmod signing
 * Copyright 2017 Endless Mobile, Inc.
 *
 * Author(s): Daniel Drake <drake@endlessm.com>
 */

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include "pesign.h"
#include "pesign_standalone.h"
#include "file_kmod.h"

static void
open_input(pesign_context *ctx)
{
	struct stat statbuf;

	if (!ctx->infile) {
		fprintf(stderr, "pesign: No input file specified.\n");
		exit(1);
	}

	ctx->infd = open(ctx->infile, O_RDONLY|O_CLOEXEC);
	if (ctx->infd < 0) {
		fprintf(stderr, "pesign: Error opening input: %m\n");
		exit(1);
	}

	if (fstat(ctx->infd, &statbuf)) {
		fprintf(stderr, "pesign: Error on stat input: %m\n");
		exit(1);
	}

	ctx->outmode = statbuf.st_mode;
	ctx->inlength = statbuf.st_size;
}

static void
close_input(pesign_context *ctx)
{
	close(ctx->infd);
	ctx->infd = -1;
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
}

static void
close_output(pesign_context *ctx)
{
	close(ctx->outfd);
	ctx->outfd = -1;
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
import_sig_input(pesign_context *ctx)
{
	unsigned char *map;
	struct stat statbuf;
	int rc;

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

	rc = fstat(ctx->insigfd, &statbuf);
	conderr(rc < 0, 1, "Could not fstat signature file \"%s\"",
		ctx->insig);

	/* Copy original module data */

	map = mmap(NULL, ctx->inlength, PROT_READ, MAP_PRIVATE, ctx->infd, 0);
	conderr(map == MAP_FAILED, 1, "Could not map kmod input");

	rc = write_file(ctx->outfd, map, ctx->inlength);
	conderr(rc < 0, 1, "Failed to write module data");

	munmap(map, ctx->inlength);

	/* Append signature to output. */

	map = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, ctx->insigfd,
		   0);
	conderr(map == MAP_FAILED, 1, "Could not map signature input \"%s\"",
		ctx->insig);

	rc = write_file(ctx->outfd, map, statbuf.st_size);
	conderr(rc < 0, 1, "Error writing output");

	munmap(map, statbuf.st_size);
}

static void
handle_signing(pesign_context *ctx, int outfd, int attached)
{
	int	rc;
	unsigned char *inmap;
	ssize_t sig_len;

	inmap = mmap(NULL, ctx->inlength, PROT_READ, MAP_PRIVATE, ctx->infd, 0);
	conderrx(inmap == MAP_FAILED, 1, "Error mapping input kmod");

	rc = kmod_generate_digest(ctx->cms_ctx, inmap, ctx->inlength);
	if (rc < 0)
		exit(1);

	if (attached) {
		rc = write_file(outfd, inmap, ctx->inlength);
		conderr(rc < 0, 1, "Failed to write module data");
	}
	munmap(inmap, ctx->inlength);

	sig_len = kmod_write_signature(ctx->cms_ctx, outfd);
	if (sig_len < 0)
		exit(1);

	if (kmod_write_sig_info(ctx->cms_ctx, outfd, sig_len) < 0)
		exit(1);
}

void
kmod_handle_action(pesign_context *ctxp, int action)
{
	int rc;

	switch (action) {
		/* generate a signature and embed it in the module */
		case IMPORT_SIGNATURE|GENERATE_SIGNATURE:
			rc = find_certificate(ctxp->cms_ctx, 1);
			conderrx(rc < 0, 1, "Could not find certificate \"%s\"",
				 ctxp->cms_ctx->certname);
			conderrx(ctxp->signum > ctxp->cms_ctx->num_signatures + 1,
				 1, "Invalid signature number.");

			open_input(ctxp);
			open_output(ctxp);
			handle_signing(ctxp, ctxp->outfd, 1);
			close_output(ctxp);
			close_input(ctxp);
			break;

		/* generate a signature and save it in a separate file */
		case EXPORT_SIGNATURE|GENERATE_SIGNATURE:
			rc = find_certificate(ctxp->cms_ctx, 1);
			conderrx(rc < 0, 1, "Could not find certificate \"%s\"",
				 ctxp->cms_ctx->certname);
			conderrx(ctxp->signum > ctxp->cms_ctx->num_signatures + 1,
				 1, "Invalid signature number.");

			open_input(ctxp);
			open_sig_output(ctxp);
			handle_signing(ctxp, ctxp->outsigfd, 0);
			close_sig_output(ctxp);
			close_input(ctxp);
			break;

		/* add a signature from a file */
		case IMPORT_SIGNATURE:
			conderrx(ctxp->signum > ctxp->cms_ctx->num_signatures + 1,
				 1, "Invalid signature number.");
			open_input(ctxp);
			open_output(ctxp);
			import_sig_input(ctxp);
			close_input(ctxp);
			close_output(ctxp);
			break;

		default:
			fprintf(stderr, "%s: Incompatible flags (0x%08x): ",
				program_invocation_short_name, action);
			for (int i = 1; i < FLAG_LIST_END; i <<= 1) {
				if (action & i)
					print_flag_name(stderr, i);
			}
			fprintf(stderr, "\n");
			exit(1);
	}
}
