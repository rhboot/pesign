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
#include <sys/stat.h>
#include <sys/types.h>

#include "pesign.h"
#include "pesign_standalone.h"

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

	int rc = parse_signatures(&ctx->cms_ctx->signatures,
				  &ctx->cms_ctx->num_signatures, ctx->inpe);
	if (rc < 0) {
		fprintf(stderr, "pesign: could not parse signature list in "
			"EFI binary\n");
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

	finalize_signatures(ctx->cms_ctx->signatures,
				ctx->cms_ctx->num_signatures, ctx->outpe);
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

	cms_context *ctx = pctx->cms_ctx;
	if (!ctx)
		return;

	printf("%s ", pctx->infile);
	int j = ctx->selected_digest;
	for (unsigned int i = 0; i < ctx->digests[j].pe_digest->len; i++)
		printf("%02x",
			(unsigned char)ctx->digests[j].pe_digest->data[i]);
	printf("\n");
}

void
pe_handle_action(pesign_context *ctxp, int action, int padding)
{
	ssize_t sigspace = 0;
	int rc;

	switch (action) {
		case IMPORT_RAW_SIGNATURE|IMPORT_SATTRS:
			check_inputs(ctxp);
			rc = find_certificate(ctxp->cms_ctx, 0);
			if (rc < 0) {
				fprintf(stderr, "pesign: Could not find "
					"certificate %s\n",
					ctxp->cms_ctx->certname);
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
			generate_digest(ctxp->cms_ctx, ctxp->outpe, 1);
			sigspace = calculate_signature_space(ctxp->cms_ctx,
								ctxp->outpe);
			allocate_signature_space(ctxp->outpe, sigspace);
			generate_signature(ctxp->cms_ctx);
			insert_signature(ctxp->cms_ctx, ctxp->signum);
			close_output(ctxp);
			break;
		case EXPORT_SATTRS:
			open_input(ctxp);
			open_sattr_output(ctxp);
			generate_digest(ctxp->cms_ctx, ctxp->inpe, 1);
			generate_sattr_blob(ctxp);
			close_sattr_output(ctxp);
			close_input(ctxp);
			break;
		/* add a signature from a file */
		case IMPORT_SIGNATURE:
			check_inputs(ctxp);
			if (ctxp->signum > ctxp->cms_ctx->num_signatures + 1) {
				fprintf(stderr, "Invalid signature number.\n");
				exit(1);
			}
			open_input(ctxp);
			open_output(ctxp);
			close_input(ctxp);
			open_sig_input(ctxp);
			parse_signature(ctxp);
			sigspace = get_sigspace_extend_amount(ctxp->cms_ctx,
					ctxp->outpe, &ctxp->cms_ctx->newsig);
			allocate_signature_space(ctxp->outpe, sigspace);
			check_signature_space(ctxp);
			insert_signature(ctxp->cms_ctx, ctxp->signum);
			close_sig_input(ctxp);
			close_output(ctxp);
			break;
		case EXPORT_PUBKEY:
			rc = find_certificate(ctxp->cms_ctx, 1);
			if (rc < 0) {
				fprintf(stderr, "pesign: Could not find "
					"certificate %s\n",
					ctxp->cms_ctx->certname);
				exit(1);
			}
			open_pubkey_output(ctxp);
			export_pubkey(ctxp);
			break;
		case EXPORT_CERT:
			rc = find_certificate(ctxp->cms_ctx, 0);
			if (rc < 0) {
				fprintf(stderr, "pesign: Could not find "
					"certificate %s\n",
					ctxp->cms_ctx->certname);
				exit(1);
			}
			open_cert_output(ctxp);
			export_cert(ctxp);
			break;
		/* find a signature in the binary and save it to a file */
		case EXPORT_SIGNATURE:
			open_input(ctxp);
			open_sig_output(ctxp);
			if (ctxp->signum > ctxp->cms_ctx->num_signatures) {
				fprintf(stderr, "Invalid signature number.\n");
				exit(1);
			}
			if (ctxp->signum < 0)
				ctxp->signum = 0;
			if (ctxp->signum >= ctxp->cms_ctx->num_signatures) {
				fprintf(stderr, "No valid signature #%d.\n",
					ctxp->signum);
				exit(1);
			}
			memcpy(&ctxp->cms_ctx->newsig,
				ctxp->cms_ctx->signatures[ctxp->signum],
				sizeof (ctxp->cms_ctx->newsig));
			export_signature(ctxp->cms_ctx, ctxp->outsigfd, ctxp->ascii);
			close_input(ctxp);
			close_sig_output(ctxp);
			memset(&ctxp->cms_ctx->newsig, '\0',
				sizeof (ctxp->cms_ctx->newsig));
			break;
		/* remove a signature from the binary */
		case REMOVE_SIGNATURE:
			check_inputs(ctxp);
			open_input(ctxp);
			open_output(ctxp);
			close_input(ctxp);
			if (ctxp->signum < 0 ||
					ctxp->signum >=
					ctxp->cms_ctx->num_signatures) {
				fprintf(stderr, "Invalid signature number %d.  "
					"Must be between 0 and %d.\n",
					ctxp->signum,
					ctxp->cms_ctx->num_signatures - 1);
				exit(1);
			}
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
			break;
		/* generate a signature and save it in a separate file */
		case EXPORT_SIGNATURE|GENERATE_SIGNATURE:
			rc = find_certificate(ctxp->cms_ctx, 1);
			if (rc < 0) {
				fprintf(stderr, "pesign: Could not find "
					"certificate %s\n",
					ctxp->cms_ctx->certname);
				exit(1);
			}
			open_input(ctxp);
			open_sig_output(ctxp);
			generate_digest(ctxp->cms_ctx, ctxp->inpe, 1);
			generate_signature(ctxp->cms_ctx);
			export_signature(ctxp->cms_ctx, ctxp->outsigfd, ctxp->ascii);
			break;
		/* generate a signature and embed it in the binary */
		case IMPORT_SIGNATURE|GENERATE_SIGNATURE:
			check_inputs(ctxp);
			rc = find_certificate(ctxp->cms_ctx, 1);
			if (rc < 0) {
				fprintf(stderr, "pesign: Could not find "
					"certificate %s\n",
					ctxp->cms_ctx->certname);
				exit(1);
			}
			if (ctxp->signum > ctxp->cms_ctx->num_signatures + 1) {
				fprintf(stderr, "Invalid signature number.\n");
				exit(1);
			}
			open_input(ctxp);
			open_output(ctxp);
			close_input(ctxp);
			generate_digest(ctxp->cms_ctx, ctxp->outpe, 1);
			sigspace = calculate_signature_space(ctxp->cms_ctx,
							     ctxp->outpe);
			allocate_signature_space(ctxp->outpe, sigspace);
			generate_digest(ctxp->cms_ctx, ctxp->outpe, 1);
			generate_signature(ctxp->cms_ctx);
			insert_signature(ctxp->cms_ctx, ctxp->signum);
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
}
