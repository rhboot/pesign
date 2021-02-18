// SPDX-License-Identifier: GPLv2
/*
 * file_pe.c - decls for our PE file type helpers.
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "fix_coverity.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <prerror.h>
#include <err.h>

#include "pesign.h"
#include "pesign_standalone.h"

static void
open_input(pesign_context *ctx)
{
	conderrx(!ctx->infile, 1, "No input file specified.");

	struct stat statbuf;
	ctx->infd = open(ctx->infile, O_RDONLY|O_CLOEXEC);
	stat(ctx->infile, &statbuf);
	ctx->outmode = statbuf.st_mode;

	conderr(ctx->infd < 0, 1, "Error opening input");

	Pe_Cmd cmd = ctx->infd == STDIN_FILENO ? PE_C_READ : PE_C_READ_MMAP;
	ctx->inpe = pe_begin(ctx->infd, cmd, NULL);
	conderrx(!ctx->inpe, 1, "could not load input file \"%s\": %s",
		 ctx->infile, pe_errmsg(pe_errno()));

	int rc = parse_signatures(&ctx->cms_ctx->signatures,
				  &ctx->cms_ctx->num_signatures, ctx->inpe);
	conderrx(rc < 0, 1, "could not parse signature list in EFI binary");
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
	conderrx(!ctx->outfile, 1, "No output file specified.");

	if (access(ctx->outfile, F_OK) == 0 && ctx->force == 0)
		errx(1, "\"%s\" exists and --force was not given.",
		     ctx->outfile);

	ctx->outfd = open(ctx->outfile, O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC,
			ctx->outmode);
	conderr(ctx->outfd < 0, 1, "Error opening \"%s\" for output",
		ctx->outfile);

	size_t size;
	char *addr;

	addr = pe_rawfile(ctx->inpe, &size);

	ftruncate(ctx->outfd, size);
	lseek(ctx->outfd, 0, SEEK_SET);
	write(ctx->outfd, addr, size);

	Pe_Cmd cmd = ctx->outfd == STDOUT_FILENO ? PE_C_RDWR : PE_C_RDWR_MMAP;
	ctx->outpe = pe_begin(ctx->outfd, cmd, NULL);
	conderrx(!ctx->outpe, 1, "could not load output file \"%s\": %s",
		 ctx->outfile, pe_errmsg(pe_errno()));

	pe_clearcert(ctx->outpe);
}

define_input_file(rawsig, rawsig, "raw signature");
define_input_file(sattr, insattrs, "signed attributes");
define_output_file(sattr, outsattrs, "signed attributes");
define_input_file(sig, insig, "signature");
define_output_file(sig, outsig, "signature");
define_output_file(pubkey, outkey, "pubkey");
define_output_file(cert, outcert, "certificate");

static void
check_inputs(pesign_context *ctx)
{
	conderrx(!ctx->infile, 1, "No input file specified.");
	conderrx(!ctx->outfile, 1, "No output file specified.");

	conderrx(!strcmp(ctx->infile, ctx->outfile), 1,
		 "in-place file editing is not yet supported.");
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
	int perr;
	int rc;

	switch (action) {
		/* in this case we have the actual binary signature and the
		 * signing cert, but not the pkcs7ish certificate that goes
		 * with it.
		 */
		case IMPORT_RAW_SIGNATURE|IMPORT_SATTRS:
			check_inputs(ctxp);
			rc = find_certificate(ctxp->cms_ctx, 0);
			conderrx(rc < 0, 1, "Could not find certificate %s\n",
				 ctxp->cms_ctx->certname);
			open_rawsig_input(ctxp);
			open_sattr_input(ctxp);
			import_raw_signature(ctxp);
			close_sattr_input(ctxp);
			close_rawsig_input(ctxp);

			open_input(ctxp);
			open_output(ctxp);
			close_input(ctxp);
			rc = generate_digest(ctxp->cms_ctx, ctxp->outpe, 1);
			if (rc < 0)
				err(1, "generate_digest() failed");
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
			rc = generate_digest(ctxp->cms_ctx, ctxp->inpe, 1);
			if (rc < 0)
				err(1, "generate_digest() failed");
			generate_sattr_blob(ctxp);
			close_sattr_output(ctxp);
			close_input(ctxp);
			break;
		/* add a signature from a file */
		case IMPORT_SIGNATURE:
			check_inputs(ctxp);
			conderrx(ctxp->signum > ctxp->cms_ctx->num_signatures + 1,
				 1, "Invalid signature number.");
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
			conderrx(rc < 0, 1, "Could not find certificate %s",
				 ctxp->cms_ctx->certname);
			open_pubkey_output(ctxp);
			export_pubkey(ctxp);
			break;
		case EXPORT_CERT:
			rc = find_certificate(ctxp->cms_ctx, 0);
			conderrx(rc < 0, 1, "Could not find certificate %s",
				 ctxp->cms_ctx->certname);
			open_cert_output(ctxp);
			export_cert(ctxp);
			break;
		/* find a signature in the binary and save it to a file */
		case EXPORT_SIGNATURE:
			open_input(ctxp);
			open_sig_output(ctxp);
			conderrx(ctxp->signum > ctxp->cms_ctx->num_signatures,
				 1, "Invalid signature number.");
			if (ctxp->signum < 0)
				ctxp->signum = 0;
			conderrx(ctxp->signum >= ctxp->cms_ctx->num_signatures,
				 1, "No valid signature #%d.", ctxp->signum);
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
			if(ctxp->signum < 0 ||
			   ctxp->signum >= ctxp->cms_ctx->num_signatures) {
				warnx("Invalid signature number %d.",
				      ctxp->signum);
				errx(1, "Must be between 0 and %d.",
				     ctxp->cms_ctx->num_signatures - 1);
			}
			remove_signature(ctxp);
			close_output(ctxp);
			break;
		/* list signatures in the binary */
		case LIST_SIGNATURES:
			open_input(ctxp);
			list_signatures(ctxp);
			break;
		case GENERATE_DIGEST|PRINT_DIGEST|OMIT_VENDOR_CERT:
			open_input(ctxp);
			rc = generate_digest(ctxp->cms_ctx, ctxp->inpe, padding);
			if (rc < 0)
				err(1, "generate_digest() failed");
			print_digest(ctxp);
			break;
		case GENERATE_DIGEST|PRINT_DIGEST:
			open_input(ctxp);
			rc = generate_digest(ctxp->cms_ctx, ctxp->inpe, padding);
			if (rc < 0)
				err(1, "generate_digest() failed");
			print_digest(ctxp);
			break;
		/* generate a signature and save it in a separate file */
		case EXPORT_SIGNATURE|GENERATE_SIGNATURE:
			perr = PORT_GetError();
			dprintf("PORT_GetError():%s:%s", PORT_ErrorToName(perr), PORT_ErrorToString(perr));
			PORT_SetError(0);
			rc = find_certificate(ctxp->cms_ctx, 1);
			conderrx(rc < 0, 1, "Could not find certificate %s",
				 ctxp->cms_ctx->certname);
			open_input(ctxp);
			open_sig_output(ctxp);
			rc = generate_digest(ctxp->cms_ctx, ctxp->inpe, 1);
			if (rc < 0)
				err(1, "generate_digest() failed");
			generate_signature(ctxp->cms_ctx);
			export_signature(ctxp->cms_ctx, ctxp->outsigfd, ctxp->ascii);
			break;
		/* generate a signature and embed it in the binary */
		case IMPORT_SIGNATURE|GENERATE_SIGNATURE:
			check_inputs(ctxp);
			perr = PORT_GetError();
			dprintf("PORT_GetError():%s:%s", PORT_ErrorToName(perr), PORT_ErrorToString(perr));
			rc = find_certificate(ctxp->cms_ctx, 1);
			conderrx(rc < 0, 1, "Could not find certificate %s",
				 ctxp->cms_ctx->certname);
			conderrx(ctxp->signum > ctxp->cms_ctx->num_signatures + 1,
				 1, "Invalid signature number.");
			open_input(ctxp);
			open_output(ctxp);
			close_input(ctxp);
			rc = generate_digest(ctxp->cms_ctx, ctxp->outpe, 1);
			if (rc < 0)
				err(1, "generate_digest() failed");
			sigspace = calculate_signature_space(ctxp->cms_ctx,
							     ctxp->outpe);
			allocate_signature_space(ctxp->outpe, sigspace);
			rc = generate_digest(ctxp->cms_ctx, ctxp->outpe, 1);
			if (rc < 0)
				err(1, "generate_digest() failed");
			generate_signature(ctxp->cms_ctx);
			insert_signature(ctxp->cms_ctx, ctxp->signum);
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

// vim:fenc=utf-8:tw=75:noet
