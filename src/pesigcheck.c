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
#include <sys/stat.h>
#include <sys/types.h>
#include <nss.h>

#include <popt.h>

#include <prerror.h>
#include <cert.h>
#include <pkcs7t.h>
#include <pk11pub.h>

#include "pesigcheck.h"

static void
open_input(pesigcheck_context *ctx)
{
	if (!ctx->infile)
		errx(1, "No input file specified");

	ctx->infd = open(ctx->infile, O_RDONLY|O_CLOEXEC);

	if (ctx->infd < 0)
		err(1, "Error opening input");

	Pe_Cmd cmd = ctx->infd == STDIN_FILENO ? PE_C_READ : PE_C_READ_MMAP;
	ctx->inpe = pe_begin(ctx->infd, cmd, NULL);
	if (!ctx->inpe)
		peerr(1, "Could not load input file");

	int rc = parse_pe_signatures(&ctx->cms_ctx->signatures,
					&ctx->cms_ctx->num_signatures,
					ctx->inpe);
	if (rc < 0)
		errx(1, "Could not parse signature list in EFI binary");
}

static void
close_input(pesigcheck_context *ctx)
{
	pe_end(ctx->inpe);
	ctx->inpe = NULL;

	close(ctx->infd);
	ctx->infd = -1;
}

static void
check_inputs(pesigcheck_context *ctx)
{
	if (!ctx->infile)
		errx(1, "No input file specified");
}

static int
cert_matches_digest(pesigcheck_context *ctx, void *data, ssize_t datalen)
{
	SECItem sig, *pe_digest, *content;
	uint8_t *digest;
	SEC_PKCS7ContentInfo *cinfo = NULL;
	int ret = -1;

	sig.data = data;
	sig.len = datalen;
	sig.type = siBuffer;

	cinfo = SEC_PKCS7DecodeItem(&sig, NULL, NULL, NULL, NULL, NULL,
				    NULL, NULL);

	if (!SEC_PKCS7ContentIsSigned(cinfo))
		goto out;

	/* TODO Find out the digest type in spc_content */
	pe_digest = ctx->cms_ctx->digests[0].pe_digest;
	content = cinfo->content.signedData->contentInfo.content.data;
	digest = content->data + content->len - pe_digest->len;
	if (memcmp(pe_digest->data, digest, pe_digest->len) != 0)
		goto out;

	ret = 0;
out:
	if (cinfo)
		SEC_PKCS7DestroyContentInfo(cinfo);

	return ret;
}

static int
check_signature(pesigcheck_context *ctx)
{
	int has_valid_cert = 0;
	int has_invalid_cert = 0;
	int rc = 0;

	pe_cert_iter iter;

	generate_digest(ctx->cms_ctx, ctx->inpe, 1);

	if (check_db_hash(DBX, ctx) == FOUND)
		return -1;

	if (check_db_hash(DB, ctx) == FOUND)
		has_valid_cert = 1;

	rc = pe_cert_iter_init(&iter, ctx->inpe);
	if (rc < 0)
		goto err;

	void *data;
	ssize_t datalen;

	while (1) {
		rc = next_pe_cert(&iter, &data, &datalen);
		if (rc <= 0)
			break;

		if (cert_matches_digest(ctx, data, datalen) < 0) {
			has_invalid_cert = 1;
			break;
		}

		if (check_db_cert(DBX, ctx, data, datalen) == FOUND) {
			has_invalid_cert = 1;
			break;
		}

		if (check_db_cert(DB, ctx, data, datalen) == FOUND)
			has_valid_cert = 1;
	}

err:
	if (has_invalid_cert)
		return -1;

	if (has_valid_cert)
		return 0;

	return -1;
}

void
callback(poptContext con, enum poptCallbackReason reason,
	 const struct poptOption *opt,
	 const char *arg, const void *data)
{
	pesigcheck_context *ctx = (pesigcheck_context *)data;
	int rc = 0;
	if (!opt)
		return;
	if (opt->shortName == 'D') {
		rc = add_cert_db(ctx, arg);
	} else if (opt->shortName == 'X') {
		rc = add_cert_dbx(ctx, arg);
	} else if (opt->shortName == 'c') {
		rc = add_cert_file(ctx, arg);
	}
	if (rc != 0)
		err(1, "Could not add %s from file \"%s\"",
			opt->shortName == 'D' ? "DB" : "DBX", arg);
}

int
main(int argc, char *argv[])
{
	int rc;

	pesigcheck_context ctx, *ctxp = &ctx;

	char *dbfile = NULL;
	char *dbxfile = NULL;
	char *certfile = NULL;
	int use_system_dbs = 1;

	SECStatus status;

	poptContext optCon;
	struct poptOption options[] = {
		{"dbfile", 'D', POPT_ARG_CALLBACK|POPT_CBFLAG_POST, (void *)callback, 0, (void *)ctxp, NULL },
		{NULL, '\0', POPT_ARG_INTL_DOMAIN, "pesign" },
		{"in", 'i', POPT_ARG_STRING, &ctx.infile, 0,
			"specify input file", "<infile>"},
		{"quiet", 'q', POPT_BIT_SET, &ctx.quiet, 1,
			"return only; no text output.", NULL },
		{"no-system-db", 'n', POPT_ARG_INT, &use_system_dbs, 0,
			"inhibit the use of DB and DBX from the running system",
			NULL },
		{"dbfile", 'D', POPT_ARG_STRING, &dbfile, 0,
			"use file for allowed certificate list", "<dbfile>" },
		{"dbxfile", 'X', POPT_ARG_STRING, &dbxfile, 0,
			"use file for disallowed certificate list","<dbxfile>"},
		{"certfile", 'c', POPT_ARG_STRING, &certfile, 0,
			"the certificate (in DER form) for verification ","<certfile>"},
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	rc = pesigcheck_context_init(ctxp);
	if (rc < 0)
		err(1, "Could not initialize context: %m");

	optCon = poptGetContext("pesigcheck", argc, (const char **)argv,
				options,0);

	while ((rc = poptGetNextOpt(optCon)) > 0)
		;

	if (rc < -1)
		errx(1, "Invalid argument: %s: %s",
			poptBadOption(optCon, 0), poptStrerror(rc));

	if (poptPeekArg(optCon))
		errx(1, "Invalid Argument: \"%s\"", poptPeekArg(optCon));

	poptFreeContext(optCon);

	check_inputs(ctxp);
	open_input(ctxp);

	init_cert_db(ctxp, use_system_dbs);

	status = NSS_NoDB_Init(NULL);
	if (status != SECSuccess)
		nsserr(1, "Could not initialize nss");

	rc = check_signature(ctxp);

	close_input(ctxp);
	if (!ctx.quiet)
		printf("pesigcheck: \"%s\" is %s.\n", ctx.infile,
			rc >= 0 ? "valid" : "invalid");
	pesigcheck_context_fini(&ctx);

	NSS_Shutdown();

	return (rc < 0);
}
