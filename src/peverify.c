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

#include "peverify.h"

static void
open_input(peverify_context *ctx)
{
	if (!ctx->infile) {
		fprintf(stderr, "pesign: No input file specified.\n");
		exit(1);
	}

	ctx->infd = open(ctx->infile, O_RDONLY|O_CLOEXEC);

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
close_input(peverify_context *ctx)
{
	pe_end(ctx->inpe);
	ctx->inpe = NULL;

	close(ctx->infd);
	ctx->infd = -1;
}

static void
check_inputs(peverify_context *ctx)
{
	if (!ctx->infile) {
		fprintf(stderr, "pesign: No input file specified.\n");
		exit(1);
	}
}

int
main(int argc, char *argv[])
{
	int rc;

	peverify_context ctx, *ctxp = &ctx;

	poptContext optCon;
	struct poptOption options[] = {
		{NULL, '\0', POPT_ARG_INTL_DOMAIN, "pesign" },
		{"in", 'i', POPT_ARG_STRING, &ctx.infile, 0,
			"specify input file", "<infile>"},
		{"quiet", 'i', POPT_BIT_SET, &ctx.quiet, 1,
			"return only; no text output.", NULL },
		{"dbfile", 'd', POPT_ARG_STRING, &ctx.dbfile, 0,
			"use file for allowed certificate list", "<dbfile>" },
		{"dbxfile", 'd', POPT_ARG_STRING, &ctx.dbxfile, 0,
			"use file for disallowed certificate list","<dbxfile>"},
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	rc = peverify_context_init(ctxp);
	if (rc < 0) {
		fprintf(stderr, "peverify: Could not initialize context: %m\n");
		exit(1);
	}

	optCon = poptGetContext("peverify", argc, (const char **)argv,
				options,0);

	while ((rc = poptGetNextOpt(optCon)) > 0)
		;

	if (rc < -1) {
		fprintf(stderr, "peverify: Invalid argument: %s: %s\n",
			poptBadOption(optCon, 0), poptStrerror(rc));
		exit(1);
	}

	if (poptPeekArg(optCon)) {
		fprintf(stderr, "peverify: Invalid Argument: \"%s\"\n",
				poptPeekArg(optCon));
		exit(1);
	}

	poptFreeContext(optCon);

	check_inputs(ctxp);
	open_input(ctxp);


	close_input(ctxp);
	peverify_context_fini(&ctx);
	return (rc < 0);
}
