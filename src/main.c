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

int main(int argc, char *argv[])
{
	int rc;

	pesign_context ctx;

	int force = 0;
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
		{"force", 'f', POPT_ARG_NONE|POPT_ARG_VAL, &force,  1,
			"force overwriting of output file", NULL },
		{"nogaps", 'n', POPT_ARG_NONE|POPT_ARG_VAL, &ctx.hashgaps, 0,
			"skip gaps between sections when signing", NULL },
		{"sign", 's', POPT_ARG_VAL, &ctx.sign, 1,
			"create a new signature", NULL },
		{"import-signature", 'm', POPT_ARG_STRING, &ctx.insig, 0,
			"import signature from file", "<insig>" },
		{"signature-number", 'u', POPT_ARG_INT, &ctx.signum, -1,
			"specify which signature to operate on","<sig-number>"},
		{"list-signatures", 'l', POPT_ARG_NONE|POPT_ARG_VAL, &list, 1,
			"list signatures", NULL },
		{"export-signature", 'e', POPT_ARG_STRING, &ctx.outsig, 0,
			"export signature to file", "<outsig>" },
		{"remove-signature", 'r', POPT_ARG_INT, &remove, -1,
			"remove signature", "<sig-number>" },
		POPT_AUTOHELP
		POPT_TABLEEND
	};
	mode_t outmode = 0644;
	struct stat statbuf;

	pesign_context_init(&ctx);

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

	if (!ctx.infile) {
		fprintf(stderr, "No input file specified.\n");
		exit(1);
	}

	if (!strcmp(ctx.infile, "-")) {
		ctx.infd = STDIN_FILENO;
	} else {
		ctx.infd = open(ctx.infile, O_RDONLY|O_CLOEXEC);
		stat(ctx.infile, &statbuf); 
		outmode = statbuf.st_mode;
	}

	if (ctx.infd < 0) {
		fprintf(stderr, "Error opening input: %m\n");
		exit(1);
	}

	Pe_Cmd cmd = ctx.infd == STDIN_FILENO ? PE_C_READ : PE_C_READ_MMAP;
	ctx.inpe = pe_begin(ctx.infd, cmd, NULL);
	if (!ctx.inpe) {
		fprintf(stderr, "pesign: could not load input file: %s\n",
			pe_errmsg(pe_errno()));
		exit(1);
	}

	if (list) {
		rc = list_signatures(&ctx);
		exit(rc);
	}

	if (!ctx.outfile) {
		fprintf(stderr, "No output file specified.\n");
		exit(1);
	}

	if (!strcmp(ctx.infile, ctx.outfile) && strcmp(ctx.infile,"-")) {
		fprintf(stderr, "pesign: in-place file editing is not yet "
				"supported\n");
		exit(1);
	}

	if (!strcmp(ctx.outfile, "-")) {
		ctx.outfd = STDOUT_FILENO;
	} else {
		if (access(ctx.outfile, F_OK) == 0 && force == 0) {
			fprintf(stderr, "pesign: \"%s\" exits and --force was "
					"not given.\n", ctx.outfile);
			exit(1);
		}
		ctx.outfd = open(ctx.outfile, O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC,
				 outmode);
	}
	if (ctx.outfd < 0) {
		fprintf(stderr, "Error opening output: %m\n");
		exit(1);
	}

	if (remove) {
		rc = remove_signature(&ctx, remove);
		exit(rc);
	}

	rc = crypto_init();
	if (rc < 0) {
		fprintf(stderr, "Could not initialize cryptographic library\n");
		exit(1);
	}

	if (ctx.certfile) {
		int certfd = open(ctx.certfile, O_RDONLY|O_CLOEXEC);

		if (certfd < 0) {
			fprintf(stderr, "pesign: could not open certificate "
					"\"%s\": %m\n", ctx.certfile);
			exit(1);
		}

		rc = read_cert(certfd, &ctx.cert);
		if (rc < 0) {
			fprintf(stderr, "pesign: could not read certificate\n");
			exit(1);
		}
	}

	cmd = ctx.outfd == STDOUT_FILENO ? PE_C_WRITE : PE_C_WRITE_MMAP;
	ctx.outpe = pe_begin(ctx.outfd, cmd, ctx.inpe);
	if (!ctx.outpe) {
		fprintf(stderr, "pesign: could not load output file: %s\n",
			pe_errmsg(pe_errno()));
		exit(1);
	}

	if (ctx.cert)
		pe_sign(&ctx);

	pesign_context_fini(&ctx);
	crypto_fini();
	return 0;
}
