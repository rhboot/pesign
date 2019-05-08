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

#include "fix_coverity.h"

#include <err.h>
#include <fcntl.h>
#include <stdbool.h>
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
	if (!ctx->infile) {
		fprintf(stderr, "pesigcheck: No input file specified.\n");
		exit(1);
	}

	ctx->infd = open(ctx->infile, O_RDONLY|O_CLOEXEC);

	if (ctx->infd < 0) {
		fprintf(stderr, "pesigcheck: Error opening input: %m\n");
		exit(1);
	}

	Pe_Cmd cmd = ctx->infd == STDIN_FILENO ? PE_C_READ : PE_C_READ_MMAP;
	ctx->inpe = pe_begin(ctx->infd, cmd, NULL);
	if (!ctx->inpe) {
		fprintf(stderr, "pesigcheck: could not load input file: %s\n",
			pe_errmsg(pe_errno()));
		exit(1);
	}

	int rc = parse_signatures(&ctx->cms_ctx->signatures,
					&ctx->cms_ctx->num_signatures,
					ctx->inpe);
	if (rc < 0) {
		fprintf(stderr, "pesigcheck: could not parse signature list in "
			"EFI binary\n");
		exit(1);
	}
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
	if (!ctx->infile) {
		fprintf(stderr, "pesign: No input file specified.\n");
		exit(1);
	}
}

static int
cert_matches_digest(pesigcheck_context *ctx, void *data, ssize_t datalen,
		    SECItem *digest_out)
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
	if (digest_out) {
		digest_out->data = malloc(pe_digest->len);
		digest_out->len = pe_digest->len;
		digest_out->type = pe_digest->type;
		memcpy(digest_out->data, digest, pe_digest->len);
	}
	if (memcmp(pe_digest->data, digest, pe_digest->len) != 0)
		goto out;

	ret = 0;
out:
	if (cinfo)
		SEC_PKCS7DestroyContentInfo(cinfo);

	return ret;
}

struct reason {
	enum {
		WHITELISTED = 0,
		INVALID = 1,
		BLACKLISTED = 2,
		NO_WHITELIST = 3,
	} reason;
	enum {
		NONE = 0,
		DIGEST = 1,
		SIGNATURE = 2,
	} type;
	union {
		struct {
			SECItem digest;
		};
		struct {
			SECItem sig;
			SECItem db_cert;
		};
	};
};

static void
print_digest(SECItem *digest)
{
	char buf[digest->len * 2 + 2];

	for (unsigned int i = 0; i < digest->len; i++)
		snprintf(buf + i * 2, digest->len * 2, "%02x",
			 digest->data[i]);
	buf[digest->len * 2] = '\0';
	printf("%s\n", buf);
}

static void
print_certificate(SECItem *cert)
{
	printf("put a breakpoint at %s:%d\n", __FILE__, __LINE__);
	printf("cert: %p\n", cert);
}

static void
print_signatures(SECItem *database_cert, SECItem *signature)
{
	printf("put a breakpoint at %s:%d\n", __FILE__, __LINE__);
	print_certificate(database_cert);
	print_certificate(signature);
}

static void
print_reason(struct reason *reason)
{
	switch (reason->reason) {
	case WHITELISTED:
		printf("Whitelist entry: ");
		if (reason->type == DIGEST)
			print_digest(&reason->digest);
		else if (reason->type == SIGNATURE)
			print_signatures(&reason->sig, &reason->db_cert);
		else
			errx(1, "Unknown data type %d\n", reason->type);
		break;
	case INVALID:
		if (reason->type == DIGEST) {
			printf("Invalid digest: ");
			print_digest(&reason->digest);
		} else if (reason->type == SIGNATURE) {
			printf("Invalid signature: ");
			print_signatures(&reason->sig, &reason->db_cert);
		} else {
			errx(1, "Unknown data type %d\n", reason->type);
		}
		break;
	case BLACKLISTED:
		if (reason->type == DIGEST) {
			printf("Invalid digest: ");
			print_digest(&reason->digest);
		} else if (reason->type == SIGNATURE) {
			printf("Invalid signature: ");
			print_signatures(&reason->sig, &reason->db_cert);
		} else {
			errx(1, "Unknown data type %d\n", reason->type);
		}
		break;
	case NO_WHITELIST:
		if (reason->type == NONE)
			printf("No matching whitelist entry.\n");
		else
			errx(1, "Invalid data type %d\n", reason->type);
		break;
	default:
		errx(1, "Unknown reason type %d\n", reason->reason);
		break;
	}
}

static void
get_digest(pesigcheck_context *ctx, SECItem *digest)
{
	struct cms_context *cms = ctx->cms_ctx;
	struct digest *cms_digest = &cms->digests[cms->selected_digest];

	memcpy(digest, cms_digest->pe_digest, sizeof (*digest));
}

static int
check_signature(pesigcheck_context *ctx, int *nreasons,
		struct reason **reasons)
{
	bool has_valid_cert = false;
	bool is_invalid = false;
	struct reason *reasonps = NULL, *reason;
	int num_reasons = 16;
	int nreason = 0;
	int rc = 0;
	int ret = -1;

	cert_iter iter;

	reasonps = calloc(sizeof(struct reason), 512);
	if (!reasonps)
		err(1, "check_signature");

	generate_digest(ctx->cms_ctx, ctx->inpe, 1);

	if (check_db_hash(DBX, ctx) == FOUND) {
		reason = &reasonps[nreason];
		reason->reason = BLACKLISTED;
		reason->type = DIGEST;
		get_digest(ctx, &reason->digest);
		reason += 1;
		is_invalid = true;
	}

	if (check_db_hash(DB, ctx) == FOUND) {
		reason = &reasonps[nreason];
		reason->reason = WHITELISTED;
		reason->type = DIGEST;
		get_digest(ctx, &reason->digest);
		nreason += 1;
		has_valid_cert = true;
	}

	rc = cert_iter_init(&iter, ctx->inpe);
	if (rc < 0)
		goto err;

	void *data;
	ssize_t datalen;

	while (1) {
		/*
		 * Make sure we always have enough for this iteration of the
		 * loop, plus one "NO_WHITELIST" entry at the end.
		 */
		if (nreason >= num_reasons - 4) {
			struct reason *new_reasons;

			num_reasons += 16;

			new_reasons = calloc(sizeof(struct reason), num_reasons);
			if (!new_reasons)
				err(1, "check_signature");
			reasonps = new_reasons;
		}

		rc = next_cert(&iter, &data, &datalen);
		if (rc <= 0)
			break;

		reason = &reasonps[nreason];
		if (cert_matches_digest(ctx, data, datalen,
					&reason->digest) < 0) {
			reason->reason = INVALID;
			reason->type = DIGEST;
			nreason += 1;
			is_invalid = true;
		}

		reason = &reasonps[nreason];
		if (check_db_cert(DBX, ctx, data, datalen,
				  &reason->db_cert) == FOUND) {
			reason->reason = INVALID;
			reason->type = SIGNATURE;
			reason->sig.data = data;
			reason->sig.len = datalen;
			reason->type = siBuffer;
			nreason += 1;
			is_invalid = true;
		}

		reason = &reasonps[nreason];
		if (check_db_cert(DB, ctx, data, datalen,
				  &reason->db_cert) == FOUND) {
			reason->reason = WHITELISTED;
			reason->type = SIGNATURE;
			reason->sig.data = data;
			reason->sig.len = datalen;
			reason->type = siBuffer;
			nreason += 1;
			has_valid_cert = true;
		}
	}

err:
	if (has_valid_cert != true) {
		if (is_invalid != true) {
			reason = &reasonps[nreason];
			reason->reason = NO_WHITELIST;
			reason->type = NONE;
			nreason += 1;
		}
		is_invalid = true;
	}

	if (is_invalid == false)
		ret = 0;

	if (nreasons && reasons) {
		*nreasons = nreason;
		*reasons = reasonps;
	} else {
		free(reasonps);
	}

	return ret;
}

void
callback(poptContext con UNUSED,
	 enum poptCallbackReason reason UNUSED,
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
	if (rc != 0) {
		fprintf(stderr, "Could not add %s from file \"%s\": %m\n",
			opt->shortName == 'D' ? "DB" : "DBX", arg);
		exit(1);
	}
}

int
main(int argc, char *argv[])
{
	int rc;

	pesigcheck_context ctx, *ctxp = &ctx;

	struct reason *reasons = NULL;
	int nreasons = 0;

	char *dbfile = NULL;
	char *dbxfile = NULL;
	char *certfile = NULL;
	int use_system_dbs = 1;

	SECStatus status;

	poptContext optCon;
	struct poptOption options[] = {
		{.argInfo = POPT_ARG_INTL_DOMAIN,
		 .arg = "pesign" },
		{.longName = "dbfile",
		 .shortName = 'D',
		 .argInfo = POPT_ARG_CALLBACK|POPT_CBFLAG_POST,
		 .arg = (void *)callback,
		 .descrip = (void *)ctxp },
		{.longName = "dbxfile",
		 .shortName = 'X',
		 .argInfo = POPT_ARG_CALLBACK|POPT_CBFLAG_POST,
		 .arg = (void *)callback,
		 .descrip = (void *)ctxp },
		{.longName = "certfile",
		 .shortName = 'c',
		 .argInfo = POPT_ARG_CALLBACK|POPT_CBFLAG_POST,
		 .arg = (void *)callback,
		 .descrip = (void *)ctxp },
		{.longName = "in",
		 .shortName = 'i',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &ctx.infile,
		 .descrip = "specify input file",
		 .argDescrip = "<infile>"},
		{.longName = "quiet",
		 .shortName = 'q',
		 .argInfo = POPT_BIT_SET,
		 .arg = &ctx.quiet,
		 .val = 1,
		 .descrip = "return only; no text output." },
		{.longName = "verbose",
		 .shortName = 'v',
		 .argInfo = POPT_BIT_SET,
		 .arg = &ctx.verbose,
		 .val = 1,
		 .descrip = "print reasons for success and failure." },
		{.longName = "no-system-db",
		 .shortName = 'n',
		 .argInfo = POPT_ARG_INT,
		 .arg = &use_system_dbs,
		 .descrip = "inhibit the use of DB and DBX from the running system" },
		{.longName = "dbfile",
		 .shortName = 'D',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &dbfile,
		 .descrip = "use file for allowed certificate list",
		 .argDescrip = "<dbfile>" },
		{.longName = "dbxfile",
		 .shortName = 'X',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &dbxfile,
		 .descrip = "use file for disallowed certificate list",
		 .argDescrip = "<dbxfile>" },
		{.longName = "certfile",
		 .shortName = 'c',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &certfile,
		 .descrip = "import certfile (in DER encoding) for allowed certificate",
		 .argDescrip = "<certfile>" },
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	setenv("NSS_DEFAULT_DB_TYPE", "sql", 0);

	rc = pesigcheck_context_init(ctxp);
	if (rc < 0) {
		fprintf(stderr, "pesigcheck: Could not initialize context: %m\n");
		exit(1);
	}

	optCon = poptGetContext("pesigcheck", argc, (const char **)argv,
				options,0);

	while ((rc = poptGetNextOpt(optCon)) > 0)
		;

	if (rc < -1) {
		fprintf(stderr, "pesigcheck: Invalid argument: %s: %s\n",
			poptBadOption(optCon, 0), poptStrerror(rc));
		exit(1);
	}

	if (poptPeekArg(optCon)) {
		fprintf(stderr, "pesigcheck: Invalid Argument: \"%s\"\n",
				poptPeekArg(optCon));
		exit(1);
	}

	poptFreeContext(optCon);

	check_inputs(ctxp);
	open_input(ctxp);

	init_cert_db(ctxp, use_system_dbs);

	status = NSS_NoDB_Init(NULL);
	if (status != SECSuccess) {
		fprintf(stderr, "Could not initialize nss: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		exit(1);
	}

	rc = check_signature(ctxp, &nreasons, &reasons);

	if (!ctx.quiet && ctx.verbose) {
		for (int i = 0; i < nreasons; i++)
			print_reason(&reasons[i]);
	}
	if (!ctx.quiet)
		printf("pesigcheck: \"%s\" is %s.\n", ctx.infile,
			rc >= 0 ? "valid" : "invalid");
	close_input(ctxp);
	pesigcheck_context_fini(&ctx);

	NSS_Shutdown();

	return (rc < 0);
}
