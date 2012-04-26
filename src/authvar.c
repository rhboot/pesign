/*
 * Copyright 2012 Red Hat, Inc.
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

#include <popt.h>

#include "authvar.h"

static void
check_name(authvar_context *ctx)
{
	if (!ctx->name || !*ctx->name) {
		fprintf(stderr, "authvar: no name specified.\n");
		exit(1);
	}
}

static void
check_value(authvar_context *ctx, int needed)
{
	if ((!ctx->value || !*ctx->value) &&
			(!ctx->valuefile || !*ctx->valuefile)) {
		if (needed)
			fprintf(stderr, "authvar: no value specified.\n");
		else
			fprintf(stderr,
				"authvar: command does not take a value.\n");
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	int rc;
	authvar_context ctx = { 0, };
	authvar_context *ctxp = &ctx;

	rc = authvar_context_init(ctxp);
	if (rc < 0) {
		fprintf(stderr, "Could not initialize context: %m\n");
		exit(1);
	}

	poptContext optCon;
	struct poptOption options[] = {
		{ NULL, '\0', POPT_ARG_INTL_DOMAIN, "pesign" },
		{ "append", 'a', POPT_ARG_VAL, &ctx.action, append,
			"append to variable" },
		{ "clear", 'c', POPT_ARG_VAL, &ctx.action, clear,
			"clear variable" },
		{ "set", 's', POPT_ARG_VAL, &ctx.action, set, "set variable" },
		{ "namespace", 'N', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
			&ctx.namespace, 0,
			"specified variable is in <namespace>" ,"<namespace>" },
		{ "name", 'n', POPT_ARG_STRING, &ctx.name, 0, "variable name",
			"<name>" },
		{ "value", 'v', POPT_ARG_STRING, &ctx.value, 0,
			"value to set or append", "<value>" },
		{ "valuefile", 'f', POPT_ARG_STRING, &ctx.valuefile, 0,
			"read value from <file>", "<file>" },
		{ "import", 'i', POPT_ARG_STRING, &ctx.importfile, 0,
			"import variable from <file>", "<file>" },
		{ "export", 'e', POPT_ARG_STRING, &ctx.exportfile, 0,
			"export variable to <file> instead of firmware",
			"<file>" },
		{ "sign", 'S', POPT_ARG_STRING, &ctx.cms_ctx.certname, 0,
			"sign variable with certificate <nickname>",
			"<nickname>" },
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext("authvar", argc, (const char **)argv,
				options, 0);
	while ((rc = poptGetNextOpt(optCon)) > 0)
		;

	if (rc < -1) {
		fprintf(stderr, "authvar: Invalid argument: %s: %s\n",
			poptBadOption(optCon, 0), poptStrerror(rc));
		exit(1);
	}

	if (poptPeekArg(optCon)) {
		fprintf(stderr, "authvar: Invalid Argument: \"%s\"\n",
			poptPeekArg(optCon));
		exit(1);
	}

	poptFreeContext(optCon);

	switch (ctx.action) {
	case none:
		fprintf(stderr, "authvar: No action specified\n");
		exit(1);
	case append:
		check_name(ctxp);
		check_value(ctxp, 1);
		break;
	case set:
		check_name(ctxp);
		check_value(ctxp, 1);
		break;
	case clear:
		check_name(ctxp);
		check_value(ctxp, 0);
		break;
	}

	if (ctx.cms_ctx.certname && *ctx.cms_ctx.certname) {
		rc = find_certificate(&ctx.cms_ctx);
		if (rc < 0) {
			fprintf(stderr, "authvar: Could not find certificate "
				"for \"%s\"\n", ctx.cms_ctx.certname);
			exit(1);
		}
	}

	authvar_context_fini(ctxp);
	return 0;
}
