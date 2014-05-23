/*
 * Copyright 2012-2013 Red Hat, Inc.
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
#include <errno.h>
#include <popt.h>

#include "authvar.h"

#define NO_FLAGS		0x00
#define GENERATE_APPEND		0x01
#define GENERATE_CLEAR		0x02
#define GENERATE_SET		0x04
#define SIGN			0x08
#define IMPORT			0x10
#define EXPORT			0x20
#define SET			0x40

#define FLAG_LIST_END		0x80

static struct {
	int flag;
	const char *name;
} flag_names[] = {
	{GENERATE_APPEND, "append" },
	{GENERATE_CLEAR, "clear" },
	{GENERATE_SET, "set" },
	{SIGN, "sign" },
	{IMPORT, "import" },
	{EXPORT, "export" },
	{SET, "set_firmware" },
	{FLAG_LIST_END, NULL },
};

static void
print_flag_name(FILE *f, int flag)
{
	for (int i = 0; flag_names[i].flag != FLAG_LIST_END; i++) {
		if (flag_names[i].flag & flag)
			fprintf(f, "%s ", flag_names[i].name);
	}
}

static void
check_name(authvar_context *ctx)
{
	if (!ctx->name || !*ctx->name)
		errx(1, "No name specified");
}

static void
check_value(authvar_context *ctx, int needed)
{
	if ((!ctx->value || !*ctx->value) &&
			(!ctx->valuefile || !*ctx->valuefile)) {
		if (needed)
			errx(1, "No value specified");
		else
			errx(1, "Command does not take a value");
	}
	if (ctx->value && *ctx->value && ctx->valuefile && *ctx->valuefile) {
		if (needed)
			errx(1, "--value and --valuefile "
				"cannot be used together.\n");
		else
			errx(1, "Command does not take a value.\n");
	}
}

static int
parse_guid(char *text, efi_guid_t *guid)
{
	char buf8[9] = "\0\0\0\0\0\0\0\0\0";
	char buf4[5] = "\0\0\0\0\0";
	char buf2[3] = "\0\0\0";

	efi_guid_t retguid;

	switch (strlen(text)) {
	case 24:
	case 28:
		errno = 0;
		strncpy(buf8, text, 8);
		text += 8;
		retguid.data1 = strtol(buf8, NULL, 16);
		if (errno)
			return -1;
		if (text[0] == '-' || text[0] == ':')
			text++;

		strncpy(buf4, text, 4);
		text += 4;
		retguid.data2 = strtol(buf4, NULL, 16);
		if (errno)
			return -1;
		if (text[0] == '-' || text[0] == ':')
			text++;

		strncpy(buf4, text, 4);
		text += 4;
		retguid.data3 = strtol(buf4, NULL, 16);
		if (errno)
			return -1;
		if (text[0] == '-' || text[0] == ':')
			text++;

		for (int i = 0; i < 8; i++) {
			strncpy(buf2, text, 2);
			text += 2;
			retguid.data4[i] = strtol(buf2, NULL, 16);
			if (errno)
				return -1;
			if (text[0] == '-' || text[0] == ':')
				text++;
		}
		memcpy(guid, &retguid, sizeof (*guid));
		return 0;
	default:
		return -1;
	}
	return 0;
}

static int
find_namespace_guid(authvar_context *ctx)
{
	efi_guid_t global = EFI_GLOBAL_VARIABLE;
	efi_guid_t security = EFI_IMAGE_SECURITY_DATABASE_GUID;
	efi_guid_t rh = RH_GUID;

	if (strcmp(ctx->namespace, "global") == 0) {
		memcpy(&ctx->guid, &global, sizeof (ctx->guid));
		return 0;
	} else if (strcmp(ctx->namespace, "security") == 0) {
		memcpy(&ctx->guid, &security, sizeof (ctx->guid));
		return 0;
	} else if (strcmp(ctx->namespace, "rh") == 0) {
		memcpy(&ctx->guid, &rh, sizeof (ctx->guid));
		return 0;
	}

	return parse_guid(ctx->namespace, &ctx->guid);
}

int main(int argc, char *argv[])
{
	int rc;
	authvar_context ctx = { 0, };
	authvar_context *ctxp = &ctx;

	int action = 0;

	rc = authvar_context_init(ctxp);
	if (rc < 0)
		err(1, "Could not initialize conext");

	poptContext optCon;
	struct poptOption options[] = {
		{ NULL, '\0', POPT_ARG_INTL_DOMAIN, "pesign" },
		{ "append", 'a', POPT_ARG_VAL|POPT_ARGFLAG_OR, &action,
			GENERATE_APPEND, "append to variable" },
		{ "clear", 'c', POPT_ARG_VAL|POPT_ARGFLAG_OR, &action,
			GENERATE_CLEAR, "clear variable" },
		{ "set", 's', POPT_ARG_VAL|POPT_ARGFLAG_OR, &action,
			GENERATE_SET, "set variable" },
		{ "namespace", 'N', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
			&ctx.namespace, 0,
			"specified variable is in <namespace> or <guid>" ,
			"{<namespace>|<guid>}" },
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

	if (ctx.importfile)
		action |= IMPORT;
	if (ctx.exportfile)
		action |= EXPORT;
	if (!(action & (IMPORT|EXPORT)))
		action |= SET;

	if (ctx.cms_ctx.certname && *ctx.cms_ctx.certname) {
		rc = find_certificate(&ctx.cms_ctx, 1);
		if (rc < 0)
			errx(1, "Could not find certificate for \"%s\"",
				ctx.cms_ctx.certname);
		action |= SIGN;
	}

	rc = find_namespace_guid(ctxp);
	if (rc < 0)
		errx(1, "Unable to find guid for \"%s\"",
			ctx.namespace);

	optCon = poptGetContext("authvar", argc, (const char **)argv,
				options, 0);
	while ((rc = poptGetNextOpt(optCon)) > 0)
		;

	if (rc < -1)
		errx(1, "Invalid argument: %s: %s",
			poptBadOption(optCon, 0), poptStrerror(rc));

	if (poptPeekArg(optCon))
		errx(1, "Invalid Argument: \"%s\"", poptPeekArg(optCon));

	poptFreeContext(optCon);

	print_flag_name(stdout, action);
	printf("\n");
	switch (action) {
	case NO_FLAGS:
		errx(1, "No action specified\n");
		break;
	case GENERATE_APPEND|EXPORT:
	case GENERATE_APPEND|SET:
		check_name(ctxp);
		check_value(ctxp, 1);
		break;
	case GENERATE_CLEAR|EXPORT:
	case GENERATE_CLEAR|SET:
		check_name(ctxp);
		check_value(ctxp, 0);
		break;
	case GENERATE_SET|EXPORT:
	case GENERATE_SET|SET:
		check_name(ctxp);
		check_value(ctxp, 1);
		break;
	case IMPORT|SET:
	case IMPORT|SIGN|SET:

	case IMPORT|SIGN|EXPORT:
	default:
		fprintf(stderr, "authvar: invalid flags: ");
		print_flag_name(stderr, action);
		fprintf(stderr, "\n");
		exit(1);
	}

	authvar_context_fini(ctxp);
	return 0;
}
