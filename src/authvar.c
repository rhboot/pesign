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

#include <errno.h>
#include <popt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include <prerror.h>
#include <nss.h>

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
			return;
		exit(1);
	}
	if (ctx->value && *ctx->value && ctx->valuefile && *ctx->valuefile) {
		if (needed)
			fprintf(stderr, "authvar: --value and --valuefile "
				"cannot be used together.\n");
		else
			fprintf(stderr,
				"authvar: command does not take a value.\n");
		exit(1);
	}

	if (ctx->value) {
		ctx->value_size = strlen(ctx->value);
	}
}

static void
open_input(authvar_context *ctx)
{
	struct stat sb;

	if (!ctx->valuefile)
		return;

	ctx->valuefd = open(ctx->valuefile, O_RDONLY|O_CLOEXEC);
	if (ctx->valuefd < 0) {
		fprintf(stderr, "authvar: Error opening valuefile: %m\n");
		exit(1);
	}

	if (fstat(ctx->valuefd, &sb) < 0) {
		fprintf(stderr, "authvar: Error mapping valuefile: %m\n");
		exit(1);
	}
	ctx->value_size = sb.st_size;

	ctx->value = (char *)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE,
			     ctx->valuefd, 0);
	if (ctx->value == MAP_FAILED) {
		fprintf(stderr, "authvar: Error mapping valuefile: %m\n");
		exit(1);
	}
}

#define EFIVAR_DIR "/sys/firmware/efi/efivars/"

static void
generate_efivars_filename(authvar_context *ctx)
{
	efi_guid_t guid = ctx->guid;
	size_t length;

	length = strlen(EFIVAR_DIR) + strlen(ctx->name) + 38;
	ctx->exportfile = (char *)malloc(length);

	sprintf(ctx->exportfile, "%s%s-%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		EFIVAR_DIR, ctx->name, guid.data1, guid.data2, guid.data3,
		guid.data4[0], guid.data4[1], guid.data4[2],
		guid.data4[3], guid.data4[4], guid.data4[5],
		guid.data4[6], guid.data4[7]);
}

static void
open_output(authvar_context *ctx)
{
	int flags;
	mode_t mode;

	if (!ctx->exportfile) {
		generate_efivars_filename(ctx);
	}

	flags = O_CREAT|O_RDWR|O_CLOEXEC;
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	ctx->exportfd = open(ctx->exportfile, flags, mode);
	if (ctx->exportfd < 0) {
		fprintf(stderr, "authvar: Error opening exportfile: %m\n");
		exit(1);
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

static void
set_timestamp(authvar_context *ctx, const char *time_str)
{
	time_t t;
	struct tm tm;

	memset(&tm, 0, sizeof(struct tm));
	if (time_str) {
		/* Accept the string like "2001-11-12 18:31:01" */
		strptime(time_str, "%Y-%m-%d %H:%M:%S", &tm);
	} else {
		time(&t);
		gmtime_r(&t, &tm);
	}

	ctx->timestamp.year = tm.tm_year + 1900;
	ctx->timestamp.month = tm.tm_mon + 1;
	ctx->timestamp.day = tm.tm_mday;
	ctx->timestamp.hour = tm.tm_hour;
	ctx->timestamp.minute = tm.tm_min;
	ctx->timestamp.second = tm.tm_sec;

	ctx->timestamp.pad1 = 0;
	ctx->timestamp.nanosecond = 0;
	ctx->timestamp.timezone = 0;
	ctx->timestamp.daylight = 0;
	ctx->timestamp.pad2 = 0;
}

int main(int argc, char *argv[])
{
	int rc;
	authvar_context ctx = { 0, };
	authvar_context *ctxp = &ctx;
	char *time_str = NULL;
	char *tokenname = "NSS Certificate DB";
	char *origtoken = tokenname;
	char *certdir = "/etc/pki/pesign";
	SECStatus status;

	int action = 0;

	rc = authvar_context_init(ctxp);
	if (rc < 0) {
		fprintf(stderr, "Could not initialize context: %m\n");
		exit(1);
	}

	poptContext optCon;
	struct poptOption options[] = {
		{ NULL, '\0', POPT_ARG_INTL_DOMAIN, "pesign" },
		{ "append", 'a', POPT_ARG_VAL|POPT_ARGFLAG_OR, &action,
			GENERATE_APPEND, "append to variable" },
		{"certdir", 'd', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
			&certdir, 0,
			"specify nss certificate database directory",
			"<certificate directory path>" },
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
		{ "timestamp", 't', POPT_ARG_STRING, &time_str, 0,
			"timestamp for the variable", "<time>" },
		{ "value", 'v', POPT_ARG_STRING, &ctx.value, 0,
			"value to set or append", "<value>" },
		{ "valuefile", 'f', POPT_ARG_STRING, &ctx.valuefile, 0,
			"read value from <file>", "<file>" },
		{ "import", 'i', POPT_ARG_STRING, &ctx.importfile, 0,
			"import variable from <file>", "<file>" },
		{ "export", 'e', POPT_ARG_STRING, &ctx.exportfile, 0,
			"export variable to <file> instead of firmware",
			"<file>" },
		{ "sign", 'S', POPT_ARG_STRING, &ctx.cms_ctx->certname, 0,
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

	if (ctx.importfile)
		action |= IMPORT;
	if (ctx.exportfile)
		action |= EXPORT;
	if (!(action & (IMPORT|EXPORT)))
		action |= SET;

	if ((action & GENERATE_APPEND) || (action & GENERATE_CLEAR) ||
	    (action & GENERATE_SET)) {
		if (!ctx.cms_ctx->certname || !*ctx.cms_ctx->certname) {
			fprintf(stderr, "authvar: Require a certificate to sign\n");
			exit(1);
		}
	}

	rc = find_namespace_guid(ctxp);
	if (rc < 0) {
		fprintf(stderr, "authvar: unable to find guid for \"%s\"\n",
			ctx.namespace);
		exit(1);
	}

	set_timestamp(ctxp, time_str);

	/* Initialize the NSS db */
	if ((action & GENERATE_APPEND) || (action & GENERATE_CLEAR) ||
	    (action & GENERATE_SET)    || (action & SIGN))
		status = NSS_Init(certdir);
	else
		status = NSS_NoDB_Init(NULL);
	if (status != SECSuccess) {
		fprintf(stderr, "Could not initialize nss: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		exit(1);
	}

	status = register_oids(ctxp->cms_ctx);
	if (status != SECSuccess) {
		fprintf(stderr, "Could not register OIDs\n");
		exit(1);
	}

	ctxp->cms_ctx->tokenname = tokenname ?
		PORT_ArenaStrdup(ctxp->cms_ctx->arena, tokenname) : NULL;
	if (tokenname && !ctxp->cms_ctx->tokenname) {
		fprintf(stderr, "could not allocate token name: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		exit(1);
	}
	if (tokenname != origtoken)
		free(tokenname);

	if (ctx.cms_ctx->certname && *ctx.cms_ctx->certname) {
		rc = find_certificate(ctx.cms_ctx, 1);
		if (rc < 0) {
			fprintf(stderr, "authvar: Could not find certificate "
				"for \"%s\"\n", ctx.cms_ctx->certname);
			exit(1);
		}
		action |= SIGN;
	}

	switch (action) {
	case NO_FLAGS:
		fprintf(stderr, "authvar: No action specified\n");
		exit(1);
		break;
	case GENERATE_APPEND|EXPORT|SIGN:
	case GENERATE_APPEND|SET|SIGN:
		check_name(ctxp);
		check_value(ctxp, 1);
		open_input(ctxp);
		ctxp->attr |= EFI_VARIABLE_APPEND_WRITE;
		ctxp->timestamp.day = 0;
		ctxp->timestamp.month = 0;

		rc = generate_descriptor(ctxp);
		if (rc < 0) {
			fprintf(stderr, "authvar: unable to generate descriptor\n");
			exit(1);
		}
		open_output(ctxp);
		write_authvar(ctxp);
		break;
	case GENERATE_CLEAR|EXPORT|SIGN:
	case GENERATE_CLEAR|SET|SIGN:
		check_name(ctxp);
		check_value(ctxp, 0);

		rc = generate_descriptor(ctxp);
		if (rc < 0) {
			fprintf(stderr, "authvar: unable to generate descriptor\n");
			exit(1);
		}
		open_output(ctxp);
		write_authvar(ctxp);
		break;
	case GENERATE_SET|EXPORT|SIGN:
	case GENERATE_SET|SET|SIGN:
		check_name(ctxp);
		check_value(ctxp, 1);
		open_input(ctxp);

		rc = generate_descriptor(ctxp);
		if (rc < 0) {
			fprintf(stderr, "authvar: unable to generate descriptor\n");
			exit(1);
		}
		open_output(ctxp);
		write_authvar(ctxp);
		break;
	case IMPORT|SET:
	case IMPORT|SIGN|SET:
		fprintf(stderr, "authvar: not implemented\n");
	case IMPORT|SIGN|EXPORT:
	default:
		fprintf(stderr, "authvar: invalid flags: ");
		print_flag_name(stderr, action);
		fprintf(stderr, "\n");
		exit(1);
	}

	authvar_context_fini(ctxp);
	if (time_str)
		xfree(time_str);

	NSS_Shutdown();

	return 0;
}
