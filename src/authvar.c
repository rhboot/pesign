// SPDX-License-Identifier: GPLv2
/*
 * authvar.c - main entry for the authvar utility
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "fix_coverity.h"

#include <err.h>
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

#include <efivar.h>
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
#define SHOW_SIGNATURE_SUPPORT	0x80

#define FLAG_LIST_END		0x100

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
	conderrx(!ctx->name || !*ctx->name, 1, "no name specified.");
}

static void
check_value(authvar_context *ctx, int needed)
{
	if ((!ctx->value || !*ctx->value) &&
			(!ctx->valuefile || !*ctx->valuefile)) {
		if (needed)
			warnx("no value specified.");
		else
			return;
		exit(1);
	}
	if (ctx->value && *ctx->value && ctx->valuefile && *ctx->valuefile) {
		conderrx(needed, 1,
			 "--value and --valuefile cannot be used together.");
		errx(1, "command does not take a value.");
	}

	if (ctx->value) {
		ctx->value_size = strlen(ctx->value);
	}
}

static void
open_input(authvar_context *ctx)
{
	struct stat sb;
	int rc;

	if (!ctx->valuefile)
		return;

	ctx->valuefd = open(ctx->valuefile, O_RDONLY|O_CLOEXEC);
	conderr(ctx->valuefd < 0, 1, "Error opening valuefile");

	rc = fstat(ctx->valuefd, &sb);
	conderr(rc < 0, 1, "Error mapping valuefile");

	ctx->value_size = sb.st_size;

	ctx->value = (char *)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE,
			     ctx->valuefd, 0);
	conderr(ctx->value == MAP_FAILED, 1, "Error mapping valuefile");
}

#define EFIVAR_DIR "/sys/firmware/efi/efivars/"

static void
generate_efivars_filename(authvar_context *ctx)
{
	char *guid = NULL;
	int rc = efi_guid_to_str(&ctx->guid, &guid);
	conderr(rc < 0, 1, "Couldn't convert guid to string");

	char *filename = NULL;
	rc = asprintf(&filename, "/sys/firmware/efi/efivars/%s-%s", ctx->name, guid);
	conderr(rc < 0, 1, "can't make string");

	free(guid);
	ctx->exportfile = filename;
}

static void
open_output(authvar_context *ctx)
{
	int flags;
	mode_t mode;

	if (!ctx->exportfile) {
		generate_efivars_filename(ctx);
		ctx->to_firmware = 1;
	} else if (access(ctx->exportfile, F_OK) == 0) {
		errx(1, "\"%s\" exists", ctx->exportfile);
	}

	flags = O_CREAT|O_RDWR|O_CLOEXEC;
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	ctx->exportfd = open(ctx->exportfile, flags, mode);
	conderr(ctx->exportfd < 0, 1, "Error opening exportfile");
}

static int
find_namespace_guid(authvar_context *ctx)
{
	int rc;
	efi_guid_t guid;

	rc = efi_name_to_guid(ctx->namespace, &guid);
	if (rc < 0)
		return rc;
	memcpy(&ctx->guid, &guid, sizeof (guid));
	return 0;
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

static int
show_signature_support(void)
{
	int rc;
	uint8_t *data = NULL;
	size_t data_size = 0;
	uint32_t attrs = 0;
	efi_guid_t *guids;

	rc = efi_get_variable(efi_guid_global, "SignatureSupport",
			      &data, &data_size, &attrs);
	if (rc < 0) {
		warn("Could not read \"SignatureSupport\" variable");
		return rc;
	}
	if (data_size == 0)
		return 0;
	if (data_size % sizeof(efi_guid_t) != 0) {
		warnx("Invalid size %zd for \"SignatureSupport\" variable",
		      data_size);
		errno = EINVAL;
		return -1;
	}

	guids = (efi_guid_t *)data;
	for (size_t i = 0; i < data_size / sizeof(efi_guid_t); i++) {
		char *id_guid = NULL;

		rc = efi_guid_to_id_guid(&guids[i], &id_guid);
		if (rc < 0)
			continue;

		printf("%s\n", id_guid);
		free(id_guid);
	}
	free(data);
	return 0;
}

static long *verbose;

long verbosity(void)
{
	if (!verbose)
		return 0;
	return *verbose;
}

int
main(int argc, char *argv[])
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

	setenv("NSS_DEFAULT_DB_TYPE", "sql", 0);

	rc = authvar_context_init(ctxp);
	conderr(rc < 0, 1, "Could not initialize context");

	poptContext optCon;
	struct poptOption options[] = {
		{.argInfo = POPT_ARG_INTL_DOMAIN,
		 .arg = "pesign" },
		{.longName = "append",
		 .shortName = 'a',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_OR,
		 .arg = &action,
		 .val = GENERATE_APPEND,
		 .descrip = "append to variable" },
		{.longName = "certdir",
		 .shortName = 'd',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
		 .arg = &certdir,
		 .descrip = "specify nss certificate database directory",
		 .argDescrip = "<certificate directory path>" },
		{.longName = "clear",
		 .shortName = 'c',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_OR,
		 .arg = &action,
		 .val = GENERATE_CLEAR,
		 .descrip = "clear variable" },
		{.longName = "set",
		 .shortName = 's',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_OR,
		 .arg = &action,
		 .val = GENERATE_SET,
		 .descrip = "set variable" },
		{.longName = "namespace",
		 .shortName = 'N',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
		 .arg = &ctx.namespace,
		 .descrip = "specified variable is in <namespace> or <guid>" ,
		 .argDescrip = "{<namespace>|<guid>}" },
		{.longName = "list-supported-sigs",
		 .shortName = 'l',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_OR,
		 .arg = &action,
		 .val = SHOW_SIGNATURE_SUPPORT,
		 .descrip = "list supported signature types" },
		{.longName = "guid",
		 .shortName = 'g',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &ctx.namespace,
		 .descrip = "specified variable is in <namespace> or <guid>",
		 .argDescrip = "{<namespace>|<guid>}" },
		{.longName = "name",
		 .shortName = 'n',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &ctx.name,
		 .descrip = "variable name",
		 .argDescrip = "<name>" },
		{.longName = "timestamp",
		 .shortName = 't',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &time_str,
		 .descrip = "timestamp for the variable",
		 .argDescrip = "<time>" },
		{.longName = "value",
		 .shortName = 'v',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &ctx.value,
		 .descrip = "value to set or append",
		 .argDescrip = "<value>" },
		{.longName = "valuefile",
		 .shortName = 'f',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &ctx.valuefile,
		 .descrip = "read value from <file>",
		 .argDescrip = "<file>" },
		{.longName = "import",
		 .shortName = 'i',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &ctx.importfile,
		 .descrip = "import variable from <file>",
		 .argDescrip = "<file>" },
		{.longName = "export",
		 .shortName = 'e',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &ctx.exportfile,
		 .descrip = "export variable to <file> instead of firmware",
		 .argDescrip = "<file>" },
		{.longName = "sign",
		 .shortName = 'S',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &ctx.cms_ctx->certname,
		 .descrip = "sign variable with certificate <nickname>",
		 .argDescrip = "<nickname>" },
		{.longName = "verbose",
		 .shortName = 'v',
		 .argInfo = POPT_ARG_VAL|POPT_ARG_LONG|POPT_ARGFLAG_OPTIONAL,
		 .arg = &ctxp->verbose,
		 .val = 1,
		 .descrip = "be more verbose" },
		{.longName = "debug",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_VAL|POPT_ARG_LONG|POPT_ARGFLAG_OPTIONAL,
		 .arg = &ctxp->verbose,
		 .val = 2,
		 .descrip = "be very verbose" },
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext("authvar", argc, (const char **)argv,
				options, 0);

	rc = poptReadDefaultConfig(optCon, 0);
	if (rc < 0 && !(rc == POPT_ERROR_ERRNO && errno == ENOENT))
		errx(1, "poptReadDefaultConfig failed: %s", poptStrerror(rc));

	while ((rc = poptGetNextOpt(optCon)) > 0)
		;

	conderrx(rc < -1, 1, "Invalid argument: %s: %s",
		 poptBadOption(optCon, 0), poptStrerror(rc));

	conderrx(poptPeekArg(optCon), 1,
		 "Invalid Argument: \"%s\"", poptPeekArg(optCon));

	poptFreeContext(optCon);

	if (ctx.importfile)
		action |= IMPORT;
	if (ctx.exportfile)
		action |= EXPORT;
	if (!(action & (IMPORT|EXPORT)) && action != SHOW_SIGNATURE_SUPPORT)
		action |= SET;

	if ((action & GENERATE_APPEND) || (action & GENERATE_CLEAR) ||
	    (action & GENERATE_SET)) {
		if (!ctx.cms_ctx->certname || !*ctx.cms_ctx->certname)
			errx(1, "Require a certificate to sign");
	}

	rc = find_namespace_guid(ctxp);
	conderrx(rc < 0, 1, "unable to find guid for \"%s\"", ctx.namespace);

	set_timestamp(ctxp, time_str);

	if (ctx.cms_ctx->certname && *ctx.cms_ctx->certname)
		action |= SIGN;

	/* Initialize the NSS db */
	if ((action & GENERATE_APPEND) || (action & GENERATE_CLEAR) ||
	    (action & GENERATE_SET)    || (action & SIGN))
		status = NSS_Init(certdir);
	else
		status = NSS_NoDB_Init(NULL);
	conderrx(status != SECSuccess, 1, "Could not initialize nss: %s",
		 PORT_ErrorToString(PORT_GetError()));

	status = register_oids(ctxp->cms_ctx);
	conderrx(status != SECSuccess, 1, "Could not register OIDs");

	ctxp->cms_ctx->tokenname = tokenname ?
		PORT_ArenaStrdup(ctxp->cms_ctx->arena, tokenname) : NULL;
	conderrx(tokenname && !ctxp->cms_ctx->tokenname, 1,
		 "could not allocate token name: %s",
		 PORT_ErrorToString(PORT_GetError()));

	if (tokenname != origtoken)
		free(tokenname);

	if (action & SIGN) {
		rc = find_certificate(ctx.cms_ctx, 1);
		errx(1, "Could not find certificate for \"%s\"",
		     ctx.cms_ctx->certname);
	}

	switch (action) {
	case NO_FLAGS:
		errx(1, "No action specified");
		break;
	case SHOW_SIGNATURE_SUPPORT:
		rc = show_signature_support();
		conderrx(rc < 0, 1, "could not show support signatures");
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
		conderrx(rc < 0, 1, "unable to generate descriptor");

		open_output(ctxp);
		write_authvar(ctxp);
		break;
	case GENERATE_CLEAR|EXPORT|SIGN:
	case GENERATE_CLEAR|SET|SIGN:
		check_name(ctxp);
		check_value(ctxp, 0);

		rc = generate_descriptor(ctxp);
		conderrx(rc < 0, 1, "unable to generate descriptor");

		open_output(ctxp);
		write_authvar(ctxp);
		break;
	case GENERATE_SET|EXPORT|SIGN:
	case GENERATE_SET|SET|SIGN:
		check_name(ctxp);
		check_value(ctxp, 1);
		open_input(ctxp);

		rc = generate_descriptor(ctxp);
		conderrx(rc < 0, 1, "unable to generate descriptor");

		open_output(ctxp);
		write_authvar(ctxp);
		break;
	case IMPORT|SET:
	case IMPORT|SIGN|SET:
		warnx("not implemented");
		/* fallthrough. */
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
