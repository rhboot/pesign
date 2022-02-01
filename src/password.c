// SPDX-License-Identifier: GPLv2
/*
 * password.c - cursed NSS password access helpers
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "fix_coverity.h"

#include <err.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "pesign.h"

#include <seccomon.h>
#include <secerr.h>
#include <secitem.h>
#include <secport.h>
#include <pk11pub.h>

#include <prtypes.h>
#include <prerror.h>
#include <prprf.h>

#include "list.h"

static const char * const pw_source_names[] = {
	[PW_SOURCE_INVALID] = "PW_SOURCE_INVALID",
	[PW_PROMPT] = "PW_PROMPT",
	[PW_DEVICE] = "PW_DEVICE",
	[PW_PLAINTEXT] = "PW_PLAINTEXT",
	[PW_FROMFILEDB] = "PW_FROMFILEDB",
	[PW_DATABASE] = "PW_DATABASE",
	[PW_FROMENV] = "PW_FROMENV",
	[PW_FROMFILE] = "PW_FROMFILE",
	[PW_FROMFD] = "PW_FROMFD",

	[PW_SOURCE_MAX] = "PW_SOURCE_MAX"
};

static void
print_prompt(FILE *in, FILE *out, char *prompt)
{
	int infd = fileno(in);
	struct termios tio;

	ingress();
	if (!isatty(infd))
		return;

	if (out) {
		fprintf(out, "%s", prompt);
		fflush(out);
	}

	tcgetattr(infd, &tio);
	tio.c_lflag &= ~ECHO;
	tcsetattr(infd, TCSAFLUSH, &tio);
	egress();
}

static inline char *
get_env(const char *name)
{
	char *value;

	value = secure_getenv(name);
	if (value)
		value = strdup(value);
	return value;
}

static int
read_password(FILE *in, FILE *out, char *buf, size_t bufsz)
{
	int infd = fileno(in);
	struct termios tio;
	char *ret;

	ingress();
	ret = fgets(buf, bufsz, in);

	if (isatty(infd)) {
		if (out) {
			fprintf(out, "\n");
			fflush(out);
		}

		tcgetattr(infd, &tio);
		tio.c_lflag |= ECHO;
		tcsetattr(infd, TCSAFLUSH, &tio);
	}
	if (ret == NULL)
		return -1;

	buf[strlen(buf)-1] = '\0';
	egress();
	return 0;
}

static PRBool
check_password(char *cp)
{
	unsigned int i;

	ingress();
	if (cp == NULL) {
		egress();
		return PR_FALSE;
	}

	for (i = 0; cp[i] != 0; i++) {
		if (!isprint(cp[i])) {
			egress();
			return PR_FALSE;
		}
	}
	if (i == 0) {
		egress();
		return PR_FALSE;
	}
	egress();
	return PR_TRUE;
}

static char *
get_password(FILE *input, FILE *output, char *prompt, PRBool (*ok)(char *))
{
	int infd = fileno(input);
	char phrase[200];
	size_t size = sizeof(phrase);

	ingress();
	memset(phrase, 0, size);

	while(true) {
		int rc;

		if (prompt)
			print_prompt(input, output, prompt);
		rc = read_password(input, output, phrase, size);
		if (rc < 0)
			return NULL;

		if (!ok)
			break;

		if ((*ok)(phrase))
			break;

		if (!isatty(infd))
			return NULL;
		fprintf(output, "Password does not meet requirements.\n");
		fflush(output);
	}

	egress();
	return (char *)PORT_Strdup(phrase);
}

static char *
SECU_GetPasswordString(void *arg UNUSED, char *prompt)
{
	char *ret;
	ingress();
	ret = get_password(stdin, stdout, prompt, NULL);
	dprintf("password:\"%s\"", ret ? ret : "(null)");
	egress();
	return ret;
}

static int token_pass_cmp(const void *tp0p, const void *tp1p)
{
	const struct token_pass * const tp0 = (const struct token_pass * const)tp0p;
	const struct token_pass * const tp1 = (const struct token_pass * const)tp1p;
	int rc;

	if (!tp1->token || !tp0->token)
		return tp1->token - tp0->token;
	rc = strcmp(tp0->token, tp1->token);
	if (rc == 0)
		rc = strcmp(tp0->pass, tp1->pass);
	return rc;
}

static int
parse_pwfile_line(char *start, struct token_pass *tp)
{
	size_t span, escspan;
	char *line = start;
	size_t offset = 0;

	span = strspn(line, whitespace_and_eol_chars);
	dprintf("whitespace span is %zd", span);
	if (span == 0 && line[span] == '\0')
		return -1;
	line += span;

	tp->token = NULL;
	tp->pass = line;

	offset = 0;
	do {
		span = strcspn(line + offset, whitespace_and_eol_chars);
		escspan = strescspn(line + offset);
		if (escspan < span)
			offset += escspan + 2;
	} while(escspan < span);
	span += offset;
	dprintf("non-whitespace span is %zd", span);

	if (line[span] == '\0') {
		dprintf("returning %td", (line + span) - start);
		return (line + span) - start;
	}
	line[span] = '\0';

	line += span + 1;
	span = strspn(line, whitespace_and_eol_chars);
	dprintf("whitespace span is %zd", span);
	line += span;
	tp->token = tp->pass;
	tp->pass = line;

	offset = 0;
	do {
		span = strcspn(line + offset, whitespace_and_eol_chars);
		escspan = strescspn(line + offset);
		if (escspan < span)
			offset += escspan + 2;
	} while(escspan < span);
	span += offset;
	dprintf("non-whitespace span is %zd", span);
	if (line[span] != '\0')
		line[span++] = '\0';

	resolve_escapes(tp->token);
	dprintf("Setting token pass %p to { %p, %p }", tp, tp->token, tp->pass);
	dprintf("token:\"%s\"", tp->token);
	dprintf("pass:\"%s\"", tp->pass);
	dprintf("returning %td", (line + span) - start);
	return (line + span) - start;
}

static char *
SECU_FilePasswd(PK11SlotInfo *slot, PRBool retry, void *arg)
{
	cms_context *cms = (cms_context *)arg;
	int fd;
	char *file = NULL;
	char *token_name = slot ? PK11_GetTokenName(slot) : NULL;
	struct token_pass *phrases = NULL;
	size_t nphrases = 0;
	char *phrase = NULL;
	char *start;
	char *ret = NULL;
	char *path;

	ingress();
	dprintf("token_name: %s", token_name);
	if (cms->pwdata.source != PW_FROMFILEDB) {
		cms->log(cms, LOG_ERR,
			 "Got to %s() but no file is specified.\n",
			 __func__);
		goto err;
	}
	path = cms->pwdata.data;

	if (!path || retry)
		goto err;

	phrases = calloc(1, sizeof(struct token_pass));
	if (!phrases)
		goto err;

	fd = open(path, O_RDONLY|O_CLOEXEC);
	if (fd < 0) {
		goto err_phrases;
	} else {
		size_t file_len = 0;
		int rc;
		rc = read_file(fd, &file, &file_len);
		set_errno_guard();
		close(fd);

		if (rc < 0 || file_len < 1)
			goto err_file;
		file[file_len-1] = '\0';
		dprintf("file_len:%zd", file_len);
		dprintf("file:\"%s\"", file);

		unbreak_line_continuations(file, file_len);
	}

	start = file;
	while (start && start[0]) {
		size_t span;
		struct token_pass *new_phrases;
		int rc;
		char c;

		/* Workaround for -fanalzer/reallocarray() bug
		 * https://bugzilla.redhat.com/show_bug.cgi?id=2047926 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-mismatching-deallocation"
		new_phrases = reallocarray(phrases, nphrases + 1, sizeof(struct token_pass));
		if (!new_phrases)
			goto err_phrases;
		phrases = new_phrases;
		memset(&new_phrases[nphrases], 0, sizeof(struct token_pass));
#pragma GCC diagnostic pop

		span = strspn(start, whitespace_and_eol_chars);
		dprintf("whitespace span is %zd", span);
		start += span;
		span = strcspn(start, eol_chars);
		dprintf("non-whitespace span is %zd", span);

		c = start[span];
		start[span] = '\0';
		dprintf("file:\"%s\"", file);
		rc = parse_pwfile_line(start, &phrases[nphrases++]);
		dprintf("parse_pwfile_line returned %d", rc);
		if (rc < 0)
			goto err_phrases;

		if (c != '\0')
			span++;
		start += span;
		dprintf("start is file[%td] == '\\x%02hhx'", start - file,
			start[0]);
	}

	qsort(phrases, nphrases, sizeof(struct token_pass), token_pass_cmp);
	cms->pwdata.source = PW_DATABASE;
	xfree(cms->pwdata.data);
	cms->pwdata.pwdb.phrases = phrases;
	cms->pwdata.pwdb.nphrases = nphrases;

	for (size_t i = 0; i < nphrases; i++) {
		if (phrases[i].token == NULL || phrases[i].token[0] == '\0'
		    || (token_name && !strcmp(token_name, phrases[i].token))) {
			phrase = phrases[i].pass;
			break;
		}
	}

	if (phrase) {
		ret = PORT_Strdup(phrase);
		if (!ret)
			errno = ENOMEM;
	}

err_file:
	xfree(file);
err_phrases:
	xfree(phrases);
err:
	dprintf("ret:\"%s\"", ret ? ret : "(null)");
	egress();
	return ret;
}

char *
get_password_passthrough(PK11SlotInfo *slot UNUSED,
			 PRBool retry, void *arg)
{
	if (retry || !arg)
		return NULL;

	char *ret = strdup(arg);
	if (!ret)
		err(1, "Could not allocate memory");

	return ret;
}

char *
get_password_fail(PK11SlotInfo *slot UNUSED,
		  PRBool retry UNUSED,
		  void *arg UNUSED)
{
	return NULL;
}

static bool
can_prompt_again(secuPWData *pwdata)
{
	if (pwdata->orig_source == PW_PROMPT)
		return true;

	if (pwdata->source == PW_DEVICE)
		return true;

	return false;
}

char *
SECU_GetModulePassword(PK11SlotInfo *slot, PRBool retry, void *arg)
{
	char *prompt = NULL;
	cms_context *cms = (cms_context *)arg;
	secuPWData *pwdata;
	secuPWData pwxtrn = { .source = PW_DEVICE, .orig_source = PW_DEVICE, .data = NULL };
	char *pw;
	int rc;
	FILE *in;

	ingress();

	if (PK11_ProtectedAuthenticationPath(slot)) {
		dprintf("prompting for PW_DEVICE data");
		pwdata = &pwxtrn;
	} else {
		dprintf("using pwdata from cms");
		pwdata = &cms->pwdata;
	}

	if (pwdata->source <= PW_SOURCE_INVALID ||
	    pwdata->source >= PW_SOURCE_MAX ||
	    pwdata->orig_source <= PW_SOURCE_INVALID ||
	    pwdata->orig_source >= PW_SOURCE_MAX) {
		dprintf("pwdata is invalid");
		return NULL;
	}

	dprintf("pwdata:%p retry:%d", pwdata, retry);
	dprintf("pwdata->source:%s (%d) orig:%s (%d)",
		pw_source_names[pwdata->source], pwdata->source,
		pw_source_names[pwdata->orig_source], pwdata->orig_source);
	dprintf("pwdata->data:%p (\"%s\")", pwdata->data,
		pwdata->data ? pwdata->data : "(null)");
	dprintf("pwdata->intdata:%ld", pwdata->intdata);

	if (retry) {
		warnx("Incorrect password/PIN entered.");
		if (!can_prompt_again(pwdata)) {
			egress();
			return NULL;
		}
	}

	switch (pwdata->source) {
	case PW_PROMPT:
		rc = asprintf(&prompt, "Enter Password or Pin for \"%s\":",
			      PK11_GetTokenName(slot));
		if (rc < 0)
			return NULL;
		pw = SECU_GetPasswordString(NULL, prompt);
		if (!pw)
			return NULL;
		free(prompt);

		pwdata->source = PW_PLAINTEXT;
		egress();
		return pw;

	case PW_DEVICE:
		rc = asprintf(&prompt,
			      "Press Enter, then enter PIN for \"%s\" on external device.\n",
			      PK11_GetTokenName(slot));
		if (rc < 0)
			return NULL;
		pw = SECU_GetPasswordString(NULL, prompt);
		free(prompt);
		return pw;

	case PW_FROMFILEDB:
	case PW_DATABASE:
		dprintf("pwdata->source:%s", pw_source_names[pwdata->source]);
		/* Instead of opening and closing the file every time, get the pw
		 * once, then keep it in memory (duh).
		 */
		pw = SECU_FilePasswd(slot, retry, cms);
		/* it's already been dup'ed */
		egress();
		return pw;

	case PW_FROMENV:
		dprintf("pwdata->source:PW_FROMENV");
		if (!pwdata || !pwdata->data)
			break;
		pw = get_env(pwdata->data);
		dprintf("env:%s pw:%s", pwdata->data, pw ? pw : "(null)");
		pwdata->data = pw;
		pwdata->source = PW_PLAINTEXT;
		goto PW_PLAINTEXT;

	case PW_FROMFILE:
		dprintf("pwdata->source:PW_FROMFILE");
		in = fopen(pwdata->data, "r");
		if (!in)
			return NULL;
		pw = get_password(in, NULL, NULL, NULL);
		fclose(in);
		pwdata->source = PW_PLAINTEXT;
		pwdata->data = pw;
		goto PW_PLAINTEXT;

	case PW_FROMFD:
		dprintf("pwdata->source:PW_FROMFD");
		rc = pwdata->intdata;
		in = fdopen(pwdata->intdata, "r");
		if (!in)
			return NULL;
		pw = get_password(in, NULL, NULL, NULL);
		fclose(in);
		close(rc);
		pwdata->source = PW_PLAINTEXT;
		pwdata->data = pw;
		pwdata->intdata = -1;
		goto PW_PLAINTEXT;

	PW_PLAINTEXT:
	case PW_PLAINTEXT:
		egress();
		if (pwdata && pwdata->data)
			return strdup(pwdata->data);
		return NULL;

	default:
		break;
	}

	warnx("Password check failed: No password found.");
	egress();
	return NULL;
}

#if 0
#warning investigate killing readpw
#endif
char *
readpw(PK11SlotInfo *slot UNUSED,
       PRBool retry UNUSED,
       void *arg UNUSED)
{
	struct termios sio, tio;
	char line[LINE_MAX], *p;
	char *ret;

	ingress();
	memset(line, '\0', sizeof (line));

	if (tcgetattr(fileno(stdin), &sio) < 0) {
		warnx("Could not read password from standard input.");
		return NULL;
	}
	tio = sio;
	tio.c_lflag &= ~ECHO;
	if (tcsetattr(fileno(stdin), 0, &tio) < 0) {
		warnx("Could not read password from standard input.");
		return NULL;
	}

	fprintf(stdout, "Enter passphrase for private key: ");
	fflush(stdout);
	ret = fgets(line, sizeof(line), stdin);
	set_errno_guard();
	tcsetattr(fileno(stdin), 0, &sio);
	fprintf(stdout, "\n");
	fflush(stdout);
	if (ret == NULL)
		return NULL;

	p = line + strcspn(line, "\r\n");
	if (p == NULL)
		p = line + strcspn(line, "\n");
	if (p != NULL)
		*p = '\0';

	ret = strdup(line);
	memset(line, '\0', sizeof (line));
	if (!ret) {
		warnx("Could not read passphrase.");
		return NULL;
	}
	egress();
	return ret;
}

// vim:fenc=utf-8:tw=75:noet
