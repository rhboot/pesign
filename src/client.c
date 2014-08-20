/* Copyright 2011-2014 Red Hat, Inc.
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
#include <fcntl.h>
#include <popt.h>
#include <pwd.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "pesign.h"

#define NO_FLAGS		0x00
#define UNLOCK_TOKEN		0x01
#define KILL_DAEMON		0x02
#define SIGN_BINARY		0x04
#define IS_TOKEN_UNLOCKED	0x08
#define FLAG_LIST_END		0x10

static struct {
	int flag;
	const char *name;
} flag_names[] = {
	{UNLOCK_TOKEN, "unlock"},
	{KILL_DAEMON, "kill"},
	{SIGN_BINARY, "sign"},
	{IS_TOKEN_UNLOCKED, "is-unlocked"},
	{FLAG_LIST_END, NULL},
};

static void
print_flag_name(FILE *f, int flag)
{
	for (int i = 0; flag_names[i].flag != FLAG_LIST_END; i++) {
		if (flag_names[i].flag == flag)
			fprintf(f, "%s ", flag_names[i].name);
	}
}

static int
connect_to_server(void)
{
	int rc = access(SOCKPATH, R_OK);
	if (rc != 0) {
		fprintf(stderr, "pesign-client: could not connect to server: "
			"%m\n");
		exit(1);
	}

	struct sockaddr_un addr_un = {
		.sun_family = AF_UNIX,
		.sun_path = SOCKPATH,
	};

	int sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd < 0) {
		fprintf(stderr, "pesign-client: could not open socket: %m\n");
		exit(1);
	}

	socklen_t len = strlen(addr_un.sun_path) +
			sizeof(addr_un.sun_family);

	rc = connect(sd, (struct sockaddr *)&addr_un, len);
	if (rc < 0) {
		fprintf(stderr, "pesign-client: could not connect to daemon: "
			"%m\n");
		exit(1);
	}

	return sd;
}

static int32_t
check_response(int sd, char **srvmsg);

static void
check_cmd_version(int sd, uint32_t command, char *name, int32_t version)
{
	struct msghdr msg;
	struct iovec iov[1];
	pesignd_msghdr pm;

	pm.version = PESIGND_VERSION;
	pm.command = CMD_GET_CMD_VERSION;
	pm.size = sizeof(command);
	iov[0].iov_base = &pm;
	iov[0].iov_len = sizeof(pm);

	memset(&msg, '\0', sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	ssize_t n;
	n = sendmsg(sd, &msg, 0);
	if (n < 0) {
		fprintf(stderr, "check-cmd-version: kill daemon failed: %m\n");
		exit(1);
	}

	iov[0].iov_base = &command;
	iov[0].iov_len = sizeof(command);

	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	n = sendmsg(sd, &msg, 0);
	if (n < 0)
		err(1, "check-cmd-version: sendmsg failed");

	char *srvmsg = NULL;
	int32_t rc = check_response(sd, &srvmsg);
	if (rc < 0)
		errx(1, "command \"%s\" not known by server", name);
	if (rc != version)
		errx(1, "command \"%s\": client version %d, server version %d",
			name, version, rc);
}

static void
send_kill_daemon(int sd)
{
	struct msghdr msg;
	struct iovec iov;
	pesignd_msghdr pm;

	check_cmd_version(sd, CMD_KILL_DAEMON, "kill-daemon", 0);

	pm.version = PESIGND_VERSION;
	pm.command = CMD_KILL_DAEMON;
	pm.size = 0;

	iov.iov_base = &pm;
	iov.iov_len = sizeof(pm);

	memset(&msg, '\0', sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ssize_t n;

	n = sendmsg(sd, &msg, 0);
	if (n < 0) {
		fprintf(stderr, "pesign-client: kill daemon failed: %m\n");
		exit(1);
	}
}

static int32_t
check_response(int sd, char **srvmsg)
{
	ssize_t n;
	struct msghdr msg;
	struct iovec iov;
	char buffer[1024];

	pesignd_msghdr *pm;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	memset(&msg, '\0', sizeof(msg));
	memset(buffer, '\0', sizeof(buffer));

	iov.iov_base = buffer;
	iov.iov_len = 1023;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	n = recvmsg(sd, &msg, 0);
	if (n < 0) {
		fprintf(stderr, "pesign-client: could not get response from "
			"server: %m\n");
		exit(1);
	}

	pm = (pesignd_msghdr *)buffer;

	if (pm->version != PESIGND_VERSION) {
		fprintf(stderr, "pesign-client: got version %d, "
			"expected version %d\n", pm->version, PESIGND_VERSION);
		exit(1);
	}

	if (pm->command != CMD_RESPONSE) {
		fprintf(stderr, "pesign-client: got unexpected response: %d\n",
			pm->command);
		exit(1);
	}

	pesignd_cmd_response *resp = (pesignd_cmd_response *)((uint8_t *)pm +
					offsetof(pesignd_msghdr, size) +
					sizeof(pm->size));

	if (resp->rc == 0)
		return 0;

	*srvmsg = strdup((char *)resp->errmsg);
	return resp->rc;
}

static char *
get_token_pin(int pinfd, char *pinfile, char *envname)
{
	char *pin = NULL;
	FILE *pinf = NULL;

	errno = 0;
	/* validate that the fd we got is real... */
	if (pinfd >= 0) {
		pinf = fdopen(pinfd, "r");
		if (!pinf) {
			if (errno != EBADF)
				close(pinfd);
			return NULL;
		}

		ssize_t n = getline(&pin, 0, pinf);
		if (n < 0 || !pin) {
			fclose(pinf);
			close(pinfd);
			return NULL;
		}

		char *c = strchrnul(pin, '\n');
		*c = '\0';

		fclose(pinf);
		close(pinfd);
		return pin;
	} else if (pinfile) {
		pinf = fopen(pinfile, "r");
		if (!pinf)
			return NULL;

		size_t len;
		ssize_t n = getline(&pin, &len, pinf);
		if (n < 0 || !pin) {
			fclose(pinf);
			return NULL;
		}

		char *c = strchrnul(pin, '\n');
		*c = '\0';

		fclose(pinf);
		return pin;
	} else {
		pin = getenv(envname);
		if (pin)
			return strdup(pin);
	}

	pin = readpw(NULL, PR_FALSE, NULL);
	return pin;
}

static void
unlock_token(int sd, char *tokenname, char *pin)
{
	struct msghdr msg;
	struct iovec iov[2];
	pesignd_msghdr pm;

	uint32_t size0 = pesignd_string_size(tokenname);

	uint32_t size1 = pesignd_string_size(pin);

	check_cmd_version(sd, CMD_UNLOCK_TOKEN, "unlock-token", 0);

	pm.version = PESIGND_VERSION;
	pm.command = CMD_UNLOCK_TOKEN;
	pm.size = size0 + size1;
	iov[0].iov_base = &pm;
	iov[0].iov_len = sizeof (pm);

	memset(&msg, '\0', sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	ssize_t n;
	n = sendmsg(sd, &msg, 0);
	if (n < 0) {
		fprintf(stderr, "pesign-client: unlock token: sendmsg failed: "
			"%m\n");
		exit(1);
	}

	uint8_t *buffer = NULL;
	buffer = calloc(1, size0 + size1);
	if (!buffer) {
		fprintf(stderr, "pesign-client: could not allocate memory: "
			"%m\n");
		exit(1);
	}

	pesignd_string *tn = (pesignd_string *)buffer;
	pesignd_string_set(tn, tokenname);
	iov[0].iov_base = tn;
	iov[0].iov_len = size0;

	pesignd_string *tp = pesignd_string_next(tn);
	pesignd_string_set(tp, pin);

	iov[1].iov_base = tp;
	iov[1].iov_len = size1;

	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	n = sendmsg(sd, &msg, 0);
	if (n < 0) {
		fprintf(stderr, "pesign-client: unlock token: sendmsg failed: "
			"%m\n");
		exit(1);
	}

	char *srvmsg = NULL;
	int rc = check_response(sd, &srvmsg);
	if (rc < 0) {
		fprintf(stderr, "pesign-client: %s\n",
			srvmsg);
		exit(1);
	}

	free(buffer);
}

static void
is_token_unlocked(int sd, char *tokenname)
{
	struct msghdr msg;
	struct iovec iov[1];
	pesignd_msghdr pm;

	uint32_t size0 = pesignd_string_size(tokenname);

	check_cmd_version(sd, CMD_IS_TOKEN_UNLOCKED, "is-token-unlocked", 0);

	pm.version = PESIGND_VERSION;
	pm.command = CMD_IS_TOKEN_UNLOCKED;
	pm.size = size0;
	iov[0].iov_base = &pm;
	iov[0].iov_len = sizeof (pm);

	memset(&msg, '\0', sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	ssize_t n;
	n = sendmsg(sd, &msg, 0);
	if (n < 0)
		err(1, "is_token_unlocked: sendmsg failed");

	uint8_t *buffer = NULL;
	buffer = calloc(1, size0);
	if (!buffer)
		err(1, "is_token_unlocked: Could not allocate memory");

	pesignd_string *tn = (pesignd_string *)buffer;
	pesignd_string_set(tn, tokenname);
	iov[0].iov_base = tn;
	iov[0].iov_len = size0;

	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	n = sendmsg(sd, &msg, 0);
	if (n < 0)
		err(1, "is_token_unlocked: sendmsg failed");

	char *srvmsg = NULL;
	int rc = check_response(sd, &srvmsg);
	if (rc < 0)
		errx(1, "%s", srvmsg);
	printf("token \"%s\" is %slocked\n", tokenname, rc == 1 ? "" : "un");

	free(buffer);
}

static void
send_fd(int sd, int fd)
{
	struct msghdr msg;
	struct iovec iov;
	char buf[2] = "\0";

	memset(&msg, '\0', sizeof(msg));

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	size_t controllen = CMSG_SPACE(sizeof(int));
	struct cmsghdr *cm = malloc(controllen);
	if (!cm) {
		fprintf(stderr, "pesign-client: could not allocate memory: "
			"%m\n");
		exit(1);
	}

	msg.msg_control = cm;
	msg.msg_controllen = controllen;

	struct cmsghdr *cme;

	cme = CMSG_FIRSTHDR(&msg);
	cme->cmsg_len = CMSG_LEN(sizeof(int));
	cme->cmsg_level = SOL_SOCKET;
	cme->cmsg_type = SCM_RIGHTS;
	*(int *)CMSG_DATA(cme) = fd;

	ssize_t n;
	n = sendmsg(sd, &msg, 0);
	if (n < 0) {
		fprintf(stderr, "pesign-client: sign: sendmsg failed: "
			"%m\n");
		exit(1);
	}
}

static void
sign(int sd, char *infile, char *outfile, char *tokenname, char *certname,
	int attached)
{
	int infd = open(infile, O_RDONLY);
	if (infd < 0) {
		fprintf(stderr, "pesign-client: could not open input file "
			"\"%s\": %m\n", infile);
		exit(1);
	}

	int outfd = open(outfile, O_RDWR|O_CREAT, 0600);
	if (outfd < 0) {
		fprintf(stderr, "pesign-client: could not open output file "
			"\"%s\": %m\n", outfile);
		exit(1);
	}

	struct msghdr msg;
	struct iovec iov[2];

	uint32_t size0 = pesignd_string_size(tokenname);
	uint32_t size1 = pesignd_string_size(certname);

	pesignd_msghdr *pm;
	pm = calloc(1, sizeof(*pm));
	if (!pm) {
oom:
		fprintf(stderr, "pesign-client: could not allocate memory: "
			"%m\n");
		exit(1);
	}

	check_cmd_version(sd, attached ? CMD_SIGN_ATTACHED : CMD_SIGN_DETACHED,
			attached ? "sign-attached" : "sign-detached", 0);

	pm->version = PESIGND_VERSION;
	pm->command = attached ? CMD_SIGN_ATTACHED : CMD_SIGN_DETACHED;
	pm->size = size0 + size1;
	iov[0].iov_base = pm;
	iov[0].iov_len = sizeof (*pm);

	memset(&msg, '\0', sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	ssize_t n;
	n = sendmsg(sd, &msg, 0);
	if (n < 0) {
		fprintf(stderr, "pesign-client: sign: sendmsg failed: "
			"%m\n");
		exit(1);
	}

	char *buffer;
	buffer = malloc(size0 + size1);
	if (!buffer)
		goto oom;

	pesignd_string *tn = (pesignd_string *)buffer;
	pesignd_string_set(tn, tokenname);
	iov[0].iov_base = tn;
	iov[0].iov_len = size0;

	pesignd_string *cn = pesignd_string_next(tn);
	pesignd_string_set(cn, certname);
	iov[1].iov_base = cn;
	iov[1].iov_len = size1;

	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	n = sendmsg(sd, &msg, 0);
	if (n < 0) {
		fprintf(stderr, "pesign-client: sign: sendmsg failed: "
			"%m\n");
		exit(1);
	}
	free(buffer);

	send_fd(sd, infd);
	send_fd(sd, outfd);

	char *srvmsg = NULL;
	int rc = check_response(sd, &srvmsg);
	if (rc < 0) {
		fprintf(stderr, "pesign-client: signing failed: \"%s\"\n",
			srvmsg);
		exit(1);
	}

	close(infd);
	close(outfd);

	return;
}

int
main(int argc, char *argv[])
{
	char *tokenname = "NSS Certificate DB";
	char *certname = NULL;
	poptContext optCon;
	int rc;
	int action = NO_FLAGS;
	char *infile = NULL;
	char *outfile = NULL;
	char *exportfile = NULL;
	int attached = 1;
	int pinfd = -1;
	char *pinfile = NULL;
	char *tokenpin = NULL;

	struct poptOption options[] = {
		{NULL, '\0', POPT_ARG_INTL_DOMAIN, "pesign" },
		{"token", 't', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
			&tokenname, 0, "NSS token holding signing key",
			"<token>" },
		{"certificate", 'c', POPT_ARG_STRING,
			&certname, 0, "NSS certificate name", "<nickname>" },
		{"unlock", 'u', POPT_ARG_VAL|POPT_ARGFLAG_OR, &action,
			UNLOCK_TOKEN, "unlock nss token", NULL },
		{"is-unlocked", 'q', POPT_ARG_VAL|POPT_ARGFLAG_OR, &action,
			IS_TOKEN_UNLOCKED, "query if an nss token is unlocked",
			NULL},
		{"kill", 'k', POPT_ARG_VAL|POPT_ARGFLAG_OR, &action,
			KILL_DAEMON, "kill running daemon", NULL },
		{"sign", 's', POPT_ARG_VAL|POPT_ARGFLAG_OR, &action,
			SIGN_BINARY, "sign binary", NULL },
		{"infile", 'i', POPT_ARG_STRING,
			&infile, 0, "input filename", "<infile>" },
		{"outfile", 'o', POPT_ARG_STRING,
			&outfile, 0, "output filename", "<outfile>" },
		{"export", 'e', POPT_ARG_STRING,
			&exportfile, 0, "create detached signature",
			"<outfile>" },
		{"pinfd", 'f', POPT_ARG_INT, &pinfd, -1,
			"read file descriptor for pin information",
			"<file descriptor>" },
		{"pinfile", 'F', POPT_ARG_STRING, &pinfile, 0,
			"read named file for pin information",
			"<pin file name>" },
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext("pesign", argc, (const char **)argv, options,0);

	rc = poptReadDefaultConfig(optCon, 0);
	if (rc < 0 && !(rc == POPT_ERROR_ERRNO && errno == ENOENT)) {
		fprintf(stderr,
			"pesign-client: poptReadDefaultConfig failed: %s\n",
			poptStrerror(rc));
		exit(1);
	}

	while ((rc = poptGetNextOpt(optCon)) > 0)
		;

	if (rc < -1) {
		fprintf(stderr, "pesign-client: Invalid argument: %s: %s\n",
			poptBadOption(optCon, 0), poptStrerror(rc));
		exit(1);
	}

	if (poptPeekArg(optCon)) {
		fprintf(stderr, "pesign-client: Invalid Argument: \"%s\"\n",
			poptPeekArg(optCon));
		exit(1);
	}

	if (action == NO_FLAGS) {
		poptPrintUsage(optCon, stdout, 0);
		poptFreeContext(optCon);
		exit(0);
	}

	if (action & SIGN_BINARY && (!outfile && !exportfile)) {
		fprintf(stderr, "pesign-client: neither --outfile nor --export "
			"specified\n");
		exit(1);
	}

	if (outfile && exportfile) {
		fprintf(stderr, "pesign-client: both --outfile and --export "
			"specified\n");
		exit(1);
	}
	if (exportfile) {
		outfile = exportfile;
		attached = 0;
	}

	poptFreeContext(optCon);

	int sd = -1;

	switch (action) {
	case UNLOCK_TOKEN:
		tokenpin = get_token_pin(pinfd, pinfile, "PESIGN_TOKEN_PIN");
		if (tokenpin == NULL) {
			if (errno)
				fprintf(stderr, "pesign-client: could not "
					"get token pin: %m\n");
			else
				fprintf(stderr, "pesign-client: no token pin "
					"specified");
			exit(1);
		}
		sd = connect_to_server();
		unlock_token(sd, tokenname, tokenpin);
		free(tokenpin);
		break;
	case IS_TOKEN_UNLOCKED:
		sd = connect_to_server();
		is_token_unlocked(sd, tokenname);
		break;
	case KILL_DAEMON:
		sd = connect_to_server();
		send_kill_daemon(sd);
		break;
	case SIGN_BINARY:
		if (!infile) {
			fprintf(stderr, "pesign-client: no input file "
				"specified\n");
			exit(1);
		}
		if (!outfile) {
			fprintf(stderr, "pesign-client: no output file "
				"specified\n");
			exit(1);
		}
		if (!certname) {
			fprintf(stderr, "pesign-client: no certificate name "
				"spefified\n");
			exit(1);
		}
		sd = connect_to_server();
		sign(sd, infile, outfile, tokenname, certname, attached);
		break;
	default:
		fprintf(stderr, "Incompatible flags (0x%08x): ", action);
		for (int i = 1; i < FLAG_LIST_END; i <<= 1) {
			if (action & i)
				print_flag_name(stderr, i);
		}
		fprintf(stderr, "\n");
		exit(1);
	}

	return 0;
}
