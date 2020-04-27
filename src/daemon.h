// SPDX-License-Identifier: GPLv2
/*
 * daemon.h - types and decls for our signing daemon
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef DAEMON_H
#define DAEMON_H 1

extern int daemonize(cms_context *ctx, char *certdir, int do_fork);

typedef struct {
	uint32_t version;
	uint32_t command;
	uint32_t size;
} pesignd_msghdr;

typedef struct  {
	int32_t rc;
	uint8_t errmsg[];
} pesignd_cmd_response;

typedef struct {
	uint32_t size;
	uint8_t value[];
} pesignd_string;

typedef enum {
	CMD_KILL_DAEMON,
	CMD_UNLOCK_TOKEN,
	CMD_SIGN_ATTACHED,
	CMD_SIGN_DETACHED,
	CMD_RESPONSE,
	CMD_IS_TOKEN_UNLOCKED,
	CMD_GET_CMD_VERSION,
	CMD_SIGN_ATTACHED_WITH_FILE_TYPE,
	CMD_SIGN_DETACHED_WITH_FILE_TYPE,
	CMD_LIST_END
} pesignd_cmd;

#define PESIGND_VERSION 0x2a9edaf0
#define SOCKPATH	"/run/pesign/socket"
#define PIDFILE		"/run/pesign.pid"

static inline uint32_t UNUSED
pesignd_string_size(char *buffer)
{
	pesignd_string *s;
	return sizeof(s->size) + (buffer ? strlen(buffer) : 0) + 1;
}

static inline void UNUSED
pesignd_string_set(pesignd_string *str, char *value)
{
	str->size = (value ? strlen(value) : 0) + 1;
	if (value)
		strcpy((char *)str->value, value);
	else
		str->value[0] = '\0';
}

static inline pesignd_string * UNUSED
pesignd_string_next(pesignd_string *str)
{
	char *buffer = (char *)str;
	buffer += sizeof(str->size) + str->size;
	return (pesignd_string *)buffer;
}

#endif /* DAEMON_H */
