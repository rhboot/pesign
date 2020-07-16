// SPDX-License-Identifier: GPLv2
/*
 * util.h - a den of scum and miscellany
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef PESIGN_UTIL_H
#define PESIGN_UTIL_H 1

#include <err.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <libdpe/pe.h>

#include "compiler.h"
#include "list.h"

#ifndef RUNDIR
#define RUNDIR "/run"
#endif

extern size_t HIDDEN page_size;

#define xfree(x) ({ if (x) { free(x); x = NULL; } })
#define xclose(fd) ({ if ((fd) >= 0) { close(fd); (fd) = -1; } })
#define xopen(path, flags, args...) ({ int fd_ = open(path, flags, ## args); if (fd_ < 0) liberr(1, "Could not open file \"%s\"", arg); fd_; })
#define xrealloc(o, s) ({ void *o_ = realloc(o, s); if (!o_) liberr(1, "Could not allocate %zd bytes", (size_t)s); o_; })
#define xcalloc(n, s) ({ void *p_ = calloc(n, s); if (!p_) liberr(1, "Could not allocate %lu entries of %lu bytes", (unsigned long)n, (unsigned long)s); p_; })
#define xstrdup(s) ({ void *p_ = strdup(s); if (!p_) liberr(1, "Could not allocate memory"); p_; })
#define xpfstat(path, fd, sb) ({ int rc_ = fstat(fd, sb); if (rc_ < 0) liberr(1, "Could not stat \"%s\"", path); })

#define saved_errno_0_ CONCATENATE(CONCATENATE(error_,__LINE__),_0_)
#define saved_errno_1_ CONCATENATE(CONCATENATE(error_,__LINE__),_1_)
#define save_pe_errno() \
	for (int saved_errno_0_ = 0, saved_errno_1_ = pe_errno(); saved_errno_0_ < 1; saved_errno_0_++, __libdpe_seterrno(saved_errno_1_))

#define conderr(cond, val, fmt, args...) ({				\
		if (cond)						\
			err(val, fmt, ## args);				\
	})
#define conderrx(cond, val, fmt, args...) ({				\
		if (cond)						\
			errx(val, fmt, ## args);			\
	})

#define condwarn(cond, fmt, args...) ({					\
		if (cond)						\
			warn(fmt, ## args);				\
	})
#define condwarnx(cond, fmt, args...) ({				\
		if (cond)						\
			warnx(fmt, ## args);				\
	})

#define nsserr(rv, fmt, args...) ({					\
		errx((rv), "%s:%s:%d: " fmt ": %s",			\
			__FILE__, __func__, __LINE__, ##args,		\
			PORT_ErrorToString(PORT_GetError()));		\
	})
#define condnsserr(cond, rv, fmt, args...) ({				\
		if ((cond))						\
			nsserr(rv, fmt, ## args);			\
	})
#define nssreterr(rv, fmt, args...) ({					\
		fprintf(stderr, "%s:%s:%d: " fmt ": %s\n",		\
			__FILE__, __func__, __LINE__, ##args,		\
			PORT_ErrorToString(PORT_GetError()));		\
		return rv;						\
	})
#define condnssreterr(cond, rv, fmt, args...) ({			\
		if ((cond))						\
			nssreterr(rv, fmt, ## args);			\
	})
#define liberr(rv, fmt, args...) ({					\
		err((rv), "%s:%s:%d: " fmt,				\
			__FILE__, __func__, __LINE__, ##args);		\
	})
#define libreterr(rv, fmt, args...) ({					\
		fprintf(stderr, "%s:%s:%d: " fmt ": %m\n",		\
			__FILE__, __func__, __LINE__, ##args);		\
		return rv;						\
	})
#define peerr(rv, fmt, args...) ({					\
		errx((rv), "%s:%s:%d: " fmt ": %s",			\
			__FILE__, __func__, __LINE__, ##args,		\
			pe_errmsg(pe_errno()));				\
	})
#define pereterr(rv, fmt, args...) ({					\
		fprintf(stderr, "%s:%s:%d: " fmt ": %s\n",		\
			__FILE__, __func__, __LINE__, ##args,		\
			pe_errmsg(pe_errno()));				\
		return rv;						\
	})

static inline int UNUSED
read_file(int fd, char **bufp, size_t *lenptr) {
    size_t alloced = 0, size = 0;
    ssize_t i = 0;
    char * buf = NULL;

    do {
	size += i;
	if ((size + (page_size >> 2)) > alloced) {
	    alloced += page_size;
	    buf = realloc(buf, ALIGN_UP(alloced + 1, page_size));
	}
    } while ((i = read(fd, buf + size, page_size >> 2)) > 0);

    if (i < 0) {
        free(buf);
	return -1;
    }

    *bufp = buf;
    *lenptr = size;

    return 0;
}

static inline int UNUSED
write_file(int fd, const void *data, size_t len)
{
	int rc;
	size_t written = 0;

	while (written < len) {
		rc = write(fd, ((unsigned char *) data) + written,
			   len - written);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			return rc;
		}
		written += rc;
	}

	return 0;
}

static int
compare_shdrs (const void *a, const void *b)
{
	const struct section_header *shdra = (const struct section_header *)a;
	const struct section_header *shdrb = (const struct section_header *)b;
	int rc;

	if (shdra->data_addr > shdrb->data_addr)
		return 1;
	if (shdrb->data_addr > shdra->data_addr)
		return -1;

	if (shdra->virtual_address > shdrb->virtual_address)
		return 1;
	if (shdrb->virtual_address > shdra->virtual_address)
		return -1;

	rc = strcmp(shdra->name, shdrb->name);
	if (rc != 0)
		return rc;

	if (shdra->virtual_size > shdrb->virtual_size)
		return 1;
	if (shdrb->virtual_size > shdra->virtual_size)
		return -1;

	if (shdra->raw_data_size > shdrb->raw_data_size)
		return 1;
	if (shdrb->raw_data_size > shdra->raw_data_size)
		return -1;

	return 0;
}

static void UNUSED
sort_shdrs (struct section_header *shdrs, size_t sections)
{
	qsort(shdrs, sections, sizeof(*shdrs), compare_shdrs);
}

static void UNUSED
free_poison(void  *addrv, ssize_t len)
{
	uint8_t *addr = addrv;
	char poison_pills[] = "\xa5\x5a";
	for (int x = 0; x < len; x++)
		addr[x] = poison_pills[x % 2];
}

static int UNUSED
content_is_empty(uint8_t *data, ssize_t len)
{
	if (len < 1)
		return 1;

	for (int i = 0; i < len; i++)
		if (data[i] != 0)
			return 0;
	return 1;
}

#define define_input_file(fname, name, descr)                           \
        static void                                                     \
        CAT3(open_, fname, _input)(pesign_context *ctx)                 \
        {                                                               \
                conderrx(!ctx->name, 1,                                 \
                         "No input file specified for %s",              \
                         descr);                                        \
                ctx->CAT(name, fd) =                                    \
                        open(ctx->name, O_RDONLY|O_CLOEXEC);            \
                conderr(ctx->CAT(name, fd) < 0, 1,                      \
                        "Error opening %s file \"%s\" for input",       \
                        descr, ctx->name);                              \
        }                                                               \
        static void                                                     \
        CAT3(close_, fname, _input)(pesign_context *ctx)                \
        {                                                               \
                close(ctx->CAT(name, fd));                              \
                ctx->CAT(name, fd) = -1;                                \
        }

#define define_output_file(fname, name, descr)                          \
        static void                                                     \
        CAT3(open_, fname, _output)(pesign_context *ctx)                \
        {                                                               \
                conderrx(!ctx->name, 1,                                 \
                         "No output file specified for %s.",            \
                         descr);                                        \
                                                                        \
                if (access(ctx->name, F_OK) == 0 && ctx->force == 0)    \
                        errx(1,                                         \
                             "\"%s\" exists and --force was not given.",\
                             ctx->name);                                \
                                                                        \
                ctx->CAT(name, fd) =                                    \
                        open(ctx->name,                                 \
                             O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC,          \
                             ctx->outmode);                             \
                conderr(ctx->CAT(name, fd) < 0, 1,                      \
                        "Error opening %s file \"%s\" for output",      \
                        descr, ctx->name);                              \
        }                                                               \
        static void                                                     \
        CAT3(close_, fname, _output)(pesign_context *ctx)               \
        {                                                               \
                close(ctx->CAT(name,fd));                               \
                ctx->CAT(name,fd) = -1;                                 \
        }

static inline void
proxy_fd_mode(int fd, char *infile, mode_t *outmode, size_t *inlength)
{
	struct stat statbuf;
	int rc;

	rc = fstat(fd, &statbuf);
	conderr(rc < 0, 1, "Could not fstat \"%s\"", infile);
	if (outmode)
		*outmode = statbuf.st_mode;
	if (inlength)
		*inlength = statbuf.st_size;
}

extern long verbosity(void);

#define dprintf_(tv, file, func, line, fmt, args...) ({struct timeval tv; gettimeofday(&tv, NULL); warnx("%ld.%lu %s:%s():%d: " fmt, tv.tv_sec, tv.tv_usec, file, func, line, ##args); })
#if defined(PESIGN_DEBUG)
#define dprintf(fmt, args...) dprintf_(CAT(CAT(CAT(tv_,__COUNTER__),__LINE__),_), __FILE__, __func__, __LINE__, fmt, ##args)
#else
#define dprintf(fmt, args...) ({ if (verbosity() > 1) dprintf_(CAT(CAT(CAT(tv_,__COUNTER__),__LINE__),_), __FILE__, __func__, __LINE__, fmt, ##args); 0; })
#endif
#define ingress() dprintf("ingress");
#define egress() dprintf("egress");

#endif /* PESIGN_UTIL_H */
// vim:fenc=utf-8:tw=75:noet
