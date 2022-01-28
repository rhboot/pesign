// SPDX-License-Identifier: GPLv2
/*
 * compiler.h - a bunch of helpers for compiler-related stuff
 * Copyright Peter Jones <pjones@redhat.com>
 */
#ifndef COMPILER_H_
#define COMPILER_H_

#include <sys/cdefs.h>

#define UNUSED __attribute__((__unused__))
#define HIDDEN __attribute__((__visibility__ ("hidden")))
#define PUBLIC __attribute__((__visibility__ ("default")))
#define DESTRUCTOR __attribute__((destructor))
#define CONSTRUCTOR __attribute__((constructor))
#define ALIAS(x) __attribute__((weak, alias (#x)))
#define NONNULL(...) __attribute__((__nonnull__(__VA_ARGS__)))
#define PRINTF(...) __attribute__((__format__(printf, __VA_ARGS__)))
#define FLATTEN __attribute__((__flatten__))
#define PACKED __attribute__((__packed__))
#define VERSION(sym, ver) __asm__(".symver " # sym "," # ver)
#define NORETURN __attribute__((__noreturn__))
#define ALIGNED(n) __attribute__((__aligned__(n)))
#define CLEANUP_FUNC(x) __attribute__((__cleanup__(x)))

#ifndef __CONCAT
#define __CONCAT(a, b) a ## b
#endif
#define __CONCAT3(a, b, c) a ## b ## c
#define CONCATENATE(a, b) __CONCAT(a, b)
#define CAT(a, b) __CONCAT(a, b)
#define CAT3(a, b, c) __CONCAT3(a, b, c)
#define STRING(x) __STRING(x)

#define WRITE_ONCE(var, val) \
        (*((volatile typeof(val) *)(&(var))) = (val))

#define READ_ONCE(var) (*((volatile typeof(var) *)(&(var))))

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

/* Are two types/vars the same type (ignoring qualifiers)? */
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))

/* Compile time object size, -1 for unknown */
#ifndef __compiletime_object_size
# define __compiletime_object_size(obj) -1
#endif
#ifndef __compiletime_warning
# define __compiletime_warning(message)
#endif
#ifndef __compiletime_error
# define __compiletime_error(message)
#endif

#define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		extern void prefix ## suffix(void) __compiletime_error(msg); \
		if (!(condition))					\
			prefix ## suffix();				\
	} while (0)

#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)

/**
 * compiletime_assert - break build and emit msg if condition is false
 * @condition: a compile-time constant condition to check
 * @msg:       a message to emit if condition is false
 *
 * In tradition of POSIX assert, this macro will break the build if the
 * supplied condition is *false*, emitting the supplied error message if the
 * compiler has support to do so.
 */
#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, __LINE__)

/**
 * BUILD_BUG_ON_MSG - break compile if a condition is true & emit supplied
 *		      error message.
 * @condition: the condition which the compiler should know is false.
 *
 * See BUILD_BUG_ON for description.
 */
#define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)

#define __ALIGN_MASK(x, mask)   (((x) + (mask)) & ~(mask))
#define __ALIGN(x, a)           __ALIGN_MASK(x, (typeof(x))(a) - 1)
#define ALIGN(x, a)             __ALIGN((x), (a))
#define ALIGN_DOWN(x, a)        __ALIGN((x) - ((a) - 1), (a))

#define ALIGNMENT_PADDING(value, align) ((align - (value % align)) % align)
#define ALIGN_UP(value, align) ((value) + ALIGNMENT_PADDING(value, align))

#endif /* !COMPILER_H_ */
// vim:fenc=utf-8:tw=75:noet
