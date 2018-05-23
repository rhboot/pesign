/*
 * compiler.h
 * Copyright 2019 Peter Jones <pjones@redhat.com>
 */

#ifndef COMPILER_H_
#define COMPILER_H_

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
#define ALIGNED(n) __attribute__((__aligned__(N)))

#endif /* !COMPILER_H_ */
// vim:fenc=utf-8:tw=75:et
