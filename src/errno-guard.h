/*
 * errno-guard.h
 * Copyright 2019 Peter Jones <pjones@redhat.com>
 */

#ifndef ERRNO_GUARD_H_
#define ERRNO_GUARD_H_

#define ERRNO_GUARD_ENTRIES_ ((int)(4096 / sizeof(int)))

extern __thread int errno_guards_[ERRNO_GUARD_ENTRIES_];
extern __thread int errno_guard_no_;

extern void clean_up_errno_guard_(int *handle);
extern int set_up_errno_guard_(int *handle);

#define guard_errno_(handle, guard_var) \
	CLEANUP_FUNC(clean_up_errno_guard_) UNUSED int guard_var = set_up_errno_guard_(handle)
#define errno_guard_var_ CAT(CAT(CAT(CAT(errno_guard_,__LINE__),_),__COUNTER__),_)

extern int override_errno_guard(int *handle, int error);
#define set_errno_guard() guard_errno_(NULL, errno_guard_var_)
#define set_errno_guard_with_override(handle) guard_errno_(handle, errno_guard_var_)

#endif /* !ERRNO_GUARD_H_ */
// vim:fenc=utf-8:tw=75:noet
