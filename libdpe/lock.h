/*
 * Copyright 2011 Red Hat, Inc.
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
#ifndef LIBDPE_LOCK_H
#define LIBDPE_LOCK_H 1

#ifdef __UEFI__ /* Not sure if this will be useful or not, but... */
#define rwlock_define(class,name) class int name
#define rwlock_init(lock) ((void) (lock))
#define rwlock_fini(lock) ((void) (lock))
#define rwlock_rdlock(lock) ((void) (lock))
#define rwlock_wrlock(lock) ((void) (lock))
#define rwlock_unlock(lock) ((void) (lock))
#else
#include <pthread.h>
#include <assert.h>
#define rwlock_define(class,name)	class pthread_rwlock_t name
#define RWLOCK_CALL(call) \
	({ int _err = pthread_rwlock_ ## call; assert_perror(_err); })
#define rwlock_init(lock)	RWLOCK_CALL(init (&lock, NULL))
#define rwlock_fini(lock)	RWLOCK_CALL(destroy (&lock))
#define rwlock_rdlock(lock)	RWLOCK_CALL(rdlock (&lock))
#define rwlock_wrlock(lock)	RWLOCK_CALL(wrlock (&lock))
#define rwlock_unlock(lock)	RWLOCK_CALL(unlock (&lock))
#endif

#endif /* LIBDPE_LOCK_H */
