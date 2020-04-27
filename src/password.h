// SPDX-License-Identifier: GPLv2
/*
 * password.h - cursed NSS password access helpers
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef PASSWORD_H
#define PASSWORD_H

extern char *SECU_GetModulePassword(PK11SlotInfo *slot, PRBool retry, void *arg);
extern char *get_password_passthrough(PK11SlotInfo *slot, PRBool retry, void *arg);
extern char *get_password_fail(PK11SlotInfo *slot, PRBool retry, void *arg);
extern char *readpw(PK11SlotInfo *slot, PRBool retry, void *arg);

#endif /* PASSWORD_H */
