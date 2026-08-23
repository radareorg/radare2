/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _SYS_UTSNAME_H
#define _SYS_UTSNAME_H

#ifdef __cplusplus
extern "C" {
#endif

struct utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
};

int uname(struct utsname *buf);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_UTSNAME_H */
