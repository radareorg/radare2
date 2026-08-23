/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _SYS_UN_H
#define _SYS_UN_H

#include <sys/socket.h>

struct sockaddr_un {
	sa_family_t sun_family;
	char sun_path[108];
};

#endif /* _SYS_UN_H */
