/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _NET_IF_H
#define _NET_IF_H

#ifdef __cplusplus
extern "C" {
#endif

#define IF_NAMESIZE 16
#define IFNAMSIZ IF_NAMESIZE

struct ifreq {
	char ifr_name[IFNAMSIZ];
	int ifr_ifindex;
};

unsigned int if_nametoindex(const char *ifname);
char *if_indextoname(unsigned int ifindex, char *ifname);

#ifdef __cplusplus
}
#endif

#endif /* _NET_IF_H */
