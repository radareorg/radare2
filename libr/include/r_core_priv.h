/* radare - LGPL - Copyright 2024-2025 - pancake */

#include <r_core.h>

#ifndef R2_CORE_PRIV_H
#define R2_CORE_PRIV_H

#ifdef __cplusplus
extern "C" {
#endif
typedef struct r_core_priv_t {
	// arch cache
	int old_bits;
	char *old_arch;
	// rtr
	RSocket *s;
	RThread *httpthread;
	RThread *rapthread;
	const char *listenport;
	char *errmsg_tmpfile;
	int errmsg_fd; // -1
	bool regnums;
} RCorePriv;

#ifdef __cplusplus
}
#endif

#endif
