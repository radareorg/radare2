/*! \file */
#ifndef QNX_CORE_H
#define QNX_CORE_H

#include "r_types.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if __UNIX__
#include <unistd.h>
#endif
#include <stdio.h>

#include "libqnxr.h"
#include "utils.h"
#include "arch.h"

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#endif

enum Breakpoint {
	BREAKPOINT,
	HARDWARE_BREAKPOINT,
	WRITE_WATCHPOINT,
	READ_WATCHPOINT,
	ACCESS_WATCHPOINT
};

int qnxr_send_vcont (libqnxr_t *g, int step, int thread_id);

int _qnxr_set_bp (libqnxr_t *g, ut64 address, const char *conditions, enum Breakpoint type);

int _qnxr_remove_bp (libqnxr_t *g, ut64 address, enum Breakpoint type);

#endif
