/*! \file */
#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdio.h>
#include "libqnxr.h"

#define LONGEST st64
#define ULONGEST ut64

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define EXTRACT_SIGNED_INTEGER(addr, len) \
	extract_signed_integer ((const ut8 *)addr, len, 0)
#define EXTRACT_UNSIGNED_INTEGER(addr, len) \
	extract_unsigned_integer ((const ut8 *)addr, len, 0)

int errnoconvert (int x);

enum target_signal target_signal_from_nto (int sig);

LONGEST extract_signed_integer (const ut8 *addr, int len, int be);
ULONGEST extract_unsigned_integer (const ut8 *addr, int len, int be);

int i386nto_regset_id (int regno);
int i386nto_reg_offset (int regnum);
int i386nto_register_area (int regno, int regset, unsigned *off);

ptid_t ptid_build (st32 pid, st64 tid);

#endif
