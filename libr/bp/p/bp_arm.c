/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_bp.h>
#include <r_lib.h>

static struct r_bp_arch_t r_bp_plugin_arm_bps[] = {
	{ 4, 0, (const ut8*)"\x01\x00\x9f\xef" }, // le         - linux only? (undefined instruction)
	{ 4, 1, (const ut8*)"\xef\x9f\x00\x01" }, // be
#if 0
	{ 4, 0, (const ut8*)"\xfe\xde\xff\xe7" }, // arm-le     - from a gdb patch
	{ 4, 1, (const ut8*)"\xe7\xff\xde\xfe" }, // arm-be
        { 4, 0, (const ut8*)"\xf0\x01\xf0\xe7" }, // eabi-le    - undefined instruction - for all kernels
	{ 4, 1, (const ut8*)"\xe7\xf0\x01\xf0" }, // eabi-be
#endif
	{ 2, 0, (const ut8*)"\xde\x01" },         // thumb-le
	{ 2, 1, (const ut8*)"\x01\xde" },         // thumb-be
	{ 2, 0, (const ut8*)"\xfe\xdf" },         // arm-thumb-le
	{ 2, 1, (const ut8*)"\xdf\xfe" },         // arm-thumb-be
	{ 0, 0, NULL }
};

struct r_bp_plugin_t r_bp_plugin_arm = {
	.name = "arm",
	.arch = "arm",
	.nbps = 6,
	.bps = r_bp_plugin_arm_bps,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &r_bp_plugin_arm,
};
#endif
