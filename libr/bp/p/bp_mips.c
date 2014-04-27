/* radare2 - LGPL - Copyright 2010-2012 pancake<nopcode.org> */

#include <r_bp.h>
#include <r_lib.h>

static struct r_bp_arch_t r_bp_plugin_mips_bps[] = {
	{ 4, 0, (const ut8*)"\x0d\x00\x00\x00" },
	{ 4, 1, (const ut8*)"\x00\x00\x00\x0d" },
	{ 0, 0, NULL }
};

struct r_bp_plugin_t r_bp_plugin_mips = {
	.name = "mips",
	.arch = "mips",
	.nbps = 10,
	.bps = r_bp_plugin_mips_bps,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &r_bp_plugin_mips,
};
#endif
