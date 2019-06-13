/* radare2 - LGPL - Copyright 2010-2015 - pancake */

#include <r_bp.h>
#include <r_lib.h>

static struct r_bp_arch_t r_bp_plugin_mips_bps[] = {
	{ 32, 4, 0, (const ut8*)"\x0d\x00\x00\x00" },
	{ 32, 4, 1, (const ut8*)"\x00\x00\x00\x0d" },
	{ 64, 4, 0, (const ut8*)"\x0d\x00\x00\x00" },
	{ 64, 4, 1, (const ut8*)"\x00\x00\x00\x0d" },
	{ 0, 0, 0, NULL }
};

struct r_bp_plugin_t r_bp_plugin_mips = {
	.name = "mips",
	.arch = "mips",
	.nbps = 10,
	.bps = r_bp_plugin_mips_bps,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &r_bp_plugin_mips,
	.version = R2_VERSION
};
#endif
