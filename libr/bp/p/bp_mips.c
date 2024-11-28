/* radare2 - LGPL - Copyright 2010-2023 - pancake */

#include <r_bp.h>
#include <r_lib.h>

static RBreakpointArch r_bp_plugin_mips_bps[] = {
	{ 32, 4, 0, (const ut8*)"\x0d\x00\x00\x00" },
	{ 32, 4, 1, (const ut8*)"\x00\x00\x00\x0d" },
	{ 64, 4, 0, (const ut8*)"\x0d\x00\x00\x00" },
	{ 64, 4, 1, (const ut8*)"\x00\x00\x00\x0d" },
	{ 0, 0, 0, NULL }
};

RBreakpointPlugin r_bp_plugin_mips = {
	.meta = {
		.name = "mips",
		.desc = "",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.arch = "mips",
	.nbps = 4,
	.bps = r_bp_plugin_mips_bps,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &r_bp_plugin_mips,
	.version = R2_VERSION
};
#endif
