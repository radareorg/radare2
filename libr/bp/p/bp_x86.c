/* radare - LGPL - Copyright 2009-2023 - pancake */

#include <r_bp.h>
#include <r_lib.h>

static RBreakpointArch r_bp_plugin_x86_bps[] = {
	{ 0, 1, 0, (const ut8*)"\xcc" }, // valid for 16, 32, 64
	{ 0, 2, 0, (const ut8*)"\xcd\x03" },
	{ 0, 0, 0, NULL },
};

RBreakpointPlugin r_bp_plugin_x86 = {
	.meta = {
		.name = "x86",
		.desc = "",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.arch = "x86",
	.nbps = 2,
	.bps = r_bp_plugin_x86_bps,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &r_bp_plugin_x86,
	.version = R2_VERSION
};
#endif
