/* radare - LGPL - Copyright 2011-2023 - pancake */

#include <r_bp.h>
#include <r_lib.h>

static RBreakpointArch r_bp_plugin_bf_bps[] = {
	{ 0, 1, 0, (const ut8*)"\xff" },
	{ 0, 1, 0, (const ut8*)"\x00" },
	{ 0, 0, 0, NULL },
};

RBreakpointPlugin r_bp_plugin_bf = {
	.name = "bf",
	.arch = "bf",
	.nbps = 2,
	.bps = r_bp_plugin_bf_bps,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &r_bp_plugin_bf,
	.version = R2_VERSION
};
#endif

