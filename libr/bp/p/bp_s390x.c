/* radare2 - LGPL - Copyright 2024 - pancake */

#include <r_bp.h>
#include <r_lib.h>

static RBreakpointArch r_bp_plugin_s390x_bps[] = {
	{ 32, 2, 0, (const ut8*)"\x00\x01" },
	{ 64, 2, 0, (const ut8*)"\x00\x01" },
	{ 64, 4, 0, (const ut8*)"\x00\x01\x00\x01" },
	{ 0, 0, 0, NULL }
};

RBreakpointPlugin r_bp_plugin_s390x = {
	.name = "s390",
	.arch = "s390",
	.nbps = 3,
	.bps = r_bp_plugin_s390x_bps,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &r_bp_plugin_s390x,
	.version = R2_VERSION
};
#endif
