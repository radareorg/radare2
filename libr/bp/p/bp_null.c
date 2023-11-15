/* radare - LGPL - Copyright 2023 - pancake */

#include <r_bp.h>
#include <r_lib.h>

static RBreakpointArch r_bp_plugin_null_bps[] = {
	{ 0, 0, 0, NULL },
};

RBreakpointPlugin r_bp_plugin_null = {
	.name = "null",
	.arch = "null",
	.nbps = 0,
	.bps = r_bp_plugin_null_bps,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &r_bp_plugin_null,
	.version = R2_VERSION
};
#endif
