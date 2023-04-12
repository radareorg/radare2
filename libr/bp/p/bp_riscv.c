/* radare2 - LGPL - Copyright 2023 - pancake */

#include <r_bp.h>
#include <r_lib.h>

static RBreakpointArch r_bp_plugin_riscv_bps[] = {
	{ 32, 2, 0, (const ut8*)"\x02\x90" },
	{ 64, 4, 0, (const ut8*)"\x02\x90\x02\x90" },
	{ 0, 0, 0, NULL }
};

RBreakpointPlugin r_bp_plugin_riscv = {
	.name = "riscv",
	.arch = "riscv",
	.nbps = 2,
	.bps = r_bp_plugin_riscv_bps,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &r_bp_plugin_riscv,
	.version = R2_VERSION
};
#endif
