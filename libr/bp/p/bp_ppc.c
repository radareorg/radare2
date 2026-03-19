/* radare - LGPL - Copyright 2010-2023 - pancake */

#include <r_bp.h>
#include <r_lib.h>

static RBreakpointArch r_bp_plugin_ppc_bps[] = {
	/* These use the illegal instruction 0x0d000000 as a software trap,
	 * not the standard PPC `trap` (tw 31,0,0 = 0x7fe00008). This
	 * works on most PPC systems but may need revisiting per-target. */
	{ 32, 4, 0, (const ut8*)"\x00\x00\x00\x0d" }, // little endian
	{ 32, 4, 1, (const ut8*)"\x0d\x00\x00\x00" }, // big endian
	{ 0, 0, 0, NULL }
};

RBreakpointPlugin r_bp_plugin_ppc = {
	.meta = {
		.name = "ppc",
		.desc = "",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.arch = "ppc",
	.nbps = 2,
	.bps = r_bp_plugin_ppc_bps,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &r_bp_plugin_ppc,
	.version = R2_VERSION
};
#endif
