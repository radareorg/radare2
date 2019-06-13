/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

#include <r_bp.h>
#include <r_lib.h>

static struct r_bp_arch_t r_bp_plugin_ppc_bps[] = {
	/* XXX: FIX those are not really breakpoint opcodes at all */
	{ 32, 4, 0, (const ut8*)"\x00\x00\x00\x0d" }, // little endian
	{ 32, 4, 1, (const ut8*)"\x0d\x00\x00\x00" }, // big endian
	{ 0, 0, 0, NULL }
};

struct r_bp_plugin_t r_bp_plugin_ppc = {
	.name = "ppc",
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
