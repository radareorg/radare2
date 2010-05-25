/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

#include <r_bp.h>
#include <r_lib.h>

static struct r_bp_arch_t r_bp_plugin_ppc_bps[] = {
	/* XXX: FIX those are not really breakpoint opcodes at all */
	{ 4, 0, (const ut8*)"\x00\x00\x00\x0d" }, // little endian
	{ 4, 1, (const ut8*)"\x0d\x00\x00\x00" }, // big endian
};

struct r_bp_plugin_t r_bp_plugin_ppc = {
	.name = "ppc",
	.arch = "ppc",
	.nbps = 2,
	.bps = r_bp_plugin_ppc_bps,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &r_bp_plugin_ppc,
};
#endif
