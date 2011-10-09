/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <r_bp.h>
#include <r_lib.h>

static struct r_bp_arch_t r_bp_plugin_bf_bps[] = {
	{ 1, 0, (const ut8*)"\xff" },
	{ 1, 0, (const ut8*)"\x00" },
	{ 0, 0, NULL },
};

struct r_bp_plugin_t r_bp_plugin_bf = {
	.name = "bf",
	.arch = "bf",
	.nbps = 2,
	.bps = r_bp_plugin_bf_bps,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &r_bp_plugin_bf,
};
#endif
