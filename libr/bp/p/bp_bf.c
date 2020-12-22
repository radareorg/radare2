/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <r_bp.h>
#include <r_lib.h>

static struct r_bp_arch_t r_bp_plugin_bf_bps[] = {
	{ 0, 1, 0, (const ut8*)"\xff" },
	{ 0, 1, 0, (const ut8*)"\x00" },
	{ 0, 0, 0, NULL },
};

struct r_bp_plugin_t r_bp_plugin_bf = {
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
