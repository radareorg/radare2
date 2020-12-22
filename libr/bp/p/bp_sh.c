/* radare - LGPL - Copyright 2009-2015 - pancake */

#include <r_bp.h>
#include <r_lib.h>

static struct r_bp_arch_t r_bp_plugin_sh_bps[] = {
	{ 32, 2, 0, (const ut8*)"\x20\xc3" }, //Little endian bp
	{ 32, 2, 1, (const ut8*)"\xc3\x20" }, //Big endian bp
	{ 0, 0, 0, NULL },
};

struct r_bp_plugin_t r_bp_plugin_sh = {
	.name = "sh",
	.arch = "sh",
	.nbps = 2,
	.bps = r_bp_plugin_sh_bps,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &r_bp_plugin_sh,
	.version = R2_VERSION
};
#endif
