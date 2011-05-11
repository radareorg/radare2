/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_bp.h>
#include <r_lib.h>

static struct r_bp_arch_t r_bp_plugin_sh_bps[] = {
	{ 2, 0, (const ut8*)"\x20\xc3" }, //Little endian bp
	{ 2, 1, (const ut8*)"\xc3\x20" }, //Big endian bp
	{ 0, 0, NULL },
};

struct r_bp_plugin_t r_bp_plugin_sh = {
	.name = "sh",
	.arch = "sh",
	.nbps = 2,
	.bps = r_bp_plugin_sh_bps,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &r_bp_plugin_sh,
};
#endif
