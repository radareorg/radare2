/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_bp.h>
#include <r_lib.h>

static struct r_bp_arch_t r_bp_plugin_x86_bps[] = {
	{ 1, 0, (const u8*)"\xcc" },
	{ 2, 0, (const u8*)"\xcd\x03" },
	{ 0, 0, NULL },
};

struct r_bp_handle_t r_bp_plugin_x86 = {
	.name = "bp_x86",
	.arch = "x86",
	.nbps = 2,
	.bps = r_bp_plugin_x86_bps,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &r_bp_plugin_x86,
};
#endif
