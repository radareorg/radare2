/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_lib.h>
#include <r_anal.h>

struct r_anal_handle_t r_anal_plugin_dummy = {
	.name = "dummy",
	.desc = "Dummy analysis plugin",
	.init = NULL,
	.fini = NULL,
	.aop = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_dummy
};
#endif
