/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_lib.h>
#include <r_anal.h>

static int aop(struct r_anal_t *anal, struct r_anal_aop_t *aop, void *data)
{
	printf("Dummy analysis plugin");

	return R_FALSE;
}

static struct r_anal_handle_t r_anal_plugin_dummy = {
	.name = R_ANAL_NAME("anal_dummy"),
	.desc = "Dummy analysis plugin",
	.init = NULL,
	.fini = NULL,
	.aop = &aop
};

struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_dummy
};
