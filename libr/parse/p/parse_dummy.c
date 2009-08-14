/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>

#include <r_lib.h>
#include <r_parse.h>

static int parse(struct r_parse_t *p, void *data, char *str)
{
	printf("Dummy parsing plugin");

	return R_FALSE;
}

struct r_parse_handle_t r_parse_plugin_dummy = {
	.name = "parse_dummy",
	.desc = "dummy parsing plugin",
	.init = NULL,
	.fini = NULL,
	.parse = &parse,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_dummy
};
#endif
