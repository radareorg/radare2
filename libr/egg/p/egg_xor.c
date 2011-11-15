/* radare - LGPL - Copyright 2011 pancake<@nopcode.org> */
#include <r_egg.h>

static RBuffer *build (REgg *egg) {
	RBuffer *buf = r_buf_new ();
	char *key = r_egg_option_get (egg, "key");
	eprintf ("TODO\n");
	free (key);
	return buf;
}

//TODO: rename plugin to run
REggPlugin r_egg_plugin_xor = {
	.name = "xor",
	.type = R_EGG_PLUGIN_ENCODER,
	.desc = "xor encoder for shellcode",
	.build = (void *)build
};

#if 0
#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_EGG,
	.data = &r_egg_plugin_xor
};
#endif
#endif
