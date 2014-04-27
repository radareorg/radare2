/* radare - LGPL - Copyright 2011 pancake<@nopcode.org> */
/* shoorisu yagana shellcode encoder */
/* wishlist:
 - fork/setuid
 - polimorphic
 - mmap to skip w^x
 - avoid 00 or alphanumeric
 - random cipher algorithm
 - trash
 - antidisasm tricks
 - virtual machine
*/

static RBuffer *build (REgg *egg) {
	RBuffer *buf = r_buf_new ();
	char *key = r_egg_option_get (egg, "key");
	char *seed = r_egg_option_get (egg, "seed");
	eprintf ("TODO: shoorisu yagana shellcode encoder\n");
	free (key);
	free (seed);
	return buf;
}

REggPlugin r_egg_plugin_shya = {
	.name = "shya",
	.type = R_EGG_PLUGIN_ENCODER,
	.desc = "shoorisu yagana",
	.build = (void *)build
};

#if 0
#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_EGG,
	.data = &r_egg_plugin_shya
};
#endif
#endif
