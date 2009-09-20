#include <r_lib.h>

int cb_1(struct r_lib_plugin_t *obj, void *a, void *b)
{
	int (*fun)() = a; /* points to 'ptr' */
	int num = *(int *)b;

	fun(); /* indirect calls ptr() */
	printf("Plugin value: 0x%x\n", num);
	return 0;
}

int cb_1_end(struct r_lib_plugin_t *obj,void *a, void *b)
{
	printf("==> Plugin '%s' unloaded (file=%s)\n", obj->handler->desc, obj->file);
	return 0;
}

int cb_2(struct r_lib_plugin_t *obj, void *a, void *b)
{
	printf("Plugin '%s' unloaded\n", obj->handler->desc);
	return 0;
}

int cb_2_end(struct r_lib_plugin_t *obj,void *a, void *b)
{
	printf("==> Plugin 'disassembler' unloaded\n");
	return 0;
}


int ptr()
{
	printf("Data pointer passed properly\n");
	return 0;
}

int main(int argc, char **argv)
{
	struct r_lib_t *lib;
	int ret;

	lib = r_lib_new("radare_plugin");
	r_lib_add_handler(lib, 1, "example plugin handler", &cb_1, &cb_1_end, &ptr);
	r_lib_add_handler(lib, 2, "disassembler plugin handler", &cb_2, &cb_2_end, &ptr);
	r_lib_add_handler(lib, 3, "file headers parser plugin handler", &cb_2, &cb_2_end, &ptr);
	ret = r_lib_open(lib, "./plugin.so");
	if (ret == -1) printf("Cannot open plugin\n");
	else printf("Plugin opened correctly\n");
	r_lib_list(lib);

	printf("  --- closing './plugin.so' ---\n");
	r_lib_close(lib, "./plugin.so");
	r_lib_list(lib);
	printf("  ---\n");


	r_lib_close(lib, "./plugin.so");
	r_lib_free(lib);

	return 0;
}

