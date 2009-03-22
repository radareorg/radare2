/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */

#include <r_bininfo.h>
#include <r_lib.h>

static char *get_path(struct r_bininfo_t *bi)
{
	return strdup("");
}

static char *get_function_name(struct r_bininfo_t *bi, u64 addr, char *file, int len)
{
	char buf[1024];
	sprintf(buf, "addr2line -f -e %s 0x%08llx | head -n 1", file, addr);
printf("==>%s\n", buf);
	system(buf);
}

static char *get_line(struct r_bininfo_t *bi, u64 addr, char *file, int line)
{
	char buf[1024];
	sprintf(buf, "addr2line -e %s 0x%08llx", addr);
printf("==>%s\n", buf);
	system(buf);
	// TODO: get output and dump it back to file buffer
}

struct r_bininfo_handle_t r_bininfo_plugin_addr2line = {
	.name = "addr2line",
	.desc = "addr2line based dwarf utility",
	.get_path = get_path,
	.get_line = get_line,
	.get_function_name = get_function_name,
	.init = NULL,
	.fini = NULL,
	.open = NULL,
	.close = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bininfo_plugin_addr2line
};
#endif
