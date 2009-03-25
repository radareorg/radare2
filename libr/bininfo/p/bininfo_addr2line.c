/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */

#include <r_bininfo.h>
#include <r_lib.h>

static char *a2l_get_path(struct r_bininfo_t *bi)
{
	return strdup("");
}

static int cmd_to_str(const char *cmd, char *out, int len)
{
	FILE *fd = popen(cmd, "r");
	if (fd == NULL) {
		fprintf(stderr, "Cannot find 'addr2line' program\n");
		return R_FALSE;
	}
	fread(out, len, 1, fd);
	if (out[strlen(out)-1]=='\n')
		out[strlen(out)-1]='\0';
	pclose(fd);
	return R_TRUE;
}

/* XXX: Bad signature */
static char *a2l_get_function_name(struct r_bininfo_t *bi, u64 addr, char *file, int len)
{
	static char buf[1024];
	sprintf(buf, "addr2line -f -e '%s' 0x%08llx | head -n 1", file, addr);
	if (!cmd_to_str(buf, file, len))
		return R_FALSE;
	return buf;
}

static int a2l_get_line(struct r_bininfo_t *bi, u64 addr, char *file, int len, int *line)
{
	char *p, buf[1024];
	// TODO: move to r_util
	sprintf(buf, "addr2line -e '%s' 0x%08llx", bi->file, addr);

	memset(file,'\0', len);
	if (!cmd_to_str(buf, file, len))
		return R_FALSE;

	p = strchr(file, ':');
	if (p) {
		*p='\0';
		*line = atoi(p+1);
	}

	return R_TRUE;
}

static int a2l_open(struct r_bininfo_t *bi)
{
	return R_TRUE;
}

struct r_bininfo_handle_t r_bininfo_plugin_addr2line = {
	.name = "bininfo_addr2line",
	.desc = "addr2line based dwarf utility",
	.get_path = a2l_get_path,
	.get_line = a2l_get_line,
	.get_function_name = a2l_get_function_name,
	.init = NULL,
	.fini = NULL,
	.open = &a2l_open,
	.close = NULL,
	.check = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BININFO,
	.data = &r_bininfo_plugin_addr2line
};
#endif
