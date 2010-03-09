/* radare - GPL3 - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_bin.h>

static int cmd_to_str(const char *cmd, char *out, int len)
{
	int ret;
	FILE *fd = popen(cmd, "r");
	if (fd == NULL) {
		fprintf(stderr, "Cannot find 'addr2line' program\n");
		return R_FALSE;
	}
	ret = fread(out, 1, len, fd);
	if (ret>0) {
		if (out[ret-1]=='\n')
			out[ret-1]='\0';
	} else *out = '\0';
	pclose(fd);
	return R_TRUE;
}

static int get_line(RBin *bin, ut64 addr, char *file, int len, int *line) {
	char *p, buf[1024];

	snprintf (buf, 1023, "addr2line -e '%s' 0x%08llx", bin->file, addr);

	memset (file,'\0', len);
	if (!cmd_to_str (buf, file, len))
		return R_FALSE;

	p = strchr (file, ':');
	if (p) {
		*p='\0';
		*line = atoi(p+1);
	} else return R_FALSE;
	if (*file=='?')
		return R_FALSE;

	return R_TRUE;
}

#if !R_BIN_ELF64
struct r_bin_meta_t r_bin_meta_elf = {
	.get_line = &get_line,
};
#endif
