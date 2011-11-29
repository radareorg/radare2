/* radare - LGPL - Copyright 2009-2011 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_bin.h>

static int get_line(RBinArch *arch, ut64 addr, char *file, int len, int *line) {
	char *p, *out = r_sys_cmd_strf ("addr2line -e '%s' 0x%08"PFMT64x"", arch->file, addr);
	if (out == NULL || *out=='?')
		return R_FALSE;
	p = strchr (out, ':');
	if (p) {
		*p = '\0';
		if (line)
			*line = atoi (p+1);
		strncpy (file, out, len);
	} else return R_FALSE;
	return R_TRUE;
}

#if !R_BIN_ELF64
struct r_bin_meta_t r_bin_meta_elf = {
	.get_line = &get_line,
};
#endif
