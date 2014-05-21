/* radare - LGPL - Copyright 2009-2014 - nibble, montekki, pancake */

#include <r_types.h>
#include <r_bin.h>

// TODO: use proper dwarf api here.. or deprecate
static int get_line(RBinFile *arch, ut64 addr, char *file, int len, int *line) {
	char *ret, *p, *offset_ptr, offset[64];

	if (arch->sdb_addrinfo) {
		offset_ptr = sdb_itoa (addr, offset, 16);
		ret = sdb_get (arch->sdb_addrinfo, offset_ptr, 0);
		if (!ret)
			return R_FALSE;
		p = strchr (ret, '|');
		if (p) {
			*p = '\0';
			strncpy(file, ret, len);
			*line = atoi(p + 1);
			return R_TRUE;
		}
	}
	return R_FALSE;
}

#if !R_BIN_ELF64
struct r_bin_dbginfo_t r_bin_dbginfo_elf = {
	.get_line = &get_line,
};
#endif
