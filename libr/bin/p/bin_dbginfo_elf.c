/* radare - LGPL - Copyright 2009-2023 - nibble, montekki, pancake */

#include <r_bin.h>

// TODO: use proper dwarf api here.. or deprecate
static bool get_line(RBinFile *bf, ut64 addr, char *file, int len, int *line, int *colu) {
	if (bf->sdb_addrinfo) {
		char offset[SDB_NUM_BUFSZ];
		char *offset_ptr = sdb_itoa (addr, 16, offset, sizeof (offset));
		char *ret = sdb_get (bf->sdb_addrinfo, offset_ptr, 0);
		if (ret) {
			char *p = strchr (ret, '|');
			if (p) {
				*p++ = '\0';
				char *c = strchr (p, ':');
				if (c) {
					*c++ = 0;
					*colu = atoi (c);
				}
				r_str_ncpy (file, ret, len);
				*line = atoi (p);
				return true;
			}
		}
	}
	return false;
}

#if R_BIN_ELF64
RBinDbgInfo r_bin_dbginfo_elf64 = {
	.get_line = &get_line,
};
#else
RBinDbgInfo r_bin_dbginfo_elf = {
	.get_line = &get_line,
};
#endif
