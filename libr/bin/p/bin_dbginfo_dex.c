/* radare - LGPL - Copyright 2009-2022 - nibble, montekki, pancake */

#include <r_bin.h>

static bool get_line(RBinFile *bf, ut64 addr, char *file, int len, int *line) {
	if (bf->sdb_addrinfo) {
		char offset[SDB_NUM_BUFSZ];
		char *offset_ptr = sdb_itoa (addr, 16, offset, sizeof (offset));
		char *ret = sdb_get (bf->sdb_addrinfo, offset_ptr, 0);
		if (ret) {
			char *p = strchr (ret, '|');
			if (p) {
				*p = '\0';
				strncpy (file, ret, len);
				*line = atoi (p + 1);
				return true;
			}
		}
	}
	return false;
}

RBinDbgInfo r_bin_dbginfo_dex = {
	.get_line = &get_line,
};
