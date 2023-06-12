/* radare - LGPL - Copyright 2009-2023 - keegan */

#include <r_bin.h>

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

RBinDbgInfo r_bin_dbginfo_p9 = {
	.get_line = &get_line,
};
