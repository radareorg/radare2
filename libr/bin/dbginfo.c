/* radare - LGPL - Copyright 2009-2014 - nibble, pancake */

#include <r_types.h>
#include <r_bin.h>

R_API int r_bin_addr2line(RBin *bin, ut64 addr, char *file, int len, int *line) {
	RBinObject *o = bin->cur->o;
	RBinPlugin *cp = bin->cur->curplugin;
	if (cp && cp->dbginfo) {
		if (addr >= o->baddr && addr < (o->baddr+bin->cur->size))
			if (cp->dbginfo->get_line)
				return cp->dbginfo->get_line (bin->cur,
					addr, file, len, line);
	}
	return R_FALSE;
}

R_API char *r_bin_addr2text(RBin *bin, ut64 addr) {
	char file[1024];
	int line;
	char *out = NULL;
	if (r_bin_addr2line (bin, addr, file, sizeof (file), &line))
		out = r_file_slurp_line (file, line, 0);
	return out;
}

R_API char *r_bin_addr2fileline(RBin *bin, ut64 addr) {
	char file[1024];
	int line;
	char *out = NULL;
	if (r_bin_addr2line (bin, addr, file, sizeof (file)-1, &line)) {
		int sz = strlen (file)+10;
		out = malloc (sz);
		snprintf (out, sizeof (sz), "%s:%d", file, line);
	}
	return out;
}
