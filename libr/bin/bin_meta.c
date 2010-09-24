/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_bin.h>

R_API int r_bin_meta_get_line(RBin *bin, ut64 addr, char *file, int len, int *line) {
	if (bin->curarch && bin->curarch->curplugin && bin->curarch->curplugin->meta) {
		// XXX quick hack to not show lines out of opened bin
		if (addr >= bin->curarch->baddr && addr < (bin->curarch->baddr+bin->curarch->size))
		if (bin->curarch->curplugin->meta->get_line)
			return bin->curarch->curplugin->meta->get_line (bin->arch, addr,
					file, len, line);
	}
	return R_FALSE;
}

R_API char *r_bin_meta_get_source_line(RBin *bin, ut64 addr) {
	char file[4096];
	int line;
	char *out = NULL;
	if (r_bin_meta_get_line (bin, addr, file, sizeof (file), &line))
		out = r_file_slurp_line (file, line, 0);
	return out;
}
