/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_bin.h>

R_API int r_bin_meta_get_line(RBin *bin, ut64 addr, char *file, int len, int *line) {
	if (bin && bin->cur && bin->cur->meta && bin->cur->meta->get_line)
		return bin->cur->meta->get_line (bin, addr, file, len, line);
	return R_FALSE;
}
