/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_bin.h>

R_API int r_bin_wr_resize_scn(RBin *bin, const char *name, ut64 size) {
	if (bin && bin->cur && bin->cur->write && bin->cur->write->resize_scn)
		return bin->cur->write->resize_scn (bin, name, size);
	return R_FALSE;
}
