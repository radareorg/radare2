/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_bin.h>

R_API int r_bin_wr_scn_set(RBin *bin, RBinSection *scn) {
	if (bin && bin->cur && bin->cur->write && bin->cur->write->scn_set)
		return bin->cur->write->scn_set (bin, scn);
	return R_FALSE;
}
