/* radare2 - LGPL - Copyright 2018 - pancake */

#include <r_bin.h>

R_API int r_bin_open(RBin *bin, const char *filename, RBinOptions *bo) {
	ut64 baddr = 0LL, laddr = 0LL;
	int iofd = -1, rawstr = 0, xtr_idx = 0;

	r_return_val_if_fail (bin && filename && bo, -1);

	baddr = bo->baseaddr;
	laddr = bo->loadaddr;
	xtr_idx = bo->xtr_idx;
	iofd = bo->iofd;
	rawstr = bo->rawstr;
	if (r_bin_load (bin, filename, baddr, laddr, xtr_idx, iofd, rawstr)) {
		int id = bin->cur->id; // TODO rename to bd?
		r_id_storage_set (bin->ids, bin->cur, id);
		return id;
	}
	return -1;
}
