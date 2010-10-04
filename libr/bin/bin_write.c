/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_bin.h>

/* XXX Implement r__bin_wr_scn_{set, del} instead */
R_API ut64 r_bin_wr_scn_resize(RBin *bin, const char *name, ut64 size) {
	if (bin->curarch.curplugin && bin->curarch.curplugin->write &&
		bin->curarch.curplugin->write->scn_resize)
		return bin->curarch.curplugin->write->scn_resize (&bin->curarch,
				name, size);
	return R_FALSE;
}

R_API int r_bin_wr_rpath_del(RBin *bin) {
	if (bin->curarch.curplugin && bin->curarch.curplugin->write &&
		bin->curarch.curplugin->write->rpath_del)
		return bin->curarch.curplugin->write->rpath_del (&bin->curarch);
	return R_FALSE;
}

R_API int r_bin_wr_output(RBin *bin, const char *filename) {
	return r_file_dump (filename, bin->curarch.buf->buf,
			bin->curarch.buf->length);
}
