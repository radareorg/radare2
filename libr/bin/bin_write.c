/* radare - LGPL - Copyright 2009-2012 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_bin.h>

/* XXX Implement r__bin_wr_scn_{set, del} instead */
R_API ut64 r_bin_wr_scn_resize(RBin *bin, const char *name, ut64 size) {
	if (bin->cur.curplugin && bin->cur.curplugin->write &&
		bin->cur.curplugin->write->scn_resize)
		return bin->cur.curplugin->write->scn_resize (&bin->cur,
				name, size);
	return R_FALSE;
}

R_API int r_bin_wr_rpath_del(RBin *bin) {
	if (bin->cur.curplugin && bin->cur.curplugin->write &&
		bin->cur.curplugin->write->rpath_del)
		return bin->cur.curplugin->write->rpath_del (&bin->cur);
	return R_FALSE;
}

R_API int r_bin_wr_output(RBin *bin, const char *filename) {
	return r_file_dump (filename, bin->cur.buf->buf,
			bin->cur.buf->length);
}
