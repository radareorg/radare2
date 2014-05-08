/* radare - LGPL - Copyright 2009-2013 - nibble */

#include <r_types.h>
#include <r_util.h>
#include <r_bin.h>

/* XXX Implement r__bin_wr_scn_{set, del} instead */
R_API ut64 r_bin_wr_scn_resize(RBin *bin, const char *name, ut64 size) {
	RBinFile *binfile = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && plugin->write &&
		plugin->write->scn_resize) {
		return plugin->write->scn_resize (bin->cur, name, size);
	}
	return R_FALSE;
}

R_API int r_bin_wr_rpath_del(RBin *bin) {
	RBinFile *binfile = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && plugin->write &&
		plugin->write->rpath_del){
		return plugin->write->rpath_del (bin->cur);
	}
	return R_FALSE;
}

R_API int r_bin_wr_output(RBin *bin, const char *filename) {
	RBinFile *binfile = r_bin_cur (bin);

	if (!binfile || !binfile->buf) return R_FALSE;
	return r_file_dump (filename, binfile->buf->buf,
			binfile->buf->length);
}
