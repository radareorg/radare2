/* radare2 - LGPL - Copyright 2009-2019 - pancake, nibble */

#include <r_types.h>
#include <r_util.h>
#include <r_bin.h>

/* XXX Implement r__bin_wr_scn_{   set, del   } instead */
R_API ut64 r_bin_wr_scn_resize(RBin *bin, const char *name, ut64 size) {
	RBinFile *bf = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	if (plugin && plugin->write && plugin->write->scn_resize) {
		return plugin->write->scn_resize (bf, name, size);
	}
	return false;
}

R_API bool r_bin_wr_scn_perms(RBin *bin, const char *name, int perms) {
	RBinFile *bf = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	if (plugin && plugin->write && plugin->write->scn_perms) {
		return plugin->write->scn_perms (bf, name, perms);
	}
	return false;
}

R_API bool r_bin_wr_rpath_del(RBin *bin) {
	RBinFile *bf = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	if (plugin && plugin->write && plugin->write->rpath_del) {
		return plugin->write->rpath_del (bf);
	}
	return false;
}

R_API bool r_bin_wr_output(RBin *bin, const char *filename) {
	r_return_val_if_fail (bin && filename, false);
	RBinFile *bf = r_bin_cur (bin);
	if (!bf || !bf->buf) {
		return false;
	}
	ut64 tmpsz;
	const ut8 *tmp = r_buf_data (bf->buf, &tmpsz);
	return r_file_dump (filename, tmp, tmpsz, 0);
}

R_API bool r_bin_wr_entry(RBin *bin, ut64 addr) {
	RBinFile *bf = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	if (plugin && plugin->write && plugin->write->entry) {
		return plugin->write->entry (bf, addr);
	}
	return false;
}

R_API bool r_bin_wr_addlib(RBin *bin, const char *lib) {
	RBinFile *bf = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	if (plugin && plugin->write && plugin->write->addlib) {
		return plugin->write->addlib (bin->cur, lib);
	}
	return false;
}
