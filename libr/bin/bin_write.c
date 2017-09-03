/* radare - LGPL - Copyright 2009-2015 - pancake, nibble */

#include <r_types.h>
#include <r_util.h>
#include <r_bin.h>

/* XXX Implement r__bin_wr_scn_{   set, del   } instead */
R_API ut64 r_bin_wr_scn_resize(RBin *bin, const char *name, ut64 size) {
	RBinFile *binfile = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && plugin->write && plugin->write->scn_resize) {
		return plugin->write->scn_resize (bin->cur, name, size);
	}
	return false;
}

R_API bool r_bin_wr_scn_perms(RBin *bin, const char *name, int perms) {
	RBinFile *binfile = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && plugin->write && plugin->write->scn_perms) {
		return plugin->write->scn_perms (bin->cur, name, perms);
	}
	return false;
}

R_API bool r_bin_wr_rpath_del(RBin *bin) {
	RBinFile *binfile = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && plugin->write && plugin->write->rpath_del) {
		return plugin->write->rpath_del (bin->cur);
	}
	return false;
}

R_API bool r_bin_wr_output(RBin *bin, const char *filename) {
	RBinFile *binfile = r_bin_cur (bin);
	if (!filename || !binfile || !binfile->buf) return false;
	return r_file_dump (filename, binfile->buf->buf,
			binfile->buf->length, 0);
}

R_API bool r_bin_wr_entry(RBin *bin, ut64 addr) {
	RBinFile *binfile = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && plugin->write && plugin->write->entry) {
		return plugin->write->entry (bin->cur, addr);
	}
	return false;
}

R_API bool r_bin_wr_addlib(RBin *bin, const char *lib) {
	RBinFile *binfile = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
	if (plugin && plugin->write && plugin->write->addlib) {
		return plugin->write->addlib (bin->cur, lib);
	}
	return false;
}
