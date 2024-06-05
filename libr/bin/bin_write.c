/* radare2 - LGPL - Copyright 2009-2024 - pancake, nibble */

#include <r_bin.h>

/* XXX Implement r__bin_wr_scn_{   set, del   } instead */
// R2_600 evaluate return bool here
R_API ut64 r_bin_wr_scn_resize(RBin *bin, const char *name, ut64 size) {
	R_RETURN_VAL_IF_FAIL (bin && name, UT64_MAX);
	RBinFile *bf = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	RBinWriteScnResize scn_resize = R_UNWRAP3 (plugin, write, scn_resize);
	if (scn_resize) {
		return scn_resize (bf, name, size);
	}
	return 0;
}

R_API bool r_bin_wr_scn_perms(RBin *bin, const char *name, int perms) {
	R_RETURN_VAL_IF_FAIL (bin && name, false);
	RBinFile *bf = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	RBinWriteScnPerms scn_perms = R_UNWRAP3 (plugin, write, scn_perms);
	if (scn_perms) {
		return scn_perms (bf, name, perms);
	}
	return false;
}

R_API bool r_bin_wr_rpath_del(RBin *bin) {
	R_RETURN_VAL_IF_FAIL (bin, false);
	RBinFile *bf = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	RBinWriteRpathDel rpath_del = R_UNWRAP3 (plugin, write, rpath_del);
	return rpath_del? rpath_del (bf): false;
}

R_API bool r_bin_wr_output(RBin *bin, const char *filename) {
	R_RETURN_VAL_IF_FAIL (bin && filename, false);
	RBinFile *bf = r_bin_cur (bin);
	if (!bf || !bf->buf) {
		return false;
	}
	ut64 tmpsz = 0;
	const ut8 *tmp = r_buf_data (bf->buf, &tmpsz);
	return r_file_dump (filename, tmp, tmpsz, 0);
}

R_API bool r_bin_wr_entry(RBin *bin, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (bin, false);
	RBinFile *bf = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	RBinWriteEntry entry = R_UNWRAP3 (plugin, write, entry);
	return entry? entry (bf, addr): false;
}

R_API bool r_bin_wr_addlib(RBin *bin, const char *lib) {
	R_RETURN_VAL_IF_FAIL (bin && lib, false);
	RBinFile *bf = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	RBinWriteAddLib addlib = R_UNWRAP3 (plugin, write, addlib);
	return addlib? addlib (bin->cur, lib): false;
}
