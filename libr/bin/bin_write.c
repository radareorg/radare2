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
	return UT64_MAX;
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

R_API bool r_bin_wr_seg_perms(RBin *bin, const char *name, int perms) {
	R_RETURN_VAL_IF_FAIL (bin && name, false);
	RBinFile *bf = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	RBinWriteSegPerms seg_perms = R_UNWRAP3 (plugin, write, seg_perms);
	if (seg_perms) {
		return seg_perms (bf, name, perms);
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
	if (bf && !r_list_empty (bf->xtr_data)) {
		R_LOG_ERROR ("Extract the binary before adding a library");
		return false;
	}
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	RBinWriteAddLib addlib = R_UNWRAP3 (plugin, write, addlib);
	return addlib? addlib (bin->cur, lib): false;
}

R_API bool r_bin_wr_lib_weak(RBin *bin, const char *lib, bool weak) {
	R_RETURN_VAL_IF_FAIL (bin && lib, false);
	RBinFile *bf = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	RBinWriteLibWeak lib_weak = R_UNWRAP3 (plugin, write, lib_weak);
	return lib_weak? lib_weak (bf, lib, weak): false;
}

R_API bool r_bin_wr_symbol_weak(RBin *bin, const char *symbol, bool weak) {
	R_RETURN_VAL_IF_FAIL (bin && symbol, false);
	RBinFile *bf = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	RBinWriteSymbolWeak symbol_weak = R_UNWRAP3 (plugin, write, symbol_weak);
	return symbol_weak? symbol_weak (bf, symbol, weak): false;
}

R_API int r_bin_wr_checksum(RBin *bin, RStrBuf *report, bool fix) {
	R_RETURN_VAL_IF_FAIL (bin && report, -1);
	RBinFile *bf = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	RBinWriteChecksum checksum = R_UNWRAP3 (plugin, write, checksum);
	return checksum? checksum (bf, report, fix): -1;
}

// compare the checksum stored at paddr with the computed one, rewriting it when fix is set
R_API bool r_bin_wr_checksum_update(RBuffer *b, RStrBuf *report, const char *name, ut64 paddr, const ut8 *computed, int len, bool fix) {
	R_RETURN_VAL_IF_FAIL (b && report && name && computed && len > 0, false);
	ut8 *stored = malloc (len);
	if (!stored) {
		return false;
	}
	bool matches = false;
	if (r_buf_read_at (b, paddr, stored, len) == len) {
		matches = !memcmp (stored, computed, len);
		char *stored_hex = r_hex_bin2strdup (stored, len);
		char *computed_hex = r_hex_bin2strdup (computed, len);
		if (matches) {
			r_strbuf_appendf (report, "%s 0x%08" PFMT64x " %s ok\n", name, paddr, stored_hex);
		} else if (fix && r_buf_write_at (b, paddr, computed, len) == len) {
			r_strbuf_appendf (report, "%s 0x%08" PFMT64x " %s fixed\n", name, paddr, computed_hex);
		} else {
			r_strbuf_appendf (report, "%s 0x%08" PFMT64x " %s bad %s\n", name, paddr, stored_hex, computed_hex);
		}
		free (stored_hex);
		free (computed_hex);
	}
	free (stored);
	return matches;
}
