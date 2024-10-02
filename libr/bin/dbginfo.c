/* radare - LGPL - Copyright 2009-2024 - nibble, pancake */

#include <r_bin.h>

// R2R db/formats/mangling/bin
// R2R db/formats/dwarf
// R2R db/perf/dex
// R2R db/cmd/lea_intel

// R2_600 - make this api public -- see row_free in dwarf.c
static void r_bin_dbgitem_free(RBinDbgItem *di) {
	if (di) {
		free (di->file);
		free (di);
	}
}

// R2_600 - make this api public
static RBinDbgItem *r_bin_dbgitem_at(RBin *bin, ut64 addr) {
	r_strf_var (key, 64, "0x%"PFMT64x, addr); // TODO: use sdb_itoa because its faster
	char *data = sdb_get (bin->cur->sdb_addrinfo, key, 0);
	if (data) {
		RBinDbgItem *di = R_NEW0 (RBinDbgItem);
		di->address = addr;
		// 0xaddr=file.c|line:column
		char *token = strchr (data, '|');
		if (!token) {
			token = strchr (data, ':');
		}
		if (token) {
			*token++ = 0;
			char *token2 = strchr (token, ':');
			if (token2) {
				*token2++ = 0;
				di->column = atoi (token2);
			} else {
				di->column = 0;
			}
			di->line = atoi (token);
		}
		di->file = data;
		return di;
	}
	return NULL;
}

// XXX this is an useless wrapper
static bool addr2line_from_sdb(RBin *bin, ut64 addr, char *file, int len, int *line, int *column) {
	R_RETURN_VAL_IF_FAIL (bin, false);
	if (!bin->cur || !bin->cur->sdb_addrinfo) {
		return false;
	}
	RBinDbgItem *di = r_bin_dbgitem_at (bin, addr);
	if (di) {
		if (line) {
			*line = di->line;
		}
		if (column) {
			*column = di->column;
		}
		r_str_ncpy (file, di->file, len);
		r_bin_dbgitem_free (di);
		return true;
	}
	return false;
}

// XXX this api must return a struct instead of pa
// R_API RBinDwarfRow *r_bin_addr2line(RBin *bin, ut64 addr) {}
R_API bool r_bin_addr2line(RBin *bin, ut64 addr, char *file, int len, int *line, int *column) {
	R_RETURN_VAL_IF_FAIL (bin, false);
	RBinFile *binfile = r_bin_cur (bin);
	RBinObject *o = r_bin_cur_object (bin);
	RBinPlugin *cp = r_bin_file_cur_plugin (binfile);
	ut64 baddr = r_bin_get_baddr (bin);
	if (baddr == UT64_MAX) {
		baddr = 0;
	}
	if (o && addr >= baddr && addr < baddr + bin->cur->bo->size) {
		if (cp && cp->dbginfo && cp->dbginfo->get_line) {
			return cp->dbginfo->get_line (bin->cur, addr, file, len, line, column);
		}
		return addr2line_from_sdb (bin, addr, file, len, line, column);
	}
	return false;
}

static RBinDbgItem *r_bin_dbgitem_api(RBin *bin, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (bin, false);
	RBinFile *binfile = r_bin_cur (bin);
	RBinObject *o = r_bin_cur_object (bin);
	RBinPlugin *cp = r_bin_file_cur_plugin (binfile);
	ut64 baddr = r_bin_get_baddr (bin);
	if (baddr == UT64_MAX) {
		baddr = 0;
	}
	if (o && addr >= baddr && addr < baddr + bin->cur->bo->size) {
		char file[4096];
		int line = 0;
		int column= 0;
		int len = sizeof (file);
		if (cp && cp->dbginfo && cp->dbginfo->get_line) {
			if (cp->dbginfo->get_line (bin->cur, addr, file, len, &line, &column)) {
				RBinDbgItem *di = R_NEW0 (RBinDbgItem);
				di->file = file;
				di->address = addr;
				di->line = line;
				di->column = column;
				return di;
			}
		}
		// like addr2line but ensure we are not calling the sdb thing again
	}
	return NULL;
}

// given an address, return the filename:line:column\tcode or filename:line:column if the file doesnt exist
// origin can be 0, 1 or 2
R_API R_NULLABLE char *r_bin_addr2text(RBin *bin, ut64 addr, int origin) {
	R_RETURN_VAL_IF_FAIL (bin, NULL);
	if (!bin->cur) {
		return NULL;
	}
	RBinDbgItem *di = r_bin_dbgitem_at (bin, addr);
	if (!di) {
		di = r_bin_dbgitem_api (bin, addr);
		if (!di) {
			return NULL;
		}
	}
	char *res = NULL;
	char *filename = strdup (di->file);
#if R2_USE_NEW_ABI
	if (R_STR_ISNOTEMPTY (bin->srcdir_base) && r_str_startswith (filename, bin->srcdir_base)) {
		char *fn = strdup (filename + strlen (bin->srcdir_base));
		free (filename);
		filename = fn;
	}
#endif
	char *basename = strdup (r_file_basename (di->file));
#if __APPLE__
	// early optimization because mac's home is slow
	if (r_str_startswith (filename, "/home")) {
		// XXX
		free (filename);
		filename = strdup (basename);
	}
#endif
#if 0
	if (R_STR_ISEMPTY (bin->srcdir) && (di->file[0] == '/')) {
		char *res = r_str_newf ("%s:%d:%d", basename, di->line, di->column);
		r_bin_dbgitem_free (di);
		return res;
	}
#endif
	// check absolute path
	if (!r_file_exists (filename)) {
		// check in current directory
		if (strcmp (filename, basename) && r_file_exists (basename)) {
			free (filename);
			filename = strdup (basename);
		} else if (R_STR_ISNOTEMPTY (bin->srcdir)) {
			char *nf = r_str_newf ("%s/%s", bin->srcdir, basename);
			// check in srcdircurrent directory
			if (r_file_exists (nf)) {
				free (filename);
				filename = nf;
			} else {
				free (nf);
			}
		}
	}
	// out contains the contents of the slurped line
	char *out = r_file_slurp_line (filename, di->line, 0);
	if (origin) {
		// filename + text or fullpath + text
		if (di->column > 0) {
			res = r_str_newf ("%s:%d:%d%s", (origin > 1)? di->file: basename,
				di->line, di->column, r_str_get (out));
		} else {
			res = r_str_newf ("%s:%d%s", (origin > 1)? di->file: basename,
				di->line, r_str_get (out));
		}
		free (out);
	} else {
		// just the text from the file
		free (res);
		res = out;
	}
	free (filename);
	free (basename);
	r_bin_dbgitem_free (di);
	return res;
}

R_API char *r_bin_addr2fileline(RBin *bin, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (bin, NULL);
	char file[1024];
	int line = 0;
	int colu = -1;
	if (r_bin_addr2line (bin, addr, file, sizeof (file) - 1, &line, &colu)) {
		const char *file_nopath = r_file_basename (file);
		if (colu > 0) {
			return r_str_newf ("%s:%d:%d", file_nopath, line, colu);
		}
		return r_str_newf ("%s:%d", file_nopath, line);
	}
	return NULL;
}
