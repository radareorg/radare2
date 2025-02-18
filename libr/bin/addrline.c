/* radare - LGPL - Copyright 2009-2025 - nibble, pancake */

#include <r_bin.h>

// R2_600 - rename all dbginfo into 'addrline'
// R2R db/formats/mangling/bin
// R2R db/formats/dwarf
// R2R db/perf/dex
// R2R db/cmd/lea_intel

#if 0
R_API RBinDbgItem *r_bin_dbgitem_at(RBin *bin, ut64 addr) {
R_API bool r_bin_addr2line(RBin *bin, ut64 addr, char *file, int len, int *line, int *column) {
R_API R_NULLABLE char *r_bin_addr2text(RBin *bin, ut64 addr, int origin) {
R_API char *r_bin_addr2fileline(RBin *bin, ut64 addr) {
#endif

R_API void r_bin_dbgitem_free(RBinDbgItem *di) {
	free (di);
}

R_API void r_bin_dbgitem_reset(RBin *bin) {
	if (bin->cur && bin->cur->addrline.storage) {
		RBinAddrLineStore *als = &bin->cur->addrline;
		if (als) {
			als->al_reset (als);
			return;
		}
	}
}

// must be tied to the rbinfile
// R2_600 - rename dbginfo to addrline
R_API void r_bin_dbginfo_reset(RBin *bin) {
	if (bin->cur) {
	       	if (bin->cur->addrline.used) {
			RBinAddrLineStore *als = &bin->cur->addrline;
			if (als && als->al_reset) {
				als->al_reset (als);
			}
		}
		sdb_reset (bin->cur->sdb_addrinfo);
	}
}

R_API void r_bin_dbginfo_reset_at(RBin *bin, ut64 addr) {
	if (bin->cur && bin->cur->addrline.used) {
		RBinAddrLineStore *als = &bin->cur->addrline;
		als->al_del (als, addr);
		return;
	}
	// R2_600 - old sdb way here, deprecate before the release
	char aoffset[SDB_NUM_BUFSZ];
	char *aoffsetptr = sdb_itoa (addr, 16, aoffset, sizeof (aoffset));
	if (!aoffsetptr) {
		R_LOG_ERROR ("Failed to convert %"PFMT64x" to a key", addr);
		return;
	}
	sdb_unset (bin->cur->sdb_addrinfo, aoffsetptr, 0);
}

R_API RList *r_bin_dbginfo_files(RBin *bin) {
	if (bin->cur && bin->cur->addrline.used) {
		RBinAddrLineStore *als = &bin->cur->addrline;
		return als->al_files (als);
	}
	return NULL;
}

R_API bool r_bin_dbginfo_foreach(RBin *bin, RBinDbgInfoCallback cb, void *user) {
	if (bin->cur && bin->cur->addrline.used) {
		RBinAddrLineStore *als = &bin->cur->addrline;
		als->al_foreach (als, cb, user);
		return true;
	}
	R_LOG_DEBUG ("Callback is not matching");
	return false;
}

R_API RBinDbgItem *r_bin_dbgitem_at(RBin *bin, ut64 addr) {
	if (bin->cur && bin->cur->addrline.used) {
		RBinAddrLineStore *als = &bin->cur->addrline;
		if (als) {
			return als->al_get (als, addr);
		}
	}
	// R2_600 - eprintf ("OLDPATH\n");
	r_strf_var (key, 64, "0x%"PFMT64x, addr); // TODO: use sdb_itoa because its faster
	char *data = sdb_get (bin->cur->sdb_addrinfo, key, 0);
	if (data) {
		RBinDbgItem *di = R_NEW0 (RBinDbgItem);
		di->addr = addr;
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

// XXX R2_600 - this api must return a struct instead of pa -- or just deprecate it
R_API bool r_bin_addr2line(RBin *bin, ut64 addr, char *file, int len, int *line, int *column) {
	R_RETURN_VAL_IF_FAIL (bin, false);

	if (bin->cur && bin->cur->addrline.used) {
		RBinAddrLineStore *als = &bin->cur->addrline;
		RBinDbgItem *item = als->al_get (als, addr);
		if (item) {
			// TODO: honor path
			r_str_ncpy (file, item->file, len);
			if (line) {
				*line = item->line;
			}
			if (column) {
				*column = item->column;
			}
			r_bin_dbgitem_free (item);
			return true;
		}
		return false;
	}

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
				di->file = strdup (file);
				di->addr = addr;
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
	if (R_STR_ISNOTEMPTY (bin->srcdir_base) && r_str_startswith (filename, bin->srcdir_base)) {
		char *fn = strdup (filename + strlen (bin->srcdir_base));
		free (filename);
		filename = fn;
	}
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

R_API void r_bin_addr2line_add(RBin *bin, ut64 addr, RBinDbgItem item) {
	eprintf ("ADD LINE\n");
	// const char *file, int line, int column) {
}

R_API RBinDbgItem *r_bin_addr2line_get(RBin *bin, ut64 addr) {
	eprintf ("GET LINE\n");
	// const char *file, int line, int column) {
	return NULL;
}
