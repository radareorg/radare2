/* radare - LGPL - Copyright 2009-2025 - nibble, pancake */

#include <r_bin.h>

// R2R db/formats/mangling/bin
// R2R db/formats/dwarf
// R2R db/perf/dex
// R2R db/cmd/lea_intel

R_API void r_bin_addrline_free(RBinAddrline *di) {
	free (di);
}

// must be tied to the rbinfile
R_API void r_bin_addrline_reset(RBin *bin) {
	if (bin->cur && bin->cur->addrline.used) {
		RBinAddrLineStore *als = &bin->cur->addrline;
		if (als && als->al_reset) {
			als->al_reset (als);
		}
	}
}

R_API void r_bin_addrline_reset_at(RBin *bin, ut64 addr) {
	if (bin->cur && bin->cur->addrline.used) {
		RBinAddrLineStore *als = &bin->cur->addrline;
		als->al_del (als, addr);
		return;
	}
}

R_API RList *r_bin_addrline_files(RBin *bin) {
	if (bin->cur && bin->cur->addrline.used) {
		RBinAddrLineStore *als = &bin->cur->addrline;
		return als->al_files (als);
	}
	return NULL;
}

R_API bool r_bin_addrline_foreach(RBin *bin, RBinDbgInfoCallback cb, void *user) {
	if (bin->cur && bin->cur->addrline.used) {
		RBinAddrLineStore *als = &bin->cur->addrline;
		als->al_foreach (als, cb, user);
		return true;
	}
	R_LOG_DEBUG ("Callback is not matching");
	return false;
}

R_API RBinAddrline *r_bin_dbgitem_at(RBin *bin, ut64 addr) {
	if (bin->cur && bin->cur->addrline.used) {
		RBinAddrLineStore *als = &bin->cur->addrline;
		if (als) {
			return als->al_get (als, addr);
		}
	}
	return NULL;
}

R_API RBinAddrline *r_bin_addrline_get(RBin *bin, ut64 addr) {
	if (bin->cur && bin->cur->addrline.used) {
		RBinAddrLineStore *als = &bin->cur->addrline;
		return als->al_get (als, addr);
	}
	return NULL;
}

static char *addr2fileline(RBin *bin, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (bin, NULL);
	RBinAddrline *al = r_bin_addrline_get (bin, addr);
	if (al) {
		const char *file_nopath = r_file_basename (al->file);
		if (al->column > 0) {
			return r_str_newf ("%s:%d:%d", file_nopath, al->line, al->column);
		}
		return r_str_newf ("%s:%d", file_nopath, al->line);
	}
	return NULL;
}

// given an address, return the filename:line:column\tcode or filename:line:column if the file doesnt exist
// origin can be 0, 1 or 2
R_API char * R_NULLABLE r_bin_addrline_tostring(RBin *bin, ut64 addr, int origin) {
	if (origin == 3) {
		return addr2fileline (bin, addr);
	}
	R_RETURN_VAL_IF_FAIL (bin, NULL);
	if (!bin->cur) {
		return NULL;
	}
	RBinAddrline *di = r_bin_dbgitem_at (bin, addr);
	if (!di) {
		return NULL;
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
	r_bin_addrline_free (di);
	return res;
}
