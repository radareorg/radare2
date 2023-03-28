/* radare - LGPL - Copyright 2009-2023 - nibble, pancake */

#include <r_bin.h>

// XXX this api must return a struct instead of pa
// R_API RBinDwarfRow *r_bin_addr2line(RBin *bin, ut64 addr) {}
// R2_590 R_API bool r_bin_addr2line(RBin *bin, ut64 addr, char *file, int len, int *line, int *column) {
R_API bool r_bin_addr2line(RBin *bin, ut64 addr, char *file, int len, int *line) {
	r_return_val_if_fail (bin, false);
	RBinFile *binfile = r_bin_cur (bin);
	RBinObject *o = r_bin_cur_object (bin);
	RBinPlugin *cp = r_bin_file_cur_plugin (binfile);
	ut64 baddr = r_bin_get_baddr (bin);
	if (baddr == UT64_MAX) {
		baddr = 0;
	}
	if (cp && cp->dbginfo) {
		if (o && addr >= baddr && addr < baddr + bin->cur->o->size) {
			if (cp->dbginfo->get_line) {
				return cp->dbginfo->get_line (
					bin->cur, addr, file, len, line);
			}
		}
	}
	return false;
}

// XXX R2_590 why dupe
R_API bool r_bin_addr2line2(RBin *bin, ut64 addr, char *file, int len, int *line) {
	r_return_val_if_fail (bin, false);
	if (!bin->cur || !bin->cur->sdb_addrinfo) {
		return false;
	}
	char *key = r_str_newf ("0x%"PFMT64x, addr);
	char *file_line = sdb_get (bin->cur->sdb_addrinfo, key, 0);
	if (file_line) {
		char *token = strchr (file_line, '|');
		if (token) {
			*token++ = 0;
			if (line) {
				*line = atoi (token);
			}
			r_str_ncpy (file, file_line, len);
			free (key);
			free (file_line);
			return true;
		}
	}
	free (key);
	return false;
}

R_API char *r_bin_addr2text(RBin *bin, ut64 addr, int origin) {
	r_return_val_if_fail (bin, NULL);
	char file[4096];
	int line;
#if R2_590
	int colu;
#endif
	char *out = NULL, *out2 = NULL;
	char *file_nopath = NULL;
	if (!bin->cur) {
		return NULL;
	}
	char *key = r_str_newf ("0x%"PFMT64x, addr);
	char *file_line = sdb_get (bin->cur->sdb_addrinfo, key, 0);
	if (file_line) {
		char *token = strchr (file_line, '|'); /// XXX use : everywhere instead of |
		if (token) {
			*token++ = 0;
			line = atoi (token);
#if R2_590
			char *colupos = strchr (token, ':');
			if (colupos) {
				colu = atoi (colupos + 1);
			}
#endif
			bool found = true;
			const char *filename = file_line;
			char *nf = NULL;
			if (!r_file_exists (file_line)) {
				const char *bn = r_file_basename (file_line);
				// TODO: use dir.source
				if (r_file_exists (bn)) {
					filename = bn;
				} else {
					nf = r_str_newf ("%s/%s", bin->srcdir, bn);
					if (r_file_exists (nf)) {
						filename = nf;
					} else {
						found = false;
						// R_LOG_WARN ("Cannot find %s", filename);
						// return NULL;
					}
				}
			}
			if (found) {
				out = r_file_slurp_line (filename, line, 0);
				*token++ = ':';
				free (nf);
			}
		} else {
			return file_line;
		}
	}
	free (key);
	if (out) {
		if (origin > 1) {
			file_nopath = file_line;
		} else {
			file_nopath = strrchr (file_line, '/');
			if (file_nopath) {
				file_nopath++;
			} else {
				file_nopath = file_line;
			}
		}
		if (origin) {
#if R2_590
			char *res = r_str_newf ("%s:%d:%d%s%s",
					r_str_get (file_nopath),
					line, colu, file_nopath? " ": "",
					r_str_get (out));
#else
			char *res = r_str_newf ("%s:%d%s%s",
					r_str_get (file_nopath),
					line, file_nopath? " ": "",
					r_str_get (out));
#endif
			free (out);
			out = res;
		}
		free (file_line);
		return out;
	}
	R_FREE (file_line);

	file[0] = 0;
	if (r_bin_addr2line (bin, addr, file, sizeof (file), &line)) {
		if (bin->srcdir && *bin->srcdir) {
			char *slash = strrchr (file, '/');
			char *nf = r_str_newf ("%s/%s", bin->srcdir, slash? slash + 1: file);
			strncpy (file, nf, sizeof (file) - 1);
			free (nf);
		}
		// TODO: this is slow. must use a cached pool of mapped files and line:off entries
		out = r_file_slurp_line (file, line, 0);
		if (!out) {
			if (origin > 1) {
				file_nopath = file;
			} else {
				file_nopath = strrchr (file, '/');
				if (file_nopath) {
					file_nopath++;
				} else {
					file_nopath = file;
				}
			}
#if R2_590
			return r_str_newf ("%s:%d:%d", r_str_get (file_nopath), line, colu);
#else
			return r_str_newf ("%s:%d", r_str_get (file_nopath), line);
#endif
		}
		out2 = malloc ((strlen (file) + 64 + strlen (out)) * sizeof (char));
		if (origin > 1) {
			file_nopath = NULL;
		} else {
			file_nopath = strrchr (file, '/');
		}
		if (origin) {
#if R2_590
			snprintf (out2, strlen (file) + 63 + strlen (out), "%s:%d:%d%s%s",
				file_nopath? file_nopath + 1: file, line, colu, *out? " ": "", out);
#else
			snprintf (out2, strlen (file) + 63 + strlen (out), "%s:%d%s%s",
				file_nopath? file_nopath + 1: file, line, *out? " ": "", out);
#endif
		} else {
			snprintf (out2, 64, "%s", out);
		}
		free (out);
	}
	return out2;
}

R_API char *r_bin_addr2fileline(RBin *bin, ut64 addr) {
	r_return_val_if_fail (bin, NULL);
	char file[1024];
	int line = 0;

	if (r_bin_addr2line (bin, addr, file, sizeof (file) - 1, &line)) {
		char *file_nopath = strrchr (file, '/');
#if R2_590
		int colu = 0;
		return r_str_newf ("%s:%d:%d", file_nopath? file_nopath + 1: file, line, colu);
#else
		return r_str_newf ("%s:%d", file_nopath? file_nopath + 1: file, line);
#endif
	}
	return NULL;
}
