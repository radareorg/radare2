/* radare - LGPL - Copyright 2009-2020 - nibble, pancake, keegan */

#include <r_types.h>
#include <r_bin.h>

R_API bool r_bin_addr2line(RBin *bin, ut64 addr, char *file, int len, int *line) {
	r_return_val_if_fail (bin, false);
	RBinFile *binfile = r_bin_cur (bin);
	RBinObject *o = r_bin_cur_object (bin);
	RBinPlugin *cp = r_bin_file_cur_plugin (binfile);
	ut64 baddr = r_bin_get_baddr (bin);
	if (cp && cp->dbginfo) {
		if (o && addr >= baddr && addr < baddr + bin->cur->o->size) {
			if (cp->dbginfo->get_line) {
				return cp->dbginfo->get_line (
					bin->cur, addr, file, len, line);
			}
		}
	}
	return r_bin_addr2line2 (bin, addr, file, len, line);
}

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
	r_return_val_if_fail (bin && bin->cur, NULL);
	char path[4096] = {0};
	int line_number;
	char *line = NULL;
	char *basename = NULL;

	if (r_bin_addr2line (bin, addr, path, sizeof (path), &line_number)) {
		char *source = NULL;
		// if we have a source dir, prepend the full file name
		if (strlen (bin->srcdir)) {
			source = r_str_newf ("%s/%s", bin->srcdir, path);
		} else {
			// otherwise use the original name
			source = strdup (path);
		}

		if (r_file_exists (source)) {
			// TODO: use a cached pool of files and line entries
			line = r_file_slurp_line (source, line_number, 0);
		}

		free (source);
	}

	if (line) {
		if (origin > 1) {
			basename = path;
		} else {
			// if there is a / use the basename. e.g. /usr/src/example.c becomes example.c
			basename = strrchr (path, '/');
			if (basename) {
				basename++;
			} else {
				basename = path;
			}
		}

		if (origin) {
			char *debug_line = r_str_newf ("%s:%d: %s", r_str_get (basename),
				line_number, r_str_get (line));
			free (line);
			line = debug_line;
		}
		return line;
	}
	return NULL;
}

R_API char *r_bin_addr2fileline(RBin *bin, ut64 addr) {
	r_return_val_if_fail (bin, NULL);
	char file[1024];
	int line = 0;

	if (r_bin_addr2line (bin, addr, file, sizeof (file) - 1, &line)) {
		char *file_nopath = strrchr (file, '/');
		return r_str_newf ("%s:%d", file_nopath? file_nopath + 1: file, line);
	}
	return NULL;
}
