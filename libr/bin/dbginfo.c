/* radare - LGPL - Copyright 2009-2014 - nibble, pancake */

#include <r_types.h>
#include <r_bin.h>

R_API int r_bin_addr2line(RBin *bin, ut64 addr, char *file, int len, int *line) {
	RBinFile *binfile = r_bin_cur (bin);
	RBinObject *o = r_bin_cur_object (bin);
	RBinPlugin *cp = r_bin_file_cur_plugin (binfile);

	if (cp && cp->dbginfo) {
		if (o && addr >= o->baddr && addr < (o->baddr+bin->cur->o->size))
			if (cp->dbginfo->get_line)
				return cp->dbginfo->get_line (bin->cur,
					addr, file, len, line);
	}
	return R_FALSE;
}

R_API char *r_bin_addr2text(RBin *bin, ut64 addr) {
	char file[1024];
	int line;
	char *out = NULL, *out2;
	char *file_nopath;

	if (r_bin_addr2line (bin, addr, file, sizeof (file), &line)) {
		out = r_file_slurp_line (file, line, 0);
		if (!out)
			return 0;
		out2 = malloc((strlen(file) + 64 + strlen(out))*sizeof(char));
		file_nopath = strrchr (file, '/');
		snprintf(out2, strlen(file) + 63 + strlen(out), "%s:%d %s",
				file_nopath ? file_nopath + 1 : file, line, out);

		free (out);
		return out2;
	}
	return 0;
}

R_API char *r_bin_addr2fileline(RBin *bin, ut64 addr) {
	char file[1024];
	int line;
	char *out = NULL;
	char *file_nopath;

	if (r_bin_addr2line (bin, addr, file, sizeof (file)-1, &line)) {
		int sz = strlen (file)+10;
		file_nopath = strrchr (file, '/');
		out = malloc (sz);
		snprintf (out, sizeof (sz), "%s:%d",
				file_nopath ? file_nopath + 1 : file , line);
	}
	return out;
}
