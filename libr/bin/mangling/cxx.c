/* radare - LGPL - Copyright 2013 - pancake */

#include <r_bin.h>

R_API int r_bin_lang_cxx(RBin *bin) {
	RListIter *iter;
	int hascxx = R_FALSE;
	const char *lib;

	if (!bin || !bin->cur.o || !bin->cur.o->info)
		return R_FALSE;
	r_list_foreach (bin->cur.o->libs, iter, lib) {
		if (!strncmp (lib, "stdc++", 6)) {
			hascxx = R_TRUE;
			bin->cur.o->info->lang = "cxx";
			break;
		}
	}
	return hascxx;
}
