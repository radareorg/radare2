/* radare - LGPL - Copyright 2013-2015 - pancake */

#include <r_bin.h>

static bool is_cxx_symbol (const char *name) {
	if (!strncmp (name, "_Z", 2)) {
		return true;
	}
	if (!strncmp (name, "__Z", 3)) {
		return true;
	}
	return false;
}

bool r_bin_is_cxx (RBinFile *binfile) {
	RListIter *iter;
	RBinSymbol *sym;
	RBinObject *o = binfile->o;
	r_list_foreach (o->symbols, iter, sym) {
		if (is_cxx_symbol (sym->name)) {
			return true;
		}
	}
	return false;
}

R_API bool r_bin_lang_cxx(RBinFile *binfile) {
	RBinObject *o = binfile ? binfile->o : NULL;
	RBinInfo *info = o ? o->info : NULL;
	RListIter *iter;
	bool hascxx = false;
	const char *lib;

	if (!info) {
		return false;
	}
	r_list_foreach (o->libs, iter, lib) {
		if (strstr (lib, "stdc++") ||
		    strstr (lib, "c++")) {
			hascxx = true;
			break;
		}
	}
	if (!hascxx) {
		hascxx = r_bin_is_cxx (binfile);
	}
	if (hascxx) {
		info->lang = "cxx";
	}
	return hascxx;
}
