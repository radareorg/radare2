/* radare - LGPL - Copyright 2013-2018 - pancake */

#include <r_bin.h>

static inline bool is_cxx_symbol (const char *name) {
	r_return_val_if_fail (name, false);
	if (!strncmp (name, "_Z", 2)) {
		return true;
	}
	if (!strncmp (name, "__Z", 3)) {
		return true;
	}
	return false;
}

R_API bool r_bin_is_cxx (RBinFile *binfile) {
	RListIter *iter;
	RBinImport *import;
	RBinObject *o = binfile->o;
	r_list_foreach (o->imports, iter, import) {
		if (is_cxx_symbol (import->name)) {
			return true;
		}
	}
	return false;
}

R_API bool r_bin_lang_cxx(RBinFile *binfile) {
	RBinObject *o = binfile ? binfile->o : NULL;
	RBinInfo *info = o ? o->info : NULL;
	RListIter *iter;
	RBinSymbol *sym;
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
		r_list_foreach (o->symbols, iter, sym) {
			if (!sym->name) {
				continue;
			}
			if (is_cxx_symbol (sym->name)) {
				hascxx = true;
				break;
			}
		}
	}
	if (hascxx) {
		info->lang = "c++";
	}
	return hascxx;
}
