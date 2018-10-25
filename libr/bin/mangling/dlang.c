/* radare - LGPL - Copyright 2015 - pancake */

#include <r_bin.h>

// The dlang-demangler is written in D and available at radare2-extras

static int is_dlang_symbol (const char *name) {
	if (!strncmp (name, "_D2", 3)) {
		return 1;
	}
	if (!strncmp (name, "_D4", 3)) {
		return 1;
	}
	return 0;
}

R_API bool r_bin_lang_dlang(RBinFile *binfile) {
	RBinObject *o = binfile ? binfile->o : NULL;
	RBinInfo *info = o ? o->info : NULL;
	bool hasdlang = false;
	RBinSymbol *sym;
	RListIter *iter;
	const char *lib;

	if (!info) {
		return false;
	}
	r_list_foreach (o->libs, iter, lib) {
		if (strstr (lib, "phobos")) {
			hasdlang = true;
			break;
		}
	}
	if (!hasdlang) {
		r_list_foreach (o->symbols, iter, sym) {
			if (sym->name && is_dlang_symbol (sym->name)) {
				hasdlang = true;
				break;
			}
		}
	}
	if (hasdlang) {
		info->lang = "dlang";
	}
	return hasdlang;
}
