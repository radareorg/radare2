/* radare - LGPL - Copyright 2012-2015 - pancake */

#include <r_bin.h>

R_API bool r_bin_lang_objc(RBinFile *binfile) {
	RBinObject *o = binfile ? binfile->o : NULL;
	RBinInfo *info = o ? o->info : NULL;
	RListIter *iter;
	RBinSymbol *sym;
	bool hasobjc = false;
	const char *ft;
	char *dsym;

	if (!info) return false;
	ft = info->rclass;
	if (!ft || (!strstr (ft, "mach") && !strstr (ft, "elf")))
		return false;
	r_list_foreach (o->symbols, iter, sym) {
		if (!hasobjc && !strncmp (sym->name, "_OBJC_", 6)) {
			hasobjc = true;
			break;
		}
		dsym = r_bin_demangle_objc (binfile, sym->name);
		if (dsym) {
			// Add type
			free (dsym);
		}
	}
	if (hasobjc)
		info->lang = "objc";
	// create class members and set method names
	// iterate on symbols to conscruct class/methods
	return hasobjc;
}
