/* radare - LGPL - Copyright 2012 - pancake */

#include <r_bin.h>

R_API int r_bin_lang_objc(RBinObject *o) {
	RListIter *iter;
	RBinSymbol *sym;
	int hasobjc = R_FALSE;
	char *dsym;
	const char *ft = o->info->rclass;

	if (!ft || (!strstr (ft, "mach") && !strstr (ft, "elf")))
		return 0;
	r_list_foreach (o->symbols, iter, sym) {
		if (!hasobjc)
			if (!strncmp (sym->name, "_OBJC_", 6))
				hasobjc = R_TRUE;
		dsym = r_bin_demangle_objc (o, sym->name);
		if (dsym) {
			// Add type
			free (dsym);
		}
	}
	if (hasobjc)
		o->info->lang = "objc";
	// create class members and set method names
	// iterate on symbols to conscruct class/methods
	return hasobjc;
}
