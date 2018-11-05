/* radare2 - LGPL - Copyright 2018 - pancake, nibble, dso */


#include <r_bin.h>

// primitives for r_flag_set_callbacks()

R_API const char *r_bin_flag_i(RBin *bin, ut64 addr) {
	r_return_val_if_fail (bin, NULL);
	if (bin->cur && bin->cur->o) {
		RListIter *iter;
		RBinSymbol *s;
		r_list_foreach (bin->cur->o->symbols, iter, s) {
			if (s->vaddr == addr) {
				return s->name;
			}
		}
	}
	return NULL;
}

R_API ut64 r_bin_flag(RBin *bin, const char *name) {
	// TODO: we should iterate over all the BinFiles
	if (!strncmp (name, "sym.", 4)) {
		RListIter *iter;
		RBinSymbol *s;
		r_list_foreach (bin->cur->o->symbols, iter, s) {
			if (!strcmp (name + 4, s->name)) {
				return s->vaddr;
			}
		}
	}
	return UT64_MAX;
}
