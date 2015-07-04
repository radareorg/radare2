/* radare - LGPL - Copyright 2015 - pancake */

#include <r_bin.h>

// TODO: optimize this api:
// - bin plugins should call r_bin_filter_name() before appending

R_API void r_bin_filter_name(Sdb *db, char *name, int maxlen) {
	ut32 hash = sdb_hash (name);
	int count = sdb_num_inc (db, sdb_fmt (0, "%x", hash), 1, 0);
	if (count>1) {
		int namelen = strlen (name);
		if (namelen>maxlen) name[maxlen] = 0;
		strcat (name, sdb_fmt(0,"_%d", count-1));
	//	eprintf ("Symbol '%s' dupped!\n", sym->name);
	}
}

R_API void r_bin_filter_symbols (RList *list) {
	RBinSymbol *sym;
	const int maxlen = sizeof (sym->name)-8;
	Sdb *db = sdb_new0 ();
	RListIter *iter;
	if (maxlen>0) {
		r_list_foreach (list, iter, sym) {
			r_bin_filter_name (db, sym->name, maxlen);
		}
		sdb_free (db);
	} else eprintf ("SymbolName is not dynamic\n");
}
