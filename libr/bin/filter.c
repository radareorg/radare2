/* radare - LGPL - Copyright 2015 - pancake */

#include <r_bin.h>

static void hashify(char *s, ut64 vaddr) {
	if (!s) return;
	while (*s) {
		if (!IS_PRINTABLE (*s)) {
			if (vaddr && vaddr != UT64_MAX) {
				sprintf (s, "_%" PFMT64d, vaddr);
			} else {
				ut32 hash = sdb_hash (s);
				sprintf (s, "%x", hash);
			}
			return;
		}
		s++;
	}
}

// TODO: optimize this api:
// - bin plugins should call r_bin_filter_name() before appending
R_API void r_bin_filter_name(Sdb *db, ut64 vaddr, char *name, int maxlen) {
	const char *uname;
	ut32 vhash, hash;
	int count;
	if (!db || !name) return;
	uname = sdb_fmt (0, "%" PFMT64x ".%s", vaddr, name);
	vhash = sdb_hash (uname); // vaddr hash - unique
	hash = sdb_hash (name);   // name hash - if dupped and not in unique hash must insert
	count = sdb_num_inc (db, sdb_fmt (0, "%x", hash), 1, 0);
	if (sdb_exists (db, sdb_fmt (1, "%x", vhash))) {
		// TODO: symbol is dupped, so symbol can be removed!
		return;
	}
	sdb_num_set (db, sdb_fmt (0, "%x", vhash), 1, 0);
	if (vaddr) {
		hashify (name, vaddr);
	}
	if (count > 1) {
		int namelen = strlen (name);
		if (namelen > maxlen) name[maxlen] = 0;
		strcat (name, sdb_fmt (2, "_%d", count - 1));
		// two symbols at different addresses and same name wtf
		//	eprintf ("Symbol '%s' dupped!\n", sym->name);
	}
}

R_API void r_bin_filter_sym(Sdb *db, ut64 vaddr, RBinSymbol *sym) {
	char *name;
	if (!db || !sym) return;
	name = sym->name;
	if (!name) return;
	const char *uname = sdb_fmt (0, "%" PFMT64x ".%s", vaddr, name);
	ut32 vhash = sdb_hash (uname); // vaddr hash - unique
	ut32 hash = sdb_hash (name);   // name hash - if dupped and not in unique hash must insert
	int count = sdb_num_inc (db, sdb_fmt (0, "%x", hash), 1, 0);
	if (sdb_exists (db, sdb_fmt (1, "%x", vhash))) {
		// TODO: symbol is dupped, so symbol can be removed!
		return;
	}
	sdb_num_set (db, sdb_fmt (0, "%x", vhash), 1, 0);
	if (vaddr) {
		//hashify (name, vaddr);
	}
	if (count > 1) {
		char *nstr = r_str_newf ("%s_%d", sym->name, count - 1);
		free (sym->name);
		sym->name = nstr;
	}
}

R_API void r_bin_filter_symbols(RList *list) {
	RBinSymbol *sym;
	const int maxlen = sizeof (sym->name) - 8;
	Sdb *db = sdb_new0 ();
	RListIter *iter, *iter2;
	if (maxlen > 0) {
		r_list_foreach_safe (list, iter, iter2, sym) {
			r_bin_filter_name (db, sym->vaddr, sym->name, maxlen);
		}
	} else {
		r_list_foreach_safe (list, iter, iter2, sym) {
			if (sym->name) {
				r_bin_filter_sym (db, sym->vaddr, sym);
			}
		}
	}
	sdb_free (db);
}

R_API void r_bin_filter_sections(RList *list) {
	RBinSection *sec;
	const int maxlen = 256;
	Sdb *db = sdb_new0 ();
	RListIter *iter;
	if (maxlen > 0) {
		r_list_foreach (list, iter, sec) {
			r_bin_filter_name (db, sec->vaddr, sec->name, maxlen);
		}
	} else eprintf ("SectionName is not dynamic\n");
	sdb_free (db);
}

R_API void r_bin_filter_classes(RList *list) {
	int namepad_len;
	char *namepad;
	Sdb *db = sdb_new0 ();
	RListIter *iter, *iter2;
	RBinClass *cls;
	RBinSymbol *sym;
	r_list_foreach (list, iter, cls) {
		if (!cls->name) continue;
		namepad_len = strlen (cls->name) + 32;
		namepad = calloc (1, namepad_len + 1);
		if (namepad) {
			strcpy (namepad, cls->name);
			r_bin_filter_name (db, cls->index, namepad, namepad_len);
			free (cls->name);
			cls->name = namepad;
			r_list_foreach (cls->methods, iter2, sym) {
				if (sym->name)
					r_bin_filter_sym (db, sym->vaddr, sym);
			}
		} else eprintf ("Cannot alloc %d bytes\n", namepad_len);
	}
	sdb_free (db);
}
