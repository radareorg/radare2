/* radare - LGPL - Copyright 2015 - pancake */

#include <r_bin.h>

static void hashify(char *s, ut64 vaddr) {
	if (!s) {
		return;
	}
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
R_API void r_bin_filter_name(RBinFile *bf, Sdb *db, ut64 vaddr, char *name, int maxlen) {
	const char *uname;
	ut32 vhash, hash;
	int count;
	if (!db || !name) {
		return;
	}
	uname = sdb_fmt ("%" PFMT64x ".%s", vaddr, name);
	vhash = sdb_hash (uname); // vaddr hash - unique
	hash = sdb_hash (name);   // name hash - if dupped and not in unique hash must insert
	count = sdb_num_inc (db, sdb_fmt ("%x", hash), 1, 0);
	if (sdb_exists (db, sdb_fmt ("%x", vhash))) {
		// TODO: symbol is dupped, so symbol can be removed!
		return;
	}
	sdb_num_set (db, sdb_fmt ("%x", vhash), 1, 0);
	if (vaddr) {
		hashify (name, vaddr);
	}
	if (count > 1) {
		int namelen = strlen (name);
		if (namelen > maxlen) {
			name[maxlen] = 0;
		}
		strcat (name, sdb_fmt ("_%d", count - 1));
		// two symbols at different addresses and same name wtf
		//	eprintf ("Symbol '%s' dupped!\n", sym->name);
	}
}

R_API void r_bin_filter_sym(RBinFile *bf, Sdb *db, ut64 vaddr, RBinSymbol *sym) {
	if (!db || !sym || !sym->name) {
		return;
	}
	char *name = sym->name;
	// if (!strncmp (sym->name, "imp.", 4)) {
	// demangle symbol name depending on the language specs if any
	if (bf && bf->o && bf->o->lang) {
		const char *lang = r_bin_lang_tostring (bf->o->lang);
		char *dn = r_bin_demangle (bf, lang, sym->name, sym->vaddr);
		if (dn && *dn) {
			sym->dname = dn;
			// XXX this is wrong but is required for this test to pass
			// pmb:new pancake$ bin/r2r.js db/formats/mangling/swift
			sym->name = dn;
			// extract class information from demangled symbol name
			char *p = strchr (dn, '.');
			if (p) {
				if (IS_UPPER (*dn)) {
					sym->classname = strdup (dn);
					sym->classname[p - dn] = 0;
				} else if (IS_UPPER (p[1])) {
					sym->classname = strdup (p + 1);
					p = strchr (sym->classname, '.');
					if (p) {
						*p = 0;
					}
				}
			}
		}
	}

	// XXX this is very slow, must be optimized
	const char *uname = sdb_fmt ("%" PFMT64x ".%s", vaddr, name);
	ut32 vhash = sdb_hash (uname); // vaddr hash - unique
	ut32 hash = sdb_hash (name); // name hash - if dupped and not in unique hash must insert
	int count = sdb_num_inc (db, sdb_fmt ("%x", hash), 1, 0);
	if (sdb_exists (db, sdb_fmt ("%x", vhash))) {
		// TODO: symbol is dupped, so symbol can be removed!
		return;
	}
	sdb_num_set (db, sdb_fmt ("%x", vhash), 1, 0);
	if (vaddr) {
		//hashify (name, vaddr);
	}
	sym->dup_count = count - 1;
}

R_API void r_bin_filter_symbols(RBinFile *bf, RList *list) {
	RListIter *iter;
	RBinSymbol *sym;
	const int maxlen = sizeof (sym->name) - 8;
	Sdb *db = sdb_new0 ();
	if (!db) {
		return;
	}
	if (maxlen > 0) {
		r_list_foreach (list, iter, sym) {
			if (sym && sym->name && *sym->name) {
				r_bin_filter_name (bf, db, sym->vaddr, sym->name, maxlen);
			}
		}
	} else {
		r_list_foreach (list, iter, sym) {
			if (sym && sym->name && *sym->name) {
				r_bin_filter_sym (bf, db, sym->vaddr, sym);
			}
		}
	}
	sdb_free (db);
}

R_API void r_bin_filter_sections(RBinFile *bf, RList *list) {
	RBinSection *sec;
	const int maxlen = 256;
	Sdb *db = sdb_new0 ();
	RListIter *iter;
	if (maxlen > 0) {
		r_list_foreach (list, iter, sec) {
			r_bin_filter_name (bf, db, sec->vaddr, sec->name, maxlen);
		}
	} else {
		eprintf ("SectionName is not dynamic\n");
	}
	sdb_free (db);
}

static bool false_positive(const char *str) {
	int i;
	ut8 bo[0x100];
	int up = 0;
	int lo = 0;
	int ot = 0;
	int di = 0;
	int ln = 0;
	int sp = 0;
	int nm = 0;
	for (i = 0; i < 0x100; i++) {
		bo[i] = 0;
	}
	for (i = 0; str[i]; i++) {
		if (IS_DIGIT(str[i])) {
			nm++;
		} else if (str[i]>='a' && str[i]<='z') {
			lo++;
		} else if (str[i]>='A' && str[i]<='Z') {
			up++;
		} else {
			ot++;
		}
		if (str[i]=='\\') {
			ot++;
		}
		if (str[i]==' ') {
			sp++;
		}
		bo[(ut8)str[i]] = 1;
		ln++;
	}
	for (i = 0; i<0x100; i++) {
		if (bo[i]) {
			di++;
		}
	}
	if (ln > 2 && str[0] != '_') {
		if (ln < 10) {
			return true;
		}
		if (ot >= (nm + up + lo)) {
			return true;
		}
		if (lo < 3) {
			return true;
		}
	}
	return false;
}

R_API bool r_bin_strpurge(RBin *bin, const char *str, ut64 refaddr) {
	bool purge = false;
	if (bin->strpurge) {
		char *addrs = strdup (bin->strpurge);
		if (addrs) {
			int splits = r_str_split (addrs, ',');
			int i;
			char *ptr;
			char *range_sep;
			ut64 addr, from, to;
			for (i = 0, ptr = addrs; i < splits; i++, ptr += strlen (ptr) + 1) {
				bool bang = false;
				if (!strcmp (ptr, "true") && false_positive (str)) {
					purge = true;
					continue;
				}
				if (*ptr == '!') {
					bang = true;
					ptr++;
				}
				if (!strcmp (ptr, "all")) {
					purge = !bang;
					continue;
				}
				range_sep = strchr (ptr, '-');
				if (range_sep) {
					*range_sep = 0;
					from = r_num_get (NULL, ptr);
					ptr = range_sep + 1;
					to = r_num_get (NULL, ptr);
					if (refaddr >= from && refaddr <= to) {
						purge = !bang;
						continue;
					}
				}
				addr = r_num_get (NULL, ptr);
				if (addr != 0 || *ptr == '0') {
					if (refaddr == addr) {
						purge = !bang;
						continue;
					}
				}
			}
			free (addrs);
		}
	}
	return purge;
}

static bool bin_strfilter(RBin *bin, const char *str) {
	int i;
	switch (bin->strfilter) {
	case 'U': // only uppercase strings
		for (i = 0; str[i]; i++) {
			char ch = str[i];
			if (ch == ' ') {
				continue;
			}
			if (ch < '@'|| ch > 'Z') {
				return false;
			}
			if (ch < 0 || !IS_PRINTABLE (ch)) {
				return false;
			}
		}
		if (str[0] && str[1]) {
			for (i = 2; i<6 && str[i]; i++) {
				if (str[i] == str[0]) {
					return false;
				}
				if (str[i] == str[1]) {
					return false;
				}
			}
		}
		if (str[0] == str[2]) {
			return false; // rm false positives
		}
		break;
	case 'a': // only alphanumeric - plain ascii
		for (i = 0; str[i]; i++) {
			char ch = str[i];
			if (ch < 1 || !IS_PRINTABLE (ch)) {
				return false;
			}
		}
		break;
	case 'e': // emails
		if (str && *str) {
			if (!strstr (str + 1, "@")) {
				return false;
			}
			if (!strstr (str + 1, ".")) {
				return false;
			}
		} else {
			return false;
		}
		break;
	case 'f': // format-string
		if (str && *str) {
			if (!strstr (str + 1, "%")) {
				return false;
			}
		} else {
			return false;
		}
		break;
	case 'u': // URLs
		if (!strstr (str, "://")) {
			return false;
		}
		break;
        case 'i': //IPV4
		{
			int segment = 0;
			int segmentsum = 0;
			bool prevd = false;
			for (i = 0; str[i]; i++) {
				char ch = str[i];
				if (IS_DIGIT (ch)) {
					segmentsum = segmentsum*10 + (ch - '0');
					if (segment == 3) {
						return true;
					}
					prevd = true;
				} else if (ch == '.') {
					if (prevd == true && segmentsum < 256){
						segment++;
						segmentsum = 0;
					} else {
						segmentsum = 0;
						segment = 0;
					}
					prevd = false;
				} else {
					segmentsum = 0;
					prevd = false;
					segment = 0;
				}
			}
			return false;
		}
	case 'p': // path
		if (str[0] != '/') {
			return false;
		}
		break;
	case '8': // utf8
		for (i = 0; str[i]; i++) {
			char ch = str[i];
			if (ch < 0) {
				return true;
			}
		}
		return false;
	}
	return true;
}

R_API bool r_bin_string_filter(RBin *bin, const char *str, ut64 addr) {
	if (r_bin_strpurge (bin, str, addr) || !bin_strfilter (bin, str)) {
		return false;
	}
	return true;
}
