/* radare - LGPL - Copyright 2015-2025 - pancake */

#include <r_bin.h>
#include <sdb/ht_su.h>
#include "i/private.h"

static char *hashify(const char *s, ut64 vaddr) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	const char *os = s;
	while (*s) {
		if (!IS_PRINTABLE (*s)) {
			if (vaddr && vaddr != UT64_MAX) {
				return r_str_newf ("_%" PFMT64d, vaddr);
			}
			const ut32 hash = sdb_hash (s);
			return r_str_newf ("%x", hash);
		}
		s++;
	}
	return strdup (os);
}

R_API char *r_bin_filter_name(RBinFile *bf, HtSU *db, ut64 vaddr, const char *name) {
	R_RETURN_VAL_IF_FAIL (db && name, NULL);

	int count = 0;

	bool found = false;
	const ut64 value = ht_su_find (db, name, &found);
	if (found) {
		count = value + 1;
		ht_su_update (db, name, count);
	} else {
		count = 1;
		ht_su_insert (db, name, 1ULL);
	}

	// check if there's another symbol with the same name and address);
	char *uname = r_str_newf ("%" PFMT64x ".%s", vaddr, name);
	found = false;
	(void)ht_su_find (db, uname, &found);
	if (found) {
		// TODO: symbol is dupped, so symbol can be removed!
		free (uname);
		return NULL; // r_str_newf ("%s_%d", name, count);
	}

	(void)ht_su_insert (db, uname, count);

	char *resname = NULL;
	if (vaddr) {
		resname = hashify (name, vaddr);
	}
	if (count > 1) {
		resname = r_str_appendf (resname, "_%d", count - 1);
		// two symbols at different addresses and same name wtf
		R_LOG_DEBUG ("Found duplicated symbol '%s'", resname);
	}

	free (uname);

	if (!resname) {
		resname = strdup (name);
	}
	return resname;
}

R_IPI bool r_bin_filter_sym(RBinFile *bf, HtPP *ht, ut64 vaddr, RBinSymbol *sym) {
	R_RETURN_VAL_IF_FAIL (ht && sym && sym->name, false);
	const char *name = r_bin_name_tostring2 (sym->name, 'o');
	if (bf && bf->bo && bf->bo->lang) {
		const char *lang = r_bin_lang_tostring (bf->bo->lang);
		char *dn = r_bin_demangle (bf, lang, name, sym->vaddr, false);
		if (R_STR_ISNOTEMPTY (dn)) {
			r_bin_name_demangled (sym->name, dn);
			// extract class information from demangled symbol name
			char *p = strchr (dn, '.');
			if (p) {
				if (isupper (*dn)) {
					sym->classname = strdup (dn);
					sym->classname[p - dn] = 0;
				} else if (isupper (p[1])) {
					sym->classname = strdup (p + 1);
					p = strchr (sym->classname, '.');
					if (p) {
						*p = 0;
					}
				}
			}
		}
		free (dn);
	}
	r_strf_var (uname, 256, "%" PFMT64x ".%c.%s", vaddr, sym->is_imported ? 'i' : 's', name);
	bool res = ht_pp_insert (ht, uname, sym);
	if (!res) {
		return false;
	}
	sym->dup_count = 0;

	r_strf_var (oname, 256, "o.0.%c.%s", sym->is_imported ? 'i' : 's', name);
	RBinSymbol *prev_sym = ht_pp_find (ht, oname, NULL);
	if (!prev_sym) {
		if (!ht_pp_insert (ht, oname, sym)) {
			R_LOG_WARN ("Failed to insert dup_count in ht");
			return false;
		}
	} else {
		sym->dup_count = prev_sym->dup_count + 1;
		ht_pp_update (ht, oname, sym);
	}
	return true;
}

R_API void r_bin_filter_symbols(RBinFile *bf, RList *list) {
	HtPP *ht = ht_pp_new0 ();
	if (R_LIKELY (ht)) {
		RListIter *iter;
		RBinSymbol *sym;
		r_list_foreach (list, iter, sym) {
			r_bin_filter_sym (bf, ht, sym->vaddr, sym);
		}
		if (bf && bf->bo) {
			if (bf->bo->filters) {
				ht_pp_free ((HtPP *)bf->bo->filters);
			}
			bf->bo->filters = ht;
			return;
		}
		ht_pp_free (ht);
	}
}

R_API void r_bin_filter_sections(RBinFile *bf, RList *list) {
	RBinSection *sec;
	HtSU *db = ht_su_new0 ();
	RListIter *iter;
	r_list_foreach (list, iter, sec) {
		if (!sec->name) {
			continue;
		}
		char *p = r_bin_filter_name (bf, db, sec->vaddr, sec->name);
		if (p) {
			free (sec->name);
			sec->name = p;
		}
	}
	ht_su_free (db);
}

static bool false_positive(const char *str) {
	int i;
	int up = 0;
	int lo = 0;
	int ot = 0;
	int ln = 0;
	int nm = 0;
#if 0
	// int di = 0;
	// int sp = 0;
//	ut8 bo[0x100];
	for (i = 0; i < 0x100; i++) {
		bo[i] = 0;
	}
#endif
	for (i = 0; str[i]; i++) {
		if (isdigit (str[i])) {
			nm++;
		} else if (str[i]>='a' && str[i]<='z') {
			lo++;
		} else if (str[i]>='A' && str[i]<='Z') {
			up++;
		} else {
			ot++;
		}
		if (str[i] == '\\') {
			ot++;
		}
#if 0
		if (str[i] == ' ') {
			sp++;
		}
		bo[(ut8)str[i]] = 1;
#endif
		ln++;
	}
#if 0
	for (i = 0; i < 0x100; i++) {
		if (bo[i]) {
			di++;
		}
	}
#endif
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
	R_RETURN_VAL_IF_FAIL (bin && str, false);
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
				if (!strcmp (ptr, "true") && false_positive (str)) {
					purge = true;
					continue;
				}
				bool bang = false;
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

static int get_char_ratio(const char ch, const char *str) {
	int i;
	int ch_count = 0;
	for (i = 0; str[i]; i++) {
		if (str[i] == ch) {
			ch_count++;
		}
	}
	return i ? ch_count * 100 / i : 0;
}

static bool bin_strfilter(RBin *bin, const char *str) {
	int i;
	bool got_uppercase, in_esc_seq;
	switch (bin->strfilter) {
	case 'U': // only uppercase strings
		got_uppercase = false;
		in_esc_seq = false;
		for (i = 0; str[i]; i++) {
			char ch = str[i];
			if (ch == ' ' ||
			    (in_esc_seq && (ch == 't' || ch == 'n' || ch == 'r'))) {
				goto loop_end;
			}
			if (ch < 0 || !IS_PRINTABLE (ch) || islower (ch)) {
				return false;
			}
			if (isupper (ch)) {
				got_uppercase = true;
			}
loop_end:
			in_esc_seq = in_esc_seq ? false : ch == '\\';
		}
		if (get_char_ratio (str[0], str) >= 60) {
			return false;
		}
		if (str[0] && get_char_ratio (str[1], str) >= 60) {
			return false;
		}
		if (!got_uppercase) {
			return false;
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
		if (R_STR_ISEMPTY (str)) {
			return false;
		}
		if (!strchr (str + 1, '@')) {
			return false;
		}
		if (!strchr (str + 1, '.')) {
			return false;
		}
		break;
	case 'f': // format-string
		if (R_STR_ISEMPTY (str)) {
			return false;
		}
		if (!strchr (str + 1, '%')) {
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
				if (isdigit (ch)) {
					segmentsum = segmentsum*10 + (ch - '0');
					if (segment == 3) {
						return true;
					}
					prevd = true;
				} else if (ch == '.') {
					if (prevd == true && segmentsum < 256) {
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
	R_RETURN_VAL_IF_FAIL (bin && str, false);
	if (r_bin_strpurge (bin, str, addr) || !bin_strfilter (bin, str)) {
		return false;
	}
	return true;
}
