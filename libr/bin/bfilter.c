/* radare - LGPL - Copyright 2015-2026 - pancake */

#include <r_bin.h>
#include <sdb/ht_su.h>

#include "i/private.h"

typedef struct {
	ut64 count;
	ut64 first_vaddr;
	RBitset *seen_vaddrs;
} RBinSectionNameState;

static void section_name_state_free(HtPPKv *kv) {
	if (kv) {
		RBinSectionNameState *state = kv->value;
		free (kv->key);
		if (state) {
			if (state->seen_vaddrs) {
				r_bitset_free (state->seen_vaddrs);
			}
			free (state);
		}
	}
}

static bool section_name_exists(RBinSectionNameState *state, ut64 vaddr) {
	if (!state->seen_vaddrs) {
		if (state->first_vaddr == vaddr) {
			return true;
		}
		state->seen_vaddrs = r_bitset_new ();
		r_bitset_set (state->seen_vaddrs, state->first_vaddr);
		r_bitset_set (state->seen_vaddrs, vaddr);
		return false;
	}
	// r_bitset_set returns true if newly set; we want the inverse for "found"
	return !r_bitset_set (state->seen_vaddrs, vaddr);
}

static char *hashify(const char *s, ut64 vaddr, ut64 suffix, bool keep_printable) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	const char *os = s;
	while (*s) {
		if (!IS_PRINTABLE (*s)) {
			char *res = NULL;
			if (vaddr && vaddr != UT64_MAX) {
				res = r_str_newf ("_%" PFMT64d, vaddr);
			} else {
				const ut32 hash = sdb_hash (s);
				res = r_str_newf ("%x", hash);
			}
			return suffix? r_str_appendf (res, "_%" PFMT64u, suffix): res;
		}
		s++;
	}
	if (!suffix && !keep_printable) {
		return NULL;
	}
	return suffix? r_str_newf ("%s_%" PFMT64u, os, suffix): strdup (os);
}

static bool is_hex_number(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return false;
	}
	if (r_str_startswith (name, "0x")) {
		name += 2;
	}
	size_t len = strlen (name);
	if (len < 4 || len > 16) {
		return false;
	}
	while (*name) {
		if (!isxdigit (*name)) {
			return false;
		}
		name++;
	}
	return true;
}

static bool has_hex_suffix(const char *name, const char *prefix) {
	return r_str_startswith (name, prefix) && is_hex_number (name + strlen (prefix));
}

static bool has_number_suffix(const char *name, const char *prefix) {
	return r_str_startswith (name, prefix) && r_str_isnumber (name + strlen (prefix));
}

R_IPI bool r_bin_name_is_unnamed(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return true;
	}
	if (!strcmp (name, "???") || !strcmp (name, "unknown")
			|| !strcmp (name, "<unknown>") || !strcmp (name, "<null>")) {
		return true;
	}
	if (r_str_isnumber (name)) {
		return true;
	}
	if (has_number_suffix (name, "sym_") || has_number_suffix (name, "UnnamedClass")
			|| has_number_suffix (name, "fcn.") || has_number_suffix (name, "global.")
			|| has_number_suffix (name, "unk_local")) {
		return true;
	}
	if (has_hex_suffix (name, "func.") || has_hex_suffix (name, "fcn.")
			|| has_hex_suffix (name, "sub.") || has_hex_suffix (name, "loc.")
			|| has_hex_suffix (name, "x86.")) {
		return true;
	}
	if (r_str_startswith (name, "UnknownModule")) {
		const char *p = name + strlen ("UnknownModule");
		while (isdigit (*p)) {
			p++;
		}
		return *p == '_' && is_hex_number (p + 1);
	}
	return false;
}

static char *filter_section_name(HtPP *db, ut64 vaddr, const char *name) {
	R_RETURN_VAL_IF_FAIL (db && name, NULL);
	RBinSectionNameState *state = ht_pp_find (db, name, NULL);
	if (!state) {
		state = R_NEW0 (RBinSectionNameState);
		state->count = 1;
		state->first_vaddr = vaddr;
		if (!ht_pp_insert (db, name, state)) {
			free (state);
			return NULL;
		}
		return hashify (name, vaddr, 0, false);
	}
	state->count++;
	if (section_name_exists (state, vaddr)) {
		return NULL;
	}
	return hashify (name, vaddr, state->count - 1, true);
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
		resname = hashify (name, vaddr, 0, true);
	}
	if (count > 1) {
		if (!resname) {
			resname = strdup (name);
		}
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
			// swift demangled names follow Module.Type.member pattern
			char *p = strchr (dn, '.');
			if (p) {
				char *p2 = strchr (p + 1, '.');
				if (p2 && isupper (*dn) && isupper (p[1])) {
					// Module.Class.method - use Module.Class as classname
					sym->classname = r_str_ndup (dn, p2 - dn);
				} else if (isupper (*dn)) {
					sym->classname = r_str_ndup (dn, p - dn);
				} else if (isupper (p[1])) {
					sym->classname = strdup (p + 1);
					char *dot = strchr (sym->classname, '.');
					if (dot) {
						*dot = 0;
					}
				}
			}
		}
		free (dn);
	}
	char *oname = r_str_newf ("o.0.%c.%s", sym->is_imported ? 'i' : 's', name);
	char *uname = r_str_newf ("%" PFMT64x ".%c.%s", vaddr, sym->is_imported ? 'i' : 's', name);
	bool res = ht_pp_insert (ht, uname, sym);
	free (uname);
	if (!res) {
		free (oname);
		return false;
	}
	sym->dup_count = 0;
	RBinSymbol *prev_sym = ht_pp_find (ht, oname, NULL);
	if (!prev_sym) {
		res = ht_pp_insert (ht, oname, sym);
		free (oname);
		if (!res) {
			R_LOG_WARN ("Failed to insert dup_count in ht");
			return false;
		}
	} else {
		sym->dup_count = prev_sym->dup_count + 1;
		ht_pp_update (ht, oname, sym);
		free (oname);
	}
	return true;
}

R_API void r_bin_filter_sections_vec(RBinFile *bf, RVecRBinSection *sections) {
	HtPP *db = ht_pp_new (NULL, section_name_state_free, NULL);
	if (!db) {
		return;
	}
	RBinSection *sec;
	R_VEC_FOREACH (sections, sec) {
		if (!sec->name) {
			continue;
		}
		char *p = filter_section_name (db, sec->vaddr, sec->name);
		if (p) {
			free (sec->name);
			sec->name = p;
		}
	}
	ht_pp_free (db);
}

R_API void r_bin_filter_sections(RBinFile *bf, RList *list) {
	RBinSection *sec;
	HtPP *db = ht_pp_new (NULL, section_name_state_free, NULL);
	RListIter *iter;
	if (!db) {
		return;
	}
	r_list_foreach (list, iter, sec) {
		if (!sec->name) {
			continue;
		}
		char *p = filter_section_name (db, sec->vaddr, sec->name);
		if (p) {
			free (sec->name);
			sec->name = p;
		}
	}
	ht_pp_free (db);
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

R_API bool r_bin_file_string_delete(RBinFile *bf, ut64 vaddr, ut64 len, char type) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && vaddr != UT64_MAX, false);
	RBinObject *bo = bf->bo;
	HtUP *strings_db = r_bin_object_ensure_strings_db (bo);
	RBinString *bs = r_bin_strings_index_get (&bo->strings, strings_db, vaddr);
	if (!bs) {
		return false;
	}
	size_t index = bs - R_VEC_START_ITER (&bo->strings);
	if ((len > 0 && bs->length != len) || (type && bs->type != type)) {
		return false;
	}
	ut64 deleted_vaddr = bs->vaddr;
	RVecRBinString_remove (&bo->strings, index);
	r_bin_strings_index_update_after_remove (&bo->strings, strings_db, deleted_vaddr, index);
	return true;
}

static int detect_string_type(const ut8 *buf, st64 len) {
	if (len >= 4 && buf[1] == 0 && buf[3] == 0) {
		return R_STRING_TYPE_WIDE32;
	}
	if (len >= 2 && buf[1] == 0) {
		return R_STRING_TYPE_WIDE;
	}
	return R_STRING_TYPE_ASCII;
}

static char *extract_wide_string(const ut8 *buf, st64 len, int charsize, ut32 *out_len, ut32 *out_size) {
	ut32 actual_len = 0;
	int i;
	for (i = 0; i < len - (charsize - 1); i += charsize) {
		bool is_null = (charsize == 2) ? (buf[i] == 0 && buf[i+1] == 0)
			: (buf[i] == 0 && buf[i+1] == 0 && buf[i+2] == 0 && buf[i+3] == 0);
		if (is_null || !IS_PRINTABLE (buf[i])) {
			break;
		}
		actual_len++;
	}
	*out_size = (actual_len > 0) ? (actual_len * charsize + charsize) : 0;
	*out_len = actual_len;
	char *str = malloc (actual_len + 1);
	if (str) {
		ut32 j;
		for (j = 0; j < actual_len; j++) {
			str[j] = buf[j * charsize];
		}
		str[actual_len] = 0;
	}
	return str;
}

R_API RBinString *r_bin_file_string_add(RBinFile *bf, ut64 paddr, ut64 vaddr, ut64 max_len, int type) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);
	RBinObject *bo = bf->bo;
	HtUP *strings_db = r_bin_object_ensure_strings_db (bo);
	if (max_len < 1 || max_len > 512) {
		max_len = 512;
	}
	ut8 *buf = malloc (max_len);
	if (!buf) {
		return NULL;
	}
	st64 len = r_buf_read_at (bf->buf, paddr, buf, max_len);
	if (len < 1) {
		free (buf);
		return NULL;
	}
	if (type == 0) {
		type = detect_string_type (buf, len);
	}
	RBinString bs = { 0 };
	ut32 actual_len = 0, actual_size = 0;
	switch (type) {
	case R_STRING_TYPE_WIDE:
		bs.string = extract_wide_string (buf, len, 2, &actual_len, &actual_size);
		break;
	case R_STRING_TYPE_WIDE32:
		bs.string = extract_wide_string (buf, len, 4, &actual_len, &actual_size);
		break;
	default:
		actual_len = (ut32)r_str_pnlen ((const char *)buf, (int)len);
		actual_size = actual_len + 1;
		bs.string = r_str_ndup ((char *)buf, actual_len);
		break;
	}
	free (buf);
	if (!bs.string) {
		bs.string = strdup ("");
	}
	bs.paddr = paddr;
	bs.vaddr = vaddr;
	bs.size = actual_size;
	bs.length = actual_len;
	bs.type = type;
	bs.ordinal = RVecRBinString_length (&bo->strings);
	RBinString *dst = RVecRBinString_emplace_back (&bo->strings);
	if (!dst) {
		r_bin_string_fini (&bs);
		return NULL;
	}
	*dst = bs;
	r_bin_strings_index_insert (strings_db, dst->vaddr, RVecRBinString_length (&bo->strings) - 1);
	return dst;
}
