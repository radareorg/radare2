/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_asm.h>

static void kv_fini(HtPPKv *kv) {
	free (kv->key);
	free (kv->value);
}

R_API RAsmCode *r_asm_code_new(void) {
	RAsmCode *ac = R_NEW0 (RAsmCode);
	HtPPOptions opts = { 0 };
	opts.cmp = (HtPPListComparator)strcmp;
	opts.hashfn = (HtPPHashFunction)sdb_hash;
	opts.dupkey = (HtPPDupKey)strdup;
	opts.dupvalue = (HtPPDupValue)strdup;
	opts.freefn = kv_fini;
	opts.elem_size = 0;
	ac->equs = ht_pp_new_opt (&opts);
	ac->cfloat_profile = R_CFLOAT_PROFILE_BINARY32;
	return ac;
}

R_API void r_asm_code_free(RAsmCode *acode) {
	if (acode) {
		ht_pp_free (acode->equs);
		free (acode->bytes);
		free (acode->assembly);
		free (acode);
	}
}

R_API void r_asm_code_set_equ(RAsmCode *code, const char *key, const char *value) {
	R_RETURN_IF_FAIL (code && key && value);
	ht_pp_insert (code->equs, key, (void *)value);
}

static bool replace_cb(void *user, const void *key, const void *value) {
	char **str = user;
	char *p = *str;
	const size_t keylen = strlen (key);
	RStrBuf *sb = r_strbuf_new (NULL);
	while (*p) {
		char *start = p;
		if (*p != ':' && r_name_validate_char (*p)) {
			while (*p != ':' && r_name_validate_char (*p)) {
				p++;
			}
		} else {
			p++;
		}
		size_t len = p - start;
		if (len == keylen && !strncmp (start, key, len)) {
			r_strbuf_append (sb, value);
		} else {
			r_strbuf_append_n (sb, start, len);
		}
	}
	free (*str);
	*str = r_strbuf_drain (sb);
	return true;
}

R_API char *r_asm_code_equ_replace(RAsmCode *code, const char *_str) {
	R_RETURN_VAL_IF_FAIL (code && _str, NULL);
	char *str = strdup (_str);
	if (str) {
		ht_pp_foreach (code->equs, replace_cb, &str);
	}
	return str;
}

R_API char *r_asm_code_get_hex(RAsmCode *acode) {
	R_RETURN_VAL_IF_FAIL (acode, NULL);
	char *str = calloc (acode->len + 1, 2);
	if (str) {
		r_hex_bin2str (acode->bytes, acode->len, str);
	}
	return str;
}

R_API char *r_asm_code_equ_get(RAsmCode *code, const char *key) {
	R_RETURN_VAL_IF_FAIL (code && key, NULL);
	bool found = false;
	return ht_pp_find (code->equs, key, &found);
}
