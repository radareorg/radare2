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

static bool equ_replace(RAsmCode *code, RStrBuf *sb, const char *str, const char **chain, size_t depth) {
	const char *p = str;
	while (*p) {
		const char *start = p;
		if (*p == ':' || !r_name_validate_char (*p)) {
			do {
				p++;
			} while (*p && (*p == ':' || !r_name_validate_char (*p)));
			if (!r_strbuf_append_n (sb, start, p - start)) {
				return false;
			}
			continue;
		}
		do {
			p++;
		} while (*p != ':' && r_name_validate_char (*p));
		const size_t len = p - start;
		if (len > INT_MAX) {
			return false;
		}
		char token[128];
		char *key = len < sizeof (token)? token: r_str_ndup (start, len);
		if (!key) {
			return false;
		}
		if (key == token) {
			memcpy (token, start, len);
			token[len] = 0;
		}
		const char *value = ht_pp_find (code->equs, key, NULL);
		if (key != token) {
			free (key);
		}
		size_t i;
		for (i = 0; i < depth && chain[i] != value; i++) {
		}
		if (!value || i < depth) {
			if (!r_strbuf_append_n (sb, start, len)) {
				return false;
			}
		} else {
			if (depth == 64) {
				R_LOG_ERROR ("Too many nested .equ substitutions");
				return false;
			}
			chain[depth] = value;
			if (!equ_replace (code, sb, value, chain, depth + 1)) {
				return false;
			}
		}
	}
	return true;
}

R_API char *r_asm_code_equ_replace(RAsmCode *code, const char *str) {
	R_RETURN_VAL_IF_FAIL (code && str, NULL);
	if (!code->equs->count) {
		return strdup (str);
	}
	const char *chain[64];
	RStrBuf sb = {0};
	if (!equ_replace (code, &sb, str, chain, 0)) {
		r_strbuf_fini (&sb);
		return NULL;
	}
	return r_strbuf_drain_nofree (&sb);
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
