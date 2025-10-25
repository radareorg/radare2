/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_asm.h>

R_API RAsmCode *r_asm_code_new(void) {
	return R_NEW0 (RAsmCode);
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
	if (!code->equs) {
		code->equs = ht_pp_new0 ();
	}
	ht_pp_insert (code->equs, key, strdup (value));
}

typedef struct {
	RAsmCode *code;
	char *str;
} UserData;

static bool replace_cb(void *user, const void *key, const void *value) {
	UserData *data = user;
	data->str = r_str_replace (data->str, key, value, true);
	return true;
}

R_API char *r_asm_code_equ_replace(RAsmCode *code, const char *_str) {
	R_RETURN_VAL_IF_FAIL (code && _str, NULL);
	char *str = strdup (_str);
	UserData data = {
		.code = code,
		.str = str
	};
	if (code->equs) {
		ht_pp_foreach (code->equs, replace_cb, &data);
		str = data.str;
	}
	return str;
}

R_API char* r_asm_code_get_hex(RAsmCode *acode) {
	R_RETURN_VAL_IF_FAIL (acode, NULL);
	char* str = calloc (acode->len + 1, 2);
	if (str) {
		r_hex_bin2str (acode->bytes, acode->len, str);
	}
	return str;
}

#if 0
// R2_600 - r_asm_code_set_hex (a->acode, "90909090"); see libr/core/vasm.c
R_API bool r_asm_code_set_hex(RAsmCode *acode, const char *hexstr) {
	ut8 out[1024];
	int len = r_hex_str2bin (str, out);
	if (len > 0) {
		free (a->acode->bytes);
		a->acode->bytes = r_mem_dup (out, len);
		a->acode->len = len;
	}
	a->codebuf[0] = 0;
}
#endif

R_API char *r_asm_code_equ_get(RAsmCode *code, const char *key) {
	R_RETURN_VAL_IF_FAIL (code && key, NULL);
	bool found = false;
	return ht_pp_find (code->equs, key, &found);
}
