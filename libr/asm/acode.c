/* radare - LGPL - Copyright 2009-2023 - pancake */

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

R_API void r_asm_equ_item_free(RAsmEqu *equ) {
	if (equ) {
		free (equ->key);
		free (equ->value);
		free (equ);
	}
}

static RAsmEqu *__asm_equ_new(const char *key, const char *value) {
	r_return_val_if_fail (key && value, NULL);
	RAsmEqu *equ = R_NEW0 (RAsmEqu);
	if (equ) {
		equ->key = strdup (key);
		equ->value = strdup (value);
	}
	return equ;
}

R_API void r_asm_code_set_equ(RAsmCode *code, const char *key, const char *value) {
	r_return_if_fail (code && key && value);
#if 0
	if (code->equs) {
		RAsmEqu *equ = r_asm_code_equ_get (code, key);
		if (equ) {
			free (equ->value);
			equ->value = strdup (value);
		}
	} else {
		code->equs = ht_pp_new0 ();
	}
#endif
	ht_pp_insert (code->equs, key, value);
}

typedef struct {
	RAsmCode *code;
	const char *str;
} UserData;

static bool replace_cb(void *user, const void *key, const void *value) {
	UserData *data = user;
	data->str = r_str_replace (data->str, key, value, true);
	return true;
}

R_API char *r_asm_code_equ_replace(RAsmCode *code, char *str) {
	r_return_val_if_fail (code && str, NULL);
	UserData data = {
		.code = code,
		.str = str
	};
	ht_pp_foreach (code->equs, replace_cb, &data);
	return str;
}

R_API char* r_asm_code_get_hex(RAsmCode *acode) {
	r_return_val_if_fail (acode, NULL);
	char* str = calloc (acode->len + 1, 2);
	if (str) {
		r_hex_bin2str (acode->bytes, acode->len, str);
	}
	return str;
}

R_API RAsmEqu *r_asm_code_equ_get(RAsmCode *code, const char *key) {
	r_return_val_if_fail (code && key, NULL);
	bool found = false;
	return ht_pp_find (code->equs, key, &found);
}
