/* radare - LGPL - Copyright 2009-2023 - pancake */

#include <r_asm.h>

R_API RAsmCode *r_asm_code_new(void) {
	return R_NEW0 (RAsmCode);
}

R_API void r_asm_code_free(RAsmCode *acode) {
	if (acode) {
		r_list_free (acode->equs);
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

	if (code->equs) {
		RAsmEqu *equ = r_asm_code_equ_get (code, key);
		if (equ) {
			free (equ->value);
			equ->value = strdup (value);
		}
	} else {
		code->equs = r_list_newf ((RListFree)r_asm_equ_item_free);
	}
	r_list_append (code->equs, __asm_equ_new (key, value));
}

R_API char *r_asm_code_equ_replace(RAsmCode *code, char *str) {
	r_return_val_if_fail (code && str, NULL);
	RAsmEqu *equ;
	RListIter *iter;
	r_list_foreach (code->equs, iter, equ) {
		str = r_str_replace (str, equ->key, equ->value, true);
	}
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

R_API RAsmEqu *r_asm_code_equ_get(RAsmCode *code, const char *key) { // R2_590
	// TODO: use a hashtable or sdb
	void *equ;
	RListIter *iter;
	r_list_foreach (code->equs, iter, equ) {
		RAsmEqu *e = (RAsmEqu*) equ;
		if (!strcmp (e->key, key)) {
			return e;
		}
	}
	return NULL;
}
