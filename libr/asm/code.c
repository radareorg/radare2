/* radare - LGPL - Copyright 2009-2018 - pancake */

#include <stdio.h>
#include <r_asm.h>

R_API RAsmCode *r_asm_code_new(void) {
	return R_NEW0 (RAsmCode);
}

R_API void* r_asm_code_free(RAsmCode *acode) {
	if (acode) {
		r_list_free (acode->equs);
		free (acode->buf);
		free (acode->buf_hex);
		free (acode->buf_asm);
		free (acode);
	}
	return NULL;
}

R_API void r_asm_equ_item_free(RAsmEqu *equ) {
	free (equ->key);
	free (equ->value);
	free (equ);
}

R_API bool r_asm_code_set_equ (RAsmCode *code, const char *key, const char *value) {
	RAsmEqu *equ;
	RListIter *iter;
	if (!code || !key || !value) {
		eprintf ("Oops, no key or value defined in r_asm_code_set_equ ()\n");
		return false;
	}
	if (!code->equs) {
		code->equs = r_list_newf ((RListFree)r_asm_equ_item_free);
	} else {
		r_list_foreach (code->equs, iter, equ) {
			if (!strcmp (equ->key, key)) {
				free (equ->value);
				equ->value = strdup (value);
				return true;
			}
		}
	}
	equ = R_NEW0 (RAsmEqu);
	equ->key = strdup (key);
	equ->value = strdup (value);
	r_list_append (code->equs, equ);
	return true;
}

R_API char *r_asm_code_equ_replace (RAsmCode *code, char *str) {
	RAsmEqu *equ;
	RListIter *iter;
	r_list_foreach (code->equs, iter, equ) {
		str = r_str_replace (str, equ->key, equ->value, true);
	}
	return str;
}
