/* radare - LGPL - Copyright 2009-2019 - pancake */

#include <stdio.h>
#include <r_asm.h>

R_API RAsmCode *r_asm_code_new(void) {
	return R_NEW0 (RAsmCode);
}

R_API void* r_asm_code_free(RAsmCode *acode) {
	if (acode) {
		r_list_free (acode->equs);
		free (acode->bytes);
		free (acode->assembly);
		free (acode);
	}
	return NULL;
}

R_API void r_asm_equ_item_free(RAsmEqu *equ) {
	if (equ) {
		free (equ->key);
		free (equ->value);
		free (equ);
	}
}

static RAsmEqu *__asm_equ_new(const char *key, const char *value) {
	RAsmEqu *equ = R_NEW0 (RAsmEqu);
	if (equ) {
		equ->key = strdup (key);
		equ->value = strdup (value);
	}
	return equ;
}

R_API bool r_asm_code_set_equ (RAsmCode *code, const char *key, const char *value) {
	r_return_val_if_fail (code && key && value, false);

	if (code->equs) {
		RAsmEqu *equ;
		RListIter *iter;
		r_list_foreach (code->equs, iter, equ) {
			if (!strcmp (equ->key, key)) {
				free (equ->value);
				equ->value = strdup (value);
				return true;
			}
		}
	} else {
		code->equs = r_list_newf ((RListFree)r_asm_equ_item_free);
	}
	r_list_append (code->equs, __asm_equ_new (key, value));
	return true;
}

R_API char *r_asm_code_equ_replace (RAsmCode *code, char *str) {
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
