/* radare - LGPL - Copyright 2009-2013 - pancake */

#include <stdio.h>
#include <r_asm.h>

R_API RAsmCode *r_asm_code_new() {
	return R_NEW0 (RAsmCode);
}

R_API void* r_asm_code_free(struct r_asm_code_t *acode) {
	if (!acode)
		return NULL;
	if (acode->buf)
		free (acode->buf);
	if (acode->buf_hex)
		free (acode->buf_hex);
	if (acode->buf_asm)
		free (acode->buf_asm);
	free (acode);
	return NULL;
}

R_API int r_asm_code_set_equ (RAsmCode *code, const char *key, const char *value) {
	RAsmEqu *equ;
	RListIter *iter;
	if (key == NULL || value == NULL) {
		eprintf ("Oops, no key or value defined in r_asm_code_set_equ ()\n");
		return R_FALSE;
	}
	if (!code->equs) {
		code->equs = r_list_new ();
		code->equs->free = free;
	} else r_list_foreach (code->equs, iter, equ)
		if (!strcmp (equ->key, key)) {
			free (equ->value);
			equ->value = strdup (value);
			return R_TRUE;
		}
	equ = R_NEW (RAsmEqu);
	equ->key = strdup (key);
	equ->value = strdup (value);
	r_list_append (code->equs, equ);
	return R_TRUE;
}

R_API char *r_asm_code_equ_replace (RAsmCode *code, char *str) {
	RAsmEqu *equ;
	RListIter *iter;
	if (code->equs)
		r_list_foreach (code->equs, iter, equ) {
			str = r_str_replace (str, equ->key, equ->value, R_TRUE);
		}
	return str;
}
