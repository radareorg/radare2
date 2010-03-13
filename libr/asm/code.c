/* radare - LGPL - Copyright 2009-2010 pancake<@nopcode.org> */

#include <stdio.h>
#include <r_asm.h>

R_API RAsmCode *r_asm_code_new() {
	RAsmCode *acode = R_NEW (RAsmCode);
	if (!acode)
		return NULL;
	r_asm_code_init(acode);
	return acode;
}

R_API int r_asm_code_init(struct r_asm_code_t *acode) {
	acode->len = 0;
	acode->equs = NULL;
	acode->buf_asm = NULL;
	acode->buf_hex = NULL;
	acode->buf = NULL;
	return R_TRUE;
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
	RListIter *iter;
	if (code->equs) {
		iter = r_list_iterator (code->equs);
		while (r_list_iter_next (iter)) {
			RAsmEqu *equ = r_list_iter_get (iter);
			str = r_str_sub (str, equ->key, equ->value, R_TRUE);
		}
	}
	return str;
}
