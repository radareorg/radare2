/* radare - LGPL - Copyright 2009-2010 pancake<@nopcode.org> */

#include <stdio.h>
#include <r_asm.h>

R_API RAsmCode *r_asm_code_new(const char *buf) {
	RAsmCode *code = R_NEW (RAsmCode);
	if (!code)
		return NULL;
	code->equs = r_list_new ();
	if (!(code->buf_asm = malloc (strlen (buf)+1)))
		return r_asm_code_free (code);
	memcpy (code->buf_asm, buf, strlen (buf)+1);
	if (!(code->buf_hex = malloc (2)))
		return r_asm_code_free (code);
	if (!(code->buf = malloc (2)))
		return r_asm_code_free (code);
	return code;
}

R_API void* r_asm_code_free(struct r_asm_code_t *acode) {
	if (acode) {
		if (acode->equs) {
			r_list_destroy (acode->equs);
			r_list_free (acode->equs);
		}
		if (acode->buf)
			free (acode->buf);
		if (acode->buf_hex)
			free (acode->buf_hex);
		if (acode->buf_asm)
			free (acode->buf_asm);
		free (acode);
	}
	return NULL;
}

R_API int r_asm_code_set_equ (RAsmCode *code, const char *key, const char *value) {
	RAsmEqu *equ;
	if (key == NULL || value == NULL) {
		eprintf ("Oops, no key or value defined in r_asm_code_set_equ ()\n");
		return R_FALSE;
	}
	if (!code->equs) {
		code->equs = r_list_new ();
		code->equs->free = free;
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
