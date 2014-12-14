/* radare - LGPL - Copyright 2013-2014 - pancake */

#include <r_anal.h>

#define DB a->sdb_hints
#define setf(x,y...) snprintf(x,sizeof(x)-1,##y)

R_API void r_anal_hint_clear (RAnal *a) {
	sdb_reset (a->sdb_hints);
}

R_API void r_anal_hint_del (RAnal *a, ut64 addr, int size) {
	char key[128];
	if (size>1) {
		eprintf ("TODO: r_anal_hint_del: in range\n");
	} else {
		setf (key, "hint.0x%08"PFMT64x, addr);
		sdb_unset (a->sdb_hints, key, 0);
	}
}

static void setHint (RAnal *a, const char *type, ut64 addr, const char *s, ut64 ptr) {
	int idx;
	char key[128], val[128], *nval = NULL;
	setf (key, "hint.0x%"PFMT64x, addr);
	idx = sdb_array_indexof (DB, key, type, 0);
	if (s) nval = sdb_encode ((const ut8*)s, 0);
	else nval = sdb_itoa (ptr, val, 16);
	if (idx != -1) {
		if (!s) nval = sdb_itoa (ptr, val, 16);
		sdb_array_set (DB, key, idx+1, nval, 0);
	} else {
		sdb_array_push (DB, key, nval, 0);
		sdb_array_push (DB, key, type, 0);
	}
	if (s) free (nval);
}

R_API void r_anal_hint_set_jump (RAnal *a, ut64 addr, ut64 ptr) {
	setHint (a, "jump:", addr, NULL, ptr);
}

R_API void r_anal_hint_set_fail(RAnal *a, ut64 addr, ut64 ptr) {
	setHint (a, "fail:", addr, NULL, ptr);
}

R_API void r_anal_hint_set_pointer (RAnal *a, ut64 addr, ut64 ptr) {
	setHint (a, "ptr:", addr, NULL, ptr);
}

R_API void r_anal_hint_set_arch (RAnal *a, ut64 addr, const char *arch) {
	setHint (a, "arch:", addr, r_str_trim_const (arch), 0);
}

R_API void r_anal_hint_set_opcode (RAnal *a, ut64 addr, const char *opcode) {
	setHint (a, "opcode:", addr, r_str_trim_const (opcode), 0);
}

R_API void r_anal_hint_set_esil (RAnal *a, ut64 addr, const char *esil) {
	setHint (a, "esil:", addr, r_str_trim_const (esil), 0);
}

R_API void r_anal_hint_set_bits (RAnal *a, ut64 addr, int bits) {
	setHint (a, "bits:", addr, NULL, bits);
}

R_API void r_anal_hint_set_size (RAnal *a, ut64 addr, int size) {
	setHint (a, "size:", addr, NULL, size);
}

R_API void r_anal_hint_free (RAnalHint *h) {
	if (!h) return;
	free (h->arch);
	free (h->esil);
	free (h->opcode);
	free (h);
}

R_API RAnalHint *r_anal_hint_from_string(RAnal *a, ut64 addr, const char *str) {
	char *r, *nxt;
	int token = 0;
	RAnalHint *hint = R_NEW0 (RAnalHint);
	char *s = strdup (str);
	hint->addr = addr;
	for (r = s; ; r = nxt) {
		r = sdb_anext (r, &nxt);
		if (token) {
			switch (token) {
			case 'j': hint->jump = sdb_atoi (r); break;
			case 'f': hint->fail = sdb_atoi (r); break;
			case 'p': hint->ptr  = sdb_atoi (r); break;
			case 'b': hint->bits = sdb_atoi (r); break;
			case 's': hint->size = sdb_atoi (r); break;
			case 'o': hint->opcode = (char*)sdb_decode (r, 0); break;
			case 'e': hint->esil = (char*)sdb_decode (r, 0); break;
			case 'a': hint->arch = (char*)sdb_decode (r, 0); break;
			}
			token = 0;
		} else token = *r;
		if (!nxt)
			break;
	}
	free (s);
	return hint;
}

R_API RAnalHint *r_anal_hint_get(RAnal *a, ut64 addr) {
	char key[128];
	const char *s;
	RAnalHint *hint;

	setf (key, "hint.0x%"PFMT64x, addr);
	s = sdb_const_get (DB, key, 0);
	if (!s) {
		return NULL;
	}
	hint = r_anal_hint_from_string (a, addr, s);
	return hint;
}
