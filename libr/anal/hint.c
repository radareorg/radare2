/* radare - LGPL - Copyright 2013 - pancake */

#include <r_anal.h>

R_API void r_anal_hint_clear (RAnal *a) {
	// XXX: memory leak!
	r_list_free (a->hints);
	a->hints = r_list_new ();
}

R_API void r_anal_hint_del (RAnal *a, ut64 addr, int size) {
	RAnalHint *hint = r_anal_hint_at (a, addr, size);
	if (hint) r_list_delete_data (a->hints, hint);
}

R_API void r_anal_hint_set_jump (RAnal *a, ut64 addr, ut64 ptr) {
	RAnalHint *hint = r_anal_hint_add (a, addr, 0);
	hint->jump = ptr;
}

R_API void r_anal_hint_set_fail(RAnal *a, ut64 addr, ut64 ptr) {
	RAnalHint *hint = r_anal_hint_add (a, addr, 0);
	hint->fail = ptr;
}

R_API void r_anal_hint_set_pointer (RAnal *a, ut64 addr, ut64 ptr) {
	RAnalHint *hint = r_anal_hint_add (a, addr, 0);
	hint->ptr = ptr;
}

R_API void r_anal_hint_set_arch (RAnal *a, ut64 addr, int size, const char *arch) {
	RAnalHint *hint = r_anal_hint_add (a, addr, size);
	free (hint->arch);
	arch = r_str_trim_head (arch);
	hint->arch = strdup (arch);
}

R_API void r_anal_hint_set_opcode (RAnal *a, ut64 addr, int size, const char *opcode) {
	RAnalHint *hint = r_anal_hint_add (a, addr, size);
	free (hint->opcode);
	opcode = r_str_trim_head (opcode);
	hint->opcode = strdup (opcode);
}

R_API void r_anal_hint_set_esil (RAnal *a, ut64 addr, int size, const char *analstr) {
	RAnalHint *hint = r_anal_hint_add (a, addr, size);
	free (hint->analstr);
	analstr = r_str_trim_head (analstr);
	hint->analstr = strdup (analstr);
}

R_API void r_anal_hint_set_bits (RAnal *a, ut64 addr, int size, int bits) {
	RAnalHint *hint = r_anal_hint_add (a, addr, size);
	hint->bits = bits;
}

R_API void r_anal_hint_set_length (RAnal *a, ut64 addr, int size, int length) {
	RAnalHint *hint = r_anal_hint_add (a, addr, size);
	hint->size = length;
}

R_API RAnalHint *r_anal_hint_at (RAnal *a, ut64 from, int size) {
	ut64 to = from+size;
	RAnalHint *hint;
	RListIter *iter;
	r_list_foreach (a->hints, iter, hint) {
		if (from == hint->from && (!size || (to == hint->to)))
			return hint;
	}
	return NULL;
}

R_API RAnalHint *r_anal_hint_add (RAnal *a, ut64 from, int size) {
	RAnalHint *hint = r_anal_hint_at (a, from, size);
	if (!hint) {
		hint = R_NEW0 (RAnalHint);
		hint->jump = UT64_MAX;
		hint->fail = UT64_MAX;
		hint->from = from;
		r_list_append (a->hints, hint);
	}
// TODO reuse entries if from and size match
	if (size<1) size = 1;
	hint->to = from+size;
	return hint;
}

R_API void r_anal_hint_free (RAnalHint *h) {
	free (h->arch);
	free (h);
}

R_API RAnalHint *r_anal_hint_get(RAnal *anal, ut64 addr) {
	RAnalHint *res = NULL;
	RAnalHint *hint;
	RListIter *iter;
	r_list_foreach (anal->hints, iter, hint) {
		if (addr >= hint->from && addr < hint->to) {
			if (!res) res = R_NEW0 (RAnalHint);
#define SETRETX(x) if(hint->x!=UT64_MAX) res->x=hint->x;
#define SETRETS(x) if(hint->x) res->x=strdup(hint->x);
#define SETRET(x) if(hint->x) res->x=hint->x
			SETRETS(arch);
			SETRET(bits);
			SETRET(ptr);
			SETRETX(jump);
			SETRETX(fail);
			SETRETS(opcode);
			SETRETS(analstr);
			SETRET(size);
		}
	}
	return res;
}
