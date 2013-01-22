/* radare - LGPL - Copyright 2013 - pancake */

#include <r_anal.h>

R_API void r_anal_hint_clear (RAnal *a) {
	// XXX: memory leak!
	r_list_free (a->hints);
	a->hints = r_list_new ();
}

R_API void r_anal_hint_del (RAnal *a, ut64 addr) {
	RAnalHint *hint = r_anal_hint_at (a, addr, 0);
	if (hint) r_list_delete_data (a->hints, hint);
}

R_API void r_anal_hint_list (RAnal *a, int mode) {
	RAnalHint *hint;
	RListIter *iter;
	// TODO: move into r_Core, show rad output mode too
	r_list_foreach (a->hints, iter, hint) {
		eprintf (" 0x%08"PFMT64x" - 0x%08"PFMT64x, hint->from, hint->to);
		if (hint->arch)
			eprintf (" arch='%s'", hint->arch);
		if (hint->bits)
			eprintf (" bits=%d", hint->bits);
		if (hint->length)
			eprintf (" length=%d", hint->length);
		if (hint->opcode)
			eprintf (" opcode='%s'", hint->opcode);
		if (hint->analstr)
			eprintf (" analstr='%s'", hint->analstr);
		eprintf ("\n");
	}
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

R_API void r_anal_hint_set_analstr (RAnal *a, ut64 addr, int size, const char *analstr) {
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
	hint->length = length;
}

R_API RAnalHint *r_anal_hint_at (RAnal *a, ut64 from, int size) {
	ut64 to = from+size;
	RAnalHint *hint;
	RListIter *iter;
	if (size>0)
		r_list_foreach (a->hints, iter, hint) {
			if (from == hint->from && (!size|| (to == hint->to)))
				return hint;
		}
	return NULL;
}

R_API RAnalHint *r_anal_hint_add (RAnal *a, ut64 from, int size) {
	RAnalHint *hint = r_anal_hint_at (a, from, size);
	if (!hint) {
		hint = R_NEW0 (RAnalHint);
		r_list_append (a->hints, hint);
	}
// TODO reuse entries if from and size match
	hint->from = from;
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
#define SETRET(x) if(hint->x)res->x=hint->x
			SETRET(arch);
			SETRET(bits);
			SETRET(opcode);
			SETRET(analstr);
			SETRET(length);
		}
	}
	return res;
}

#if 0
#if 0
ahl 33 0x80340
ahb 16 0x8048 10
aha ppc $$ 128
ah- $$
// hints
 - instruction length
 - instruction text
 - bits
 - arch
 - analysis string (not yet)
#endif

R_API RAnalHint *r_anal_init (RAnal* anal) {
	// TODO
}

R_API RAnalHint *r_anal_fini (RAnal* anal) {
	// TODO
}

R_API RAnalHint *r_anal_hint_cmd (RAnal* anal, const char *cmd) {
	// TODO
}

R_API int r_anal_hint_unset (RAnal* anal, ut64 addr) {
	// TODO
}

R_API RAnalHint *r_anal_hint_set_bits(RAnal* anal, ut64 addr, int bits, int len) {
	// TODO
}

R_API RAnalHint *r_anal_hint_get (RAnal* anal, ut64 addr) {
	RAnalHint *rah = NULL;
	//r_list_foreach (anal->hints, iter, h) { }
	// bits
	// if (h->arch) hint->arch = h->arch; 
	// if (h->bits) hint->bits = h->bits; 
	return rah;
}
#endif
