/* radare - LGPL - Copyright 2013 - pancake */

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
