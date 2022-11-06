/* radare2 - LGPL - Copyright 2022 - condret */

#include <r_arch.h>
#include <r_util.h>

// plaintext to opcdes bytes, returns length
// why not returning an RBuffer?
// R_API RBuffer *r_arch_encode(RArch *a, ut64 addr, const char *s) { }

R_API int r_arch_encode(RArch *a, ut64 addr, const char *s, ut8 *outbuf, int outlen) {
	int res = 0;
	RArchOpAsmCallback opasm = R_UNWRAP4 (a, current, p, opasm);

	if (opasm) { // a->current && a->current->p && a->current->p->opasm) {
		res = opasm (a, addr, s, outbuf, outlen);
	}
	return res;
}
