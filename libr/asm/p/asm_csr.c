/* radare - LGPL - Copyright 2009-2014 - nibble */

#include <stdio.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>
#include "csr/dis.c"

static int arch_csr_disasm(char *str, const unsigned char *buf, ut64 seek) {
	struct state *s = get_state();
	struct directive *d;
	memset(s, 0, sizeof(*s));
	s->s_buf = buf;
	s->s_off = seek;
	s->s_out = NULL;
	d = next_inst(s);
	if (d != NULL) {
		csr_decode(s, d);
		strcpy(str, d->d_asm);
		free(d);
	} else *str = '\0';
#if 0
	if (s->s_ff_quirk) {
		sprintf(d->d_asm, "DC\t0x%x", i2u16(&d->d_inst));
		s->s_ff_quirk = 0;
	}
#endif
	return 0;
}
static int disassemble(RAsm *a, struct r_asm_op_t *op, const ut8 *buf, int len) {
	arch_csr_disasm (op->buf_asm, buf, a->pc);
	return (op->size=2);
}

RAsmPlugin r_asm_plugin_csr = {
	.name = "csr",
	.arch = "csr",
	.license = "PD",
	.bits = 16,
	.desc = "Cambridge Silicon Radio (CSR)",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_csr
};
#endif
