/* radare - LGPL - Copyright 2009-2021 - pancake, nibble */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>

#if HAVE_GPERF
extern SdbGperf gperf_z80;
extern SdbGperf gperf_6502;
extern SdbGperf gperf_i4004;
extern SdbGperf gperf_avr;
//extern SdbGperf gperf_chip8;
extern SdbGperf gperf_i8080;
extern SdbGperf gperf_java;
extern SdbGperf gperf_lm32;
extern SdbGperf gperf_m68k;
extern SdbGperf gperf_malbolge;
extern SdbGperf gperf_mips;
extern SdbGperf gperf_ppc;
extern SdbGperf gperf_riscv;
extern SdbGperf gperf_sh;
extern SdbGperf gperf_sparc;
extern SdbGperf gperf_tricore;
extern SdbGperf gperf_x86;
extern SdbGperf gperf_v810;
extern SdbGperf gperf_s390;
extern SdbGperf gperf_v850;
extern SdbGperf gperf_8051;
extern SdbGperf gperf_LH5801;
extern SdbGperf gperf_arc;
extern SdbGperf gperf_arm;
extern SdbGperf gperf_msp430;
extern SdbGperf gperf_propeller;
extern SdbGperf gperf_pic18c;

static const SdbGperf *gperfs[] = {
	&gperf_z80,
	&gperf_6502,
	&gperf_i4004,
	&gperf_avr,
	// &gperf_chip8,
	&gperf_i8080,
	&gperf_java,
	&gperf_s390,
	&gperf_lm32,
	&gperf_m68k,
	&gperf_malbolge,
	&gperf_mips,
	&gperf_tricore,
	&gperf_ppc,
	&gperf_riscv,
	&gperf_sh,
	&gperf_sparc,
	&gperf_x86,
	&gperf_v810,
	&gperf_v850,
	&gperf_8051,
	&gperf_LH5801,
	&gperf_arc,
	&gperf_arm,
	&gperf_msp430,
	&gperf_propeller,
	&gperf_pic18c,
	NULL
};

R_API SdbGperf *r_asm_get_gperf(const char *k) {
	SdbGperf **gp = (SdbGperf**)gperfs;
	while (*gp) {
		SdbGperf *g = *gp;
		if (!strcmp (k, g->name)) {
			return *gp;
		}
		gp++;
	}
	return NULL;
}
#else
R_API SdbGperf *r_asm_get_gperf(const char *k) {
	return NULL;
}
#endif
