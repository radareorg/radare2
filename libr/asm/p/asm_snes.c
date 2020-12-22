/* radare - LGPL - Copyright 2012-2015 - condret, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include "../arch/snes/snesdis.c"
#include "asm_snes.h"

static struct snes_asm_flags* snesflags = NULL;

static bool snes_asm_init (void* user) {
	if (!snesflags) {
		snesflags = malloc (sizeof (struct snes_asm_flags));
	}
	memset(snesflags,0,sizeof (struct snes_asm_flags));
	return 0;
}

static bool snes_asm_fini (void* user) {
	free(snesflags);
	snesflags = NULL;
	return 0;
}

static int dis(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int dlen = snesDisass (snesflags->M, snesflags->X, a->pc, op, buf, len);
	if (dlen < 0) {
		dlen = 0;
	}
	op->size = dlen;
	if (buf[0] == 0xc2) { //REP
		if (buf[1] & 0x10) {
			snesflags->X = 0;
		}
		if (buf[1] & 0x20) {
			snesflags->M = 0;
		}
	} else if (buf[0] == 0xe2) { //SEP
		if (buf[1] & 0x10) {
			snesflags->X = 1;
		}
		if (buf[1] & 0x20) {
			snesflags->M = 1;
		}
	}
	return dlen;
}

RAsmPlugin r_asm_plugin_snes = {
	.name = "snes",
	.desc = "SuperNES CPU",
	.arch = "snes",
	.bits = 8|16,
	.init = snes_asm_init,
	.fini = snes_asm_fini,
	.endian = R_SYS_ENDIAN_LITTLE,
	.license = "LGPL3",
	.disassemble = &dis
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_snes,
	.version = R2_VERSION
};
#endif
