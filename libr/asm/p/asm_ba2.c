#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#define BA2_INSTR_MAXLEN	20

struct op_cmd {
	char	instr[BA2_INSTR_MAXLEN];
	char	operands[BA2_INSTR_MAXLEN];
};

//uint8_t revbits[256];

#include "../asm/arch/ba2/ba2_disas.c"

#define BUILD_BUG_ON_ZERO(e) (sizeof(char[1 - 2 * !!(e)]) - 1)
/* &a[0] degrades to a pointer: a different type from an array */
#define __must_be_array(a) \
  BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(typeof(a), typeof(&a[0])))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))

static bool init(void * user)
{
	(void)user;
//	int cnta;
//	int cntb;
//	for(cnta=0;cnta<ARRAY_SIZE(revbits);cnta++){
//		uint32_t b = cnta;
//		uint32_t r = 0;
//		for(cntb=0;cntb<sizeof(revbits[0])*8;cntb++){
//			r <<= 1;
//			r |= b & 1;
//			b >>= 1;
//		}
//		revbits[cnta] = r;
//	}
	return 1;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	struct op_cmd cmd = {
		.instr = "",
		.operands = ""
	};
//	if (len < 2){ return -1;}
//	if (len < 2){ printf("addr:%x,len=%d\r\n", a->pc, len); return 0;}
	int ret = ba2_decode_opcode (a->pc, buf, len, &cmd, NULL, NULL);
	if((len < ret) || (!ret && len<6)){ 
//		printf("addr:%x,len=%d/%d - truncated\r\n", a->pc, len, ret);
//		snprintf (op->buf_asm.buf, sizeof(op->buf_asm.buf), "truncated"); 
		r_strbuf_set (&op->buf_asm, "truncated");
		op->size = 0; 
		return 0;
	}
	if (ret > 0) {
//		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %s",
		snprintf (op->buf_asm.buf, sizeof(op->buf_asm.buf), "%s %s", cmd.instr, cmd.operands);
	}else{
		r_strbuf_set (&op->buf_asm, "invalid");
		return -1;
	}
	return op->size = ret;
}

RAsmPlugin r_asm_plugin_ba2 = {
	.name = "ba2",
	.license = "LGPL3",
	.desc = "Beyond Architecture 2 disassembly plugin",
	.arch = "ba2",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE,
	.init = &init,
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_ba2,
	.version = R2_VERSION
};
#endif

/*
#include <ba2_ass.h>
#include "../arch/ba2/ba2_disas.c"


static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int dlen = 0;
	char *s = r_ba2_disas (a->pc, buf, len, &dlen);
	if (dlen < 0) {
		dlen = 0;
	}
	if (s) {
		r_strbuf_set (&op->buf_asm, s);
		free (s);
	}
	op->size = dlen;
	return dlen;
}

RAsmPlugin r_asm_plugin_ba2 = {
	.name = "ba2",
	.arch = "ba2",
	.bits = 8,
	.endian = R_SYS_ENDIAN_NONE,
	.desc = "Beyond Architecture 2",
	.disassemble = &disassemble,
	.assemble = &assemble_ba2,
	.license = "PD",
	.cpus =
		"ba2-generic," // First one is default
		"ba2-shared-code-xdata"
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_ba2,
	.version = R2_VERSION
};
#endif
*/

