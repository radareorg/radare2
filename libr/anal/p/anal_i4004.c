/* radare - LGPL - Copyright 2016 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#define	AVR_SOFTCAST(x,y)	((x)+((y)*0x100))

static int set_reg_profile(RAnal *anal) {
	const char *p =
		"=PC	PC\n"
		/* syntax not yet supported */
		// "=SP	&PC1\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
		"=R0	r0\n"
		"gpr	r0	.4	0	0\n"
		"gpr	r1	.4	1	0\n"
		"gpr	r2	.4	2	0\n"
		"gpr	r3	.4	3	0\n"
		"gpr	r4	.4	4	0\n"
		"gpr	r5	.4	5	0\n"
		"gpr	r6	.4	6	0\n"
		"gpr	r7	.4	7	0\n"
		"gpr	r8	.4	8	0\n"
		"gpr	r9	.4	9	0\n"
		"gpr	r10	.4	10	0\n"
		"gpr	r11	.4	11	0\n"
		"gpr	r12	.4	12	0\n"
		"gpr	r13	.4	13	0\n"
		"gpr	r14	.4	14	0\n"
		"gpr	r15	.4	15	0\n"
		"gpr	PC	.64	32	0\n"
		/* stack */
		"gpr	PC1	.64	34	0\n"
		"gpr	PC2	.64	34	0\n"
		"gpr	PC3	.64	34	0\n"
		;

	return r_reg_set_profile_string (anal->reg, p);
}

/* That 3 is a hack */
static const int i4004_ins_len[16] = {
	1, 2, 3, 1, 2, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1
};

static const char *i4004_e[16] = {
	"wrm",
	"wmp",
	"wrr",
	"wpm",
	"wr0",
	"wr1",
	"wr2",
	"wr3",
	"sbm",
	"rdm",
	"rdr",
	"adm",
	"rd0",
	"rd1",
	"rd2",
	"rd3"
};

static const char *i4004_f[16] = {
	"clb",
	"clc",
	"iac",
	"cmc",
	"cma",
	"ral",
	"rar",
	"tcc",
	"dac", // decrement
	"tcs",
	"stc",
	"daa",
	"kbp",
	"dcl",
	"invalid",
	"invalid"
};

static int i4004_get_ins_len (ut8 hex) {
	ut8 high = (hex & 0xf0)>>4;
	int ret = i4004_ins_len[high];
	if (ret == 3) {
		ret = (hex & 1) ? 1 : 2;
	}
	return ret;
}

static int i4004_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	char basm[128];
	const size_t basz = sizeof (basm)-1;
	int rlen = i4004_get_ins_len (*buf);
	if (!op) {
		return 2;
	}
	r_strbuf_init (&op->esil);
	ut8 high = (*buf & 0xf0)>>4;
	ut8 low = (*buf & 0xf);
	basm[0] = 0;

	if (rlen > len) {
		return op->size = 0;
	}
	switch (high) {
	case 0:
		if (low) {
			op->type = R_ANAL_OP_TYPE_ILL;
		} else {
			op->type = R_ANAL_OP_TYPE_NOP;
		}
		break;
	case 1: //snprintf (basm, basz, "jcn %d 0x%02x", low, buf[1]); break;
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = (addr & (~0xFF)) + buf[1];
		op->fail = addr + rlen;
		break;
	case 2:
		if (rlen == 1) {
			snprintf (basm, basz, "scr r%d", (low & 0xe));
		} else {
			op->type = R_ANAL_OP_TYPE_MOV;
			op->val = buf[1];
			snprintf (basm, basz, "fim r%d, 0x%02x", (low & 0xe), buf[1]);
		}
		break;
	case 3:
		if (low & 1) {
			op->type = R_ANAL_OP_TYPE_RJMP;
		} else {
			op->type = R_ANAL_OP_TYPE_MOV;
			snprintf (basm, basz, "fin r%d", (low & 0xe));
		}
		break;
	case 4:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = (ut16) (low<<8) | buf[1];
		break;
	case 5: //snprintf (basm, basz, "jms 0x%03x", ((ut16)(low<<8) | buf[1])); break;
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = (ut16) (low<<8) | buf[1];
		op->fail = addr + rlen;
		break;
	case 6: //snprintf (basm, basz, "inc r%d", low); break;
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 7: //snprintf (basm, basz, "isz r%d, 0x%02x", low, buf[1]); 
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->fail = (addr & (~0xFF)) + buf[1];
		op->jump = addr + rlen;
		break;
	case 8:
		op->type = R_ANAL_OP_TYPE_ADD;
		//snprintf (basm, basz, "add r%d", low); break;
		break;
	case 9:
		op->type = R_ANAL_OP_TYPE_SUB;
		//snprintf (basm, basz, "sub r%d", low); break;
		break;
	case 10: //snprintf (basm, basz, "ld r%d", low); break;
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 11: //snprintf (basm, basz, "xch r%d", low); break;
		op->type = R_ANAL_OP_TYPE_XCHG;
		break;
	case 12: //snprintf (basm, basz, "bbl %d", low); break;
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case 13:
		op->type = R_ANAL_OP_TYPE_LOAD;
		//snprintf (basm, basz, "ldm %d", low); break;
		break;
	case 14:
		strncpy (basm, i4004_e[low], basz);
		basm[basz] = '\0';
		break;
	case 15:
		strncpy (basm, i4004_f[low], basz);
		basm[basz] = '\0';
		if (!strcmp (basm, "dac")) {
			op->type = R_ANAL_OP_TYPE_SUB;
		}
		break;
	}
	if (!strcmp (basm, "invalid")) {
		op->type = R_ANAL_OP_TYPE_ILL;
	} else if (!strcmp (basm, "ral")) {
		op->type = R_ANAL_OP_TYPE_SHL;
	} else if (!strcmp (basm, "rar")) {
		op->type = R_ANAL_OP_TYPE_SHR;
	}
	return op->size = rlen;
}

RAnalPlugin r_anal_plugin_i4004 = {
	.name = "i4004",
	.desc = "i4004 code analysis plugin",
	.license = "LGPL3",
	.arch = "i4004",
	.esil = true,
	.bits = 8,
	.op = &i4004_op,
	.set_reg_profile = &set_reg_profile
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_i4004,
	.version = R2_VERSION
};
#endif
