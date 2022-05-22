/* radare - MIT - Copyright 2021-2022 - pancake, brainstorm */

#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../arch/v850np/v850dis.h"

#define DEFAULT_CPU_MODEL V850_CPU_E2
static int cpumodel_from_string(const char *s) {
	if (R_STR_ISEMPTY (s) || !strcmp (s, "v850")) {
		return DEFAULT_CPU_MODEL;
	}
	if (strstr (s, "all")) {
		return V850_CPU_ALL;
	}
	if (strstr (s, "e2v3")) {
		return V850_CPU_E2V3;
	}
	if (strstr (s, "e3v5")) {
		return V850_CPU_E3V5;
	}
	if (strstr (s, "e2")) {
		return V850_CPU_E2;
	}
	if (strstr (s, "e1")) {
		return V850_CPU_E1;
	}
	if (*s == 'e') {
		return V850_CPU_E;
	}
	if (strstr (s, "0")) {
		return V850_CPU_0;
	}
	int num = r_num_get (NULL, s);
	return num? num: DEFAULT_CPU_MODEL;
}

static int v850_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	int cpumodel = cpumodel_from_string (anal->config->cpu);
#if 0
	cpumodel |= V850_CPU_OPTION_ALIAS;
	cpumodel |= V850_CPU_OPTION_EXTENSION;
#endif
	v850np_inst inst = {0};
	op->size = v850np_disasm (&inst, cpumodel, addr, buf, len);
	if (op->size < 2) {
		op->size = 2;
	}
	if (mask & R_ANAL_OP_MASK_ESIL) {
		r_strbuf_set (&op->esil, inst.esil);
	}
	if (inst.op) {
		op->type = inst.op->type;
		if (!memcmp (buf, "\x7f\x00", 2)) {
			op->type = R_ANAL_OP_TYPE_RET;
		}
	}
	switch (op->type) {
	case R_ANAL_OP_TYPE_JMP:
		op->jump = addr + inst.value;
		break;
	case R_ANAL_OP_TYPE_CJMP:
		op->jump = addr + inst.value;
		op->fail = addr + inst.size;
		break;
	case R_ANAL_OP_TYPE_CALL:
		op->jump = addr + inst.value;
		op->fail = addr + inst.size;
		break;
	}
	op->size = inst.size;
	if (mask & R_ANAL_OP_MASK_DISASM) {
		if (anal->config->syntax == R_ASM_SYNTAX_ATT) {
			op->mnemonic = r_str_replace (inst.text, " r", " %r", -1);
			op->mnemonic = r_str_replace (op->mnemonic, "(r", "(%r", -1);
		} else {
			op->mnemonic = inst.text;
		}
		return inst.size;
	}
	free (inst.text);
	return inst.size;
}

static char *get_reg_profile(RAnal *anal) {
	const char *p =
		"=PC	pc\n"
		"=SP	r3\n"
		"=SN	r1\n"
		"=ZF	z\n"
		"=A0	r1\n"
		"=A1	r5\n"
		"=A2	r6\n"
		"=A3	r7\n"
		"=A4	r8\n"
		"=SF	s\n"
		"=OF	ov\n"
		"=CF	cy\n"

		"gpr	r0	.32	?   0\n"
		"gpr	r1	.32	4   0\n"
		"gpr	r2	.32	8   0\n"
		"gpr	sp	.32	12  0\n"
		"gpr	r3	.32	12  0\n"
		"gpr	gp	.32	16  0\n"
		"gpr	r4	.32	16  0\n"
		"gpr	r5	.32	20  0\n"
		"gpr	tp	.32	20  0\n"
		"gpr	r6	.32	24  0\n"
		"gpr	r7	.32	28  0\n"
		"gpr	r8	.32	32  0\n"
		"gpr	r9	.32	36  0\n"
		"gpr	r10	.32	40  0\n"
		"gpr	r11	.32	44  0\n"
		"gpr	r12	.32	48  0\n"
		"gpr	r13	.32	52  0\n"
		"gpr	r14	.32	56  0\n"
		"gpr	r15	.32	60  0\n"
		"gpr	r16	.32	64  0\n"
		"gpr	r17	.32	68  0\n"
		"gpr	r18	.32	72  0\n"
		"gpr	r19	.32	76  0\n"
		"gpr	r20	.32	80  0\n"
		"gpr	r21	.32	84  0\n"
		"gpr	r22	.32	88  0\n"
		"gpr	r23	.32	92  0\n"
		"gpr	r24	.32	96  0\n"
		"gpr	r25	.32	100 0\n"
		"gpr	r26	.32	104 0\n"
		"gpr	r27	.32	108 0\n"
		"gpr	r28	.32	112 0\n"
		"gpr	r29	.32	116 0\n"
		"gpr	r30	.32	120 0\n"
		"gpr	ep	.32	120 0\n"
		"gpr	r31	.32	124 0\n"
		"gpr	lp	.32	124 0\n"
		"gpr	pc	.32	128 0\n"

		// 32bit [   RFU   ][NP EP ID SAT CY OV S Z]
		"gpr	psw .32 132 0\n" // program status word
		"gpr	npi  .1 132.16 0\n" // non maskerable interrupt (NMI)
		"gpr	epi  .1 132.17 0\n" // exception processing interrupt
		"gpr	id   .1 132.18 0\n" // :? should be id
		"gpr	sat  .1 132.19 0\n" // saturation detection
		"flg	cy  .1 132.28 0 carry\n" // carry or borrow
		"flg	ov  .1 132.29 0 overflow\n" // overflow
		"flg	s   .1 132.30 0 sign\n" // signed result
		"flg	z   .1 132.31 0 zero\n"; // zero result
	return strdup (p);
}

static RList *anal_preludes(RAnal *anal) {
#define KW(d,ds,m,ms) r_list_append (l, r_search_keyword_new((const ut8*)d,ds,(const ut8*)m, ms, NULL))
	RList *l = r_list_newf ((RListFree)r_search_keyword_free);
	KW ("\x80\x07", 2, "\xf0\xff", 2);
	KW ("\x50\x1a\x63\x0f", 4, "\xf0\xff\xff\x0f", 4);
	return l;
}

static int archinfo(RAnal *anal, int q) {
	switch (q) {
	case R_ANAL_ARCHINFO_ALIGN:
	case R_ANAL_ARCHINFO_DATA_ALIGN:
		return 2;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return 8;
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		return 2;
	}
	return 0;
}

static int v850_opasm(RAnal *anal, ut64 addr, const char *s, ut8 *buf, int len) {
	r_return_val_if_fail (anal && s && buf && len >= 0, -1);
	if (!strcmp (s, "nop")) {
		memset (buf, 0, R_MIN (len, 2));
		return 2;
	}
	return 0;
}

RAnalPlugin r_anal_plugin_v850_np = {
	.name = "v850.np",
	.desc = "V850 code analysis plugin",
	.license = "MIT",
	.preludes = anal_preludes,
	.cpus = "0,e,e1,e2,e2v3,e3v5,all",
	.arch = "v850",
	.bits = 32,
	.op = v850_op,
	.opasm = v850_opasm,
	.esil = true,
	.archinfo = archinfo,
	.get_reg_profile = get_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_v850_np,
	.version = R2_VERSION
};
#endif
