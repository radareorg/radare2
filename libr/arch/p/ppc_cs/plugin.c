/* radare2 - LGPL - Copyright 2013-2026 - pancake, phix33 */

#include <r_arch.h>
#include <r_esil.h>
#include <capstone/capstone.h>
#include <capstone/ppc.h>
#include "../ppc/libvle/vle.h"
#include "../ppc/libps/libps.h"

#define SPR_HID0 0x3f0 /* Hardware Implementation Register 0 */
#define SPR_HID1 0x3f1 /* Hardware Implementation Register 1 */
#define SPR_HID2 0x3f3 /* Hardware Implementation Register 2 */
#define SPR_HID4 0x3f4 /* Hardware Implementation Register 4 */
#define SPR_HID5 0x3f6 /* Hardware Implementation Register 5 */
#define SPR_HID6 0x3f9 /* Hardware Implementation Register 6 */

struct Getarg {
	csh handle;
	cs_insn *insn;
	int bits;
};

#define INSOPS insn->detail->ppc.op_count
#define INSOP(n) insn->detail->ppc.operands[n]
#define IMM(x) (ut64)(insn->detail->ppc.operands[x].imm)

#ifndef PFMT32x
#define PFMT32x "lx"
#endif

// * cs6 - compatibility *
#if CS_API_MAJOR < 6
#define BC() insn->detail->ppc.bc
#else
#define BC() insn->detail->ppc.bc.pred_cr

#define PPC_INS_CMP PPC_INS_ALIAS_CMP
#define PPC_INS_CMPI PPC_INS_ALIAS_CMPI
#define PPC_INS_CMPL PPC_INS_ALIAS_CMPL
#define PPC_INS_CMPLI PPC_INS_ALIAS_CMPLI
#define PPC_INS_MR PPC_INS_ALIAS_MR
#define PPC_INS_LI PPC_INS_ALIAS_LI
#define PPC_INS_LIS PPC_INS_ALIAS_LIS
#define PPC_INS_CLRLWI PPC_INS_ALIAS_CLRLWI
#define PPC_INS_LWSYNC PPC_INS_ALIAS_LWSYNC
#define PPC_INS_PTESYNC PPC_INS_ALIAS_PTESYNC
#define PPC_INS_SUB PPC_INS_ALIAS_SUB
#define PPC_INS_SUBC PPC_INS_ALIAS_SUBC
#define PPC_INS_CRCLR PPC_INS_ALIAS_CRCLR
#define PPC_INS_CRSET PPC_INS_ALIAS_CRSET
#define PPC_INS_CRMOVE PPC_INS_ALIAS_CRMOVE
#define PPC_INS_CRNOT PPC_INS_ALIAS_CRNOT
#define PPC_INS_BNE PPC_INS_ALIAS_BNE
#define PPC_INS_BNEA PPC_INS_ALIAS_BNEA
#define PPC_INS_BNECTR PPC_INS_ALIAS_BNECTR
#define PPC_INS_BNECTRL PPC_INS_ALIAS_BNECTRL
#define PPC_INS_BNEL PPC_INS_ALIAS_BNEL
#define PPC_INS_BNELA PPC_INS_ALIAS_BNELA
#define PPC_INS_BNELR PPC_INS_ALIAS_BNELR
#define PPC_INS_BNELRL PPC_INS_ALIAS_BNELRL
#define PPC_INS_BNG PPC_INS_ALIAS_BNG
#define PPC_INS_BNGA PPC_INS_ALIAS_BNGA
#define PPC_INS_BNGCTR PPC_INS_ALIAS_BNGCTR
#define PPC_INS_BNGCTRL PPC_INS_ALIAS_BNGCTRL
#define PPC_INS_BNGL PPC_INS_ALIAS_BNGL
#define PPC_INS_BNGLA PPC_INS_ALIAS_BNGLA
#define PPC_INS_BNGLR PPC_INS_ALIAS_BNGLR
#define PPC_INS_BNGLRL PPC_INS_ALIAS_BNGLRL
#define PPC_INS_BNL PPC_INS_ALIAS_BNL
#define PPC_INS_BNLA PPC_INS_ALIAS_BNLA
#define PPC_INS_BNLCTR PPC_INS_ALIAS_BNLCTR
#define PPC_INS_BNLCTRL PPC_INS_ALIAS_BNLCTRL
#define PPC_INS_BNLL PPC_INS_ALIAS_BNLL
#define PPC_INS_BNLLA PPC_INS_ALIAS_BNLLA
#define PPC_INS_BNLLR PPC_INS_ALIAS_BNLLR
#define PPC_INS_BNLLRL PPC_INS_ALIAS_BNLLRL
#define PPC_INS_BNS PPC_INS_ALIAS_BNS
#define PPC_INS_BNSA PPC_INS_ALIAS_BNSA
#define PPC_INS_BNSCTR PPC_INS_ALIAS_BNSCTR
#define PPC_INS_BNSCTRL PPC_INS_ALIAS_BNSCTRL
#define PPC_INS_BNSL PPC_INS_ALIAS_BNSL
#define PPC_INS_BNSLA PPC_INS_ALIAS_BNSLA
#define PPC_INS_BNSLR PPC_INS_ALIAS_BNSLR
#define PPC_INS_BNSLRL PPC_INS_ALIAS_BNSLRL
#define PPC_INS_BNU PPC_INS_ALIAS_BNU
#define PPC_INS_BNUA PPC_INS_ALIAS_BNUA
#define PPC_INS_BNUCTR PPC_INS_ALIAS_BNUCTR
#define PPC_INS_BNUCTRL PPC_INS_ALIAS_BNUCTRL
#define PPC_INS_BNUL PPC_INS_ALIAS_BNUL
#define PPC_INS_BNULA PPC_INS_ALIAS_BNULA
#define PPC_INS_BNULR PPC_INS_ALIAS_BNULR
#define PPC_INS_BNULR PPC_INS_ALIAS_BNULR
#define PPC_INS_BNULRL PPC_INS_ALIAS_BNULRL
#define PPC_INS_BEQ PPC_INS_ALIAS_BEQ
#define PPC_INS_BEQA PPC_INS_ALIAS_BEQA
#define PPC_INS_BEQCTR PPC_INS_ALIAS_BEQCTR
#define PPC_INS_BEQCTRL PPC_INS_ALIAS_BEQCTRL
#define PPC_INS_BEQL PPC_INS_ALIAS_BEQL
#define PPC_INS_BEQLA PPC_INS_ALIAS_BEQLA
#define PPC_INS_BEQLR PPC_INS_ALIAS_BEQLR
#define PPC_INS_BEQLRL PPC_INS_ALIAS_BEQLRL
#define PPC_INS_BGE PPC_INS_ALIAS_BGE
#define PPC_INS_BGEA PPC_INS_ALIAS_BGEA
#define PPC_INS_BGECTR PPC_INS_ALIAS_BGECTR
#define PPC_INS_BGECTRL PPC_INS_ALIAS_BGECTRL
#define PPC_INS_BGEL PPC_INS_ALIAS_BGEL
#define PPC_INS_BGELA PPC_INS_ALIAS_BGELA
#define PPC_INS_BGELR PPC_INS_ALIAS_BGELR
#define PPC_INS_BGELRL PPC_INS_ALIAS_BGELRL
#define PPC_INS_BGT PPC_INS_ALIAS_BGT
#define PPC_INS_BGTA PPC_INS_ALIAS_BGTA
#define PPC_INS_BGTCTR PPC_INS_ALIAS_BGTCTR
#define PPC_INS_BGTCTRL PPC_INS_ALIAS_BGTCTRL
#define PPC_INS_BGTL PPC_INS_ALIAS_BGTL
#define PPC_INS_BGTLA PPC_INS_ALIAS_BGTLA
#define PPC_INS_BGTLR PPC_INS_ALIAS_BGTLR
#define PPC_INS_BGTLRL PPC_INS_ALIAS_BGTLRL
#define PPC_INS_BLE PPC_INS_ALIAS_BLE
#define PPC_INS_BLEA PPC_INS_ALIAS_BLEA
#define PPC_INS_BLECTR PPC_INS_ALIAS_BLECTR
#define PPC_INS_BLECTRL PPC_INS_ALIAS_BLECTRL
#define PPC_INS_BLEL PPC_INS_ALIAS_BLEL
#define PPC_INS_BLELA PPC_INS_ALIAS_BLELA
#define PPC_INS_BLELR PPC_INS_ALIAS_BLELR
#define PPC_INS_BLELRL PPC_INS_ALIAS_BLELRL
#define PPC_INS_BLT PPC_INS_ALIAS_BLT
#define PPC_INS_BLTA PPC_INS_ALIAS_BLTA
#define PPC_INS_BLTCTR PPC_INS_ALIAS_BLTCTR
#define PPC_INS_BLTCTRL PPC_INS_ALIAS_BLTCTRL
#define PPC_INS_BLTL PPC_INS_ALIAS_BLTL
#define PPC_INS_BLTLA PPC_INS_ALIAS_BLTLA
#define PPC_INS_BLTLR PPC_INS_ALIAS_BLTLR
#define PPC_INS_BLTLRL PPC_INS_ALIAS_BLTLRL
#define PPC_INS_BSO PPC_INS_ALIAS_BSO
#define PPC_INS_BSOA PPC_INS_ALIAS_BSOA
#define PPC_INS_BSOCTR PPC_INS_ALIAS_BSOCTR
#define PPC_INS_BSOCTRL PPC_INS_ALIAS_BSOCTRL
#define PPC_INS_BSOL PPC_INS_ALIAS_BSOL
#define PPC_INS_BSOLA PPC_INS_ALIAS_BSOLA
#define PPC_INS_BSOLR PPC_INS_ALIAS_BSOLR
#define PPC_INS_BSOLRL PPC_INS_ALIAS_BSOLRL
#define PPC_INS_BUN PPC_INS_ALIAS_BUN
#define PPC_INS_BUNA PPC_INS_ALIAS_BUNA
#define PPC_INS_BUNCTR PPC_INS_ALIAS_BUNCTR
#define PPC_INS_BUNCTRL PPC_INS_ALIAS_BUNCTRL
#define PPC_INS_BUNL PPC_INS_ALIAS_BUNL
#define PPC_INS_BUNLA PPC_INS_ALIAS_BUNLA
#define PPC_INS_BUNLR PPC_INS_ALIAS_BUNLR
#define PPC_INS_BUNLRL PPC_INS_ALIAS_BUNLRL
#define PPC_INS_BT PPC_INS_ALIAS_BT
#define PPC_INS_BF PPC_INS_ALIAS_BF
#define PPC_INS_BDNZ PPC_INS_ALIAS_BDNZ
#define PPC_INS_BDNZA PPC_INS_ALIAS_BDNZA
#define PPC_INS_BDNZL PPC_INS_ALIAS_BDNZL
#define PPC_INS_BDNZLA PPC_INS_ALIAS_BDNZLA
#define PPC_INS_BDNZLR PPC_INS_ALIAS_BDNZLR
#define PPC_INS_BDZ PPC_INS_ALIAS_BDZ
#define PPC_INS_BDZA PPC_INS_ALIAS_BDZA
#define PPC_INS_BDZL PPC_INS_ALIAS_BDZL
#define PPC_INS_BDZLA PPC_INS_ALIAS_BDZLA
#define PPC_INS_BDZLR PPC_INS_ALIAS_BDZLR
#define PPC_INS_BDZLRL PPC_INS_ALIAS_BDZLRL
#define PPC_INS_BDZLRL PPC_INS_ALIAS_BDZLRL
#define PPC_INS_MFPVR PPC_INS_ALIAS_MFPVR
#define PPC_INS_MFDCCR PPC_INS_ALIAS_MFDCCR
#define PPC_INS_MFICCR PPC_INS_ALIAS_MFICCR
#define PPC_INS_MFDEAR PPC_INS_ALIAS_MFDEAR
#define PPC_INS_MTDCCR PPC_INS_ALIAS_MTDCCR
#define PPC_INS_MTICCR PPC_INS_ALIAS_MTICCR
#define PPC_INS_MTDEAR PPC_INS_ALIAS_MTDEAR
#define PPC_INS_CLRLDI PPC_INS_ALIAS_CLRLDI
#define PPC_INS_ROTLDI PPC_INS_ALIAS_ROTLDI
#define PPC_INS_ROTLW PPC_INS_ALIAS_ROTLW
#define PPC_INS_ROTLWI PPC_INS_ALIAS_ROTLWI
#define PPC_INS_ROTLD PPC_INS_ALIAS_ROTLD
#define PPC_INS_BDNZLRL PPC_INS_ALIAS_BDNZLRL

#define PPC_BC_LT PPC_PRED_LT
#define PPC_BC_LE PPC_PRED_LE
#define PPC_BC_EQ PPC_PRED_EQ
#define PPC_BC_GE PPC_PRED_GE
#define PPC_BC_GT PPC_PRED_GT
#define PPC_BC_NE PPC_PRED_NE
#define PPC_BC_INVALID PPC_PRED_INVALID
#define PPC_BC_NS PPC_PRED_NS
#define PPC_BC_SO PPC_PRED_SO
#endif
// ***********************

typedef struct plugin_data_t PluginData;
static const char* getspr(PluginData *pd, struct Getarg *gop, int n);
static char *getarg2(PluginData *pd, struct Getarg *gop, int n, const char *setstr);

static ut64 mask64(ut64 mb, ut64 me) {
	ut64 maskmb = UT64_MAX >> mb;
	ut64 maskme = UT64_MAX << (63 - me);
	return (mb <= me) ? maskmb & maskme : maskmb | maskme;
}

static ut32 mask32(ut32 mb, ut32 me) {
	ut32 maskmb = UT32_MAX >> mb;
	ut32 maskme = UT32_MAX << (31 - me);
	return (mb <= me) ? maskmb & maskme : maskmb | maskme;
}

#define cmaskbuf_SIZEOF 32
static const char* cmask64(char *cmaskbuf, const char *mb_c, const char *me_c) {
	ut64 mb = 0;
	ut64 me = 0;
	if (mb_c) {
		mb = strtol (mb_c, NULL, 16);
	}
	if (me_c) {
		me = strtol (me_c, NULL, 16);
	}
	snprintf (cmaskbuf, cmaskbuf_SIZEOF, "0x%"PFMT64x, mask64 (mb, me));
	return cmaskbuf;
}

static const char* cmask32(char *cmaskbuf, const char *mb_c, const char *me_c) {
	ut32 mb = mb_c? strtol (mb_c, NULL, 16): 0;
	ut32 me = me_c? strtol (me_c, NULL, 16): 0;
	snprintf (cmaskbuf, cmaskbuf_SIZEOF, "0x%"PFMT32x, mask32 (mb, me));
	return cmaskbuf;
}

static ut64 getarg(struct Getarg *gop, int n) {
	ut64 value = 0;
	cs_insn *insn = gop->insn;
	cs_ppc_op op;

	if (n < 0 || n >= 8) {
		return 0;
	}

	op = INSOP (n);
	switch (op.type) {
	case PPC_OP_INVALID:
		break;
	case PPC_OP_REG:
		value = op.reg;
		break;
	case PPC_OP_IMM:
		value = (ut64) op.imm;
		break;
	case PPC_OP_MEM:
		value = op.mem.disp + op.mem.base;
		break;
#if CS_API_MAJOR < 6
	case PPC_OP_CRX: // Condition Register field
		value = (ut64) op.imm;
		break;
#endif
	}
	return value;
}

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ka (pj, "operands");
	cs_ppc *x = &insn->detail->ppc;
	for (i = 0; i < x->op_count; i++) {
		cs_ppc_op *op = x->operands + i;
		pj_o (pj);
		switch (op->type) {
		case PPC_OP_REG:
			pj_ks (pj, "type", "reg");
			// rA==0 in indexed forms (e.g. lwbrx r0, 0, rB) is an invalid reg
			if (op->reg != PPC_REG_INVALID) {
				pj_ks (pj, "value", cs_reg_name (handle, op->reg));
			}
			break;
		case PPC_OP_IMM:
			pj_ks (pj, "type", "imm");
			pj_kN (pj, "value", op->imm);
			break;
		case PPC_OP_MEM:
			pj_ks (pj, "type", "mem");
			if (op->mem.base != PPC_REG_INVALID) {
				pj_ks (pj, "base", cs_reg_name (handle, op->mem.base));
			}
			pj_ki (pj, "disp", op->mem.disp);
			break;
		default:
			pj_ks (pj, "type", "invalid");
			break;
		}
		pj_end (pj); /* o operand */
	}
	pj_end (pj); /* a operands */
	pj_end (pj);

	r_strbuf_init (buf);
	r_strbuf_append (buf, pj_string (pj));
	pj_free (pj);
}

#define PPCSPR(n) getspr(pd, &gop, n)
#define ARG(n) getarg2(pd, &gop, n, "")
#define ARG2(n,m) getarg2(pd, &gop, n, m)

static char *regs(RArchSession *as) {
	if (as->config->bits == 32) {
		const char p[] =
			"=PC	pc\n"
			"=SP	r1\n"
			"=BP	r31\n"
			"=SR	srr1\n" // status register ??
			"=SN	r3\n" // also for ret
			"=R0	r3\n" // ret
			"=A0	r3\n" // also for ret
			"=A1	r4\n"
			"=A2	r5\n"
			"=A3	r6\n"
			"=A4	r7\n"
			"=A5	r8\n"
			"=A6	r6\n"
			"gpr	srr0   .32 0   0\n"
			"gpr	srr1   .32 4   0\n"
			"gpr	r0   .32 8   0\n"
			"gpr	r1   .32 12  0\n"
			"gpr	r2   .32 16  0\n"
			"gpr	r3   .32 20  0\n"
			"gpr	r4   .32 24  0\n"
			"gpr	r5   .32 28  0\n"
			"gpr	r6   .32 32  0\n"
			"gpr	r7   .32 36  0\n"
			"gpr	r8   .32 40  0\n"
			"gpr	r9   .32 44  0\n"
			"gpr	r10 .32 48  0\n"
			"gpr	r11 .32 52  0\n"
			"gpr	r12 .32 56  0\n"
			"gpr	r13 .32 60  0\n"
			"gpr	r14 .32 64  0\n"
			"gpr	r15 .32 68  0\n"
			"gpr	r16 .32 72  0\n"
			"gpr	r17 .32 76  0\n"
			"gpr	r18 .32 80  0\n"
			"gpr	r19 .32 84  0\n"
			"gpr	r20 .32 88  0\n"
			"gpr	r21 .32 92  0\n"
			"gpr	r22 .32 96  0\n"
			"gpr	r23 .32 100 0\n"
			"gpr	r24 .32 104 0\n"
			"gpr	r25 .32 108 0\n"
			"gpr	r26 .32 112 0\n"
			"gpr	r27 .32 116 0\n"
			"gpr	r28 .32 120 0\n"
			"gpr	r29 .32 124 0\n"
			"gpr	r30 .32 128 0\n"
			"gpr	r31 .32 132 0\n"
			"gpr	lr   .32 136 0\n"
			"gpr	ctr .32 140 0\n"
			"gpr	msr .32 144 0\n"
			"gpr	pc   .32 148 0\n"
			"gpr	cr  .64 152 0\n"
			"gpr	cr0 .8  152 0\n"
			"gpr	cr1 .8  153 0\n"
			"gpr	cr2 .8  154 0\n"
			"gpr	cr3 .8  155 0\n"
			"gpr	cr4 .8  156 0\n"
			"gpr	cr5 .8  157 0\n"
			"gpr	cr6 .8  158 0\n"
			"gpr	cr7 .8  159 0\n"
			"gpr	xer .32 160 0\n"
			"gpr	mq   .32 164 0\n"
			"gpr	fpscr  .32 168 0\n"
			"gpr	vrsave .32 172 0\n"
			"gpr	pvr .32 176 0\n"
			"gpr	dccr   .32 180 0\n"
			"gpr	iccr   .32 184 0\n"
			"gpr	dear   .32 188 0\n"
			"gpr	hid0   .32 192 0\n"
			"gpr	hid1   .32 196 0\n"
			"gpr	hid2   .32 200 0\n"
			"gpr	hid3   .32 204 0\n"
			"gpr	hid4   .32 208 0\n"
			"gpr	hid5   .32 212 0\n"
			"gpr	hid6   .32 216 0\n"
			"gpr	ibat0  .64 220 0\n"
			"gpr	ibat1  .64 228 0\n"
			"gpr	ibat2  .64 236 0\n"
			"gpr	ibat3  .64 244 0\n"
			"gpr	ibat0l .32 220 0\n"
			"gpr	ibat1l .32 228 0\n"
			"gpr	ibat2l .32 236 0\n"
			"gpr	ibat3l .32 244 0\n"
			"gpr	ibat0u .32 224 0\n"
			"gpr	ibat1u .32 232 0\n"
			"gpr	ibat2u .32 240 0\n"
			"gpr	ibat3u .32 248 0\n"
			"gpr	dbat0  .64 256 0\n"
			"gpr	dbat1  .64 264 0\n"
			"gpr	dbat2  .64 272 0\n"
			"gpr	dbat3  .64 280 0\n"
			"gpr	dbat0l .32 256 0\n"
			"gpr	dbat1l .32 264 0\n"
			"gpr	dbat2l .32 272 0\n"
			"gpr	dbat3l .32 280 0\n"
			"gpr	dbat0u .32 260 0\n"
			"gpr	dbat1u .32 268 0\n"
			"gpr	dbat2u .32 276 0\n"
			"gpr	dbat3u .32 284 0\n"
			"gpr	mask   .32 288 0\n"
			"fpu	f0  .64 292 0\n"
			"fpu	f1  .64 300 0\n"
			"fpu	f2  .64 308 0\n"
			"fpu	f3  .64 316 0\n"
			"fpu	f4  .64 324 0\n"
			"fpu	f5  .64 332 0\n"
			"fpu	f6  .64 340 0\n"
			"fpu	f7  .64 348 0\n"
			"fpu	f8  .64 356 0\n"
			"fpu	f9  .64 364 0\n"
			"fpu	f10 .64 372 0\n"
			"fpu	f11 .64 380 0\n"
			"fpu	f12 .64 388 0\n"
			"fpu	f13 .64 396 0\n"
			"fpu	f14 .64 404 0\n"
			"fpu	f15 .64 412 0\n"
			"fpu	f16 .64 420 0\n"
			"fpu	f17 .64 428 0\n"
			"fpu	f18 .64 436 0\n"
			"fpu	f19 .64 444 0\n"
			"fpu	f20 .64 452 0\n"
			"fpu	f21 .64 460 0\n"
			"fpu	f22 .64 468 0\n"
			"fpu	f23 .64 476 0\n"
			"fpu	f24 .64 484 0\n"
			"fpu	f25 .64 492 0\n"
			"fpu	f26 .64 500 0\n"
			"fpu	f27 .64 508 0\n"
			"fpu	f28 .64 516 0\n"
			"fpu	f29 .64 524 0\n"
			"fpu	f30 .64 532 0\n"
			"fpu	f31 .64 540 0\n"
			"gpr	ca .1 292 0\n";
		return strdup (p);
	}

	const char p[] =
		"=PC	pc\n"
		"=SP	r1\n"
		"=BP	r31\n"
		"=SR	srr1\n" // status register ??
		"=SN	r0\n" // also for ret
		"=R0	r3\n" // ret
		"=A0	r3\n" // also for ret
		"=A1	r4\n"
		"=A2	r5\n"
		"=A3	r6\n"
		"=A4	r7\n"
		"=A5	r8\n"
		"=A6	r6\n"
		"gpr	srr0   .64 0   0\n"
		"gpr	srr1   .64 8   0\n"
		"gpr	r0   .64 16  0\n"
		"gpr	r1   .64 24  0\n"
		"gpr	r2   .64 32  0\n"
		"gpr	r3   .64 40  0\n"
		"gpr	r4   .64 48  0\n"
		"gpr	r5   .64 56  0\n"
		"gpr	r6   .64 64  0\n"
		"gpr	r7   .64 72  0\n"
		"gpr	r8   .64 80  0\n"
		"gpr	r9   .64 88  0\n"
		"gpr	r10 .64 96  0\n"
		"gpr	r11 .64 104 0\n"
		"gpr	r12 .64 112 0\n"
		"gpr	r13 .64 120 0\n"
		"gpr	r14 .64 128 0\n"
		"gpr	r15 .64 136 0\n"
		"gpr	r16 .64 144 0\n"
		"gpr	r17 .64 152 0\n"
		"gpr	r18 .64 160 0\n"
		"gpr	r19 .64 168 0\n"
		"gpr	r20 .64 176 0\n"
		"gpr	r21 .64 184 0\n"
		"gpr	r22 .64 192 0\n"
		"gpr	r23 .64 200 0\n"
		"gpr	r24 .64 208 0\n"
		"gpr	r25 .64 216 0\n"
		"gpr	r26 .64 224 0\n"
		"gpr	r27 .64 232 0\n"
		"gpr	r28 .64 240 0\n"
		"gpr	r29 .64 248 0\n"
		"gpr	r30 .64 256 0\n"
		"gpr	r31 .64 264 0\n"
		"gpr	lr   .64 272 0\n"
		"gpr	ctr .64 280 0\n"
		"gpr	msr .64 288 0\n"
		"gpr	pc   .64 296 0\n"
		"gpr	cr  .64 304 0\n"
		"gpr	cr0 .8  304 0\n"
		"gpr	cr1 .8  305 0\n"
		"gpr	cr2 .8  306 0\n"
		"gpr	cr3 .8  307 0\n"
		"gpr	cr4 .8  308 0\n"
		"gpr	cr5 .8  309 0\n"
		"gpr	cr6 .8  310 0\n"
		"gpr	cr7 .8  311 0\n"
		"gpr	xer .64 312 0\n"
		"gpr	mq   .64 320 0\n"
		"gpr	fpscr  .64 328 0\n"
		"gpr	vrsave .64 336 0\n"
		"gpr	pvr .64 344 0\n"
		"gpr	dccr   .32 352 0\n"
		"gpr	iccr   .32 356 0\n"
		"gpr	dear   .32 360 0\n"
		"gpr	hid0   .64 364 0\n"
		"gpr	hid1   .64 372 0\n"
		"gpr	hid2   .64 380 0\n"
		"gpr	hid3   .64 388 0\n"
		"gpr	hid4   .64 396 0\n"
		"gpr	hid5   .64 404 0\n"
		"gpr	hid6   .64 412 0\n"
		"gpr	ibat0  .64 420 0\n"
		"gpr	ibat1  .64 428 0\n"
		"gpr	ibat2  .64 436 0\n"
		"gpr	ibat3  .64 444 0\n"
		"gpr	ibat0l .32 420 0\n"
		"gpr	ibat1l .32 428 0\n"
		"gpr	ibat2l .32 436 0\n"
		"gpr	ibat3l .32 444 0\n"
		"gpr	ibat0u .32 424 0\n"
		"gpr	ibat1u .32 432 0\n"
		"gpr	ibat2u .32 440 0\n"
		"gpr	ibat3u .32 448 0\n"
		"gpr	dbat0  .64 456 0\n"
		"gpr	dbat1  .64 464 0\n"
		"gpr	dbat2  .64 472 0\n"
		"gpr	dbat3  .64 480 0\n"
		"gpr	dbat0l .32 456 0\n"
		"gpr	dbat1l .32 464 0\n"
		"gpr	dbat2l .32 472 0\n"
		"gpr	dbat3l .32 480 0\n"
		"gpr	dbat0u .32 460 0\n"
		"gpr	dbat1u .32 468 0\n"
		"gpr	dbat2u .32 476 0\n"
		"gpr	dbat3u .32 484 0\n"
		"gpr	mask   .64 488 0\n" //not a real register used on complex functions
		"fpu	f0  .64 496 0\n"
		"fpu	f1  .64 504 0\n"
		"fpu	f2  .64 512 0\n"
		"fpu	f3  .64 520 0\n"
		"fpu	f4  .64 528 0\n"
		"fpu	f5  .64 536 0\n"
		"fpu	f6  .64 544 0\n"
		"fpu	f7  .64 552 0\n"
		"fpu	f8  .64 560 0\n"
		"fpu	f9  .64 568 0\n"
		"fpu	f10 .64 576 0\n"
		"fpu	f11 .64 584 0\n"
		"fpu	f12 .64 592 0\n"
		"fpu	f13 .64 600 0\n"
		"fpu	f14 .64 608 0\n"
		"fpu	f15 .64 616 0\n"
		"fpu	f16 .64 624 0\n"
		"fpu	f17 .64 632 0\n"
		"fpu	f18 .64 640 0\n"
		"fpu	f19 .64 648 0\n"
		"fpu	f20 .64 656 0\n"
		"fpu	f21 .64 664 0\n"
		"fpu	f22 .64 672 0\n"
		"fpu	f23 .64 680 0\n"
		"fpu	f24 .64 688 0\n"
		"fpu	f25 .64 696 0\n"
		"fpu	f26 .64 704 0\n"
		"fpu	f27 .64 712 0\n"
		"fpu	f28 .64 720 0\n"
		"fpu	f29 .64 728 0\n"
		"fpu	f30 .64 736 0\n"
		"fpu	f31 .64 744 0\n"
		"gpr	ca .1 496 0\n";
	return strdup (p);
}

static int analop_vle(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	vle_t* instr = NULL;
	vle_handle handle = {0};
	op->size = 2;
	if (len > 1 && !vle_init (&handle, buf, len) && (instr = vle_next (&handle))) {
		op->size = instr->size;
		op->type = instr->anal_op;
		//op->id = instr->type;

		switch (op->type) {
		case R_ANAL_OP_TYPE_ILL:
			break;
		case R_ANAL_OP_TYPE_ADD:
			break;
		case R_ANAL_OP_TYPE_AND:
			break;
		case R_ANAL_OP_TYPE_CALL:
			op->jump = addr + instr->fields[instr->n - 1].value;
			op->fail = addr + op->size;
			break;
		case R_ANAL_OP_TYPE_CCALL:
			op->eob = true;
			op->jump = addr + instr->fields[instr->n - 1].value;
			op->fail = addr + op->size;
			break;
		case R_ANAL_OP_TYPE_CJMP:
			op->cond = instr->cond; //R_ANAL_CONDTYPE_NE;
			op->eob = true;
			op->jump = addr + instr->fields[instr->n - 1].value;
			op->fail = addr + op->size;
			break;
		case R_ANAL_OP_TYPE_CMP:
			break;
		case R_ANAL_OP_TYPE_JMP:
			op->jump = addr + instr->fields[instr->n - 1].value;
			break;
		case R_ANAL_OP_TYPE_LOAD:
			break;
		case R_ANAL_OP_TYPE_MOV:
			break;
		case R_ANAL_OP_TYPE_MUL:
			break;
		case R_ANAL_OP_TYPE_NOT:
			break;
		case R_ANAL_OP_TYPE_OR:
			break;
		case R_ANAL_OP_TYPE_ROR:
			break;
		case R_ANAL_OP_TYPE_ROL:
			break;
		case R_ANAL_OP_TYPE_RCALL:
			op->eob = true;
			break;
		case R_ANAL_OP_TYPE_RET:
			op->eob = true;
			break;
		case R_ANAL_OP_TYPE_RJMP:
			break;
		case R_ANAL_OP_TYPE_SHL:
			break;
		case R_ANAL_OP_TYPE_SHR:
			break;
		case R_ANAL_OP_TYPE_STORE:
			break;
		case R_ANAL_OP_TYPE_SUB:
			break;
		case R_ANAL_OP_TYPE_SWI:
			break;
		case R_ANAL_OP_TYPE_SYNC:
			break;
		case R_ANAL_OP_TYPE_TRAP:
			break;
		case R_ANAL_OP_TYPE_XOR:
			break;
		default:
			// R_LOG_WARN ("Missing an R_ANAL_OP_TYPE (%"PFMT64u")", op->type);
			break;
		}
		vle_free (instr);
		return op->size;
	}
	return -1;
}

static const char *parse_reg_name(csh handle, cs_insn *insn, int reg_num) {
	switch (INSOP (reg_num).type) {
	case PPC_OP_REG:
		return cs_reg_name (handle, INSOP (reg_num).reg);
	case PPC_OP_MEM:
		if (INSOP (reg_num).mem.base != PPC_REG_INVALID) {
			return cs_reg_name (handle, INSOP (reg_num).mem.base);
		}
		break;
	default:
		break;
	}
	return NULL;
}

static void create_src_dst(RAnalOp *op) {
	R_UNUSED RArchValue *_ = NULL;
	_ = RVecRArchValue_emplace_back (&op->srcs);
	_ = RVecRArchValue_emplace_back (&op->srcs);
	_ = RVecRArchValue_emplace_back (&op->srcs);
	_ = RVecRArchValue_emplace_back (&op->dsts);
}

static void set_src_dst(RAnalValue *val, csh *handle, cs_insn *insn, int x) {
	cs_ppc_op ppcop = INSOP (x);
	val->reg = parse_reg_name (*handle, insn, x);
	switch (ppcop.type) {
	case PPC_OP_REG:
		break;
	case PPC_OP_MEM:
		val->delta = ppcop.mem.disp;
		break;
	case PPC_OP_IMM:
		val->imm = ppcop.imm;
		break;
	default:
		break;
	}
}

static void op_fillval(RAnalOp *op, csh handle, cs_insn *insn) {
	create_src_dst (op);
	RAnalValue *src0 = RVecRArchValue_at (&op->srcs, 0);
	RAnalValue *src1 = RVecRArchValue_at (&op->srcs, 1);
	RAnalValue *src2 = RVecRArchValue_at (&op->srcs, 2);
	RAnalValue *dst = RVecRArchValue_at (&op->dsts, 0);
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_CMP:
	case R_ANAL_OP_TYPE_ADD:
	case R_ANAL_OP_TYPE_SUB:
	case R_ANAL_OP_TYPE_MUL:
	case R_ANAL_OP_TYPE_DIV:
	case R_ANAL_OP_TYPE_SHR:
	case R_ANAL_OP_TYPE_SHL:
	case R_ANAL_OP_TYPE_SAL:
	case R_ANAL_OP_TYPE_SAR:
	case R_ANAL_OP_TYPE_OR:
	case R_ANAL_OP_TYPE_AND:
	case R_ANAL_OP_TYPE_XOR:
	case R_ANAL_OP_TYPE_NOR:
	case R_ANAL_OP_TYPE_NOT:
	case R_ANAL_OP_TYPE_LOAD:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_ROR:
	case R_ANAL_OP_TYPE_ROL:
	case R_ANAL_OP_TYPE_CAST:
		set_src_dst (src2, &handle, insn, 3);
		set_src_dst (src1, &handle, insn, 2);
		set_src_dst (src0, &handle, insn, 1);
		set_src_dst (dst, &handle, insn, 0);
		break;
	case R_ANAL_OP_TYPE_STORE:
		set_src_dst (dst, &handle, insn, 1);
		set_src_dst (src0, &handle, insn, 0);
		break;
	}
}

static char *shrink(char *op) {
	if (!op) {
		return NULL;
	}
	size_t len = strlen(op);
	if (!len) {
		return NULL;
	}
	op[len - 1] = 0;
	return op;
}

#undef PPC
#define CSINC PPC
#if 0
#define CSINC_MODE \
	((as->config->bits == 64) ? CS_MODE_64 : (as->config->bits == 32) ? CS_MODE_32 : 0) \
	| (R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config)? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN)
#else
#define CSINC_MODE \
	((as->config->bits == 64) ? CS_MODE_64 : (as->config->bits == 32) ? CS_MODE_32 : 0)
#endif
#include "../capstone.inc.c"

typedef struct plugin_data_t {
	CapstonePluginData cpd;
	char cspr[16];
	char words[8][64];
	// PPC64 ELFv1 TOC base per GPR: addis rX,r2,HA stores gp+(HA<<16); a later ld/addi/st rY,LO(rX) resolves op->ptr/val (0 = no pending value)
	ut64 toc_map[32];
} PluginData;

/* Map a capstone PPC register ID to a GPR index 0..31, or -1 for non-GPRs. */
static inline int toc_reg_idx(unsigned int cs_reg) {
	int idx = (int)cs_reg - (int)PPC_REG_R0;
	return (idx >= 0 && idx < 32) ? idx : -1;
}

static void set_toc_ptr(RAnalOp *op, PluginData *pd, cs_insn *insn, bool stateful) {
	if (stateful && INSOP (1).type == PPC_OP_MEM) {
		int ridx = toc_reg_idx (INSOP (1).mem.base);
		if (ridx >= 0 && pd->toc_map[ridx]) {
			op->ptr = pd->toc_map[ridx] + INSOP (1).mem.disp;
		}
	}
}

static void set_toc_val(RAnalOp *op, PluginData *pd, cs_insn *insn, bool stateful) {
	if (stateful && INSOP (1).type == PPC_OP_REG && INSOP (2).type == PPC_OP_IMM) {
		int ridx = toc_reg_idx (INSOP (1).reg);
		if (ridx >= 0 && pd->toc_map[ridx]) {
			op->val = pd->toc_map[ridx] + (ut64)(st64)INSOP (2).imm;
		}
	}
}

// Update-form ld/st writes the EA back into the base register; op0 keying misses it and capstone has no writeback flag
static int toc_update_form_base(cs_insn *insn) {
	switch (insn->id) {
	case PPC_INS_LBZU: case PPC_INS_LBZUX: case PPC_INS_LHZU: case PPC_INS_LHZUX:
	case PPC_INS_LHAU: case PPC_INS_LHAUX: case PPC_INS_LWZU: case PPC_INS_LWZUX:
	case PPC_INS_LWAUX: case PPC_INS_LDU: case PPC_INS_LDUX: case PPC_INS_LFSU:
	case PPC_INS_LFSUX: case PPC_INS_LFDU: case PPC_INS_LFDUX: case PPC_INS_STBU:
	case PPC_INS_STBUX: case PPC_INS_STHU: case PPC_INS_STHUX: case PPC_INS_STWU:
	case PPC_INS_STWUX: case PPC_INS_STDU: case PPC_INS_STDUX: case PPC_INS_STFSU:
	case PPC_INS_STFSUX: case PPC_INS_STFDU: case PPC_INS_STFDUX:
		break;
	default:
		return -1;
	}
	cs_ppc_op *base = &INSOP (1);
	if (base->type == PPC_OP_MEM) {
		return toc_reg_idx (base->mem.base);
	}
	return (base->type == PPC_OP_REG)? toc_reg_idx (base->reg): -1;
}

// A write into r2 drops every derived entry, any other GPR only its own
static void toc_clobber(PluginData *pd, int ridx) {
	if (ridx == 2) {
		memset (pd->toc_map, 0, sizeof (pd->toc_map));
	} else if (ridx >= 0) {
		pd->toc_map[ridx] = 0;
	}
}

// Invalidate toc_map entries made stale by a return, a call, or a write to the holding/r2 base
static void toc_invalidate(PluginData *pd, RAnalOp *op, cs_insn *insn) {
	if (op->type == R_ANAL_OP_TYPE_RET || op->type == R_ANAL_OP_TYPE_CRET) {
		memset (pd->toc_map, 0, sizeof (pd->toc_map));
		return;
	}
	if (op->type == R_ANAL_OP_TYPE_CALL) {
		int i;
		pd->toc_map[0] = 0; // r0, r3..r12 are caller-saved across a call
		for (i = 3; i <= 12; i++) {
			pd->toc_map[i] = 0;
		}
		return;
	}
	toc_clobber (pd, toc_update_form_base (insn));
	// addis owns its entry; PPC capstone lacks cs_regs_access so infer the written GPR from op0
	if (insn->id == PPC_INS_ADDIS || INSOP (0).type != PPC_OP_REG) {
		return;
	}
	switch (op->type & R_ANAL_OP_TYPE_MASK & ~R_ANAL_OP_TYPE_COND) {
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_LOAD:
	case R_ANAL_OP_TYPE_ADD:
	case R_ANAL_OP_TYPE_SUB:
	case R_ANAL_OP_TYPE_MUL:
	case R_ANAL_OP_TYPE_DIV:
	case R_ANAL_OP_TYPE_MOD:
	case R_ANAL_OP_TYPE_AND:
	case R_ANAL_OP_TYPE_OR:
	case R_ANAL_OP_TYPE_XOR:
	case R_ANAL_OP_TYPE_SHL:
	case R_ANAL_OP_TYPE_SHR:
	case R_ANAL_OP_TYPE_SAR:
	case R_ANAL_OP_TYPE_ROL:
	case R_ANAL_OP_TYPE_ROR:
	case R_ANAL_OP_TYPE_NOT:
	case R_ANAL_OP_TYPE_CPL:
		toc_clobber (pd, toc_reg_idx (INSOP (0).reg));
		break;
	}
}

// algebraic shift right: ca = sign(rs) & (low bits shifted out != 0); set ca before rd to stay alias-safe
static void set_sra(RAnalOp *op, const char *rd, const char *rs, const char *cnt, bool w64, const char *mask) {
	const char *sgn = w64? "0x8000000000000000": "0x80000000";
	const char *lo = w64? "0xffffffffffffffff": "0xffffffff";
	esilprintf (op, "%s,%s,&,!,!,%s,%s,&,%s,&,!,!,&,ca,=,%s,%s,ASR,%s,=",
		sgn, rs, mask, rs, lo, cnt, rs, rd);
}

// ca = (val <unsigned a) | (cin & val==a), then store val into rd LAST so the carry stays
// correct when rd aliases ra. wm masks val to the register width; sub uses ~ra (subf forms).
static void set_ca(RAnalOp *op, const char *ra, const char *wm, bool sub, const char *rd, const char *cin, const char *val) {
	const char *sb = "0x8000000000000000"; // sign bit for the unsigned-< sign flip
	char abuf[80], v[128];
	const char *a = ra;
	if (sub) {
		snprintf (abuf, sizeof (abuf), "%s,%s,^", ra, wm);
		a = abuf;
	}
	snprintf (v, sizeof (v), "%s,%s,&", val, wm);
	if (!strcmp (cin, "0")) {
		esilprintf (op, "%s,%s,^,%s,%s,^,<,%s,%s,=,ca,=", sb, a, sb, v, val, rd);
	} else {
		esilprintf (op, "%s,%s,^,%s,%s,^,<,%s,%s,%s,-,!,&,|,%s,%s,=,ca,=",
			sb, a, sb, v, cin, a, v, val, rd);
	}
}

static const char* getspr(PluginData *pd, struct Getarg *gop, int n) {
	if (n < 0 || n >= 8) {
		return NULL;
	}
	const ut32 spr = getarg (gop, n);
	switch (spr) {
	case SPR_HID0:
		return "hid0";
	case SPR_HID1:
		return "hid1";
	case SPR_HID2:
		return "hid2";
	case SPR_HID4:
		return "hid4";
	case SPR_HID5:
		return "hid5";
	case SPR_HID6:
		return "hid6";
	default:
		snprintf (pd->cspr, sizeof (pd->cspr), "spr_%u", spr);
		break;
	}
	return pd->cspr;
}

static char *getarg2(PluginData *pd, struct Getarg *gop, int n, const char *setstr) {
	cs_insn *insn = gop->insn;
	csh handle = gop->handle;
	cs_ppc_op op;

	if (n < 0 || n >= 8) {
		return NULL;
	}
	op = INSOP (n);
	switch (op.type) {
	case PPC_OP_INVALID:
		pd->words[n][0] = '\0';
		//strcpy (pd->words[n], "invalid");
		break;
	case PPC_OP_REG:
		snprintf (pd->words[n], sizeof (pd->words[n]),
				"%s%s", cs_reg_name (handle, op.reg), setstr);
		break;
	case PPC_OP_IMM:
		snprintf (pd->words[n], sizeof (pd->words[n]),
				"0x%"PFMT64x"%s", (ut64) op.imm, setstr);
		break;
	case PPC_OP_MEM:
		snprintf (pd->words[n], sizeof (pd->words[n]),
				"%"PFMT64d",%s,+,%s",
				(ut64) op.mem.disp,
				cs_reg_name (handle, op.mem.base), setstr);
		break;
#if CS_API_MAJOR < 6
	case PPC_OP_CRX: // Condition Register field
		snprintf (pd->words[n], sizeof (pd->words[n]),
				"%"PFMT64d"%s", (ut64) op.imm, setstr);
		break;
#endif
	}
	return pd->words[n];
}

// Decode an isel CR-bit operand (named "cr<N><suffix>") into profile reg "crN"
// and a condition 0=lt 1=gt 2=eq (-1 = unparseable or unmodelled so/un bit).
static int ppc_isel_crbit(struct Getarg *gop, int n, char *regbuf, size_t sz) {
	cs_ppc_op op = gop->insn->detail->ppc.operands[n];
	if (op.type != PPC_OP_REG) {
		return -1;
	}
	const char *name = cs_reg_name (gop->handle, op.reg);
	if (!name || strncmp (name, "cr", 2) || name[2] < '0' || name[2] > '7') {
		return -1;
	}
	const char *suf = name + 3;
	snprintf (regbuf, sz, "cr%c", name[2]);
	return !strcmp (suf, "lt") ? 0
		: !strcmp (suf, "gt") ? 1
		: !strcmp (suf, "eq") ? 2 : -1;
}

// Byte-reverse load/store ESIL for `nbytes` (2/4/8) at the indexed (rA|0)+rB
// address, built per-byte so it is endianness-independent (ESIL has no bswap).
static void ppc_esil_brx(RAnalOp *op, PluginData *pd, struct Getarg *gop, int nbytes, bool store) {
	cs_insn *insn = gop->insn;
	const char *reg = getarg2 (pd, gop, 0, "");
	const char *rb = getarg2 (pd, gop, 2, "");
	char ea[32];
	// rA==0 in indexed forms (e.g. lwbrx r0, 0, rB) is an invalid reg
	if (INSOP (1).type == PPC_OP_REG && INSOP (1).reg != PPC_REG_INVALID) {
		snprintf (ea, sizeof (ea), "%s,%s,+", getarg2 (pd, gop, 1, ""), rb);
	} else {
		snprintf (ea, sizeof (ea), "%s", rb);
	}
	RStrBuf *sb = r_strbuf_new ("");
	int i;
	if (store) {
		r_strbuf_appendf (sb, "0xff,%s,&,%s,=[1]", reg, ea);
		for (i = 1; i < nbytes; i++) {
			r_strbuf_appendf (sb, ",%d,%s,>>,0xff,&,%d,%s,+,=[1]", i * 8, reg, i, ea);
		}
	} else {
		r_strbuf_appendf (sb, "%s,[1]", ea);
		for (i = 1; i < nbytes; i++) {
			r_strbuf_appendf (sb, ",%d,%d,%s,+,[1],<<,|", i * 8, i, ea);
		}
		r_strbuf_appendf (sb, ",%s,=", reg);
	}
	esilprintf (op, "%s", r_strbuf_get (sb));
	r_strbuf_free (sb);
}

static char *ppc_idx_ea(PluginData *pd, struct Getarg *gop, char *buf, size_t sz) {
	cs_insn *insn = gop->insn;
	const char *rb = getarg2 (pd, gop, 2, "");
	if (INSOP (1).type == PPC_OP_REG && INSOP (1).reg != PPC_REG_INVALID) {
		snprintf (buf, sz, "%s,%s,+", getarg2 (pd, gop, 1, ""), rb);
	} else {
		snprintf (buf, sz, "%s", rb);
	}
	return buf;
}

// signbits != 0 sign-extends the load (algebraic forms)
static void ppc_ldbody(char *load, size_t sz, const char *ea, int width, int signbits) {
	if (signbits) {
		snprintf (load, sz, "%d,%s,[%d],~", signbits, ea, width);
	} else {
		snprintf (load, sz, "%s,[%d]", ea, width);
	}
}

static void ppc_esil_ldx(RAnalOp *op, PluginData *pd, struct Getarg *gop, int width, bool update, int signbits) {
	char ea[64], load[96];
	ppc_idx_ea (pd, gop, ea, sizeof (ea));
	const char *rd = getarg2 (pd, gop, 0, "");
	ppc_ldbody (load, sizeof (load), ea, width, signbits);
	if (update) {
		esilprintf (op, "%s,%s,=,%s,%s,=", load, rd, ea, getarg2 (pd, gop, 1, ""));
	} else {
		esilprintf (op, "%s,%s,=", load, rd);
	}
}

// D-form load; update writes back rA via ea+=
static void ppc_esil_ld(RAnalOp *op, const char *ea, const char *rd, int width, bool update, int signbits) {
	char load[96];
	ppc_ldbody (load, sizeof (load), ea, width, signbits);
	if (update) {
		esilprintf (op, "%s,%s,=,%s=", load, rd, ea);
	} else {
		esilprintf (op, "%s,%s,=", load, rd);
	}
}

static void ppc_esil_stx(RAnalOp *op, PluginData *pd, struct Getarg *gop, int width, bool update) {
	char ea[64];
	ppc_idx_ea (pd, gop, ea, sizeof (ea));
	const char *rs = getarg2 (pd, gop, 0, "");
	if (update) {
		esilprintf (op, "%s,%s,=[%d],%s,%s,=", rs, ea, width, ea, getarg2 (pd, gop, 1, ""));
	} else {
		esilprintf (op, "%s,%s,=[%d]", rs, ea, width);
	}
}

// 32-bit rotate by hand (ESIL ROL is 64-bit); wrapping mask (MB>ME) also fills bits 32:63
static void ppc_esil_rlwnm(RAnalOp *op, PluginData *pd, struct Getarg *gop, const char *mask, bool wrap) {
	const char *sh = getarg2 (pd, gop, 2, "");
	const char *rs = getarg2 (pd, gop, 1, "");
	const char *rd = getarg2 (pd, gop, 0, "");
	char rot[128];
	snprintf (rot, sizeof (rot), "%s,0x1f,&,%s,<<,%s,0x1f,&,32,-,%s,0xffffffff,&,>>,|,0xffffffff,&",
		sh, rs, sh, rs);
	if (wrap) {
		esilprintf (op, "%s,%s,&,32,%s,<<,|,%s,=", rot, mask, rot, rd);
	} else {
		esilprintf (op, "%s,%s,&,%s,=", rot, mask, rd);
	}
}

static void ppc_fpop(RAnalOp *op, PluginData *pd, struct Getarg *gop, bool single, int nsrc, const char *fop) {
	char body[96];
	switch (nsrc) {
	case 3:
		snprintf (body, sizeof (body), "%s,%s,%s,%s",
			getarg2 (pd, gop, 3, ""), getarg2 (pd, gop, 2, ""), getarg2 (pd, gop, 1, ""), fop);
		break;
	case 2:
		snprintf (body, sizeof (body), "%s,%s,%s",
			getarg2 (pd, gop, 2, ""), getarg2 (pd, gop, 1, ""), fop);
		break;
	default:
		snprintf (body, sizeof (body), "%s,%s", getarg2 (pd, gop, 1, ""), fop);
		break;
	}
	const char *dst = getarg2 (pd, gop, 0, "");
	if (single) {
		esilprintf (op, "32,DUP,%s,D2F,F2D,%s,=", body, dst);
	} else {
		esilprintf (op, "%s,%s,=", body, dst);
	}
}

// predicate-guarded pc write shared by bc, b<cond>lr and b<cond>ctr forms
static void ppc_cond_branch(RAnalOp *op, int bc, const char *cr, const char *target) {
	switch (bc) {
	case PPC_BC_LT:
		esilprintf (op, "0x80,%s,&,!,!,?{,%s,pc,=,},", cr, target);
		break;
	case PPC_BC_LE:
		esilprintf (op, "0x80,%s,&,!,!,%s,!,|,?{,%s,pc,=,},", cr, cr, target);
		break;
	case PPC_BC_EQ:
		esilprintf (op, "%s,!,?{,%s,pc,=,},", cr, target);
		break;
	case PPC_BC_GE:
		esilprintf (op, "0x80,%s,&,!,%s,!,|,?{,%s,pc,=,},", cr, cr, target);
		break;
	case PPC_BC_GT:
		esilprintf (op, "0x80,%s,&,!,%s,!,!,&,?{,%s,pc,=,},", cr, cr, target);
		break;
	case PPC_BC_NE:
		esilprintf (op, "%s,!,!,?{,%s,pc,=,},", cr, target);
		break;
	default:
		break;
	}
}

static int decompile_vle(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	vle_t* instr = 0;
	vle_handle handle = {0};
	if (len < 2) {
		return -1;
	}
	if (!vle_init (&handle, buf, len) && (instr = vle_next (&handle))) {
		op->size = instr->size;
		char buf_asm[64];
		vle_snprint (buf_asm, sizeof (buf_asm), addr, instr);
		op->mnemonic = strdup (buf_asm);
		vle_free (instr);
	} else {
		op->mnemonic = strdup ("invalid");
		op->size = 2;
		return -1;
	}
	return op->size;
}

static int decompile_ps(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	ppcps_t instr = {0};
	if (len < 4) {
		eprintf ("not eno\n");
		return -1;
	}
	op->size = 4;
	const ut32 data = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
	if (libps_decode (data, &instr) < 1) {
		return -1;
	}
	char buf_asm[64] = {0};
	libps_snprint (buf_asm, sizeof (buf_asm), addr, &instr);
	op->mnemonic = strdup (buf_asm);
	// eprintf ("Mnemonic (%s)\n", buf_asm);
	return op->size;
}

static csh cs_handle_for_session(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, 0);
	CapstonePluginData *pd = as->data;
	return pd->cs_handle;
}

static void swap4(ut8 *buf) {
	ut8 swap = buf[0];
	buf[0] = buf[3];
	buf[3] = swap;
	swap = buf[1];
	buf[1] = buf[2];
	buf[2] = swap;
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut64 addr = op->addr;
	ut8 *buf = op->bytes;
	const int len = op->size;
	char cmaskbuf[cmaskbuf_SIZEOF] = {0};
	csh handle = cs_handle_for_session (as);
	if (handle == 0 || len < 4) {
		return false;
	}

	int ret, ridx;
	char *op1;
	char ea[64];
	char vbuf[96];

	PluginData *pd = as->data;
	const bool stateful = mask & R_ARCH_OP_MASK_STATEFUL;
	const char *cpu = as->config->cpu;
	const char *cm = (as->config->bits == 32)? "0xffffffff": "0xffffffffffffffff";
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config);
	ut8 csbuf[4];
	memcpy (csbuf, buf, 4);
	if (be) {
		swap4 (csbuf);
	}
	// capstone-next
	RArchCSInsn csi;
	bool ok = r_arch_cs_disasm_iter (handle, csbuf, len, addr, &csi);
	cs_insn *insn = &csi.insn;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		ret = -1;
		if (cpu && !strcmp (cpu, "vle")) {
			if (!be) {
				return false;
			}
			// vle is big-endian only
			ret = decompile_vle (as, op, addr, buf, len);
		} else if (cpu && !strcmp (cpu, "ps")) {
			// libps is big-endian only
			if (!be) {
				return false;
			}
			ret = decompile_ps (as, op, addr, buf, len);
		}
		if (ret < 1) {
			if (ok) {
				op->mnemonic = r_str_newf ("%s%s%s",
					insn->mnemonic,
					insn->op_str[0]? " ": "",
					insn->op_str);
			} else {
				op->mnemonic = strdup ("invalid");
			}
		}
	}
	if (cpu && !strcmp (cpu, "vle")) {
		// vle is big-endian only
		if (!be) {
			return false;
		}
		ret = analop_vle (as, op, addr, buf, len);
		if (ret >= 0) {
			return op->size > 0;
		}
	}

	op->size = 4;

	if (!ok) {
		op->type = R_ANAL_OP_TYPE_ILL;
	} else {
		if (mask & R_ARCH_OP_MASK_OPEX) {
			opex (&op->opex, handle, insn);
		}
		struct Getarg gop = {
			.handle = handle,
			.insn = insn,
			.bits = as->config->bits
		};
		op->size = insn->size;
		op->id = insn->id;
		switch (insn->id) {
		case PPC_INS_CMPB:
			// per-byte equality mask into a gpr, not a cr compare; not modeled in esil
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		case PPC_INS_CMPD:
		case PPC_INS_CMPDI:
		case PPC_INS_CMPLD:
		case PPC_INS_CMPLDI:
		case PPC_INS_CMPLW:
		case PPC_INS_CMPLWI:
		case PPC_INS_CMPW:
		case PPC_INS_CMPWI:
#if CS_API_MAJOR > 4
		case PPC_INS_CMP:
		case PPC_INS_CMPI:
		case PPC_INS_CMPL:
		case PPC_INS_CMPLI:
#endif
		{
			bool usig = false, word = false;
			switch (insn->id) {
			case PPC_INS_CMPLW:
			case PPC_INS_CMPLWI:
				usig = true;
				// fallthrough
			case PPC_INS_CMPW:
			case PPC_INS_CMPWI:
				word = true;
				break;
			case PPC_INS_CMPLD:
			case PPC_INS_CMPLDI:
				usig = true;
				break;
#if CS_API_MAJOR > 4
			case PPC_INS_CMPL:
			case PPC_INS_CMPLI:
				usig = true;
				// fallthrough
			case PPC_INS_CMP:
			case PPC_INS_CMPI:
				word = as->config->bits == 32;
				break;
#endif
			}
			op->type = R_ANAL_OP_TYPE_CMP;
			op->sign = !usig;
			const bool impcr = ARG (2)[0] == '\0';
			const char *cr = impcr? "cr0": ARG (0);
			const char *a = impcr? ARG (0): ARG (1);
			const char *b = impcr? ARG (1): ARG (2);
			char wa[96], wb[96];
			if (word && usig) {
				// zero-extended low words are positive in the 64-bit signed esil <, so it orders them unsigned
				snprintf (wa, sizeof (wa), "0xffffffff,%s,&", a);
				snprintf (wb, sizeof (wb), "0xffffffff,%s,&", b);
			} else if (word) {
				snprintf (wa, sizeof (wa), "32,%s,~", a);
				snprintf (wb, sizeof (wb), "32,%s,~", b);
			} else if (usig) {
				snprintf (wa, sizeof (wa), "0x8000000000000000,%s,^", a);
				snprintf (wb, sizeof (wb), "0x8000000000000000,%s,^", b);
			} else {
				r_str_ncpy (wa, a, sizeof (wa));
				r_str_ncpy (wb, b, sizeof (wb));
			}
			// lossless flag byte like fcmpu: lt 0x80, gt 1, eq 0
			esilprintf (op, "0x80,%s,%s,<,*,%s,%s,<,+,%s,=", wb, wa, wa, wb, cr);
			break;
		}
		case PPC_INS_MFLR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "lr,%s,=", ARG (0));
			break;
		case PPC_INS_MTLR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,lr,=", ARG (0));
			break;
		case PPC_INS_MR:
			op->type = R_ANAL_OP_TYPE_RMOV;
			esilprintf (op, "%s,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_ISEL: {
			// isel rD, rA, rB, crb -> rD = CR[crb] ? (rA|0) : rB
			// unmodelled so/un bits decode to cond < 0: keep the type, emit no ESIL
			op->type = R_ANAL_OP_TYPE_CMOV;
			char crbuf[8];
			int cond = ppc_isel_crbit (&gop, 3, crbuf, sizeof (crbuf));
			if (cond < 0) {
				break;
			}
			const char *src = (INSOP (1).type == PPC_OP_REG
				&& INSOP (1).reg != PPC_REG_INVALID) ? ARG (1) : "0";
			const char *rb = ARG (2);
			const char *dst = ARG (0);
			switch (cond) {
			case 2:
				esilprintf (op, "%s,!,?{,%s,}{,%s,},%s,=", crbuf, src, rb, dst);
				break;
			case 0:
				esilprintf (op, "0x80,%s,&,!,!,?{,%s,}{,%s,},%s,=", crbuf, src, rb, dst);
				break;
			case 1:
				esilprintf (op, "0x80,%s,&,!,%s,!,!,&,?{,%s,}{,%s,},%s,=",
					crbuf, crbuf, src, rb, dst);
				break;
			}
			break;
		}
		case PPC_INS_LI:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_LIS:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s0000,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_CLRLWI:
			op->type = R_ANAL_OP_TYPE_AND;
			esilprintf (op, "%s,%s,&,%s,=", ARG (1), cmask32 (cmaskbuf, ARG (2), "0x1F"), ARG (0));
			break;
		case PPC_INS_RLWINM:
			op->type = R_ANAL_OP_TYPE_ROL;
			ppc_esil_rlwnm (op, pd, &gop, cmask32 (cmaskbuf, ARG (3), ARG (4)), getarg (&gop, 3) > getarg (&gop, 4));
			break;
		case PPC_INS_SC:
			op->type = R_ANAL_OP_TYPE_SWI;
			esilprintf (op, "0,$");
			break;
		case PPC_INS_EXTSB:
			op->sign = true;
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "8,%s,~,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_EXTSH:
			op->sign = true;
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "16,%s,~,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_EXTSW:
			op->sign = true;
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "32,%s,~,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_SYNC:
		case PPC_INS_ISYNC:
		case PPC_INS_LWSYNC:
#if CS_API_MAJOR < 6
		case PPC_INS_MSYNC:
#endif
		case PPC_INS_PTESYNC:
		case PPC_INS_TLBSYNC:
		case PPC_INS_SLBIA:
		case PPC_INS_SLBIE:
		case PPC_INS_SLBMFEE:
		case PPC_INS_SLBMTE:
		case PPC_INS_EIEIO:
		case PPC_INS_NOP:
			op->type = R_ANAL_OP_TYPE_NOP;
			esilprintf (op, ",");
			break;
		case PPC_INS_STW:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[4]"));
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_STWU:
			op->type = R_ANAL_OP_TYPE_STORE;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf (op, "%s,%s,=[4],%s=", ARG (0), op1, op1);
			if (INSOP (1).type == PPC_OP_MEM && INSOP (1).mem.base == PPC_REG_R1) {
				op->stackop = R_ANAL_STACK_INC;
				op->stackptr = -INSOP (1).mem.disp;
			}
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_STHBRX:
			op->type = R_ANAL_OP_TYPE_STORE;
			ppc_esil_brx (op, pd, &gop, 2, true);
			break;
		case PPC_INS_STWBRX:
			op->type = R_ANAL_OP_TYPE_STORE;
			ppc_esil_brx (op, pd, &gop, 4, true);
			break;
		case PPC_INS_STDBRX:
			op->type = R_ANAL_OP_TYPE_STORE;
			ppc_esil_brx (op, pd, &gop, 8, true);
			break;
		case PPC_INS_STB:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[1]"));
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_STBU:
			op->type = R_ANAL_OP_TYPE_STORE;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf (op, "%s,%s,=[1],%s=", ARG (0), op1, op1);
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_STH:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[2]"));
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_STHU:
			op->type = R_ANAL_OP_TYPE_STORE;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf (op, "%s,%s,=[2],%s=", ARG (0), op1, op1);
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_STD:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[8]"));
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_STDU:
			op->type = R_ANAL_OP_TYPE_STORE;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf (op, "%s,%s,=[8],%s=", ARG (0), op1, op1);
			if (INSOP (1).type == PPC_OP_MEM && INSOP (1).mem.base == PPC_REG_R1) {
				op->stackop = R_ANAL_STACK_INC;
				op->stackptr = -INSOP (1).mem.disp;
			}
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_LBZU:
			op->type = R_ANAL_OP_TYPE_LOAD;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf (op, "%s,[1],%s,=,%s=", op1, ARG (0), op1);
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_LBZ:
		case PPC_INS_LBZCIX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "%s,%s,=", ARG2 (1, "[1]"), ARG (0));
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_LD:
		case PPC_INS_LDCIX:
		case PPC_INS_LDU:
			op->type = R_ANAL_OP_TYPE_LOAD;
			op1 = shrink (ARG(1));
			if (!op1) {
				break;
			}
			// only ldu writes back rA
			ppc_esil_ld (op, op1, ARG (0), 8, insn->id == PPC_INS_LDU, 0);
			set_toc_ptr (op, pd, insn, stateful);
			break;
		// X-form indexed: EA = rA + rB (separate capstone regs)
		case PPC_INS_LBZX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_ldx (op, pd, &gop, 1, false, 0);
			break;
		case PPC_INS_LBZUX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_ldx (op, pd, &gop, 1, true, 0);
			break;
		case PPC_INS_LHZX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_ldx (op, pd, &gop, 2, false, 0);
			break;
		case PPC_INS_LHAX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_ldx (op, pd, &gop, 2, false, 16);
			break;
		case PPC_INS_LHZUX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_ldx (op, pd, &gop, 2, true, 0);
			break;
		case PPC_INS_LHAUX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_ldx (op, pd, &gop, 2, true, 16);
			break;
		case PPC_INS_LWZX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_ldx (op, pd, &gop, 4, false, 0);
			break;
		case PPC_INS_LWAX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_ldx (op, pd, &gop, 4, false, 32);
			break;
		case PPC_INS_LWZUX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_ldx (op, pd, &gop, 4, true, 0);
			break;
		case PPC_INS_LWAUX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_ldx (op, pd, &gop, 4, true, 32);
			break;
		case PPC_INS_LDX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_ldx (op, pd, &gop, 8, false, 0);
			break;
		case PPC_INS_LDUX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_ldx (op, pd, &gop, 8, true, 0);
			break;
		case PPC_INS_STBX:
			op->type = R_ANAL_OP_TYPE_STORE;
			ppc_esil_stx (op, pd, &gop, 1, false);
			break;
		case PPC_INS_STBUX:
			op->type = R_ANAL_OP_TYPE_STORE;
			ppc_esil_stx (op, pd, &gop, 1, true);
			break;
		case PPC_INS_STHX:
			op->type = R_ANAL_OP_TYPE_STORE;
			ppc_esil_stx (op, pd, &gop, 2, false);
			break;
		case PPC_INS_STHUX:
			op->type = R_ANAL_OP_TYPE_STORE;
			ppc_esil_stx (op, pd, &gop, 2, true);
			break;
		case PPC_INS_STWX:
			op->type = R_ANAL_OP_TYPE_STORE;
			ppc_esil_stx (op, pd, &gop, 4, false);
			break;
		case PPC_INS_STWUX:
			op->type = R_ANAL_OP_TYPE_STORE;
			ppc_esil_stx (op, pd, &gop, 4, true);
			break;
		case PPC_INS_STDX:
			op->type = R_ANAL_OP_TYPE_STORE;
			ppc_esil_stx (op, pd, &gop, 8, false);
			break;
		case PPC_INS_STDUX:
			op->type = R_ANAL_OP_TYPE_STORE;
			ppc_esil_stx (op, pd, &gop, 8, true);
			break;
		// larx/stcx.: only the memory access is modelled, not the reservation/CR0
		case PPC_INS_LWARX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_ldx (op, pd, &gop, 4, false, 0);
			break;
		case PPC_INS_LDARX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_ldx (op, pd, &gop, 8, false, 0);
			break;
		case PPC_INS_STWCX:
			op->type = R_ANAL_OP_TYPE_STORE;
			ppc_esil_stx (op, pd, &gop, 4, false);
			break;
		case PPC_INS_STDCX:
			op->type = R_ANAL_OP_TYPE_STORE;
			ppc_esil_stx (op, pd, &gop, 8, false);
			break;
		case PPC_INS_LDBRX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_brx (op, pd, &gop, 8, false);
			break;
		case PPC_INS_LFD:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "%s,%s,=", ARG2 (1, "[8]"), ARG (0));
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_LFDU:
			op->type = R_ANAL_OP_TYPE_LOAD;
			op1 = shrink (ARG (1));
			if (!op1) {
				break;
			}
			esilprintf (op, "%s,[8],%s,=,%s=", op1, ARG (0), op1);
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_LFDX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "%s,[8],%s,=", ppc_idx_ea (pd, &gop, ea, sizeof (ea)), ARG (0));
			break;
		case PPC_INS_LFDUX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_idx_ea (pd, &gop, ea, sizeof (ea));
			esilprintf (op, "%s,[8],%s,=,%s,%s,=", ea, ARG (0), ea, ARG (1));
			break;
		case PPC_INS_LFS:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "32,%s,F2D,%s,=", ARG2 (1, "[4]"), ARG (0));
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_LFSU:
			op->type = R_ANAL_OP_TYPE_LOAD;
			op1 = shrink (ARG (1));
			if (!op1) {
				break;
			}
			esilprintf (op, "32,%s,[4],F2D,%s,=,%s=", op1, ARG (0), op1);
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_LFSX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "32,%s,[4],F2D,%s,=", ppc_idx_ea (pd, &gop, ea, sizeof (ea)), ARG (0));
			break;
		case PPC_INS_LFSUX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_idx_ea (pd, &gop, ea, sizeof (ea));
			esilprintf (op, "32,%s,[4],F2D,%s,=,%s,%s,=", ea, ARG (0), ea, ARG (1));
			break;
		case PPC_INS_LFIWAX:
		case PPC_INS_LFIWZX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "%s,[4],%s,=", ppc_idx_ea (pd, &gop, ea, sizeof (ea)), ARG (0));
			break;
		case PPC_INS_STFD:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[8]"));
			break;
		case PPC_INS_STFDU:
			op->type = R_ANAL_OP_TYPE_STORE;
			op1 = shrink (ARG (1));
			if (!op1) {
				break;
			}
			esilprintf (op, "%s,%s,=[8],%s=", ARG (0), op1, op1);
			break;
		case PPC_INS_STFDX:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s,=[8]", ARG (0), ppc_idx_ea (pd, &gop, ea, sizeof (ea)));
			break;
		case PPC_INS_STFDUX:
			op->type = R_ANAL_OP_TYPE_STORE;
			ppc_idx_ea (pd, &gop, ea, sizeof (ea));
			esilprintf (op, "%s,%s,=[8],%s,%s,=", ARG (0), ea, ea, ARG (1));
			break;
		case PPC_INS_STFS:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "32,%s,D2F,%s", ARG (0), ARG2 (1, "=[4]"));
			break;
		case PPC_INS_STFSU:
			op->type = R_ANAL_OP_TYPE_STORE;
			op1 = shrink (ARG (1));
			if (!op1) {
				break;
			}
			esilprintf (op, "32,%s,D2F,%s,=[4],%s=", ARG (0), op1, op1);
			break;
		case PPC_INS_STFSX:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "32,%s,D2F,%s,=[4]", ARG (0), ppc_idx_ea (pd, &gop, ea, sizeof (ea)));
			break;
		case PPC_INS_STFSUX:
			op->type = R_ANAL_OP_TYPE_STORE;
			ppc_idx_ea (pd, &gop, ea, sizeof (ea));
			esilprintf (op, "32,%s,D2F,%s,=[4],%s,%s,=", ARG (0), ea, ea, ARG (1));
			break;
		case PPC_INS_STFIWX:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s,=[4]", ARG (0), ppc_idx_ea (pd, &gop, ea, sizeof (ea)));
			break;
		case PPC_INS_FADD:
		case PPC_INS_FADDS:
			op->type = R_ANAL_OP_TYPE_ADD;
			ppc_fpop (op, pd, &gop, insn->id == PPC_INS_FADDS, 2, "F+");
			break;
		case PPC_INS_FSUB:
		case PPC_INS_FSUBS:
			op->type = R_ANAL_OP_TYPE_SUB;
			ppc_fpop (op, pd, &gop, insn->id == PPC_INS_FSUBS, 2, "F-");
			break;
		case PPC_INS_FMUL:
		case PPC_INS_FMULS:
			op->type = R_ANAL_OP_TYPE_MUL;
			ppc_fpop (op, pd, &gop, insn->id == PPC_INS_FMULS, 2, "F*");
			break;
		case PPC_INS_FDIV:
		case PPC_INS_FDIVS:
			op->type = R_ANAL_OP_TYPE_DIV;
			ppc_fpop (op, pd, &gop, insn->id == PPC_INS_FDIVS, 2, "F/");
			break;
		case PPC_INS_FSQRT:
		case PPC_INS_FSQRTS:
			op->type = R_ANAL_OP_TYPE_MOV;
			ppc_fpop (op, pd, &gop, insn->id == PPC_INS_FSQRTS, 1, "SQRT");
			break;
		case PPC_INS_FMADD:
		case PPC_INS_FMADDS:
			op->type = R_ANAL_OP_TYPE_MOV;
			ppc_fpop (op, pd, &gop, insn->id == PPC_INS_FMADDS, 3, "F*,F+");
			break;
		case PPC_INS_FMSUB:
		case PPC_INS_FMSUBS:
			op->type = R_ANAL_OP_TYPE_MOV;
			ppc_fpop (op, pd, &gop, insn->id == PPC_INS_FMSUBS, 3, "F*,F-");
			break;
		case PPC_INS_FNMADD:
		case PPC_INS_FNMADDS:
			op->type = R_ANAL_OP_TYPE_MOV;
			ppc_fpop (op, pd, &gop, insn->id == PPC_INS_FNMADDS, 3, "F*,F+,-F");
			break;
		case PPC_INS_FNMSUB:
		case PPC_INS_FNMSUBS:
			op->type = R_ANAL_OP_TYPE_MOV;
			ppc_fpop (op, pd, &gop, insn->id == PPC_INS_FNMSUBS, 3, "F*,F-,-F");
			break;
		case PPC_INS_FRE:
		case PPC_INS_FRES:
		case PPC_INS_FRSQRTE:
		case PPC_INS_FRSQRTES:
		case PPC_INS_FSEL:
#if CS_API_MAJOR > 4
		case PPC_INS_FTSQRT:
#endif
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case PPC_INS_FMR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_FNEG:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "0x8000000000000000,%s,^,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_FCPSGN:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "0x8000000000000000,%s,&,0x7fffffffffffffff,%s,&,|,%s,=",
				ARG (1), ARG (2), ARG (0));
			break;
		case PPC_INS_FABS:
			op->type = R_ANAL_OP_TYPE_ABS;
			esilprintf (op, "0x7fffffffffffffff,%s,&,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_FNABS:
			op->type = R_ANAL_OP_TYPE_ABS;
			esilprintf (op, "0x8000000000000000,%s,|,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_FCMPU:
			op->type = R_ANAL_OP_TYPE_CMP;
			esilprintf (op, "0x80,%s,%s,F<,*,%s,%s,F<,+,%s,=",
				ARG (2), ARG (1), ARG (1), ARG (2), ARG (0));
			break;
		case PPC_INS_FCFID:
		case PPC_INS_FCFIDS:
			op->type = R_ANAL_OP_TYPE_CAST;
			ppc_fpop (op, pd, &gop, insn->id == PPC_INS_FCFIDS, 1, "I2D");
			break;
		case PPC_INS_FCFIDU:
		case PPC_INS_FCFIDUS:
			op->type = R_ANAL_OP_TYPE_CAST;
			ppc_fpop (op, pd, &gop, insn->id == PPC_INS_FCFIDUS, 1, "U2D");
			break;
		case PPC_INS_FCTID:
		case PPC_INS_FCTIDUZ:
		case PPC_INS_FCTIDZ:
		case PPC_INS_FCTIW:
		case PPC_INS_FCTIWUZ:
#if CS_API_MAJOR > 4
		case PPC_INS_FCTIDU:
		case PPC_INS_FCTIWU:
#endif
		case PPC_INS_FCTIWZ:
			op->type = R_ANAL_OP_TYPE_CAST;
			ppc_fpop (op, pd, &gop, false, 1, "D2I");
			break;
		case PPC_INS_FRSP:
			op->type = R_ANAL_OP_TYPE_CAST;
			esilprintf (op, "32,DUP,%s,D2F,F2D,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_FRIM:
			op->type = R_ANAL_OP_TYPE_CAST;
			ppc_fpop (op, pd, &gop, false, 1, "FLOOR");
			break;
		case PPC_INS_FRIP:
			op->type = R_ANAL_OP_TYPE_CAST;
			ppc_fpop (op, pd, &gop, false, 1, "CEIL");
			break;
		case PPC_INS_FRIN:
			op->type = R_ANAL_OP_TYPE_CAST;
			ppc_fpop (op, pd, &gop, false, 1, "ROUND");
			break;
		case PPC_INS_FRIZ:
			op->type = R_ANAL_OP_TYPE_CAST;
			ppc_fpop (op, pd, &gop, false, 1, "D2I,I2D");
			break;
		case PPC_INS_LMW:
		case PPC_INS_LSWI:
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case PPC_INS_STMW:
		case PPC_INS_STSWI:
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case PPC_INS_LHA:
		case PPC_INS_LHAU:
		case PPC_INS_LHZ:
		case PPC_INS_LHZU:
			op->type = R_ANAL_OP_TYPE_LOAD;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			// algebraic (sign-extend 16); only *u forms update rA
			ppc_esil_ld (op, op1, ARG (0), 2,
				insn->id == PPC_INS_LHAU || insn->id == PPC_INS_LHZU,
				(insn->id == PPC_INS_LHA || insn->id == PPC_INS_LHAU)? 16: 0);
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_LHBRX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_brx (op, pd, &gop, 2, false);
			break;
		case PPC_INS_LWA:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "32,%s,~,%s,=", ARG2 (1, "[4]"), ARG (0));
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_LWZ:
		case PPC_INS_LWZCIX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "%s,%s,=", ARG2 (1, "[4]"), ARG (0));
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_LWZU:
			op->type = R_ANAL_OP_TYPE_LOAD;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf (op, "%s,[4],%s,=,%s=", op1, ARG (0), op1);
			set_toc_ptr (op, pd, insn, stateful);
			break;
		case PPC_INS_LWBRX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			ppc_esil_brx (op, pd, &gop, 4, false);
			break;
		case PPC_INS_SLW:
		case PPC_INS_SLWI:
			op->type = R_ANAL_OP_TYPE_SHL;
			esilprintf (op, "%s,0x3f,&,%s,<<,0xffffffff,&,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_SLD:
		case PPC_INS_SLDI:
			op->type = R_ANAL_OP_TYPE_SHL;
			// rB[57:63] shift count; >= 64 yields 0
			esilprintf (op, "%s,0x40,&,!,%s,0x3f,&,%s,<<,*,%s,=", ARG (2), ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_SRW:
		case PPC_INS_SRWI:
			op->type = R_ANAL_OP_TYPE_SHR;
			esilprintf (op, "%s,0x3f,&,%s,0xffffffff,&,>>,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_SRD:
		// case PPC_INS_SRDI: // not available in some capstone versions
			op->type = R_ANAL_OP_TYPE_SHR;
			// rB[57:63] shift count; >= 64 yields 0
			esilprintf (op, "%s,0x40,&,!,%s,0x3f,&,%s,>>,*,%s,=", ARG (2), ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_SRAW:
		case PPC_INS_SRAD:
			{
				char m[32];
				const bool w64 = insn->id == PPC_INS_SRAD;
				op->sign = true;
				op->type = R_ANAL_OP_TYPE_SAR;
				snprintf (m, sizeof (m), "1,%s,0x3f,&,1,<<,-", ARG (2));
				set_sra (op, ARG (0), ARG (1), ARG (2), w64, m);
			}
			break;
		case PPC_INS_SRAWI:
		case PPC_INS_SRADI:
			{
				char m[24];
				const bool w64 = insn->id == PPC_INS_SRADI;
				op->sign = true;
				op->type = R_ANAL_OP_TYPE_SAR;
				snprintf (m, sizeof (m), "0x%"PFMT64x, (ut64)((1ULL << (INSOP (2).imm & (w64? 63: 31))) - 1));
				set_sra (op, ARG (0), ARG (1), ARG (2), w64, m);
			}
			break;
		case PPC_INS_CNTLZW:
		case PPC_INS_CNTLZD:
			op->type = R_ANAL_OP_TYPE_MOV;
			// type only: ESIL has no count-leading-zeros operator
			break;
		case PPC_INS_MULLI:
			op->sign = true;
		case PPC_INS_MULLW:
		case PPC_INS_MULLD:
			op->type = R_ANAL_OP_TYPE_MUL;
			esilprintf (op, "%s,%s,*,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_MULHW:
		case PPC_INS_MULHD:
			op->sign = true;
		case PPC_INS_MULHWU:
		case PPC_INS_MULHDU:
			op->type = R_ANAL_OP_TYPE_MUL;
			// type only: ESIL has no high-half multiply operator
			break;
		case PPC_INS_SUB:
		case PPC_INS_SUBC:
		case PPC_INS_SUBF:
			op->type = R_ANAL_OP_TYPE_SUB;
			esilprintf (op, "%s,%s,-,%s,=", ARG (1), ARG (2), ARG (0));
			break;
		case PPC_INS_SUBFIC:
		case PPC_INS_SUBFC:
			op->type = R_ANAL_OP_TYPE_SUB;
			snprintf (vbuf, sizeof (vbuf), "%s,%s,-", ARG (1), ARG (2));
			set_ca (op, ARG (1), cm, true, ARG (0), "1", vbuf);
			break;
		case PPC_INS_NEG:
			op->type = R_ANAL_OP_TYPE_SUB;
			esilprintf (op, "%s,0,-,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_SUBFE:
			op->type = R_ANAL_OP_TYPE_SUB;
			snprintf (vbuf, sizeof (vbuf), "%s,%s,^,%s,+,ca,+", ARG (1), cm, ARG (2));
			set_ca (op, ARG (1), cm, true, ARG (0), "ca", vbuf);
			break;
		case PPC_INS_SUBFZE:
			op->type = R_ANAL_OP_TYPE_SUB;
			snprintf (vbuf, sizeof (vbuf), "%s,%s,^,ca,+", ARG (1), cm);
			set_ca (op, ARG (1), cm, true, ARG (0), "ca", vbuf);
			break;
		case PPC_INS_SUBFME:
			op->type = R_ANAL_OP_TYPE_SUB;
			snprintf (vbuf, sizeof (vbuf), "%s,%s,^,%s,+,ca,+", ARG (1), cm, cm);
			set_ca (op, ARG (1), cm, true, ARG (0), "ca", vbuf);
			break;
		case PPC_INS_ADD:
		case PPC_INS_ADDI:
			op->sign = true;
			op->type = R_ANAL_OP_TYPE_ADD;
			esilprintf (op, "%s,%s,+,%s,=", ARG (2), ARG (1), ARG (0));
			set_toc_val (op, pd, insn, stateful);
			break;
		case PPC_INS_CRCLR:
		case PPC_INS_CRSET:
		case PPC_INS_CRMOVE:
		case PPC_INS_CRXOR:
		case PPC_INS_CRNOR:
		case PPC_INS_CRNOT:
			// reset conditional bits
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case PPC_INS_ADDC:
		case PPC_INS_ADDIC:
			op->type = R_ANAL_OP_TYPE_ADD;
			snprintf (vbuf, sizeof (vbuf), "%s,%s,+", ARG (2), ARG (1));
			set_ca (op, ARG (1), cm, false, ARG (0), "0", vbuf);
			break;
		case PPC_INS_ADDIS:
			op->type = R_ANAL_OP_TYPE_ADD;
			esilprintf (op, "16,%s,<<,%s,+,%s,=", ARG (2), ARG (1), ARG (0));
			// TOC pair start: addis rX,r2,HA records gp+(HA<<16) so a later ld/addi/st via rX resolves (gp = anal.gp)
			if (stateful && INSOP(0).type == PPC_OP_REG) {
				ridx = toc_reg_idx (INSOP(0).reg);
				if (ridx >= 0) {
					if (as->config->gp
							&& INSOP(1).type == PPC_OP_REG
							&& INSOP(1).reg  == PPC_REG_R2
							&& INSOP(2).type == PPC_OP_IMM) {
						pd->toc_map[ridx] = as->config->gp
							+ (ut64)((st64)INSOP(2).imm << 16);
					} else {
						pd->toc_map[ridx] = 0; /* dest clobbered, invalidate */
					}
				}
			}
			break;
		case PPC_INS_ADDE:
			op->type = R_ANAL_OP_TYPE_ADD;
			snprintf (vbuf, sizeof (vbuf), "%s,%s,+,ca,+", ARG (2), ARG (1));
			set_ca (op, ARG (1), cm, false, ARG (0), "ca", vbuf);
			break;
		case PPC_INS_ADDZE:
			op->type = R_ANAL_OP_TYPE_ADD;
			snprintf (vbuf, sizeof (vbuf), "ca,%s,+", ARG (1));
			set_ca (op, ARG (1), cm, false, ARG (0), "ca", vbuf);
			break;
		case PPC_INS_ADDME:
			op->type = R_ANAL_OP_TYPE_ADD;
			snprintf (vbuf, sizeof (vbuf), "%s,%s,+,ca,+", ARG (1), cm);
			set_ca (op, ARG (1), cm, false, ARG (0), "ca", vbuf);
			break;
		case PPC_INS_MTSPR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,%s,=", ARG (1), PPCSPR (0));
			break;
		case PPC_INS_MFCR:
		case PPC_INS_MFOCRF:
		case PPC_INS_MTCRF:
		case PPC_INS_MTOCRF:
			op->type = R_ANAL_OP_TYPE_MOV;
			// type only: the CR model tracks only cr0, not the full cr0-cr7 word
			break;
		case PPC_INS_BCTR: // switch table here
		case PPC_INS_BCCTR:
			op->type = R_ANAL_OP_TYPE_UJMP;
			esilprintf (op, "ctr,pc,=");
			break;
		case PPC_INS_BCTRL: // switch table here
		case PPC_INS_BCCTRL:
			op->type = R_ANAL_OP_TYPE_CALL;
			esilprintf (op, "pc,lr,=,ctr,pc,=");
			break;
#if CS_VERSION_MAJOR >= 5
		case PPC_INS_BNE:
		case PPC_INS_BNEA:
		case PPC_INS_BNECTR:
		case PPC_INS_BNECTRL:
		case PPC_INS_BNEL:
		case PPC_INS_BNELA:
		case PPC_INS_BNELR:
		case PPC_INS_BNELRL:
		case PPC_INS_BNG:
		case PPC_INS_BNGA:
		case PPC_INS_BNGCTR:
		case PPC_INS_BNGCTRL:
		case PPC_INS_BNGL:
		case PPC_INS_BNGLA:
		case PPC_INS_BNGLR:
		case PPC_INS_BNGLRL:
		case PPC_INS_BNL:
		case PPC_INS_BNLA:
		case PPC_INS_BNLCTR:
		case PPC_INS_BNLCTRL:
		case PPC_INS_BNLL:
		case PPC_INS_BNLLA:
		case PPC_INS_BNLLR:
		case PPC_INS_BNLLRL:
		case PPC_INS_BNS:
		case PPC_INS_BNSA:
		case PPC_INS_BNSCTR:
		case PPC_INS_BNSCTRL:
		case PPC_INS_BNSL:
		case PPC_INS_BNSLA:
		case PPC_INS_BNSLR:
		case PPC_INS_BNSLRL:
		case PPC_INS_BNU:
		case PPC_INS_BNUA:
		case PPC_INS_BNUCTR:
		case PPC_INS_BNUCTRL:
		case PPC_INS_BNUL:
		case PPC_INS_BNULA:
		case PPC_INS_BNULR:
		case PPC_INS_BNULRL:
		case PPC_INS_BEQ:
		case PPC_INS_BEQA:
		case PPC_INS_BEQCTR:
		case PPC_INS_BEQCTRL:
		case PPC_INS_BEQL:
		case PPC_INS_BEQLA:
		case PPC_INS_BEQLR:
		case PPC_INS_BEQLRL:
		case PPC_INS_BGE:
		case PPC_INS_BGEA:
		case PPC_INS_BGECTR:
		case PPC_INS_BGECTRL:
		case PPC_INS_BGEL:
		case PPC_INS_BGELA:
		case PPC_INS_BGELR:
		case PPC_INS_BGELRL:
		case PPC_INS_BGT:
		case PPC_INS_BGTA:
		case PPC_INS_BGTCTR:
		case PPC_INS_BGTCTRL:
		case PPC_INS_BGTL:
		case PPC_INS_BGTLA:
		case PPC_INS_BGTLR:
		case PPC_INS_BGTLRL:
		case PPC_INS_BLE:
		case PPC_INS_BLEA:
		case PPC_INS_BLECTR:
		case PPC_INS_BLECTRL:
		case PPC_INS_BLEL:
		case PPC_INS_BLELA:
		case PPC_INS_BLELR:
		case PPC_INS_BLELRL:
		case PPC_INS_BLT:
		case PPC_INS_BLTA:
		case PPC_INS_BLTCTR:
		case PPC_INS_BLTCTRL:
		case PPC_INS_BLTL:
		case PPC_INS_BLTLA:
		case PPC_INS_BLTLR:
		case PPC_INS_BLTLRL:
		case PPC_INS_BSO:
		case PPC_INS_BSOA:
		case PPC_INS_BSOCTR:
		case PPC_INS_BSOCTRL:
		case PPC_INS_BSOL:
		case PPC_INS_BSOLA:
		case PPC_INS_BSOLR:
		case PPC_INS_BSOLRL:
		case PPC_INS_BUN:
		case PPC_INS_BUNA:
		case PPC_INS_BUNCTR:
		case PPC_INS_BUNCTRL:
		case PPC_INS_BUNL:
		case PPC_INS_BUNLA:
		case PPC_INS_BUNLR:
		case PPC_INS_BUNLRL:
#endif
		case PPC_INS_B:
		case PPC_INS_BC:
		case PPC_INS_BA: {
			// cs>=5 routes b<cond>lr/ctr aliases here; target is lr/ctr, never an immediate (which would fabricate jump 0)
			const char *mn = insn->mnemonic;
			const char *cr = ARG (1)[0] == '\0' ? "cr0" : ARG (0);
			if (r_str_endswith (mn, "ctr") || r_str_endswith (mn, "ctrl")) {
				const bool link = r_str_endswith (mn, "ctrl");
				op->type = link ? R_ANAL_OP_TYPE_UCCALL : R_ANAL_OP_TYPE_UCJMP;
				op->fail = addr + op->size;
				ppc_cond_branch (op, BC (), ARG (0)[0] == '\0' ? "cr0" : ARG (0), link ? "pc,lr,=,ctr" : "ctr");
				break;
			}
			if (r_str_endswith (mn, "lr") || r_str_endswith (mn, "lrl")) {
				op->type = R_ANAL_OP_TYPE_CRET;
				op->fail = addr + op->size;
				ppc_cond_branch (op, BC (), ARG (0)[0] == '\0' ? "cr0" : ARG (0), "lr");
				break;
			}
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = ARG (1)[0] == '\0' ? IMM (0) : IMM (1);
			op->fail = addr + op->size;
			if (BC () == PPC_BC_INVALID) {
				op->type = R_ANAL_OP_TYPE_JMP;
				esilprintf (op, "%s,pc,=", ARG (0));
			} else {
				ppc_cond_branch (op, BC (), cr, ARG (1)[0] == '\0' ? ARG (0) : ARG (1));
			}
			break;
		}
		case PPC_INS_BT:
		case PPC_INS_BF:
			switch (insn->detail->ppc.operands[0].type) {
#if CS_API_MAJOR < 6
			case PPC_OP_CRX:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->fail = addr + op->size;
				break;
#endif
			case PPC_OP_REG:
				if (op->type == R_ANAL_OP_TYPE_CJMP) {
					op->type = R_ANAL_OP_TYPE_UCJMP;
				} else {
					op->type = R_ANAL_OP_TYPE_CJMP;
				}
				op->jump = IMM (1);
				op->fail = addr + op->size;
				//op->type = R_ANAL_OP_TYPE_UJMP;
			default:
				break;
			}
			break;
		case PPC_INS_BDNZ:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			esilprintf (op, "1,ctr,-=,$z,!,?{,%s,pc,=,}", ARG (0));
			break;
#if CS_API_MAJOR < 6
		case PPC_INS_BDNZA:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
#endif
		case PPC_INS_BDNZL:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDNZLA:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDNZLR:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			esilprintf (op, "1,ctr,-=,$z,!,?{,lr,pc,=,},");
			break;
		case PPC_INS_BDNZLRL:
			op->fail = addr + op->size;
			op->type = R_ANAL_OP_TYPE_CJMP;
			break;
		case PPC_INS_BDZ:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			esilprintf (op, "1,ctr,-=,$z,?{,%s,pc,=,}", ARG (0));
			break;
#if CS_API_MAJOR < 6
		case PPC_INS_BDZA:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
#endif
		case PPC_INS_BDZL:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDZLA:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDZLR:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			esilprintf (op, "1,ctr,-=,$z,?{,lr,pc,=,}");
			break;
		case PPC_INS_BDZLRL:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			break;
		case PPC_INS_BLR:
		case PPC_INS_BLRL:
		case PPC_INS_BCLR:
		case PPC_INS_BCLRL:
			op->type = R_ANAL_OP_TYPE_CRET;
			op->fail = addr + op->size;
			if (BC () == PPC_BC_INVALID) {
				op->type = R_ANAL_OP_TYPE_RET;
				esilprintf (op, "lr,pc,=");
			} else {
				ppc_cond_branch (op, BC (), ARG (1)[0] == '\0' ? "cr0" : ARG (0), "lr");
			}
			break;
		case PPC_INS_RFI:
		case PPC_INS_RFID:
			op->type = R_ANAL_OP_TYPE_RET;
			op->eob = true;
			esilprintf (op, "srr0,pc,=");
			break;
		case PPC_INS_RFCI:
		case PPC_INS_RFDI:
		case PPC_INS_RFMCI:
#if CS_API_MAJOR > 4
		case PPC_INS_RFEBB:
		case PPC_INS_HRFID:
#endif
			op->type = R_ANAL_OP_TYPE_RET;
			op->eob = true;
			break;
		case PPC_INS_NOR:
			op->type = R_ANAL_OP_TYPE_NOR;
			esilprintf (op, "%s,%s,|,0xffffffffffffffff,^,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_XOR:
		case PPC_INS_XORI:
			op->type = R_ANAL_OP_TYPE_XOR;
			esilprintf (op, "%s,%s,^,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_XORIS:
			op->type = R_ANAL_OP_TYPE_XOR;
			esilprintf (op, "16,%s,<<,%s,^,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_DIVD:
			op->sign = true;
			op->type = R_ANAL_OP_TYPE_DIV;
			esilprintf (op, "%s,%s,~/,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_DIVW:
			op->sign = true;
			op->type = R_ANAL_OP_TYPE_DIV;
			esilprintf (op, "32,%s,~,32,%s,~,~/,0xffffffff,&,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_DIVDU:
			op->type = R_ANAL_OP_TYPE_DIV;
			esilprintf (op, "%s,%s,/,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_DIVWU:
			op->type = R_ANAL_OP_TYPE_DIV;
			esilprintf (op, "%s,0xffffffff,&,%s,0xffffffff,&,/,%s,=", ARG (2), ARG (1), ARG (0));
			break;
#if CS_API_MAJOR > 4
		case PPC_INS_DIVDE:
		case PPC_INS_DIVWE:
			op->sign = true;
		case PPC_INS_DIVDEU:
		case PPC_INS_DIVWEU:
			op->type = R_ANAL_OP_TYPE_DIV;
			break;
		case PPC_INS_MODSW:
		case PPC_INS_MODSD:
			op->sign = true;
			op->type = R_ANAL_OP_TYPE_MOD;
			esilprintf (op, "%s,%s,~%%,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_MODUW:
		case PPC_INS_MODUD:
			op->type = R_ANAL_OP_TYPE_MOD;
			esilprintf (op, "%s,%s,%%,%s,=", ARG (2), ARG (1), ARG (0));
			break;
#endif
		case PPC_INS_BL:
		case PPC_INS_BLA:
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			esilprintf (op, "pc,lr,=,%s,pc,=", ARG (0));
			break;
		case PPC_INS_TRAP:
			op->sign = true;
			op->type = R_ANAL_OP_TYPE_TRAP;
			break;
		case PPC_INS_AND:
		case PPC_INS_ANDI:
			op->type = R_ANAL_OP_TYPE_AND;
			esilprintf (op, "%s,%s,&,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_NAND:
			op->type = R_ANAL_OP_TYPE_AND;
			esilprintf (op, "%s,%s,&,0xffffffffffffffff,^,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_ANDIS:
			op->type = R_ANAL_OP_TYPE_AND;
			esilprintf (op, "16,%s,<<,%s,&,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_OR:
		case PPC_INS_ORI:
			op->type = R_ANAL_OP_TYPE_OR;
			esilprintf (op, "%s,%s,|,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_ORIS:
			op->type = R_ANAL_OP_TYPE_OR;
			esilprintf (op, "16,%s,<<,%s,|,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_ANDC:
			op->type = R_ANAL_OP_TYPE_AND;
			esilprintf (op, "0xffffffffffffffff,%s,^,%s,&,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_ORC:
			op->type = R_ANAL_OP_TYPE_OR;
			esilprintf (op, "0xffffffffffffffff,%s,^,%s,|,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_EQV:
			op->type = R_ANAL_OP_TYPE_XOR;
			esilprintf (op, "%s,%s,^,0xffffffffffffffff,^,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_MFPVR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "pvr,%s,=", ARG (0));
			break;
		case PPC_INS_MFSPR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,%s,=", PPCSPR (1), ARG (0));
			break;
		case PPC_INS_MFCTR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "ctr,%s,=", ARG (0));
			break;
		case PPC_INS_MFDCCR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "dccr,%s,=", ARG (0));
			break;
		case PPC_INS_MFICCR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "iccr,%s,=", ARG (0));
			break;
		case PPC_INS_MFDEAR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "dear,%s,=", ARG (0));
			break;
		case PPC_INS_MFMSR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "msr,%s,=", ARG (0));
			break;
		case PPC_INS_MTCTR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,ctr,=", ARG (0));
			break;
		case PPC_INS_MTDCCR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,dccr,=", ARG (0));
			break;
		case PPC_INS_MTICCR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,iccr,=", ARG (0));
			break;
		case PPC_INS_MTDEAR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,dear,=", ARG (0));
			break;
		case PPC_INS_MTMSR:
		case PPC_INS_MTMSRD:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,msr,=", ARG (0));
			break;
			// Data Cache Block Zero
		case PPC_INS_DCBZ:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, ",=[128]"));
			break;
		case PPC_INS_CLRLDI:
			op->type = R_ANAL_OP_TYPE_AND;
			esilprintf (op, "%s,%s,&,%s,=", ARG (1), cmask64 (cmaskbuf, ARG (2), "0x3F"), ARG (0));
			break;
		case PPC_INS_ROTLDI:
			op->type = R_ANAL_OP_TYPE_ROL;
			esilprintf (op, "%s,%s,ROL,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_ROTLD:
			op->type = R_ANAL_OP_TYPE_ROL;
			esilprintf (op, "%s,%s,ROL,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_ROTLW:
		case PPC_INS_ROTLWI:
			op->type = R_ANAL_OP_TYPE_ROL;
			ppc_esil_rlwnm (op, pd, &gop, "0xffffffff", false);
			break;
		case PPC_INS_RLWNM:
			op->type = R_ANAL_OP_TYPE_ROL;
			if (ARG (3)[0] && ARG (4)[0]) {
				ppc_esil_rlwnm (op, pd, &gop, cmask32 (cmaskbuf, ARG (3), ARG (4)), getarg (&gop, 3) > getarg (&gop, 4));
			}
			break;
		case PPC_INS_RLWIMI:
			op->type = R_ANAL_OP_TYPE_ROL;
			break;
		case PPC_INS_RLDCL:
		case PPC_INS_RLDICL:
			op->type = R_ANAL_OP_TYPE_ROL;
			esilprintf (op, "%s,%s,ROL,%s,&,%s,=", ARG (2), ARG (1), cmask64 (cmaskbuf, ARG (3), "0x3F"), ARG (0));
			break;
		case PPC_INS_RLDCR:
		case PPC_INS_RLDICR:
			op->type = R_ANAL_OP_TYPE_ROL;
			esilprintf (op, "%s,%s,ROL,%s,&,%s,=", ARG (2), ARG (1), cmask64 (cmaskbuf, 0, ARG (3)), ARG (0));
			break;
		case PPC_INS_RLDIC:
		case PPC_INS_RLDIMI:
			op->type = R_ANAL_OP_TYPE_ROL;
			// type only: rldic masks mb..63-sh and rldimi inserts into the
			// destination; neither is expressible via cmask64(mb,me)
			break;
		}
		if (stateful) {
			toc_invalidate (pd, op, insn);
		}
		const char m0 = insn->mnemonic[0];
		if (op->type == R_ANAL_OP_TYPE_NULL && m0 == 't' && (insn->mnemonic[1] == 'w' || insn->mnemonic[1] == 'd')) {
			op->sign = true;
			op->type = R_ANAL_OP_TYPE_TRAP;
		} else if (m0 == 'f') {
			op->family = R_ANAL_OP_FAMILY_FPU;
		}
		if (op->type == R_ANAL_OP_TYPE_NULL && m0 == 'm') {
			// capstone v5 emits per-spr alias ids for these, never PPC_INS_MFSPR/MTSPR
			if (!strcmp (insn->mnemonic, "mfspr")) {
				op->type = R_ANAL_OP_TYPE_MOV;
				esilprintf (op, "%s,%s,=", PPCSPR (1), ARG (0));
			} else if (!strcmp (insn->mnemonic, "mtspr")) {
				op->type = R_ANAL_OP_TYPE_MOV;
				esilprintf (op, "%s,%s,=", ARG (1), PPCSPR (0));
			} else if (!strcmp (insn->mnemonic, "mfxer")) {
				op->type = R_ANAL_OP_TYPE_MOV;
				esilprintf (op, "xer,%s,=", ARG (0));
			} else if (!strcmp (insn->mnemonic, "mtxer")) {
				op->type = R_ANAL_OP_TYPE_MOV;
				esilprintf (op, "%s,xer,=", ARG (0));
			}
		}
		if (mask & R_ARCH_OP_MASK_VAL) {
			op_fillval (op, handle, insn);
		}
		if (!(mask & R_ARCH_OP_MASK_ESIL)) {
			r_strbuf_fini (&op->esil);
		}
	}
	return op->size > 0;
}

static int archinfo(RArchSession *as, ut32 q) {
	if (q == R_ARCH_INFO_WODST) {
		return 1;
	}
	const char *cpu = as->config->cpu;
	if (cpu && !strncmp (cpu, "vle", 3)) {
		// vle mixes 2-byte se_* and 4-byte e_* forms
		return (q == R_ARCH_INFO_MAXOP_SIZE)? 4: 2;
	}
	return 4;
}

static RList *preludes(RArchSession *as) {
	RList *l = r_list_newf (free);
	r_list_append (l, r_str_newf ("7c0802a6"));
	return l;
}

static char *mnemonics(RArchSession *as, int id, bool json) {
	CapstonePluginData *cpd = as->data;
	return r_arch_cs_mnemonics (as, cpd->cs_handle, id, json);
}

static bool init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}
	as->data = R_NEW0 (PluginData);
	PluginData *pd = as->data;
	if (!r_arch_cs_init (as, &pd->cpd.cs_handle)) {
		R_LOG_ERROR ("Cannot initialize capstone");
		R_FREE (as->data);
		return false;
	}
	return true;
}

static bool fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	CapstonePluginData *cpd = as->data;
	cs_close (&cpd->cs_handle);
	R_FREE (as->data);
	return true;
}

static bool reset(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, false);
	PluginData *pd = as->data;
	memset (pd->toc_map, 0, sizeof (pd->toc_map));
	return true;
}

const RArchPlugin r_arch_plugin_ppc_cs = {
	.meta = {
		.name = "ppc",
		.author = "pancake,deroad",
		.desc = "PowerPC +vle +ps (capstone)",
		.license = "Apache-2.0",
	},
	.arch = "ppc",
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.cpus = "ppc,vle,ps",
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.info = archinfo,
	.preludes = preludes,
	.decode = decode,
	.regs = regs,
	.mnemonics = mnemonics,
	.init = init,
	.fini = fini,
	.reset = reset,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_ppc_cs,
	.version = R2_VERSION
};
#endif
