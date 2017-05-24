/* radare2 - LGPL - Copyright 2013-2017 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone/capstone.h>
#include <capstone/ppc.h>

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

#define esilprintf(op, fmt, ...) r_strbuf_appendf (&op->esil, fmt, ##__VA_ARGS__)
#define INSOPS insn->detail->ppc.op_count
#define INSOP(n) insn->detail->ppc.operands[n]
#define IMM(x) (ut64)(insn->detail->ppc.operands[x].imm)

#ifndef PFMT32x
#define PFMT32x "lx"
#endif

static ut64 mask64(ut64 mb, ut64 me) {
	int i;
	ut64 mask = 0;
	if (mb > 63 || me > 63) {
		return mask;
	}

	if (mb < (me + 1)) {
		for(i = mb; i <= me ; i++) {
			mask = mask | (ut64)(1LL << (63 - i));
		}
	} else if (mb == (me + 1)) {
		mask = 0xffffffffffffffffull;
	} else if (mb > (me + 1)) {
		ut64 lo = mask64(0, me);
		ut64 hi = mask64(mb, 63);
		mask = lo | hi;
	}
	return mask;
}

static const char* cmask64(const char *mb_c, const char *me_c){
	static char cmask[32];
	ut64 mb = 0;
	ut64 me = 0;
	if (mb_c) mb = atol(mb_c);
	if (me_c) me = atol(me_c);
	snprintf(cmask, sizeof(cmask), "0x%"PFMT64x"", mask64(mb, me));
	return cmask;
}

static ut32 mask32(ut32 mb, ut32 me) {
	int i;
	ut32 mask = 0;
	if (mb > 31 || me > 31) {
		return mask;
	}

	if (mb < (me + 1)) {
		for(i = mb; i <= me ; i++) {
			mask = mask | (ut32)(1LL << (31 - i));
		}
	} else if (mb == (me + 1)) {
		mask = 0xffffffffu;
	} else if (mb > (me + 1)) {
		ut32 lo = mask32(0, me);
		ut32 hi = mask32(mb, 31);
		mask = lo | hi;
	}
	return mask;
}

static const char* cmask32(const char *mb_c, const char *me_c){
	static char cmask[32];
	ut32 mb = 32;
	ut32 me = 32;
	if (mb_c) mb += atol(mb_c);
	if (me_c) me += atol(me_c);
	snprintf(cmask, sizeof(cmask), "0x%"PFMT32x"", mask32(mb, me));
	return cmask;
}

#if 0
static const char* inv_mask64(const char *mb_c, const char *sh){
	static char cmask[32];
	ut64 mb = 0;
	ut64 me = 0;
	if (mb_c) mb = atol(mb_c);
	if (sh) {
		me = atol (sh);
	}
	snprintf (cmask, sizeof (cmask), "0x%"PFMT64x"", mask64(mb, ~me));
	return cmask;
}

static const char* inv_mask32(const char *mb_c, const char *sh){
	static char cmask[32];
	ut32 mb = 0;
	ut32 me = 0;
	if (mb_c) mb = atol(mb_c);
	if (sh) me = atol(sh);
	snprintf(cmask, sizeof(cmask), "0x%"PFMT32x"", mask32(mb, ~me));
	return cmask;
}
#endif

static char *getarg2(struct Getarg *gop, int n, const char *setstr) {
	cs_insn *insn = gop->insn;
	csh handle = gop->handle;
	static char words[8][64];
	cs_ppc_op op;

	if (n < 0 || n >= 8) {
		return NULL;
	}
	op = INSOP (n);
	switch (op.type) {
	case PPC_OP_INVALID:
		words[n][0] = '\0';
		//strcpy (words[n], "invalid");
		break;
	case PPC_OP_REG:
		snprintf (words[n], sizeof (words[n]), 
			"%s%s", cs_reg_name (handle, op.reg), setstr);
		break;
	case PPC_OP_IMM:
		snprintf (words[n], sizeof (words[n]), 
			"0x%"PFMT64x"%s", (ut64)op.imm, setstr);
		break;
	case PPC_OP_MEM:
		snprintf (words[n], sizeof (words[n]), 
			"%"PFMT64d",%s,+,%s",
			(ut64)op.mem.disp,
			cs_reg_name (handle, op.mem.base), setstr);
		break;
	case PPC_OP_CRX: // Condition Register field
		snprintf (words[n], sizeof (words[n]), 
			"%"PFMT64d"%s", (ut64)op.imm, setstr);
		break;
	}
	return words[n];
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
	case PPC_OP_CRX: // Condition Register field
		value = (ut64) op.imm;
		break;
	}
	return value;
}

static const char* getspr(struct Getarg *gop, int n) {
	static char cspr[16];
	ut32 spr = 0;
	if (n < 0 || n >= 8) {
		return NULL;
	}
	spr = getarg(gop, 0);
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
		snprintf(cspr, sizeof(cspr), "spr_%u", spr);
		break;
	}
	return cspr;
}

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	r_strbuf_init (buf);
	r_strbuf_append (buf, "{");
	cs_sysz *x = &insn->detail->sysz;
	r_strbuf_append (buf, "\"operands\":[");
	for (i = 0; i < x->op_count; i++) {
		cs_sysz_op *op = &x->operands[i];
		if (i > 0) {
			r_strbuf_append (buf, ",");
		}
		r_strbuf_append (buf, "{");
		switch (op->type) {
		case SYSZ_OP_REG:
			r_strbuf_append (buf, "\"type\":\"reg\"");
			r_strbuf_appendf (buf, ",\"value\":\"%s\"", cs_reg_name (handle, op->reg));
			break;
		case SYSZ_OP_IMM:
			r_strbuf_append (buf, "\"type\":\"imm\"");
			r_strbuf_appendf (buf, ",\"value\":%"PFMT64d, op->imm);
			break;
		case SYSZ_OP_MEM:
			r_strbuf_append (buf, "\"type\":\"mem\"");
			if (op->mem.base != SYSZ_REG_INVALID) {
				r_strbuf_appendf (buf, ",\"base\":\"%s\"", cs_reg_name (handle, op->mem.base));
			}
			r_strbuf_appendf (buf, ",\"index\":%"PFMT64d"", (st64)op->mem.index);
			r_strbuf_appendf (buf, ",\"length\":%"PFMT64d"", (st64)op->mem.length);
			r_strbuf_appendf (buf, ",\"disp\":%"PFMT64d"", (st64)op->mem.disp);
			break;
		default:
			r_strbuf_append (buf, "\"type\":\"invalid\"");
			break;
		}
		r_strbuf_append (buf, "}");
	}
	r_strbuf_append (buf, "]}");
}

#define PPCSPR(n) getspr(&gop, n)
#define ARG(n) getarg2(&gop, n, "")
#define ARG2(n,m) getarg2(&gop, n, m)

static int set_reg_profile(RAnal *anal) {
	const char *p = NULL;
	if (anal->bits == 32) {
		p =
		"=PC	pc\n"
		"=SP	r1\n"
		"=SR	srr1\n" // status register ??
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
		"gpr	mask   .32 288 0\n";
	} else {
		p =
		"=PC	pc\n"
		"=SP	r1\n"
		"=SR	srr1\n" // status register ??
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
		"gpr	mask   .64 488 0\n"; //not a real register used on complex functions
	}
	return r_reg_set_profile_string (anal->reg, p);
}

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	static csh handle = 0;
	static int omode = -1;
	int n, ret;
	cs_insn *insn;
	int mode = (a->bits == 64)? CS_MODE_64: (a->bits == 32)? CS_MODE_32: 0;
	mode |= CS_MODE_BIG_ENDIAN;
	if (mode != omode) {
		cs_close (&handle);
		handle = 0;
		omode = mode;
	}
	if (handle == 0) {
		ret = cs_open (CS_ARCH_PPC, mode, &handle);
		if (ret != CS_ERR_OK) {
			return -1;
		}
		cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	}
	op->delay = 0;
	op->type = R_ANAL_OP_TYPE_NULL;
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->ptr = op->val = UT64_MAX;
	op->size = 4;

	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");

	// capstone-next
	n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
	} else {
		opex (&op->opex, handle, insn);
		struct Getarg gop = {
			.handle = handle,
			.insn = insn,
			.bits = a->bits
		};
		op->size = insn->size;
		op->id = insn->id;
		switch (insn->id) {
#if CS_API_MAJOR >= 4
		case PPC_INS_CMPB:
#endif
		case PPC_INS_CMPD:
		case PPC_INS_CMPDI:
		case PPC_INS_CMPLD:
		case PPC_INS_CMPLDI:
		case PPC_INS_CMPLW:
		case PPC_INS_CMPLWI:
		case PPC_INS_CMPW:
		case PPC_INS_CMPWI:
			op->type = R_ANAL_OP_TYPE_CMP;
			if (ARG (2)[0] == '\0') esilprintf (op, "%s,%s,-,0xff,&,cr0,=", ARG (1), ARG (0));
			else  esilprintf (op, "%s,%s,-,0xff,&,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_MFLR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "lr,%s,=", ARG (0));
			break;
		case PPC_INS_MTLR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,lr,=", ARG (0));
			break;
		case PPC_INS_MR:
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
			esilprintf (op, "%s,0x%"PFMT64x",&,%s,=", ARG (1), cmask32 (ARG (2), "31"), ARG (0));
			break;
		case PPC_INS_RLWINM:
			op->type = R_ANAL_OP_TYPE_ROL;
			esilprintf (op, "%s,%s,<<<,0x%"PFMT64x",&,%s,=", ARG (2), ARG (1), cmask32 (ARG (3), ARG (4)), ARG (0));
			break;
		case PPC_INS_SC:
			op->type = R_ANAL_OP_TYPE_SWI;
			esilprintf (op, "0,$");
			break;
		case PPC_INS_EXTSB:
			op->type = R_ANAL_OP_TYPE_MOV;
			if(a->bits == 64) esilprintf (op, "%s,0x80,&,?{,0xFFFFFFFFFFFFFF00,%s,|,%s,=,}", ARG (1), ARG (1), ARG (0));
			else esilprintf (op, "%s,0x80,&,?{,0xFFFFFF00,%s,|,%s,=,}", ARG (1), ARG (1), ARG (0));
			break;
		case PPC_INS_EXTSH:
			if(a->bits == 64) esilprintf (op, "%s,0x8000,&,?{,0xFFFFFFFFFFFF0000,%s,|,%s,=,}", ARG (1), ARG (1), ARG (0));
			else esilprintf (op, "%s,0x8000,&,?{,0xFFFF0000,%s,|,%s,=,}", ARG (1), ARG (1), ARG (0));
			break;
		case PPC_INS_EXTSW:
			esilprintf (op, "%s,0x80000000,&,?{,0xFFFFFFFF00000000,%s,|,%s,=,}", ARG (1), ARG (1), ARG (0));
			break;
		case PPC_INS_SYNC:
		case PPC_INS_ISYNC:
		case PPC_INS_LWSYNC:
		case PPC_INS_MSYNC:
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
		case PPC_INS_STWU:
		case PPC_INS_STWUX:
		case PPC_INS_STWX:
		case PPC_INS_STWBRX:
		case PPC_INS_STWCX:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[4]"));
			break;
		case PPC_INS_STB:
		case PPC_INS_STBU:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[1]"));
			break;
		case PPC_INS_STH:
		case PPC_INS_STHU:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[2]"));
			break;
		case PPC_INS_STD:
		case PPC_INS_STDU:
			op->type = R_ANAL_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[8]"));
			break;
		case PPC_INS_LA:
		case PPC_INS_LBZ:
		case PPC_INS_LBZU:
		case PPC_INS_LBZUX:
		case PPC_INS_LBZX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "%s,%s,=", ARG2 (1, "[1]"), ARG (0));
			break;
		case PPC_INS_LD:
		case PPC_INS_LDARX:
		case PPC_INS_LDBRX:
		case PPC_INS_LDU:
		case PPC_INS_LDUX:
		case PPC_INS_LDX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "%s,%s,=", ARG2 (1, "[8]"), ARG (0));
			break;
		case PPC_INS_LFD:
		case PPC_INS_LFDU:
		case PPC_INS_LFDUX:
		case PPC_INS_LFDX:
		case PPC_INS_LFIWAX:
		case PPC_INS_LFIWZX:
		case PPC_INS_LFS:
		case PPC_INS_LFSU:
		case PPC_INS_LFSUX:
		case PPC_INS_LFSX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "%s,%s,=", ARG2 (1, "[4]"), ARG (0));
			break;
		case PPC_INS_LHA:
		case PPC_INS_LHAU:
		case PPC_INS_LHAUX:
		case PPC_INS_LHAX:
		case PPC_INS_LHBRX:
		case PPC_INS_LHZ:
		case PPC_INS_LHZU:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "%s,%s,=", ARG2 (1, "[2]"), ARG (0));
			break;
		case PPC_INS_LWA:
		case PPC_INS_LWARX:
		case PPC_INS_LWAUX:
		case PPC_INS_LWAX:
		case PPC_INS_LWBRX:
		case PPC_INS_LWZ:
		case PPC_INS_LWZU:
		case PPC_INS_LWZUX:
		case PPC_INS_LWZX:
			op->type = R_ANAL_OP_TYPE_LOAD;
			esilprintf (op, "%s,%s,=", ARG2 (1, "[4]"), ARG (0));
			break;
		case PPC_INS_SLW:
		case PPC_INS_SLWI:
			op->type = R_ANAL_OP_TYPE_SHL;
			esilprintf (op, "%s,%s,<<,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_SRW:
		case PPC_INS_SRWI:
			op->type = R_ANAL_OP_TYPE_SHR;
			esilprintf (op, "%s,%s,>>,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_MULLI:
		case PPC_INS_MULLW:
		case PPC_INS_MULLD:
			op->type = R_ANAL_OP_TYPE_MUL;
			esilprintf (op, "%s,%s,*,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_SUB:
		case PPC_INS_SUBC:
		case PPC_INS_SUBF:
		case PPC_INS_SUBFIC:
		case PPC_INS_SUBFZE:
			op->type = R_ANAL_OP_TYPE_SUB;
			esilprintf (op, "%s,%s,-,%s,=", ARG (1), ARG (2), ARG (0));
			break;
		case PPC_INS_ADD:
		case PPC_INS_ADDI:
			op->type = R_ANAL_OP_TYPE_ADD;
			esilprintf (op, "%s,%s,+,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_ADDC:
		case PPC_INS_ADDIC:
			op->type = R_ANAL_OP_TYPE_ADD;
			esilprintf (op, "%s,%s,+,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_ADDE:
		case PPC_INS_ADDIS:
		case PPC_INS_ADDME:
		case PPC_INS_ADDZE:
			op->type = R_ANAL_OP_TYPE_ADD;
			esilprintf (op, "%s,%s,+,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_MTSPR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,%s,=", ARG (1), PPCSPR(0));
			break;
		case PPC_INS_BCTR: // switch table here
			op->type = R_ANAL_OP_TYPE_UJMP;
			esilprintf (op, "ctr,pc,=");
			break;
		case PPC_INS_BCTRL: // switch table here
			op->type = R_ANAL_OP_TYPE_CALL;
			esilprintf (op, "pc,lr,=,ctr,pc,=");
			break;
		case PPC_INS_B:
		case PPC_INS_BC:
			op->jump = ARG (1)[0] == '\0' ? IMM (0) : IMM (1);
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			switch (insn->detail->ppc.bc) {
			case PPC_BC_LT:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0,cr0,<,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "0,%s,<,?{,%s,pc,=,},", ARG (0), ARG (1));
				}
				break;
			case PPC_BC_LE:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0,cr0,<=,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "0,%s,<=,?{,%s,pc,=,},", ARG (0), ARG (1));
				}
				break;
			case PPC_BC_EQ:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0,cr0,==,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "0,%s,==,?{,%s,pc,=,},", ARG (0), ARG (1));
				}
				break;
			case PPC_BC_GE:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0,cr0,>=,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "0,%s,>=,?{,%s,pc,=,},", ARG (0), ARG (1));
				}
				break;
			case PPC_BC_GT:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0,cr0,>,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "0,%s,>,?{,%s,pc,=,},", ARG (0), ARG (1));
				}
				break;
			case PPC_BC_NE:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "cr0,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "%s,?{,%s,pc,=,},", ARG (0), ARG (1));
				}
				break;
			case PPC_BC_INVALID:
				op->type = R_ANAL_OP_TYPE_JMP;
				esilprintf (op, "%s,pc,=", ARG (0));
			case PPC_BC_UN: // unordered
			case PPC_BC_NU: // not unordered
			case PPC_BC_SO: // summary overflow
			case PPC_BC_NS: // not summary overflow
			default:
				break;
			}
			break;
		case PPC_INS_BA:
			switch (insn->detail->ppc.operands[0].type) {
			case PPC_OP_CRX:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->fail = addr + op->size;
				break;
			case PPC_OP_REG:
				if (op->type == R_ANAL_OP_TYPE_CJMP) {
					op->type = R_ANAL_OP_TYPE_UCJMP;
				} else {
					op->type = R_ANAL_OP_TYPE_CJMP;
				}
				op->jump = IMM(1);
				op->fail = addr + op->size;
				//op->type = R_ANAL_OP_TYPE_UJMP;
			default:
				break;
			}
			break;
		case PPC_INS_BDNZ:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			esilprintf (op, "ctr,?{,%s,pc,=,}", ARG (0));
			break;
		case PPC_INS_BDNZA:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDNZL:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDNZLA:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDNZLR:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			esilprintf (op, "ctr,?{,lr,pc,=,},");
			break;
		case PPC_INS_BDNZLRL:
			op->fail = addr + op->size;
			op->type = R_ANAL_OP_TYPE_CJMP;
			break;
		case PPC_INS_BDZ:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			esilprintf (op, "ctr,0,==,?{,%s,pc,=,}", ARG (0));
			break;
		case PPC_INS_BDZA:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDZL:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDZLA:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDZLR:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			esilprintf (op, "ctr,0,==,?{,lr,pc,=,}");
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
			switch (insn->detail->ppc.bc) {
			case PPC_BC_INVALID:
				op->type = R_ANAL_OP_TYPE_RET;
				esilprintf (op, "lr,pc,=");
				break;
			case PPC_BC_LT:
				if (ARG (0)[0] == '\0') {
					esilprintf (op, "0,cr0,<,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "0,%s,<,?{,lr,pc,=,},", ARG (0));
				}
				break;
			case PPC_BC_LE:
				if (ARG (0)[0] == '\0') {
					esilprintf (op, "0,cr0,<=,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "0,%s,<=,?{,lr,pc,=,},", ARG (0));
				}
				break;
			case PPC_BC_EQ:
				if (ARG (0)[0] == '\0') {
					esilprintf (op, "0,cr0,==,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "0,%s,==,?{,lr,pc,=,},", ARG (0));
				}
				break;
			case PPC_BC_GE:
				if (ARG (0)[0] == '\0') {
					esilprintf (op, "0,cr0,>=,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "0,%s,>=,?{,lr,pc,=,},", ARG (0));
				}
				break;
			case PPC_BC_GT:
				if (ARG (0)[0] == '\0') {
					esilprintf (op, "0,cr0,>,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "0,%s,>,?{,lr,pc,=,},", ARG (0));
				}
				break;
			case PPC_BC_NE:
				if (ARG (0)[0] == '\0') {
					esilprintf (op, "cr0,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "%s,?{,lr,pc,=,},", ARG (0));
				}
				break;
			case PPC_BC_UN: // unordered
			case PPC_BC_NU: // not unordered
			case PPC_BC_SO: // summary overflow
			case PPC_BC_NS: // not summary overflow
			default:
				break;
			}
			break;
		case PPC_INS_NOR:
			op->type = R_ANAL_OP_TYPE_NOR;
			esilprintf (op, "%s,!,%s,|,%s,=", ARG (1), ARG (2), ARG (0));
			break;
		case PPC_INS_XOR:
		case PPC_INS_XORI:
			op->type = R_ANAL_OP_TYPE_XOR;
			esilprintf (op, "%s,%s,^,%s,=", ARG (1), ARG (2), ARG (0));
			break;
		case PPC_INS_XORIS:
			op->type = R_ANAL_OP_TYPE_XOR;
			esilprintf (op, "16,%s,>>,%s,^,%s,=", ARG (1), ARG (2), ARG (0));
			break;
		case PPC_INS_DIVD:
		case PPC_INS_DIVDU:
		case PPC_INS_DIVW:
		case PPC_INS_DIVWU:
			op->type = R_ANAL_OP_TYPE_DIV;
			esilprintf (op, "%s,%s,/,%s,=", ARG (1), ARG (2), ARG (0));
			break;
		case PPC_INS_BL:
		case PPC_INS_BLA:
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			esilprintf (op, "pc,lr,=,%s,pc,=", ARG (0));
			break;
		case PPC_INS_TRAP:
			op->type = R_ANAL_OP_TYPE_TRAP;
			break;
		case PPC_INS_AND:
		case PPC_INS_NAND:
		case PPC_INS_ANDI:
		case PPC_INS_ANDIS:
			op->type = R_ANAL_OP_TYPE_AND;
			esilprintf (op, "%s,%s,&,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_OR:
		case PPC_INS_ORC:
		case PPC_INS_ORI:
		case PPC_INS_ORIS:
			op->type = R_ANAL_OP_TYPE_OR;
			esilprintf (op, "%s,%s,|,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_MFPVR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "pvr,%s,=", ARG (0));
			break;
		case PPC_INS_MFSPR:
			op->type = R_ANAL_OP_TYPE_MOV;
			esilprintf (op, "%s,%s,=", PPCSPR(1), ARG (0));
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
			esilprintf (op, "%s,0x%"PFMT64x",&,%s,=", ARG (1), cmask64 (ARG (2), "63"), ARG (0));
			break;
		case PPC_INS_ROTLDI:
			op->type = R_ANAL_OP_TYPE_ROL;
			esilprintf (op, "%s,%s,<<<,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_RLDCL:
		case PPC_INS_RLDICL:
			op->type = R_ANAL_OP_TYPE_ROL;
			esilprintf (op, "%s,%s,<<<,0x%"PFMT64x",&,%s,=", ARG (2), ARG (1), cmask64 (ARG (3), "63"), ARG (0));
			break;
		}
		r_strbuf_fini (&op->esil);
		cs_free (insn, n);
		//cs_close (&handle);
	}
	return op->size;
}

static int archinfo(RAnal *anal, int q) {
	return 4; /* :D */
}

RAnalPlugin r_anal_plugin_ppc_cs = {
	.name = "ppc",
	.desc = "Capstone PowerPC analysis",
	.license = "BSD",
	.esil = true,
	.arch = "ppc",
	.bits = 32|64,
	.archinfo = archinfo,
	.op = &analop,
	.set_reg_profile = &set_reg_profile,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_ppc_cs,
	.version = R2_VERSION
};
#endif
