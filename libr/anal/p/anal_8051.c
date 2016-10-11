/* radare - LGPL - Copyright 2013-2016 - pancake, dkreuter  */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include <8051_disas.h>

#define IRAM 0x10000

static bool i8051_is_init = false;

static ut8 bitindex[] = {
	// bit 'i' can be found in (ram[bitindex[i>>3]] >> (i&7)) & 1
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, // 0x00
	0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, // 0x40
	0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8, // 0x80
	0x00, 0x00, 0xD0, 0x00, 0xE0, 0x00, 0xF0, 0x00  // 0xC0
};

typedef struct {
	const char *name;
	ut8 offset; // offset into memory, where the value is held
	ut8 resetvalue; // value the register takes in case of a reset
	ut8 num_bytes; // no more than sizeof(ut64)
	ut8 banked : 1;
	ut8 isdptr : 1;
} RI8015Reg;

static RI8015Reg registers[] = {
	// keep these sorted
	{"acc",   0xE0, 0x00, 1, 0},
	{"b",     0xF0, 0x00, 1, 0},
	{"dph",   0x83, 0x00, 1, 0},
	{"dpl",   0x82, 0x00, 1, 0},
	{"dptr",  0x00, 0x00, 2, 0, 1},
	{"ie",    0xA8, 0x00, 1, 0},
	{"ip",    0xB8, 0x00, 1, 0},
	{"p0",    0x80, 0xFF, 1, 0},
	{"p1",    0x90, 0xFF, 1, 0},
	{"p2",    0xA0, 0xFF, 1, 0},
	{"p3",    0xB0, 0xFF, 1, 0},
	{"pcon",  0x87, 0x00, 1, 0},
	{"psw",   0xD0, 0x00, 1, 0},
	{"r0",    0x00, 0x00, 1, 1},
	{"r1",    0x01, 0x00, 1, 1},
	{"r2",    0x02, 0x00, 1, 1},
	{"r3",    0x03, 0x00, 1, 1},
	{"r4",    0x04, 0x00, 1, 1},
	{"r5",    0x05, 0x00, 1, 1},
	{"r6",    0x06, 0x00, 1, 1},
	{"r7",    0x07, 0x00, 1, 1},
	{"sbuf",  0x99, 0x00, 1, 0},
	{"scon",  0x98, 0x00, 1, 0},
	{"sp",    0x81, 0x07, 1, 0},
	{"tcon",  0x88, 0x00, 1, 0},
	{"th0",   0x8C, 0x00, 1, 0},
	{"th1",   0x8D, 0x00, 1, 0},
	{"tl0",   0x8A, 0x00, 1, 0},
	{"tl1",   0x8B, 0x00, 1, 0},
	{"tmod",  0x89, 0x00, 1, 0}
};

#define emit(frag) r_strbuf_appendf(&op->esil, frag)
#define emitf(...) r_strbuf_appendf(&op->esil, __VA_ARGS__)

#define j(frag) emitf(frag, 1 & buf[0], buf[1], buf[2])
#define h(frag) emitf(frag, 7 & buf[0], buf[1], buf[2])
#define k(frag) emitf(frag, bitindex[buf[1]>>3], buf[1] & 7, buf[2])

// on 8051 the stack grows upward and lsb is pushed first meaning
// that on little-endian esil vms =[2] works as indended
#define PUSH1 "1,sp,+=,sp,=[1]"
#define POP1  "sp,[1],1,sp,-=,"
#define PUSH2 "1,sp,+=,sp,=[2],1,sp,+="
#define POP2  "1,sp,-=,sp,[2],1,sp,-=,"
#define CALL(skipbytes) skipbytes",pc,+," PUSH2
#define JMP(skipbytes) skipbytes",+,pc,+="
#define CJMP(target, skipbytes) "?{," ESX_##target "" JMP(skipbytes) ",}"
#define BIT_R "%2$d,%1$d,[1],>>,1,&,"
#define F_BIT_R "%d,%d,[1],>>,1,&,"
#define A_BIT_R a2, a1

#define IRAM_BASE  "0x10000"
#define XRAM_BASE  "0x10100"

#define ES_IB1 IRAM_BASE ",%2$d,+,"
#define ES_IB2 IRAM_BASE ",%3$d,+,"
#define ES_R0I "r%1$d,"
#define ES_AI "A,"
#define ES_R0  "r%1$d,"
#define ES_R1 "r%2$d,"
#define ES_A "A,"
#define ES_L1 "%2$d,"
#define ES_L2 "%3$d,"
#define ES_C "C,"

// signed char variant
#define ESX_L1 "%2$hhd,"
#define ESX_L2 "%2$hhd,"

#define ACC_IB1 "[1],"
#define ACC_IB2 "[1],"
#define ACC_R0I "[1],"
#define ACC_AI  "[1],"
#define ACC_R0  ""
#define ACC_R1  ""
#define ACC_A   ""
#define ACC_L1  ""
#define ACC_L2  ""
#define ACC_C   ""

#define XR(subject)            ES_##subject               ACC_##subject
#define XW(subject)            ES_##subject "="           ACC_##subject
#define XI(subject, operation) ES_##subject operation "=" ACC_##subject

#define TEMPLATE_4(base, format, src4, arg1, arg2) \
	case base + 0x4: \
		h (format(0, src4, arg1, arg2)); break; \
		\
	case base + 0x5: \
		h (format(1, IB1,  arg1, arg2)); break; \
		\
	case base + 0x6: \
	case base + 0x7: \
		j (format(0, R0I,  arg1, arg2)); break; \
		\
	case base + 0x8: case base + 0x9: \
	case base + 0xA: case base + 0xB: \
	case base + 0xC: case base + 0xD: \
	case base + 0xE: case base + 0xF: \
		h (format(0, R0,   arg1, arg2)); break;

#define OP_GROUP_INPLACE_LHS_4(base, lhs, op) TEMPLATE_4(base, OP_GROUP_INPLACE_LHS_4_FMT, L1, lhs, op)
#define OP_GROUP_INPLACE_LHS_4_FMT(databyte, rhs, lhs, op) XR(rhs) XI(lhs, op)

#define OP_GROUP_UNARY_4(base, op) TEMPLATE_4(base, OP_GROUP_UNARY_4_FMT, A, op, XXX)
#define OP_GROUP_UNARY_4_FMT(databyte, lhs, op, xxx) XI(lhs, op)

static void analop_esil(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, const char *buf_asm) {
	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");

	const ut32 a1 = bitindex[buf[1] >> 3];
	const ut32 a2 = buf[1] & 7;
	const ut32 a3 = buf[2];

	switch (buf[0]) {
	// Irregulars sorted by lower nibble
	case 0x00: /* nop  */ emit(","); break;
	case 0x10: /* jbc  */
		emitf(F_BIT_R "&,?{,%d,1,<<,255,^,%d,&=[1],%hhd,3,+,pc,+=,}", A_BIT_R, a2, a1, a3);
		break;
	case 0x20: /* jb   */
		emitf(F_BIT_R "&,?{,%hhd,3,+,pc,+=,}", A_BIT_R, a3);
		break;
	case 0x30: /* jnb  */
		emitf(F_BIT_R "&,!,?{,%hhd,3,+,pc,+=,}", A_BIT_R, a3);
		break;
	case 0x40: /* jc   */ emitf("C,!,?{,%d,2,+,pc,+=,}", (st8)buf[1]); break;
	case 0x50: /* jnc  */ emitf("C,""?{,%d,2,+,pc,+=,}", (st8)buf[1]); break;
	case 0x60: /* jz   */ emitf("A,!,?{,%d,2,+,pc,+=,}", (st8)buf[1]); break;
	case 0x70: /* jnz  */ emitf("A,""?{,%d,2,+,pc,+=,}", (st8)buf[1]); break;
	case 0x80: /* sjmp */ j(ESX_L1 JMP("2")); break;
	case 0x90: /* mov  */ emitf("%d,dptr,=", (buf[1]<<8) + buf[2]); break;
	case 0xA0: /* orl  */ k(BIT_R "C,|="); break;
	case 0xB0: /* anl  */ k(BIT_R "C,&="); break;
	case 0xC0: /* push */ h(XR(IB1) PUSH1); break;
	case 0xD0: /* pop  */ h(POP1 XW(IB1)); break;
	case 0xE0: /* movx */ /* TODO */ break;
	case 0xF0: /* TODO: movx */
		break;
	case 0x11: case 0x31: case 0x51: case 0x71:
	case 0x91: case 0xB1: case 0xD1: case 0xF1:
		emit (CALL ("2"));
		/* fall through */
	case 0x01: case 0x21: case 0x41: case 0x61:
	case 0x81: case 0xA1: case 0xC1: case 0xE1:
		emitf ("0x%x,pc,=", (addr & 0xF800) | ((((ut16)buf[0])<<3) & 0x0700) | buf[1]);
		break;
	case 0x02: /* ljmp  */ emitf (          "%d,pc,=", (ut32)((buf[1] << 8) + buf[2])); break;
	case 0x12: /* lcall */ emitf (CALL ("3")",%d,pc,=", (ut32)((buf[1] << 8) + buf[2])); break;
	case 0x22: /* ret   */ emitf (POP2 "pc,="); break;
	case 0x32: /* reti  */ /* TODO */ break;
	case 0x72: /* orl   */ /* TODO */ break;
	case 0x82: /* anl   */ /* TODO */ break;
	case 0x92: /* mov   */ /* TODO */ break;
	case 0xA2: /* mov   */ /* TODO */ break;
	case 0xB2: /* cpl   */
		emitf ("%d,1,<<,%d,^=[1]", a2, a1);
		break;
	case 0xC2: /* clr   */ /* TODO */ break;

	case 0x03: /* rr   */ emit("1,A,0x101,*,>>,A,="); break;
	case 0x13: /* rrc  */ /* TODO */ break;
	case 0x23: /* rl   */ emit("7,A,0x101,*,>>,A,="); break;
	case 0x33: /* rlc  */ /* TODO */ break;
	case 0x73: /* jmp  */ emit("dptr,A,+,pc,="); break;
	case 0x83: /* movc */ emit("A,dptr,+,[1],A,="); break;
	case 0x93: /* movc */ emit("A,pc,+,[1],A,="); break;
	case 0xA3: /* inc  */ h(XI(IB1, "++")); break;
	case 0xB3: /* cpl  */ emit("1," XI(C, "^")); break;
	case 0xC3: /* clr  */ emit("0,C,="); break;

	// Regulars sorted by upper nibble
	OP_GROUP_UNARY_4(0x00, "++")
	OP_GROUP_UNARY_4(0x10, "--")
	OP_GROUP_INPLACE_LHS_4(0x20, A, "+")

	case 0x34:
		h (XR(L1)  "C,+," XI(A, "+"));
		 break;
	case 0x35:
		h (XR(IB1) "C,+," XI(A, "+")); 
		break;
	case 0x36: case 0x37:
		j (XR(R0I) "C,+," XI(A, "+"));
		break;
	case 0x38: case 0x39:
	case 0x3A: case 0x3B:
	case 0x3C: case 0x3D:
	case 0x3E: case 0x3F:
		h (XR(R0)  "C,+," XI(A, "+"));
		break;
	OP_GROUP_INPLACE_LHS_4 (0x40, A, "|")
	OP_GROUP_INPLACE_LHS_4 (0x50, A, "&")
	OP_GROUP_INPLACE_LHS_4 (0x60, A, "^")
	case 0x74:
		h (XR(L1) XW(A));
		break;
	case 0x75:
		h (XR(L2) XW(IB1));
		break;
	case 0x76: case 0x77:
		j (XR(L1) XW(R0I));
		break;
	case 0x78: case 0x79:
	case 0x7A: case 0x7B:
	case 0x7C: case 0x7D:
	case 0x7E: case 0x7F:
		h (XR(L1) XW(R0));
		break;
	case 0x84: /* div */
		emit("B,!,OV,=,0,A,B,A,/=,A,B,*,-,-,B,=,0,C,=");
		break;
	case 0x85: /* mov */
		h(IRAM_BASE ",%2$d,+,[1]," IRAM_BASE ",%2$d,+,=[1]");
		break;
	case 0x86: case 0x87:
		j (XR(R0I) XW(IB1));
		break;
	case 0x88: case 0x89:
	case 0x8A: case 0x8B:
	case 0x8C: case 0x8D:
	case 0x8E: case 0x8F:
		h (XR(R0) XW(IB1));
		break;
	OP_GROUP_INPLACE_LHS_4(0x90, A, ".")
	case 0xA4:
		/* mul */ emit("8,A,B,*,NUM,>>,NUM,!,!,OV,=,B,=,A,=,0,C,="); break;
	case 0xA5: /* ??? */ emit("0,TRAP"); break;
	case 0xA6: case 0xA7:
		j (XR(IB1) XW(R0I));
		break;
	case 0xA8: case 0xA9:
	case 0xAA: case 0xAB:
	case 0xAC: case 0xAD:
	case 0xAE: case 0xAF:
		h (XR(IB1) XW(R0));
		break;
	case 0xB4:
		h (XR(L1)  XR(A)   "!=,?{,%3$hhd,2,+pc,+=,}");
		break;
	case 0xB5:
		h (XR(IB1) XR(A)   "!=,?{,%3$hhd,2,+pc,+=,}");
		break;
	case 0xB6: case 0xB7:
		j (XR(L1)  XR(R0I) "!=,?{,%3$hhd,2,+pc,+=,}");
		break;
	case 0xB8: case 0xB9:
	case 0xBA: case 0xBB:
	case 0xBC: case 0xBD:
	case 0xBE: case 0xBF:
		h (XR(L1)  XR(R0)  "!=,?{,%3$hhd,2,+pc,+=,}");
		break;
	case 0xC4: /* swap */
		emit("4,A,0x101,*,>>,A,=");
		break;
	case 0xC5:
		/* xch  */ /* TODO */
		break;
	case 0xC6: case 0xC7:
		/* xch  */ /* TODO */
		break;
	case 0xC8: case 0xC9:
	case 0xCA: case 0xCB:
	case 0xCC: case 0xCD:
	case 0xCE: case 0xCF: /* xch  */
		h (XR(A) XR(R0) XW(A) ","  XW(R0));
		break;
	case 0xD2:
		/* setb */ /* TODO */ break;
	case 0xD3:
		/* setb */ /* TODO */ break;
	case 0xD4:
		/* da   */ emit("A,--="); break;
	case 0xD5:
		/* djnz */ h(XI(R0I, "--") "," XR(R0I) CJMP(L2, "2")); break;
	case 0xD6:
		/* xchd */ /* TODO */ break;
	case 0xD7:
		/* xchd */ /* TODO */ break;

	case 0xD8: case 0xD9:
	case 0xDA: case 0xDB:
	case 0xDC: case 0xDD:
	case 0xDE: case 0xDF:
		/* djnz */ h(XI(R0, "--") "," XR(R0) CJMP(L1, "2")); break;

	case 0xE2: case 0xE3:
		/* movx */ 
		j(XRAM_BASE "r%0$d,+,[1]," XW(A)); 
		break;
	case 0xE4:
		/* clr  */ 
		emit("0,A,="); 
		break;
	case 0xE5:
		/* mov  */ 
		h (XR(IB1) XW(A)); 
		break;
	case 0xE6: case 0xE7:
		/* mov  */ 
		j (XR(R0I) XW(A));
		break;
	case 0xE8: case 0xE9:
	case 0xEA: case 0xEB:
	case 0xEC: case 0xED:
	case 0xEE: case 0xEF:
		/* mov  */ 
		h (XR(R0)  XW(A));
		break;
	case 0xF2: case 0xF3:
		/* movx */ 
		j(XR(A) XRAM_BASE "r%0$d,+,=[1]");
		break;
	case 0xF4:
		/* cpl  */ 
		h ("255" XI(A, "^")); 
		break;
	case 0xF5:
		/* mov  */ 
		h (XR(A) XW(IB1)); 
		break;
	case 0xF6: case 0xF7:
		/* mov  */ 
		j (XR(A) XW(R0I)); 
		break;
	case 0xF8: case 0xF9:
	case 0xFA: case 0xFB:
	case 0xFC: case 0xFD:
	case 0xFE: case 0xFF:
		/* mov  */ 
		h (XR(A) XW(R0)); 
		break;
	default: break;
	}
}

static int i8051_hook_reg_read(RAnalEsil *, const char *, ut64 *, int *);

static int i8051_reg_compare(const void *name, const void *reg) {
	return strcmp ((const char*)name, ((RI8015Reg*)reg)->name);
}

static RI8015Reg *i8051_reg_find(const char *name) {
	return (RI8015Reg *) bsearch (
		name, registers,
		sizeof (registers) / sizeof (registers[0]),
		sizeof (registers[0]),
		i8051_reg_compare);
}

static int i8051_reg_get_offset(RAnalEsil *esil, RI8015Reg *ri) {
	ut8 offset = ri->offset;
	if (ri->banked) {
		ut64 psw = 0LL;
		i8051_hook_reg_read (esil, "psw", &psw, NULL);
		offset += psw & 0x18;
	}
	return offset;
}

// dkreuter: It would be nice if we could attach hooks to RRegItems directly.
//           That way we could avoid doing a string lookup on register names
//           as r_reg_get already does this. Also, the anal esil callbacks
//           approach interferes with r_reg_arena_swap.

#define ocbs ((struct r_i8051_user*)esil->cb.user)->cbs

struct r_i8051_user {
	RAnalEsilCallbacks cbs;
};

static int i8051_hook_reg_read(RAnalEsil *esil, const char *name, ut64 *res, int *size) {
	int ret = 0;
	ut64 val = 0LL;
	RI8015Reg *ri;
	RAnalEsilCallbacks cbs = esil->cb;

	if ((ri = i8051_reg_find (name))) {
		ut8 offset = i8051_reg_get_offset(esil, ri);
		ret = r_anal_esil_mem_read (esil, IRAM + offset, (ut8*)res, ri->num_bytes);
	}
	esil->cb = ocbs;
	if (!ret && ocbs.hook_reg_read) {
		ret = ocbs.hook_reg_read (esil, name, res, NULL);
	}
	if (!ret && ocbs.reg_read) {
		ret = ocbs.reg_read (esil, name, &val, NULL);
	}
	esil->cb = cbs;

	return ret;
}

static int i8051_hook_reg_write(RAnalEsil *esil, const char *name, ut64 *val) {
	int ret = 0;
	RI8015Reg *ri;
	RAnalEsilCallbacks cbs = esil->cb;
	if ((ri = i8051_reg_find (name))) {
		ut8 offset = i8051_reg_get_offset(esil, ri);
		ret = r_anal_esil_mem_write (esil, IRAM + offset, (ut8*)val, ri->num_bytes);
	}
	esil->cb = ocbs;
	if (!ret && ocbs.hook_reg_write) {
		ret = ocbs.hook_reg_write (esil, name, val);
	}
	esil->cb = cbs;
	return ret;
}

static int esil_i8051_init (RAnalEsil *esil) {
	if (esil->cb.user) {
		return true;
	}
	esil->cb.user = R_NEW0 (struct r_i8051_user);
	ocbs = esil->cb;
	esil->cb.hook_reg_read = i8051_hook_reg_read;
	esil->cb.hook_reg_write = i8051_hook_reg_write;
	i8051_is_init = true;
	return true;
}

static int esil_i8051_fini (RAnalEsil *esil) {
	if (!i8051_is_init) {
		return false;
	}
	esil->cb = ocbs;
	R_FREE (esil->cb.user);
	i8051_is_init = false;
	return true;
}

static int set_reg_profile(RAnal *anal) {
	const char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"gpr	r0	.8	0	0\n"
		"gpr	r1	.8	1	0\n"
		"gpr	r2	.8	2	0\n"
		"gpr	r3	.8	3	0\n"
		"gpr	r4	.8	4	0\n"
		"gpr	r5	.8	5	0\n"
		"gpr	r6	.8	6	0\n"
		"gpr	r7	.8	7	0\n"
		"gpr	A	.8	8	0\n"
		"gpr	B	.8	9	0\n"
		"gpr	sp	.8	10	0\n"
		"gpr	pc	.16	12	0\n"
		"gpr	dptr	.16	14	0\n"
		"gpr	C	.1	16	0\n"
		"gpr	OV	.1	17	0\n";
	return r_reg_set_profile_string (anal->reg, p);
}


// TODO: Cleanup the code, remove unneeded data copies

static int i8051_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	char *tmp =  NULL;
	char buf_asm[64];
	op->delay = 0;
	r_8051_op o = r_8051_decode (buf, len);
	memset (buf_asm, 0, sizeof (buf_asm));
	if (!o.name) {
		// invalid instruction
		return 0;
	}
	tmp = r_8051_disasm (o, addr, buf_asm, sizeof (buf_asm));
	if (tmp) {
		if (strlen (tmp) < sizeof (buf_asm)) {
			strncpy (buf_asm, tmp, strlen (tmp));
		} else {
			eprintf ("8051 analysis: too big opcode!\n");
			free (tmp);
			op->size = -1;
			return -1;
		}
		free (tmp);
	}
	if (!strncmp (buf_asm, "push", 4)) {
		op->type = R_ANAL_OP_TYPE_UPUSH;
		op->ptr = 0;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 1;
	} else if (!strncmp (buf_asm, "pop", 3)) {
		op->type = R_ANAL_OP_TYPE_POP;
		op->ptr = 0;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -1;
	} else if (!strncmp (buf_asm, "ret", 3)) {
		op->type = R_ANAL_OP_TYPE_RET;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -2;
	} else if (!strncmp (buf_asm, "nop", 3)) {
		op->type = R_ANAL_OP_TYPE_NOP;
	} else if (!strncmp (buf_asm, "inv", 3)) {
		op->type = R_ANAL_OP_TYPE_ILL;
	} else if ((!strncmp (buf_asm, "inc", 3)) ||
		(!strncmp (buf_asm, "add", 3))) {
		op->type = R_ANAL_OP_TYPE_ADD;
	} else if ((!strncmp (buf_asm, "dec", 3)) ||
		(!strncmp (buf_asm, "sub", 3))) {
		op->type = R_ANAL_OP_TYPE_SUB;
	} else if (!strncmp (buf_asm, "mov", 3)) {
		op->type = R_ANAL_OP_TYPE_MOV;
	} else if (*buf_asm && !strncmp (buf_asm+1, "call", 4)) {
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = o.addr;
		op->fail = addr + o.length;
	} else {
		/* CJNE, DJNZ, JC, JNC, JZ, JB, JNB, LJMP, SJMP */
		if (buf_asm[0]=='j' || (buf_asm[0] && buf_asm[1] == 'j')) {
			op->type = R_ANAL_OP_TYPE_JMP;
			if (o.operand == OFFSET) {
				op->jump = o.addr + addr + o.length;
			} else {
				op->jump = o.addr;
			}
			op->fail = addr + o.length;
		}
	}
	if (anal->decode) {
		ut8 copy[3] = {0, 0, 0};
		memcpy (copy, buf, len >= 3 ? 3 : len);
		analop_esil (anal, op, addr, copy, buf_asm);
	}
	return op->size = o.length;
}

RAnalPlugin r_anal_plugin_8051 = {
	.name = "8051",
	.arch = "8051",
	.bits = 8|16,
	.desc = "8051 CPU code analysis plugin",
	.license = "LGPL3",
	.op = &i8051_op,
	.set_reg_profile = set_reg_profile,
	.esil_init = esil_i8051_init,
	.esil_fini = esil_i8051_fini
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_8051,
	.version = R2_VERSION
};
#endif
