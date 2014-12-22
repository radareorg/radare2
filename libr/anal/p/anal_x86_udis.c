/* radare - LGPL - Copyright 2009-2014 - nibble, pancake */

#include <r_lib.h>
#include <r_types.h>
#include <r_anal.h>
#include <r_util.h>

#include "udis86/types.h"
#include "udis86/extern.h"
#include "esil.h"

static st64 getval(ud_operand_t *op);
// XXX Copypasta from udis
#define UD_REG_TAB_SIZE (sizeof (ud_reg_tab)/sizeof (*ud_reg_tab))
static const char* ud_reg_tab[] =
{
  "al",   "cl",   "dl",   "bl",
  "ah",   "ch",   "dh",   "bh",
  "spl",  "bpl",  "sil",  "dil",
  "r8b",  "r9b",  "r10b", "r11b",
  "r12b", "r13b", "r14b", "r15b",

  "ax",   "cx",   "dx",   "bx",
  "sp",   "bp",   "si",   "di",
  "r8w",  "r9w",  "r10w", "r11w",
  "r12w", "r13w", "r14w", "r15w",

  "eax",  "ecx",  "edx",  "ebx",
  "esp",  "ebp",  "esi",  "edi",
  "r8d",  "r9d",  "r10d", "r11d",
  "r12d", "r13d", "r14d", "r15d",

  "rax",  "rcx",    "rdx",    "rbx",
  "rsp",  "rbp",    "rsi",    "rdi",
  "r8",   "r9",     "r10",    "r11",
  "r12",  "r13",    "r14",    "r15",

  "es",   "cs",   "ss",   "ds",
  "fs",   "gs",

  "cr0",  "cr1",    "cr2",    "cr3",
  "cr4",  "cr5",    "cr6",    "cr7",
  "cr8",  "cr9",    "cr10",   "cr11",
  "cr12", "cr13",   "cr14",   "cr15",

  "dr0",  "dr1",    "dr2",    "dr3",
  "dr4",  "dr5",    "dr6",    "dr7",
  "dr8",  "dr9",    "dr10",   "dr11",
  "dr12", "dr13",   "dr14",   "dr15",

  "mm0",  "mm1",    "mm2",    "mm3",
  "mm4",  "mm5",    "mm6",    "mm7",

  "st0",  "st1",    "st2",    "st3",
  "st4",  "st5",    "st6",    "st7",

  "xmm0", "xmm1",   "xmm2",   "xmm3",
  "xmm4", "xmm5",   "xmm6",   "xmm7",
  "xmm8", "xmm9",   "xmm10",  "xmm11",
  "xmm12","xmm13",  "xmm14",  "xmm15",

  "ymm0", "ymm1",   "ymm2",   "ymm3",
  "ymm4", "ymm5",   "ymm6",   "ymm7",
  "ymm8", "ymm9",   "ymm10",  "ymm11",
  "ymm12","ymm13",  "ymm14",  "ymm15",

  "rip"
};

static int getarg(char *src, struct ud *u, st64 mask, int idx, int regsz) {
	ud_operand_t *op = &u->operand[idx];
	st64 n;
	src[0] = 0;
	if (!mask) mask = UT64_MAX;

	switch (op->type) {
	case UD_OP_PTR:
	case UD_OP_CONST:
	case UD_OP_JIMM:
	case UD_OP_IMM:
		n = getval (op) & mask;
		//mask = UT64_MAX; // uhm?
		if (op->type == UD_OP_JIMM) n += u->pc;
		if (n>=0 && n<256)
			sprintf (src, "%"PFMT64d, n & mask);
		else sprintf (src, "0x%"PFMT64x, n&mask);
		break;
	case UD_OP_REG:
		idx = op->base-UD_R_AL;
		if (idx>=0 && idx<UD_REG_TAB_SIZE)
			strcpy (src, ud_reg_tab[idx]);
		break;
	case UD_OP_MEM:
		n = getval (op);
		// TODO ->scale
		if (op->base != UD_NONE) {
			idx = op->base-UD_R_AL;
			if (idx>=0 && idx<UD_REG_TAB_SIZE) {
				sprintf (src, "%s", ud_reg_tab[idx]);
                                src += strlen (src);
                                if (op->index != UD_NONE) {
                                        idx = op->index - UD_R_AL;
                                        if (idx >= 0 && idx < UD_REG_TAB_SIZE) {
                                                sprintf (src, ",%d,%s,*,+",
						op->scale, ud_reg_tab[idx]);
					}
                                        src += strlen (src);
                                }
                                if (u->mnemonic == UD_Ilea) {
					if ((st16)n>0) sprintf (src, ",%"PFMT64d",+", n);
					else if ((st16)n<0) sprintf (src, ",%"PFMT64d",-", UT32_MAX-n);
				} else if ((st16)n >= -256 && (st16)n < 256) {
					char nb = (char)n;
					char absn = ((st16)nb<0)? -nb: nb;
					if (n==0) sprintf (src, ",[%d]", regsz);
					else sprintf (src, ",%d,%c,[%d]",
						absn, nb<0?'-':'+', regsz);
				} else {
					sprintf (src, ",0x%"PFMT64x",+,[%d]",
						mask & n, regsz);
				}
			} else {
				/* If UDis86 works properly, it will never reach this point.
				 * Only useful for debug purposes ("unknown reg" is clearer
				 * than an empty string, right?)
				 */
			}
		} else sprintf (src, "0x%"PFMT64x",[%d]", n & mask, regsz);
		break;
	default:
		break;
	}

	return 0;
}

static st64 getval(ud_operand_t *op) {
	int bits = op->size;
	switch (op->type) {
	case UD_OP_PTR:
		return (op->lval.ptr.seg<<4) + (op->lval.ptr.off & 0xFFFF);
	default:
		break;
	}
	if (!bits) bits = 32;
	if (op->signed_lval) { // TODO: honor sign
		switch (bits) {
		case 8: return (st64)(char) (op->lval.sbyte);
		case 16: return (st64)(short) op->lval.uword;
		case 32: return (ut64)(ut32)(op->lval.udword&UT32_MAX);
		case 64: return op->lval.uqword;
		}
	} else {
		switch (bits) {
		case 8: return (st64)(char)(255-op->lval.sbyte); // XXX?
		case 16: return (st64)(short) (op->lval.uword& UT16_MAX);
		case 32: return (ut64)(ut32)(op->lval.udword & UT32_MAX);
		case 64: return op->lval.uqword;
		}
	}
	return 0LL;
}

int x86_udis86_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	const char *pc = anal->bits==64? "rip": anal->bits==32? "eip": "ip";
	const char *sp = anal->bits==64? "rsp": anal->bits==32? "esp": "sp";
        const char *bp = anal->bits==64? "rbp": anal->bits==32? "ebp": "bp";
	int delta, oplen, regsz = 4;
	char str[64], src[32], dst[32];
	struct ud u;
	switch (anal->bits) {
	case 64: regsz = 8; break;
	case 16: regsz = 2; break;
	default:
	case 32: regsz = 4; break;
	}

	UDis86Esil *handler;
	UDis86OPInfo info = {0, anal->bits, (1LL << anal->bits) - 1, regsz, 0, pc, sp, bp};
	memset (op, '\0', sizeof (RAnalOp));
	op->addr = addr;
	op->jump = op->fail = -1;
	op->ptr = op->val = -1;

	ud_init (&u);
	ud_set_pc (&u, addr);
	ud_set_mode (&u, anal->bits);
	ud_set_syntax (&u, NULL);
	ud_set_input_buffer (&u, data, len);
	ud_disassemble (&u);

	oplen = op->size = ud_insn_len (&u);
	r_strbuf_init (&op->esil);
	if (anal->decode && (handler = udis86_esil_get_handler (u.mnemonic))) {
		info.oplen = oplen;
		//if (anal->bits==32)
			info.bitmask = UT32_MAX;
		if (handler->argc > 0) {
			info.n = getval (u.operand);
			getarg (dst, &u, info.bitmask, 0, regsz);
			if (handler->argc > 1) {
				getarg (src, &u, info.bitmask, 1, regsz);
				if (handler->argc > 2)
					getarg (str, &u, info.bitmask, 2, regsz);
			}
		}
		handler->callback (&info, op, dst, src, str);
	}
#if 0
	u->pfx_seg   = 0;
	u->pfx_opr   = 0;
	u->pfx_adr   = 0;
	u->pfx_lock  = 0;
	u->pfx_repne = 0;
	u->pfx_rep   = 0;
	u->pfx_repe  = 0;
	u->pfx_rex   = 0;
	u->pfx_str   = 0;
#endif
	op->prefix = 0;
	if (u.pfx_rep) op->prefix |= R_ANAL_OP_PREFIX_REP;
	if (u.pfx_repe) op->prefix |= R_ANAL_OP_PREFIX_REP;
	if (u.pfx_repne) op->prefix |= R_ANAL_OP_PREFIX_REPNE;
	if (u.pfx_lock) op->prefix |= R_ANAL_OP_PREFIX_LOCK;
	switch (u.mnemonic) {
	case UD_Iinvalid:
		oplen = op->size = -1;
		return -1;
		break;
	case UD_Itest:
	case UD_Icmp:
		op->type = R_ANAL_OP_TYPE_CMP;
		// TODO: support 2nd parameter too?
		switch (u.operand[0].type) {
		case UD_OP_MEM:
			op->refptr = u.operand[0].size /8;
			switch (u.operand[0].base) {
			case UD_R_RIP:
				// Self modifying code? relative local vars
				switch (u.operand[1].size) {
				case  8:
				case 16:
				case 32: delta = u.operand[1].lval.udword; break;
				case 64: delta = u.operand[1].lval.uqword; break;
				default: delta = u.operand[1].lval.udword; break;
				}
				op->ptr = addr + oplen + delta;
				break;
			case UD_R_RBP:
				op->stackop = R_ANAL_STACK_SET;
				op->ptr = getval (&u.operand[0]); //-(st64)u.operand[0].lval.sbyte; //getval (&u.operand[0]);
				op->ptr = (st64)((char)u.operand[0].lval.sbyte); //getval (&u.operand[0]);
				// if positive = arg
				// if negative = var
				break;
			default:
				op->ptr = getval (&u.operand[0]);
				break;
			}
			break;
		case UD_OP_IMM:
			op->ptr = getval (&u.operand[0]);
		default:
			break;
		}
		switch (u.operand[1].type) {
		case UD_OP_MEM:
			op->refptr = u.operand[0].size /8;
			switch (u.operand[1].base) {
			case UD_R_RIP:
				// Self modifying code? relative local vars
				delta = u.operand[1].lval.uword;
				op->ptr = addr + oplen + delta;
				break;
			case UD_R_RBP:
				op->stackop = R_ANAL_STACK_SET;
				op->ptr = getval (&u.operand[1]); //-(st64)u.operand[0].lval.sbyte; //getval (&u.operand[0]);
				op->ptr = (st64)((char)u.operand[1].lval.sbyte); //getval (&u.operand[0]);
				// if positive = arg
				// if negative = var
				break;
			default:
				op->ptr = getval (&u.operand[1]);
				break;
			}
			break;
		case UD_OP_IMM:
			op->ptr = getval (&u.operand[0]);
		default:
			break;
		}
		break;
	case UD_Isalc: // ??
		// al = cf
		break;
	case UD_Ixor:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case UD_Ior:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case UD_Iand:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case UD_Isar:
		op->type = R_ANAL_OP_TYPE_SAR;
		break;
	// XXX: sal ?!?
	case UD_Ishl:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case UD_Ishr:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case UD_Irol:
		op->type = R_ANAL_OP_TYPE_ROL;
		break;
	case UD_Iror:
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	case UD_Iint1:
	case UD_Iint3:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case UD_Iint:
		op->type = R_ANAL_OP_TYPE_SWI;
		op->val = u.operand[0].lval.uword;
		break;
	case UD_Ilea:
	case UD_Imov:
		op->type = R_ANAL_OP_TYPE_MOV;
		switch (u.operand[0].type) {
		case UD_OP_MEM:
			op->refptr = u.operand[0].size/8;
			switch (u.operand[0].base) {
			case UD_R_RIP:
				// Self modifying code? relative local vars
				// op->type == 9
				//switch (op->size) {
				switch (u.operand[0].size) {
				case  8:
				case 16:
				case 32: delta = u.operand[0].lval.udword; break;
				case 64: delta = u.operand[0].lval.uqword; break;
				default: delta = u.operand[0].lval.udword; break;
				}
				op->ptr = addr + oplen + delta;
				break;
			case UD_R_RBP:
				op->stackop = R_ANAL_STACK_SET;
				op->ptr = getval (&u.operand[0]); //-(st64)u.operand[0].lval.sbyte; //getval (&u.operand[0]);
				// op->ptr = (st64)((char)u.operand[0].lval.sbyte); //getval (&u.operand[0]);
				// if positive = arg
				// if negative = var
				break;
			default:
				/* nothing to do here yet */
				op->ptr = getval (&u.operand[1]);
				break;
			}
			break;
		default:
			switch (u.operand[1].type) {
			case UD_OP_MEM:
				op->refptr = u.operand[1].size /8;
				switch (u.operand[1].base) {
				case UD_R_RIP:
					switch (u.operand[1].size) {
					case  8:
					case 16:
					case 32: delta = u.operand[1].lval.udword; break;
					case 64: delta = u.operand[1].lval.uqword; break;
					default: delta = u.operand[1].lval.udword; break;
					}
					op->ptr = addr + oplen + delta;
					break;
				case UD_R_RBP:
					op->stackop = R_ANAL_STACK_GET;
					op->ptr = getval (&u.operand[1]);
					// op->ptr = (st64)((char)u.operand[1].lval.sbyte); //getval (&u.operand[0]);
					// if positive = arg
					// if negative = var
					break;
				default:
					/* nothing to do here yet */
					op->ptr = getval (&u.operand[1]); //-(st64)u.operand[0].lval.sbyte; //getval (&u.operand[0]);
					break;
				}
				break;
			default:
				op->ptr = getval (&u.operand[1]);
				// XX
				break;
			}
			break;
		}
		op->stackptr = regsz;
		break;
	case UD_Ipush:
	case UD_Ipusha:
	case UD_Ipushad:
	case UD_Ipushfq:
	case UD_Ipushfd:
	case UD_Ipushfw:
		switch (u.operand[0].type) {
		case UD_OP_CONST:
		case UD_OP_JIMM:
		case UD_OP_IMM:
			op->type = R_ANAL_OP_TYPE_PUSH;
			op->ptr = getval (&u.operand[0]);
			break;
		case UD_OP_REG:
		case UD_OP_PTR:
		case UD_OP_MEM:
		default:
			op->type = R_ANAL_OP_TYPE_UPUSH;
			op->ptr = 0;
			break;
		}
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = regsz;
		break;
	case UD_Ipop:
	case UD_Ipopa:
	case UD_Ipopad:
	case UD_Ipopfw:
	case UD_Ipopfd:
	case UD_Ipopfq:
		op->type = R_ANAL_OP_TYPE_POP;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -regsz;
		break;
	case UD_Ileave:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -regsz;
		break;
	case UD_Iadd:
	case UD_Isub:
		op->type = (u.mnemonic==UD_Iadd)? R_ANAL_OP_TYPE_ADD: R_ANAL_OP_TYPE_SUB;
		op->ptr = 0;
		op->stackptr = 0;
		if (u.operand[0].type == UD_OP_REG) {
			if (u.operand[0].base == UD_R_RSP) {
				int o = (int)getval (&u.operand[1]);
				op->stackop = R_ANAL_STACK_INC;
				if (u.mnemonic ==UD_Iadd) {
					op->stackptr = -o;
				} else {
					op->stackptr = o;
				}
			}
			if (u.operand[1].type != UD_OP_REG)
				op->val = getval (&u.operand[1]);
		}
		op->stackptr = 4;
		break;
	case UD_Iadc:
	case UD_Iinc:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case UD_Isbb:
	case UD_Idec:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case UD_Ijmp:
		switch (u.operand[0].type) {
		case UD_OP_MEM:
			op->ptr = getval (&u.operand[0]);
			op->type = R_ANAL_OP_TYPE_UJMP;
			break;
		case UD_OP_REG:
			op->type = R_ANAL_OP_TYPE_UJMP;
			break;
		default:
			op->type = R_ANAL_OP_TYPE_JMP;
#if 0
{
ut16 a = (op->lval.ptr.seg & 0xFFFF);
ut16 b = (op->lval.ptr.off);
switch (op->size) {
case 32:
	sprintf (src, "%04x:%04x", a, b & 0xFFFF);
	break;
case 48:
	sprintf (src, "%04x:%04x", a, b);
	break;
default:
	eprintf ("FUCK YOU\n");
}
}
#endif
			if (u.operand[0].type==UD_OP_PTR) {
				op->jump = getval (&u.operand[0]);
			} else {
				if (anal->bits==16) {
					// honor segment
					op->jump = (addr&0xf0000) + oplen + \
						((((addr&0xffff)+getval (&u.operand[0]))&0xffff));
				} else {
					op->jump = addr + oplen + (int)getval (&u.operand[0]);
				}
			}
		}
		break;
	case UD_Ije:
	case UD_Ijne:
	case UD_Ijb:
	case UD_Ijbe:
	case UD_Ija:
	case UD_Ijae:
	case UD_Ijs:
	case UD_Ijns:
	case UD_Ijo:
	case UD_Ijno:
	case UD_Ijp:
	case UD_Ijnp:
	case UD_Ijl:
	case UD_Ijge:
	case UD_Ijle:
	case UD_Ijg:
	case UD_Ijcxz:
	case UD_Iloop:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + oplen + (int)getval (&u.operand[0]);
		op->fail = addr+oplen;
		break;
	case UD_Icall:
		op->type = R_ANAL_OP_TYPE_CALL;
		switch (u.operand[0].type) {
		case UD_OP_REG:
			op->type = R_ANAL_OP_TYPE_UCALL;
			op->jump = 0; // EAX, EBX, ... use anal->reg
			break;
		case UD_OP_PTR:
			op->jump = (int)getval (&u.operand[0]);
			break;
		case UD_OP_IMM:
		case UD_OP_MEM:
		default:
			op->jump = addr + oplen + (int)getval (&u.operand[0]);
		}
		op->fail = addr + oplen;
		break;
	case UD_Ihlt:
		op->type = R_ANAL_OP_TYPE_TRAP; //HALT;
		break;
	case UD_Iin:
	case UD_Iout:
		op->type = R_ANAL_OP_TYPE_IO;
		break;
	case UD_Iret:
	case UD_Iiretd:
	case UD_Iretf:
	case UD_Isysret:
		op->type = R_ANAL_OP_TYPE_RET;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -regsz;
		break;
	case UD_Isyscall:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case UD_Inop:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	default:
		break;
	}
	return oplen;
}

static int set_reg_profile(RAnal *anal) {
	const char *p = NULL;
	switch (anal->bits) {
	case 16: p=
		"=pc	ip\n"
		"=sp	sp\n"
		"=bp	bp\n"
		"=a0	ax\n"
		"=a1	bx\n"
		"=a2	cx\n"
		"=a3	di\n"
		"gpr	ip	.16	48	0\n"
		"gpr	ax	.16	24	0\n"
		"gpr	ah	.8	24	0\n"
		"gpr	al	.8	25	0\n"
		"gpr	bx	.16	0	0\n"
		"gpr	bh	.8	0	0\n"
		"gpr	bl	.8	1	0\n"
		"gpr	cx	.16	4	0\n"
		"gpr	ch	.8	4	0\n"
		"gpr	cl	.8	5	0\n"
		"gpr	dx	.16	8	0\n"
		"gpr	dh	.8	8	0\n"
		"gpr	dl	.8	9	0\n"
		"gpr	sp	.16	60	0\n"
		"gpr	bp	.16	20	0\n"
		"gpr	si	.16	12	0\n"
		"gpr	di	.16	16	0\n"
		"seg	cs	.16	52	0\n"
		"gpr	flags	.16	56	0\n"
		"gpr	cf	.1	.448	0\n"
		"flg	flag_p	.1	.449	0\n"
		"flg	flag_a	.1	.450	0\n"
		"gpr	zf	.1	.451	0\n"
		"gpr	sf	.1	.452	0\n"
		"flg	flag_t	.1	.453	0\n"
		"flg	flag_i	.1	.454	0\n"
		"flg	flag_d	.1	.455	0\n"
		"flg	of	.1	.456	0\n"
		"flg	flag_r	.1	.457	0\n";
#if 0
		"drx	dr0	.32	0	0\n"
		"drx	dr1	.32	4	0\n"
		"drx	dr2	.32	8	0\n"
		"drx	dr3	.32	12	0\n"
		//"drx	dr4	.32	16	0\n"
		//"drx	dr5	.32	20	0\n"
		"drx	dr6	.32	24	0\n"
		"drx	dr7	.32	28	0\n"
#endif
		break;
	case 32: p=
		"=pc	eip\n"
		"=sp	esp\n"
		"=bp	ebp\n"
		"=a0	eax\n"
		"=a1	ebx\n"
		"=a2	ecx\n"
		"=a3	edi\n"
		"gpr	eip	.32	48	0\n"
		"gpr	ip	.16	48	0\n"
		"gpr	oeax	.32	44	0\n"
		"gpr	eax	.32	24	0\n"
		"gpr	ax	.16	24	0\n"
		"gpr	ah	.8	24	0\n"
		"gpr	al	.8	25	0\n"
		"gpr	ebx	.32	0	0\n"
		"gpr	bx	.16	0	0\n"
		"gpr	bh	.8	0	0\n"
		"gpr	bl	.8	1	0\n"
		"gpr	ecx	.32	4	0\n"
		"gpr	cx	.16	4	0\n"
		"gpr	ch	.8	4	0\n"
		"gpr	cl	.8	5	0\n"
		"gpr	edx	.32	8	0\n"
		"gpr	dx	.16	8	0\n"
		"gpr	dh	.8	8	0\n"
		"gpr	dl	.8	9	0\n"
		"gpr	esp	.32	60	0\n"
		"gpr	sp	.16	60	0\n"
		"gpr	ebp	.32	20	0\n"
		"gpr	bp	.16	20	0\n"
		"gpr	esi	.32	12	0\n"
		"gpr	si	.16	12	0\n"
		"gpr	edi	.32	16	0\n"
		"gpr	di	.16	16	0\n"
		"seg	xfs	.32	36	0\n"
		"seg	xgs	.32	40	0\n"
		"seg	xcs	.32	52	0\n"
		"seg	cs	.16	52	0\n"
		"seg	xss	.32	52	0\n"
		"gpr	eflags	.32	56	0	c1p.a.zstido.n.rv\n"
		"gpr	flags	.16	56	0\n"
		"gpr	cf	.1	.448	0\n"
		"flg	flag_p	.1	.449	0\n"
		"flg	flag_a	.1	.450	0\n"
		"gpr	zf	.1	.451	0\n"
		"gpr	sf	.1	.452	0\n"
		"flg	flag_t	.1	.453	0\n"
		"flg	flag_i	.1	.454	0\n"
		"flg	flag_d	.1	.455	0\n"
		"flg	of	.1	.456	0\n"
		"flg	flag_r	.1	.457	0\n"
		"drx	dr0	.32	0	0\n"
		"drx	dr1	.32	4	0\n"
		"drx	dr2	.32	8	0\n"
		"drx	dr3	.32	12	0\n"
		//"drx	dr4	.32	16	0\n"
		//"drx	dr5	.32	20	0\n"
		"drx	dr6	.32	24	0\n"
		"drx	dr7	.32	28	0\n";
		 break;
	default: p=
		 "=pc	rip\n"
		 "=sp	rsp\n"
		 "=bp	rbp\n"
		 "=a0	rax\n"
		 "=a1	rbx\n"
		 "=a2	rcx\n"
		 "=a3	rdx\n"
		 "# no profile defined for x86-64\n"
		 "gpr	r15	.64	0	0\n"
		 "gpr	r14	.64	8	0\n"
		 "gpr	r13	.64	16	0\n"
		 "gpr	r12	.64	24	0\n"
		 "gpr	rbp	.64	32	0\n"
		 "gpr	ebp	.32	32	0\n"
		 "gpr	rbx	.64	40	0\n"
		 "gpr	ebx	.32	40	0\n"
		 "gpr	bx	.16	40	0\n"
		 "gpr	bh	.8	40	0\n"
		 "gpr	bl	.8	41	0\n"
		 "gpr	r11	.64	48	0\n"
		 "gpr	r10	.64	56	0\n"
		 "gpr	r9	.64	64	0\n"
		 "gpr	r8	.64	72	0\n"
		 "gpr	rax	.64	80	0\n"
		 "gpr	eax	.32	80	0\n"
		 "gpr	rcx	.64	88	0\n"
		 "gpr	ecx	.32	88	0\n"
		 "gpr	rdx	.64	96	0\n"
		 "gpr	edx	.32	96	0\n"
		 "gpr	rsi	.64	104	0\n"
		 "gpr	esi	.32	104	0\n"
		 "gpr	rdi	.64	112	0\n"
		 "gpr	edi	.32	112	0\n"
		 "gpr	oeax	.64	120	0\n"
		 "gpr	rip	.64	128	0\n"
		 "seg	cs	.64	136	0\n"
		 //"flg	eflags	.64	144	0\n"
		 "gpr	eflags	.32	144	0	c1p.a.zstido.n.rv\n"
		 "gpr	cf	.1	.1152	0\n"
		 "flg	flag_p	.1	.1153	0\n"
		 "flg	flag_a	.1	.1154	0\n"
		 "gpr	zf	.1	.1155	0\n"
		 "gpr	sf	.1	.1156	0\n"
		 "flg	flag_t	.1	.1157	0\n"
		 "flg	flag_i	.1	.1158	0\n"
		 "flg	flag_d	.1	.1159	0\n"
		 "flg	of	.1	.1160	0\n"
		 "flg	flag_r	.1	.1161	0\n"
		 "gpr	rsp	.64	152	0\n"
		 "seg	ss	.64	160	0\n"
		 "seg	fs_base	.64	168	0\n"
		 "seg	gs_base	.64	176	0\n"
		 "seg	ds	.64	184	0\n"
		 "seg	es	.64	192	0\n"
		 "seg	fs	.64	200	0\n"
		 "seg	gs	.64	208	0\n"
		 "drx	dr0	.32	0	0\n"
		 "drx	dr1	.32	4	0\n"
		 "drx	dr2	.32	8	0\n"
		 "drx	dr3	.32	12	0\n"
		 "drx	dr6	.32	24	0\n"
		 "drx	dr7	.32	28	0\n";
		 break;
	}
	return r_reg_set_profile_string (anal->reg, p);
}

struct r_anal_plugin_t r_anal_plugin_x86_udis = {
	.name = "x86.udis",
	.desc = "X86 analysis plugin (udis86 backend)",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_X86,
	.esil = R_TRUE,
	.bits = 16|32|64,
	.init = NULL,
	.fini = NULL,
	.op = &x86_udis86_op,
	.set_reg_profile = &set_reg_profile,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_x86_udis
};
#endif
