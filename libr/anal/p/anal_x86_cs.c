/* radare2 - LGPL - Copyright 2013-2015 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>

// TODO: when capstone-4 is released, add proper check here

#if CS_NEXT_VERSION>0
#define HAVE_CSGRP_PRIVILEGE 1
#else
#define HAVE_CSGRP_PRIVILEGE 0
#endif

#define USE_ITER_API 0

#if CS_API_MAJOR < 2
#error Old Capstone not supported
#endif

#define esilprintf(op, fmt, arg...) r_strbuf_setf (&op->esil, fmt, ##arg)
#define INSOP(n) insn->detail->x86.operands[n]
#define INSOPS insn->detail->x86.op_count

/**
 * Translates operand N to esil
 *
 * @param  handle  csh
 * @param  insn    cs_insn
 * @param  n       Operand index
 * @param  set     if 1 it adds set (=) to the operand
 * @param  setoper Extra operation for the set (^, -, +, etc...)
 * @return         char* with the esil operand
 */
static char *getarg(csh handle, cs_insn *insn, int n, int set, char *setop) {
	char buf[64];
	char *setarg = setop? setop : "";
	cs_x86_op op = {0};
	if (!insn->detail)
		return NULL;
	buf[0] = 0;
	if (n<0 || n>=INSOPS)
		return NULL;
	op = INSOP (n);
	switch (op.type) {
	case X86_OP_INVALID:
		return strdup ("invalid");
	case X86_OP_REG:
		if (set == 1) {
			snprintf (buf, sizeof (buf), "%s,%s=",
				cs_reg_name (handle, op.reg), setarg);
			return strdup (buf);
		} else {
			return strdup (cs_reg_name (handle, op.reg));
		}
	case X86_OP_IMM:
		if (set == 1)
			snprintf (buf, sizeof (buf), "%"PFMT64d",%s=[%d]",
				(ut64)op.imm, setarg, op.size);
		else
			snprintf (buf, sizeof (buf), "%"PFMT64d, (ut64)op.imm);
		return strdup (buf);
	case X86_OP_MEM:
		{
		const char *base = cs_reg_name (handle, op.mem.base);
		const char *index = cs_reg_name (handle, op.mem.index);
		int scale = op.mem.scale;
		st64 disp = op.mem.disp;
		if (scale>1) {
			if (set>1) {
				if (base) {
					if (disp) {
						snprintf (buf, sizeof (buf), "%s,0x%x,+,%d,*", base, (int)disp, scale);
					} else {
						snprintf (buf, sizeof (buf), "%s,%d,*", base, scale);
					}
				} else {
					if (disp) {
						snprintf (buf, sizeof (buf), "%d,0x%x,*,[%d]", scale, (int)disp, op.size);
					} else {
						snprintf (buf, sizeof (buf), "%d,[%d]", scale, op.size);
					}
				}
			} else {
				if (base) {
					if (disp) {
						snprintf (buf, sizeof (buf), "0x%x,%s,+,%d,*,[%d]", (int)disp, base, scale, op.size);
					} else {
						snprintf (buf, sizeof (buf), "%s,%d,*,[%d]", base, scale, op.size);
					}
				} else {
					if (disp) {
						snprintf (buf, sizeof (buf), "0x%x,%d,*,[%d]", (int)disp, scale, op.size);
					} else {
						snprintf (buf, sizeof (buf), "%d,[%d]", scale, op.size);
					}
				}
			}
		} else {
			if (set>1) {
				if (base) {
					if (disp) {
						int v = (int)disp;
						if (v<0) {
							snprintf (buf, sizeof (buf), "0x%x,%s,-", -v, base);
						} else {
							snprintf (buf, sizeof (buf), "0x%x,%s,+", v, base);
						}
					} else {
						snprintf (buf, sizeof (buf), "%s", base);
					}
				} else {
					if (disp) {
						snprintf (buf, sizeof (buf), "%d", (int)disp);
					}
				}
			} else {
				if (base) {
					if (disp) {
						int v = (int)disp;
						if (v<0) {
							snprintf (buf, sizeof (buf), "0x%x,%s,-,%s%s[%d]",
								-(int)disp, base, setarg, set?"=":"", op.size);
						} else {
							snprintf (buf, sizeof (buf), "0x%x,%s,+,%s%s[%d]",
								(int)disp, base, setarg, set?"=":"", op.size);
						}
					} else {
						if (index)
							if (set)
								snprintf (buf, sizeof (buf), "%s,%s,+,%s=[%d]",
									base, index, setarg, op.size);
							else
								snprintf (buf, sizeof (buf), "%s,%s,+", base, index);
						else
							snprintf (buf, sizeof (buf), "%s,%s%s[%d]",
								base, setarg, set?"=":"", op.size);
					}
				} else {
					if (disp) {
						snprintf (buf, sizeof (buf), "0x%x,%s%s[%d]",
							(int)disp, setarg, set?"=":"", op.size);
					} else {
						snprintf (buf, sizeof (buf), "%s%s,[%d]",
							setarg, set?"=":"", op.size);
					}
				}
			}
		}
		}
		return strdup (buf);
	case X86_OP_FP:
		break;
	}
	return strdup ("PoP");
}

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	csh handle;
#if USE_ITER_API
	static
#endif
	cs_insn *insn = NULL;
	int mode = (a->bits==64)? CS_MODE_64:
		(a->bits==32)? CS_MODE_32:
		(a->bits==16)? CS_MODE_16: 0;
	int n, ret = cs_open (CS_ARCH_X86, mode, &handle);
	int regsz = 4;

	if (ret != CS_ERR_OK) {
		return 0;
	}
	switch (a->bits) {
	case 64: regsz = 8; break;
	case 16: regsz = 2; break;
	default:
	case 32: regsz = 4; break;
	}
	memset (op, '\0', sizeof (RAnalOp));
	op->cycles = 1; // aprox
	op->type = R_ANAL_OP_TYPE_NULL;
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->ptr = op->val = UT64_MAX;
	op->src[0] = NULL;
	op->src[1] = NULL;
	op->size = 0;
	op->delay = 0;
	r_strbuf_init (&op->esil);
	cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	// capstone-next
#if USE_ITER_API
	{
		ut64 naddr = addr;
		size_t size = len;
		if (insn == NULL)
			insn = cs_malloc (handle);
		n = cs_disasm_iter (handle, (const uint8_t**)&buf,
			&size, (uint64_t*)&naddr, insn);
	}
#else
	n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
#endif
	if (n<1) {
		op->type = R_ANAL_OP_TYPE_ILL;
	} else {
		int rs = a->bits/8;
		const char *pc = (a->bits==16)?"ip":
			(a->bits==32)?"eip":"rip";
		const char *sp = (a->bits==16)?"sp":
			(a->bits==32)?"esp":"rsp";
		const char *bp = (a->bits==16)?"bp":
			(a->bits==32)?"ebp":"rbp";
		op->size = insn->size;
		op->family = 0;
		op->prefix = 0;
		switch (insn->detail->x86.prefix[0]) {
		case X86_PREFIX_REPNE:
			op->prefix |= R_ANAL_OP_PREFIX_REPNE;
			break;
		case X86_PREFIX_REP:
			op->prefix |= R_ANAL_OP_PREFIX_REP;
			break;
		case X86_PREFIX_LOCK:
			op->prefix |= R_ANAL_OP_PREFIX_LOCK;
			break;
		}
		switch (insn->id) {
		case X86_INS_FNOP:
		case X86_INS_NOP:
		case X86_INS_PAUSE:
			op->type = R_ANAL_OP_TYPE_NOP;
			if (a->decode)
				esilprintf (op, ",");
			break;
		case X86_INS_HLT:
			op->type = R_ANAL_OP_TYPE_TRAP;
			break;
		case X86_INS_FBLD:
		case X86_INS_FBSTP:
		case X86_INS_FCOMPP:
		case X86_INS_FDECSTP:
		case X86_INS_FEMMS:
		case X86_INS_FFREE:
		case X86_INS_FICOM:
		case X86_INS_FICOMP:
		case X86_INS_FINCSTP:
		case X86_INS_FNCLEX:
		case X86_INS_FNINIT:
		case X86_INS_FNSTCW:
		case X86_INS_FNSTSW:
		case X86_INS_FPATAN:
		case X86_INS_FPREM:
		case X86_INS_FPREM1:
		case X86_INS_FPTAN:
#if CS_API_MAJOR >=4
		case X86_INS_FFREEP:
#endif
		case X86_INS_FRNDINT:
		case X86_INS_FRSTOR:
		case X86_INS_FNSAVE:
		case X86_INS_FSCALE:
		case X86_INS_FSETPM:
		case X86_INS_FSINCOS:
		case X86_INS_FNSTENV:
		case X86_INS_FXAM:
		case X86_INS_FXSAVE:
		case X86_INS_FXSAVE64:
		case X86_INS_FXTRACT:
		case X86_INS_FYL2X:
		case X86_INS_FYL2XP1:
		case X86_INS_FISTTP:
		case X86_INS_FSQRT:
		case X86_INS_FXCH:
		case X86_INS_FTST:
		case X86_INS_FUCOMPI:
		case X86_INS_FUCOMI:
		case X86_INS_FUCOMPP:
		case X86_INS_FUCOMP:
		case X86_INS_FUCOM:
			op->type = R_ANAL_OP_TYPE_SUB;
			op->family = R_ANAL_OP_FAMILY_FPU;
			break;
		case X86_INS_FLDCW:
		case X86_INS_FLDENV:
		case X86_INS_FLDL2E:
		case X86_INS_FLDL2T:
		case X86_INS_FLDLG2:
		case X86_INS_FLDLN2:
		case X86_INS_FLDPI:
		case X86_INS_FLDZ:
		case X86_INS_FLD1:
		case X86_INS_FLD:
			op->type = R_ANAL_OP_TYPE_LOAD;
			op->family = R_ANAL_OP_FAMILY_FPU;
			break;
		case X86_INS_FIST:
		case X86_INS_FISTP:
		case X86_INS_FST:
		case X86_INS_FSTP:
		case X86_INS_FSTPNCE:
		case X86_INS_FXRSTOR:
		case X86_INS_FXRSTOR64:
			op->type = R_ANAL_OP_TYPE_STORE;
			op->family = R_ANAL_OP_FAMILY_FPU;
			break;
		case X86_INS_FDIV:
		case X86_INS_FIDIV:
		case X86_INS_FDIVP:
		case X86_INS_FDIVR:
		case X86_INS_FIDIVR:
		case X86_INS_FDIVRP:
		case X86_INS_FSUBR:
		case X86_INS_FISUBR:
		case X86_INS_FSUBRP:
		case X86_INS_FSUB:
		case X86_INS_FISUB:
		case X86_INS_FSUBP:
			op->type = R_ANAL_OP_TYPE_SUB;
			op->family = R_ANAL_OP_FAMILY_FPU;
			break;
		case X86_INS_FMUL:
		case X86_INS_FIMUL:
		case X86_INS_FMULP:
			op->type = R_ANAL_OP_TYPE_MUL;
			op->family = R_ANAL_OP_FAMILY_FPU;
			break;
		case X86_INS_CLI:
		case X86_INS_STI:
		case X86_INS_CLC:
		case X86_INS_STC:
			op->type = R_ANAL_OP_TYPE_SWI;
			op->family = R_ANAL_OP_FAMILY_PRIV;
			break;
		// cmov
		case X86_INS_SETNE:
		case X86_INS_SETNO:
		case X86_INS_SETNP:
		case X86_INS_SETNS:
		case X86_INS_SETO:
		case X86_INS_SETP:
		case X86_INS_SETS:
		case X86_INS_SETL:
		case X86_INS_SETLE:
		case X86_INS_SETB:
		case X86_INS_SETG:
		case X86_INS_SETAE:
		case X86_INS_SETA:
		case X86_INS_SETBE:
		case X86_INS_SETE:
		case X86_INS_SETGE:
			op->type = R_ANAL_OP_TYPE_CMOV;
			op->family = 0;
			if (a->decode) {
				char *dst = getarg (handle, insn, 0, 0, NULL);
				switch (insn->id) {
				case X86_INS_SETE:  esilprintf (op, "zf,%s,=", dst); break;
				case X86_INS_SETNE: esilprintf (op, "zf,!,%s,=", dst); break;
				case X86_INS_SETO:  esilprintf (op, "of,%s,=", dst); break;
				case X86_INS_SETNO: esilprintf (op, "of,!,%s,=", dst); break;
				case X86_INS_SETP:  esilprintf (op, "pf,%s,=", dst); break;
				case X86_INS_SETNP: esilprintf (op, "pf,!,%s,=", dst); break;
				case X86_INS_SETS:  esilprintf (op, "sf,%s,=", dst); break;
				case X86_INS_SETNS: esilprintf (op, "sf,!,%s,=", dst); break;

				case X86_INS_SETB:  esilprintf (op, "cf,%s,=", dst); break;
				case X86_INS_SETAE: esilprintf (op, "cf,!,%s,=", dst); break;

				/* TODO */
#if 0
SETLE/SETNG
	Sets the byte in the operand to 1 if the Zero Flag is set or the
	Sign Flag is not equal to the Overflow Flag,  otherwise sets the
	operand to 0.
SETBE/SETNA
	Sets the byte in the operand to 1 if the Carry Flag or the Zero
        Flag is set, otherwise sets the operand to 0.
SETL/SETNGE
	Sets the byte in the operand to 1 if the Sign Flag is not equal
        to the Overflow Flag, otherwise sets the operand to 0.

				case X86_INS_SETL:  esilprintf (op, "pf,!,%s,=", dst); break;
				case X86_INS_SETLE: esilprintf (op, "pf,!,%s,=", dst); break;
				case X86_INS_SETG:  esilprintf (op, "pf,!,%s,=", dst); break;
				case X86_INS_SETA:  esilprintf (op, "pf,!,%s,=", dst); break;
				case X86_INS_SETBE: esilprintf (op, "pf,!,%s,=", dst); break;
				case X86_INS_SETGE: esilprintf (op, "pf,!,%s,=", dst); break;
						    break;
#endif
				}
				free (dst);
			}
			break;
		// cmov
		case X86_INS_CMOVA:
		case X86_INS_CMOVAE:
		case X86_INS_CMOVB:
		case X86_INS_CMOVBE:
		case X86_INS_FCMOVBE:
		case X86_INS_FCMOVB:
		case X86_INS_CMOVE:
		case X86_INS_FCMOVE:
		case X86_INS_CMOVG:
		case X86_INS_CMOVGE:
		case X86_INS_CMOVL:
		case X86_INS_CMOVLE:
		case X86_INS_FCMOVNBE:
		case X86_INS_FCMOVNB:
		case X86_INS_CMOVNE:
		case X86_INS_FCMOVNE:
		case X86_INS_CMOVNO:
		case X86_INS_CMOVNP:
		case X86_INS_FCMOVNU:
		case X86_INS_CMOVNS:
		case X86_INS_CMOVO:
		case X86_INS_CMOVP:
		case X86_INS_FCMOVU:
		case X86_INS_CMOVS:
		// mov
		case X86_INS_MOV:
		case X86_INS_MOVAPS:
		case X86_INS_MOVAPD:
		case X86_INS_MOVZX:
		case X86_INS_MOVABS:
		case X86_INS_MOVHPD:
		case X86_INS_MOVHPS:
		case X86_INS_MOVLPD:
		case X86_INS_MOVLPS:
		case X86_INS_MOVBE:
		case X86_INS_MOVSB:
		case X86_INS_MOVSD:
		case X86_INS_MOVSQ:
		case X86_INS_MOVSS:
		case X86_INS_MOVSX:
		case X86_INS_MOVSXD:
		case X86_INS_MOVSW:
		case X86_INS_MOVD:
		case X86_INS_MOVQ:
		case X86_INS_MOVDQ2Q:
			{
			op->type = R_ANAL_OP_TYPE_MOV;
			switch (INSOP(0).type) {
			case X86_OP_MEM:
				op->ptr = INSOP(0).mem.disp;
				op->refptr = INSOP(0).size;
				if (INSOP(0).mem.base == X86_REG_RIP) {
					op->ptr += addr + insn->size;
				} else if (INSOP(0).mem.base == X86_REG_RBP || INSOP(0).mem.base == X86_REG_EBP) {
					op->stackop = R_ANAL_STACK_SET;
					op->stackptr = regsz;
				}
				if (a->decode) {
					if (op->prefix & R_ANAL_OP_PREFIX_REP) {
						int width = INSOP(0).size;
						const char *src = cs_reg_name(handle, INSOP(1).mem.base);
						const char *dst = cs_reg_name(handle, INSOP(0).mem.base);
						const char *counter = (a->bits==16)?"cx":
							(a->bits==32)?"ecx":"rcx";
						esilprintf (op, "%s,!,?{,BREAK,},%s,DUP,%s,DUP,"\
											"%s,[%d],%s,=[%d],df,?{,%d,%s,-=,%d,%s,-=,},"\
											"df,!,?{,%d,%s,+=,%d,%s,+=,},%s,--=,%s," \
											"?{,8,GOTO,},%s,=,%s,=",
											counter, src, dst, src, width, dst,
											width, width, src, width, dst, width, src,
											width, dst, counter, counter, dst, src);
					}
					else {
						char *src = getarg (handle, insn, 1, 0, NULL);
						char *dst = getarg (handle, insn, 0, 1, NULL);
						esilprintf (op, "%s,%s", src, dst);
					   free (src);
					   free (dst);
					}
				}
				break;
			default:
				if (a->decode) {
					char *src = getarg (handle, insn, 1, 0, NULL);
					char *dst = getarg (handle, insn, 0, 0, NULL);
					esilprintf (op, "%s,%s,=", src, dst);
					free (src);
					free (dst);
				}
				break;
			}
			switch (INSOP(1).type) {
			case X86_OP_MEM:
				op->ptr = INSOP(1).mem.disp;
				op->refptr = INSOP(1).size;
				if (INSOP(1).mem.base == X86_REG_RIP) {
					op->ptr += addr + insn->size;
				} else if (INSOP(1).mem.base == X86_REG_RBP || INSOP(1).mem.base == X86_REG_EBP) {
					op->stackop = R_ANAL_STACK_GET;
					op->stackptr = regsz;
				}
				break;
			case X86_OP_IMM:
				if (INSOP(1).imm > 10)
					op->ptr = INSOP(1).imm;
				break;
			default:
				break;
			}
			}
			break;
		case X86_INS_SHL:
		case X86_INS_SHLD:
		case X86_INS_SHLX:
			op->type = R_ANAL_OP_TYPE_SHL;
			if (a->decode) {
				char *src = getarg (handle, insn, 1, 0, NULL);
				char *dst = getarg (handle, insn, 0, 1, "<<");
				esilprintf (op, "%s,%s,cz,%%z,zf,=", src, dst);
				free (src);
				free (dst);
			}
			break;
		case X86_INS_SAR:
		case X86_INS_SARX:
			op->type = R_ANAL_OP_TYPE_SAR;
			if (a->decode) {
				char *src = getarg (handle, insn, 1, 0, NULL);
				char *dst = getarg (handle, insn, 0, 1, ">>");
				esilprintf (op, "%s,%s,%%z,zf,=", src, dst);
				free (src);
				free (dst);
			}
			break;
		case X86_INS_SAL:
		case X86_INS_SALC:
			op->type = R_ANAL_OP_TYPE_SAL;
			if (a->decode) {
				char *src = getarg (handle, insn, 1, 0, NULL);
				char *dst = getarg (handle, insn, 0, 1, "<<");
				esilprintf (op, "%s,%s,%%z,zf,=", src, dst);
				free (src);
				free (dst);
			}
			break;
		case X86_INS_SHR:
		case X86_INS_SHRD:
		case X86_INS_SHRX:
			op->type = R_ANAL_OP_TYPE_SHR;
			if (a->decode) {
				char *src = getarg (handle, insn, 1, 0, NULL);
				char *dst = getarg (handle, insn, 0, 0, NULL);
				esilprintf (op, "%s,%s,>>=,cz,%%z,zf,=", src, dst);
				free (src);
				free (dst);
			}
			break;
		case X86_INS_CMP:
		case X86_INS_CMPPD:
		case X86_INS_CMPPS:
		case X86_INS_CMPSW:
		case X86_INS_CMPSD:
		case X86_INS_CMPSQ:
		case X86_INS_CMPSB:
		case X86_INS_CMPSS:
		case X86_INS_TEST:
			if (insn->id == X86_INS_TEST) {
				op->type = R_ANAL_OP_TYPE_ACMP;					//compare via and
				if (a->decode) {
					char *src = getarg (handle, insn, 1, 0, NULL);
					char *dst = getarg (handle, insn, 0, 0, NULL);
					esilprintf (op, "0,%s,%s,&,==,%%z,zf,=,%%p,pf,=,%%s,sf,=,0,cf,=,0,of,=",
						src, dst);
					free (src);
					free (dst);
				}
			} else {
				op->type = R_ANAL_OP_TYPE_CMP;
				if (a->decode) {
					char *src = getarg (handle, insn, 1, 0, NULL);
					char *dst = getarg (handle, insn, 0, 0, NULL);
					esilprintf (op,  "%s,%s,==,%%z,zf,=,%%b%d,cf,=,%%p,pf,=,%%s,sf,=",
						src, dst, (INSOP(0).size*8));
					free (src);
					free (dst);
				}
			}
			switch (INSOP(0).type) {
			case X86_OP_MEM:
				op->ptr = INSOP(0).mem.disp;
				op->refptr = INSOP(0).size;
				if (INSOP(0).mem.base == X86_REG_RIP) {
					op->ptr += addr + insn->size;
				} else if (INSOP(0).mem.base == X86_REG_RBP || INSOP(0).mem.base == X86_REG_EBP) {
					op->stackop = R_ANAL_STACK_SET;
					op->stackptr = regsz;
				}
				op->ptr = INSOP(1).imm;
				break;
			default:
				switch (INSOP(1).type) {
				case X86_OP_MEM:
					op->ptr = INSOP(1).mem.disp;
					op->refptr = INSOP(1).size;
					if (INSOP(1).mem.base == X86_REG_RIP) {
						op->ptr += addr + insn->size;
					} else if (INSOP(1).mem.base == X86_REG_RBP || INSOP(1).mem.base == X86_REG_EBP) {
						op->stackop = R_ANAL_STACK_SET;
						op->stackptr = regsz;
					}
					break;
				case X86_OP_IMM:
					op->ptr = INSOP(1).imm;
					break;
				default:
					break;
				}
				break;
			}
			break;
		case X86_INS_LEA:
			op->type = R_ANAL_OP_TYPE_LEA;
			if (a->decode) {
				char *src = getarg (handle, insn, 0, 0, NULL);
				char *dst = getarg (handle, insn, 1, 2, NULL);
				esilprintf (op, "%s,%s,=", dst, src);
				free (src);
				free (dst);
			}
			switch (INSOP(1).type) {
			case X86_OP_MEM:
				op->ptr = INSOP(1).mem.disp;
				op->refptr = INSOP(1).size;
				switch (INSOP(1).mem.base) {
				case X86_REG_RIP:
					op->ptr += addr + op->size;
					break;
				case X86_REG_RBP:
				case X86_REG_EBP:
					op->stackop = R_ANAL_STACK_GET;
					op->stackptr = regsz;
					break;
				default:
					/* unhandled */
					break;
				}
				break;
			case X86_OP_IMM:
				if (INSOP(1).imm > 10)
					op->ptr = INSOP(1).imm;
				break;
			default:
				break;
			}
			break;
		case X86_INS_ENTER:
		case X86_INS_PUSH:
		case X86_INS_PUSHAW:
		case X86_INS_PUSHAL:
		case X86_INS_PUSHF:
			{
				char *dst = getarg (handle, insn, 0, 0, NULL);
				esilprintf (op,  "%d,%s,-=,%s,%s,=[%d]", rs, sp, dst, sp, rs);
				free (dst);
			}
			switch (INSOP(0).type) {
			case X86_OP_IMM:
				op->ptr = INSOP(0).imm;
				op->type = R_ANAL_OP_TYPE_PUSH;
				break;
			default:
				op->type = R_ANAL_OP_TYPE_UPUSH;
				break;
			}
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = regsz;
			break;
		case X86_INS_LEAVE:
			op->type = R_ANAL_OP_TYPE_POP;
			if (a->decode) {
				esilprintf (op, "%s,%s,=,%s,[%d],%s,%d,%s,-=",
					bp, sp, sp, rs, bp, rs, sp);
			}
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -regsz;
			break;
		case X86_INS_POP:
		case X86_INS_POPF:
		case X86_INS_POPAW:
		case X86_INS_POPAL:
		case X86_INS_POPCNT:
			op->type = R_ANAL_OP_TYPE_POP;
			if (a->decode) {
				char *dst = getarg (handle, insn, 0, 0, NULL);
				esilprintf (op,
					"%s,[%d],%s,=,%d,%s,+=",
					sp, rs, dst, rs, sp);
				free (dst);
			}
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -regsz;
			break;
		case X86_INS_RET:
		case X86_INS_RETF:
		case X86_INS_RETFQ:
		case X86_INS_IRET:
		case X86_INS_IRETD:
		case X86_INS_IRETQ:
		case X86_INS_SYSRET:
			op->type = R_ANAL_OP_TYPE_RET;
			if (a->decode)
				esilprintf (op, "%s,[%d],%s,=,%d,%s,+=",
					sp, rs, pc, rs, sp);
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -regsz;
			break;
		case X86_INS_INT:
			if (a->decode)
				esilprintf (op, "%d,$", R_ABS((int)INSOP(0).imm));
			op->type = R_ANAL_OP_TYPE_SWI;
			break;
		case X86_INS_SYSCALL:
			op->type = R_ANAL_OP_TYPE_SWI;
			break;
		case X86_INS_INT1:
		case X86_INS_INT3:
		case X86_INS_INTO:
		case X86_INS_VMCALL:
		case X86_INS_VMMCALL:
			op->type = R_ANAL_OP_TYPE_TRAP;
			if (a->decode)
				esilprintf (op, "%d,$", (int)INSOP(0).imm);
			break;
		case X86_INS_JL:
		case X86_INS_JLE:
		case X86_INS_JA:
		case X86_INS_JAE:
		case X86_INS_JB:
		case X86_INS_JBE:
		case X86_INS_JCXZ:
		case X86_INS_JECXZ:
		case X86_INS_JRCXZ:
		case X86_INS_JO:
		case X86_INS_JNO:
		case X86_INS_JS:
		case X86_INS_JNS:
		case X86_INS_JP:
		case X86_INS_JNP:
		case X86_INS_JE:
		case X86_INS_JNE:
		case X86_INS_JG:
		case X86_INS_JGE:
		case X86_INS_LOOP:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = INSOP(0).imm;
			op->fail = addr+op->size;
			if (a->decode) {
				char *dst = getarg (handle, insn, 0, 2, NULL);
				switch (insn->id) {
				case X86_INS_JL:
					esilprintf (op, "of,sf,^,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JLE:
					esilprintf (op, "of,sf,^,zf,|,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JA:
					esilprintf (op, "cf,zf,|,!,?{,%s,%s,=,}",dst, pc);
					break;
				case X86_INS_JAE:
					esilprintf (op, "cf,!,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JB:
					esilprintf (op, "cf,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JO:
					esilprintf (op, "of,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JNO:
					esilprintf (op, "of,!,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JE:
					esilprintf (op, "zf,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JGE:
					esilprintf (op, "of,!,sf,^,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JNE:
					esilprintf (op, "zf,!,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JG:
					esilprintf (op, "sf,of,!,^,zf,!,&,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JS:
					esilprintf (op, "sf,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JNS:
					esilprintf (op, "sf,!,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JP:
					esilprintf (op, "pf,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JNP:
					esilprintf (op, "pf,!,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JBE:
					esilprintf (op, "zf,cf,|,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JCXZ:
					esilprintf (op, "cx,!,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JECXZ:
					esilprintf (op, "ecx,!,?{,%s,%s,=,}", dst, pc);
					break;
				case X86_INS_JRCXZ:
					esilprintf (op, "rcx,!,?{,%s,%s,=,}", dst, pc);
					break;
				}
				free (dst);
			}
			break;
		case X86_INS_CALL:
		case X86_INS_LCALL:
			switch (INSOP(0).type) {
			case X86_OP_IMM:
				op->type = R_ANAL_OP_TYPE_CALL;
				// TODO: what if UCALL?
				// TODO: use imm_size
				op->jump = INSOP(0).imm;
				op->fail = addr+op->size;
				break;
			case X86_OP_MEM:
				op->type = R_ANAL_OP_TYPE_UCALL;
				op->jump = UT64_MAX;
				if (INSOP(0).mem.base == 0) {
					op->ptr = INSOP(0).mem.disp;
				}
				break;
			default:
				op->type = R_ANAL_OP_TYPE_UCALL;
				op->jump = UT64_MAX;
				break;
			}
			if (a->decode) {
				char* arg = getarg (handle, insn, 0, 0, NULL);
				esilprintf (op,
						"%d,%s,+,"
						"%d,%s,-=,%s,"
						"=[],"
						"%s,%s,=",
						op->size, pc,
						rs, sp, sp, arg, pc);
				free (arg);
			}
			break;
		case X86_INS_JMP:
		case X86_INS_LJMP:
			if (a->decode) {
				char *src = getarg (handle, insn, 0, 0, NULL);
				esilprintf (op, "%s,%s,=", src, pc);
				free (src);
			}
			// TODO: what if UJMP?
			switch (INSOP(0).type) {
			case X86_OP_IMM:
				op->jump = INSOP(0).imm;
				op->type = R_ANAL_OP_TYPE_JMP;
				if (a->decode) {
					ut64 dst = INSOP(0).imm;
					esilprintf (op, "0x%"PFMT64x",%s,=", dst, pc);
				}
				break;
			case X86_OP_MEM:
				{
					cs_x86_op in = INSOP(0);
					op->type = R_ANAL_OP_TYPE_UJMP;
					if (in.mem.index == 0 && in.mem.base == 0 && in.mem.scale == 1) {
						op->type = R_ANAL_OP_TYPE_UJMP;
						op->ptr= in.mem.disp;
						if (a->decode) {
							esilprintf (op, "0x%"PFMT64x",[],%s,=", op->ptr, pc);
						}
					}
				}
				break;
			case X86_OP_REG:
			case X86_OP_FP:
			default: // other?
				op->type = R_ANAL_OP_TYPE_UJMP;
				break;
			}
			break;
		case X86_INS_IN:
		case X86_INS_INSW:
		case X86_INS_INSD:
		case X86_INS_INSB:
		case X86_INS_OUT:
		case X86_INS_OUTSB:
		case X86_INS_OUTSD:
		case X86_INS_OUTSW:
			op->type = R_ANAL_OP_TYPE_IO;
			break;
		case X86_INS_VXORPD:
		case X86_INS_VXORPS:
		case X86_INS_VPXORD:
		case X86_INS_VPXORQ:
		case X86_INS_VPXOR:
		case X86_INS_KXORW:
		case X86_INS_PXOR:
		case X86_INS_XOR:
			op->type = R_ANAL_OP_TYPE_XOR;
			if (a->decode) {
				char *src = getarg (handle, insn, 1, 0, NULL);
				char *dst = getarg (handle, insn, 0, 1, "^");
				esilprintf (op, "%s,%s,%%z,zf,=,%%p,pf,=,0,cf,=,0,of,=,%%s,sf,=",
					src, dst);
				free (src);
				free (dst);
			}
			break;
		case X86_INS_OR:
			op->type = R_ANAL_OP_TYPE_OR;
			if (a->decode) {
				char *src = getarg (handle, insn, 1, 0, NULL);
				char *dst = getarg (handle, insn, 0, 0, NULL);
				esilprintf (op, "%s,%s,|=", src, dst);
				free (src);
				free (dst);
			}
			break;
		case X86_INS_INC:
			op->type = R_ANAL_OP_TYPE_ADD;
			op->val = 1;
			if (a->decode) {
				char *src = getarg (handle, insn, 0, 0, NULL);
				esilprintf (op, "%s,++=", src);
				free (src);
			}
			break;
		case X86_INS_DEC:
			op->type = R_ANAL_OP_TYPE_SUB;
			op->val = 1;
			if (a->decode) {
				char *src = getarg (handle, insn, 0, 0, NULL);
				esilprintf (op, "%s,--=", src);
				free (src);
			}
			break;
		case X86_INS_SUB:
		case X86_INS_PSUBB:
		case X86_INS_PSUBW:
		case X86_INS_PSUBD:
		case X86_INS_PSUBQ:
		case X86_INS_PSUBSB:
		case X86_INS_PSUBSW:
		case X86_INS_PSUBUSB:
		case X86_INS_PSUBUSW:
			op->type = R_ANAL_OP_TYPE_SUB;
			if (a->decode) {
				char *src = getarg (handle, insn, 1, 0, NULL);
				char *dst = getarg (handle, insn, 0, 1, "-");
				esilprintf (op, "%s,%s,%%c,cf,=,%%z,zf,=,%%s,sf,=,%%o,of,=",
					src, dst); // TODO: update flags
				free (src);
				free (dst);
			}
			if (INSOP(0).type == X86_OP_REG && INSOP(1).type == X86_OP_IMM) {
				if (INSOP(0).reg == X86_REG_RSP || INSOP(0).reg == X86_REG_ESP) {
					op->stackop = R_ANAL_STACK_INC;
					op->stackptr = INSOP(1).imm;
				}
			}
			break;
		case X86_INS_LIDT:
			op->type = R_ANAL_OP_TYPE_LOAD;
			op->family = R_ANAL_OP_FAMILY_PRIV;
			break;
		case X86_INS_SIDT:
			op->type = R_ANAL_OP_TYPE_STORE;
			op->family = R_ANAL_OP_FAMILY_PRIV;
			break;
		case X86_INS_RDRAND:
		case X86_INS_RDSEED:
		case X86_INS_RDMSR:
		case X86_INS_RDPMC:
		case X86_INS_RDTSC:
		case X86_INS_RDTSCP:
		case X86_INS_CRC32:
		case X86_INS_SHA1MSG1:
		case X86_INS_SHA1MSG2:
		case X86_INS_SHA1NEXTE:
		case X86_INS_SHA1RNDS4:
		case X86_INS_SHA256MSG1:
		case X86_INS_SHA256MSG2:
		case X86_INS_SHA256RNDS2:
		case X86_INS_AESDECLAST:
		case X86_INS_AESDEC:
		case X86_INS_AESENCLAST:
		case X86_INS_AESENC:
		case X86_INS_AESIMC:
		case X86_INS_AESKEYGENASSIST:
			// AES instructions
			op->family = R_ANAL_OP_FAMILY_CRYPTO;
			op->type = R_ANAL_OP_TYPE_MOV; // XXX
			break;
		case X86_INS_AND:
		case X86_INS_ANDN:
		case X86_INS_ANDPD:
		case X86_INS_ANDPS:
		case X86_INS_ANDNPD:
		case X86_INS_ANDNPS:
			op->type = R_ANAL_OP_TYPE_AND;
			if (a->decode) {
				char *src = getarg (handle, insn, 1, 0, NULL);
				char *dst = getarg (handle, insn, 0, 1, "&");
				// TODO: update of = cf = 0
				// TODO: update sf, zf and pf
				// TODO: af is undefined
				esilprintf (op, "0,of,=,0,cf,=," // set carry and overflow flags
					"%s,%s," // set reg value
					"%%z,zf,="  // update zero flag
					"%%s,sf,="  // update sign flag
					"%%o,pf,=", // update parity flag
					// TODO: add sign and parity flags here
					src, dst);
				free (src);
				free (dst);
			}
			break;
		case X86_INS_DIV:
			op->type = R_ANAL_OP_TYPE_DIV;
			if (a->decode) {
				char *src = getarg (handle, insn, 1, 0, NULL);
				char *dst = getarg (handle, insn, 0, 1, "/");
				esilprintf (op, "%s,%s", src, dst);
				free (src);
				free (dst);
			}
			break;
		case X86_INS_IDIV:
			op->type = R_ANAL_OP_TYPE_DIV;
			if (a->decode) {
				int width = INSOP(0).size;
				char *dst = getarg (handle, insn, 0, 0, NULL);
				const char *r_ax = (width==2)?"ax": (width==4)?"eax":"rax";
				const char *r_dx = (width==2)?"dx": (width==4)?"edx":"rdx";
				// TODO update flags & handle signedness
				esilprintf (op, "%s,%s,%%,%s,=,%s,%s,/,%s,=",
								dst, r_ax, r_dx, dst, r_ax, r_ax);
				free (dst);
			}
			break;
		case X86_INS_MUL:
		case X86_INS_MULX:
		case X86_INS_MULPD:
		case X86_INS_MULPS:
		case X86_INS_MULSD:
		case X86_INS_MULSS:
			op->type = R_ANAL_OP_TYPE_MUL;
			if (a->decode) {
				char *src = getarg (handle, insn, 1, 0, NULL);
				char *dst = getarg (handle, insn, 0, 1, "*");
				esilprintf (op, "%s,%s", src, dst);
				free (src);
				free (dst);
			}
			break;
		case X86_INS_PACKSSDW:
		case X86_INS_PACKSSWB:
		case X86_INS_PACKUSWB:
			op->type = R_ANAL_OP_TYPE_MOV;
			op->family = R_ANAL_OP_FAMILY_MMX;
			break;
		case X86_INS_PADDB:
		case X86_INS_PADDD:
		case X86_INS_PADDW:
		case X86_INS_PADDSB:
		case X86_INS_PADDSW:
		case X86_INS_PADDUSB:
		case X86_INS_PADDUSW:
			op->type = R_ANAL_OP_TYPE_ADD;
			op->family = R_ANAL_OP_FAMILY_MMX;
			break;
		case X86_INS_FADD:
		case X86_INS_FADDP:
			op->family = R_ANAL_OP_FAMILY_FPU;
			/* pass thru */
		case X86_INS_ADD:
		case X86_INS_ADDPS:
		case X86_INS_ADDSD:
		case X86_INS_ADDSS:
		case X86_INS_ADDSUBPD:
		case X86_INS_ADDSUBPS:
		case X86_INS_ADDPD:
		case X86_INS_XADD:
			op->type = R_ANAL_OP_TYPE_ADD;
			if (a->decode) {
				char *src = getarg (handle, insn, 1, 0, NULL);
				char *dst = getarg (handle, insn, 0, 1, "+");
				esilprintf (op, "%s,%s", src, dst);		// TODO: update flags
				free (src);
				free (dst);
			}
			if (INSOP(0).type == X86_OP_REG && INSOP(1).type == X86_OP_IMM) {
				if (INSOP(0).reg == X86_REG_RSP || INSOP(0).reg == X86_REG_ESP) {
					op->stackop = R_ANAL_STACK_INC;
					op->stackptr = -INSOP(1).imm;
				}
			}
			break;
			/* Direction flag */
		case X86_INS_CLD:
			if (a->decode)
				esilprintf (op, "0,df,=");
			break;
		case X86_INS_STD:
			if (a->decode)
				esilprintf (op, "1,df,=");
			break;
		}
	}
//#if X86_GRP_PRIVILEGE>0
	if (insn) {
#if HAVE_CSGRP_PRIVILEGE
		if (cs_insn_group (handle, insn, X86_GRP_PRIVILEGE))
			op->family = R_ANAL_OP_FAMILY_PRIV;
#endif
#if !USE_ITER_API
		cs_free (insn, n);
#endif
	}
	cs_close (&handle);
	return op->size;
}

static int x86_int_0x80 (RAnalEsil *esil, int interrupt)
{
	int syscall;
	ut64 eax, ebx, ecx, edx;
	if (!esil || (interrupt != 0x80))
		return R_FALSE;
	r_anal_esil_reg_read (esil, "eax", &eax);
	r_anal_esil_reg_read (esil, "ebx", &ebx);
	r_anal_esil_reg_read (esil, "ecx", &ecx);
	r_anal_esil_reg_read (esil, "edx", &edx);
	syscall = (int) eax;
	switch (syscall) {
		case 3:
			{
				char *dst = calloc (1, (size_t)edx);
				read ((ut32)ebx, dst, (size_t)edx);
				r_anal_esil_mem_write (esil, ecx, (ut8 *)dst, (int)edx);
				free (dst);
				return R_TRUE;
			}
		case 4:
			{
				char *src = malloc ((size_t)edx);
				r_anal_esil_mem_read (esil, ecx, (ut8 *)src, (int)edx);
				write ((ut32)ebx, src, (size_t)edx);
				free (src);
				return R_TRUE;
			}
		
	}
	eprintf ("syscall %d not implemented yet\n", syscall);
	return R_FALSE;
}

static int esil_x86_cs_init (RAnalEsil *esil)
{
	if (!esil)
		return R_FALSE;
	r_anal_esil_set_interrupt (esil, 0x80, x86_int_0x80);
	return R_TRUE;
}

static int esil_x86_cs_fini (RAnalEsil *esil)
{
	return R_TRUE;
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
		"flg	pf	.1	.449	0\n"
		"flg	af	.1	.450	0\n"
		"gpr	zf	.1	.451	0\n"
		"gpr	sf	.1	.452	0\n"
		"flg	tf	.1	.453	0\n"
		"flg	if	.1	.454	0\n"
		"flg	df	.1	.455	0\n"
		"flg	of	.1	.456	0\n"
		"flg	rf	.1	.457	0\n";
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
		"flg	pf	.1	.449	0\n"
		"flg	af	.1	.450	0\n"
		"gpr	zf	.1	.451	0\n"
		"gpr	sf	.1	.452	0\n"
		"flg	tf	.1	.453	0\n"
		"flg	if	.1	.454	0\n"
		"flg	df	.1	.455	0\n"
		"flg	of	.1	.456	0\n"
		"flg	rf	.1	.457	0\n"
		"drx	dr0	.32	0	0\n"
		"drx	dr1	.32	4	0\n"
		"drx	dr2	.32	8	0\n"
		"drx	dr3	.32	12	0\n"
		//"drx	dr4	.32	16	0\n"
		//"drx	dr5	.32	20	0\n"
		"drx	dr6	.32	24	0\n"
		"drx	dr7	.32	28	0\n";
		 break;
	case 64:
		 p =
		 "=pc	rip\n"
		 "=sp	rsp\n"
		 "=bp	rbp\n"
		 "=a0	rdi\n"
		 "=a1	rsi\n"
		 "=a2	rdx\n"
		 "=a3	r10\n"
		 "=a4	r8\n"
		 "=a5	r9\n"
		 "=sn	orax\n"
		 "# no profile defined for x86-64\n"
		 "gpr	r15	.64	0	0\n"
		 "gpr	r14	.64	8	0\n"
		 "gpr	r13	.64	16	0\n"
		 "gpr	r12	.64	24	0\n"
		 "gpr	rbp	.64	32	0\n"
		 "gpr	rbx	.64	40	0\n"
		 "gpr	ebx	.32	40	0\n"
		 "gpr	bx	.16	40	0\n"
		 "gpr	bh	.8	41	0\n"
		 "gpr	bl	.8	40	0\n"
		 "gpr	r11	.64	48	0\n"
		 "gpr	r10	.64	56	0\n"
		 "gpr	r9	.64	64	0\n"
		 "gpr	r8	.64	72	0\n"
		 "gpr	rax	.64	80	0\n"
		 "gpr	eax	.32	80	0\n"
		 "gpr	ax	.16	80	0\n"
		 "gpr	ah	.8	81	0\n"
		 "gpr	al	.8	80	0\n"
		 "gpr	rcx	.64	88	0\n"
		 "gpr	ecx	.32	88	0\n"
		 "gpr	cx	.16	88	0\n"
		 "gpr	ch	.8	89	0\n"
		 "gpr	cl	.8	88	0\n"
		 "gpr	rdx	.64	96	0\n"
		 "gpr	edx	.32	96	0\n"
		 "gpr	dx	.16	96	0\n"
		 "gpr	dh	.8	97	0\n"
		 "gpr	dl	.8	96	0\n"
		 "gpr	rsi	.64	104	0\n"
		 "gpr	esi	.32	104	0\n"
		 "gpr	si	.16	104	0\n"
		 "gpr	rdi	.64	112	0\n"
		 "gpr	edi	.32	112	0\n"
		 "gpr	di	.16	112	0\n"
		 "gpr	orax	.64	120	0\n"
		 "gpr	rip	.64	128	0\n"
		 "seg	cs	.64	136	0\n"
		 "gpr	rflags	.64	144	0	c1p.a.zstido.n.rv\n"
		 "gpr	eflags	.32	144	0	c1p.a.zstido.n.rv\n"
		 "gpr	cf	.1	.1152	0	carry\n"
		 "gpr	pf	.1	.1154	0	parity\n"
		 "gpr	af	.1	.1156	0	adjust\n"
		 "gpr	zf	.1	.1158	0	zero\n"
		 "gpr	sf	.1	.1159	0	sign\n"
		 "gpr	tf	.1	.1160	0	trap\n"
		 "gpr	if	.1	.1161	0	interrupt\n"
		 "gpr	df	.1	.1162	0	direction\n"
		 "gpr	of	.1	.1163	0	overflow\n"

		 "gpr	rsp	.64	152	0\n"
		 "seg	ss	.64	160	0\n"
		 "seg	fs_base	.64	168	0\n"
		 "seg	gs_base	.64	176	0\n"
		 "seg	ds	.64	184	0\n"
		 "seg	es	.64	192	0\n"
		 "seg	fs	.64	200	0\n"
		 "seg	gs	.64	208	0\n"
		 "drx	dr0	.64	0	0\n"
		 "drx	dr1	.64	8	0\n"
		 "drx	dr2	.64	16	0\n"
		 "drx	dr3	.64	24	0\n"
		 // dr4 32
		 // dr5 40
		 "drx	dr6	.64	48	0\n"
		 "drx	dr7	.64	56	0\n"

		 /*0030 struct user_fpregs_struct
		   0031 {
		   0032   __uint16_t        cwd;
		   0033   __uint16_t        swd;
		   0034   __uint16_t        ftw;
		   0035   __uint16_t        fop;
		   0036   __uint64_t        rip;
		   0037   __uint64_t        rdp;
		   0038   __uint32_t        mxcsr;
		   0039   __uint32_t        mxcr_mask;
		   0040   __uint32_t        st_space[32];   // 8*16 bytes for each FP-reg = 128 bytes
		   0041   __uint32_t        xmm_space[64];  // 16*16 bytes for each XMM-reg = 256 bytes
		   0042   __uint32_t        padding[24];
		   0043 };
		  */
		 "fpu    cwd .16 0   0\n"
		 "fpu    swd .16 2   0\n"
		 "fpu    ftw .16 4   0\n"
		 "fpu    fop .16 6   0\n"
		 "fpu    frip .64 8   0\n"
		 "fpu    frdp .64 16  0\n"
		 "fpu    mxcsr .32 24  0\n"
		 "fpu    mxcr_mask .32 28  0\n"

		 "fpu    st0 .64 32  0\n"
		 "fpu    st1 .64 48  0\n"
		 "fpu    st2 .64 64  0\n"
		 "fpu    st3 .64 80  0\n"
		 "fpu    st4 .64 96  0\n"
		 "fpu    st5 .64 112  0\n"
		 "fpu    st6 .64 128  0\n"
		 "fpu    st7 .64 144  0\n"

		 "fpu    xmm0h .64 160  0\n"
		 "fpu    xmm0l .64 168  0\n"

		 "fpu    xmm1h .64 176  0\n"
		 "fpu    xmm1l .64 184  0\n"

		 "fpu    xmm2h .64 192  0\n"
		 "fpu    xmm2l .64 200  0\n"

		 "fpu    xmm3h .64 208  0\n"
		 "fpu    xmm3l .64 216  0\n"

		 "fpu    xmm4h .64 224  0\n"
		 "fpu    xmm4l .64 232  0\n"

		 "fpu    xmm5h .64 240  0\n"
		 "fpu    xmm5l .64 248  0\n"

		 "fpu    xmm6h .64 256  0\n"
		 "fpu    xmm6l .64 264  0\n"

		 "fpu    xmm7h .64 272  0\n"
		 "fpu    xmm7l .64 280  0\n"
		 "fpu    x64   .64 288  0\n";
		 break;
	default: p= /* XXX */
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
		 "flg	pf	.1	.1153	0\n"
		 "flg	af	.1	.1154	0\n"
		 "gpr	zf	.1	.1155	0\n"
		 "gpr	sf	.1	.1156	0\n"
		 "flg	tf	.1	.1157	0\n"
		 "flg	if	.1	.1158	0\n"
		 "flg	df	.1	.1159	0\n"
		 "flg	of	.1	.1160	0\n"
		 "flg	rf	.1	.1161	0\n"
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

RAnalPlugin r_anal_plugin_x86_cs = {
	.name = "x86",
	.desc = "Capstone X86 analysis",
	.esil = R_TRUE,
	.license = "BSD",
	.arch = R_SYS_ARCH_X86,
	.bits = 16|32|64,
	.op = &analop,
	.set_reg_profile = &set_reg_profile,
	.esil_init = esil_x86_cs_init,
	.esil_fini = esil_x86_cs_fini,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_x86_cs
};
#endif
