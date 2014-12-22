/* radare2 - LGPL - Copyright 2013-2014 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone.h>
#include <x86.h>

#define USE_ITER_API 0

#if CS_API_MAJOR < 2
#error Old Capstone not supported
#endif

#define esilprintf(op, fmt, arg...) r_strbuf_setf (&op->esil, fmt, ##arg)
#define INSOP(n) insn->detail->x86.operands[n]
#define INSOPS insn->detail->x86.op_count

// TODO: lowercase
static const char *cs_x86_regnames[] = {
        "invalid",
        "ah", "al", "ax", "bh", "bl",
        "bp", "bpl", "bx", "ch", "cl",
        "cs", "cx", "dh", "di", "dil",
        "dl", "ds", "dx", "eax", "ebp",
        "ebx", "ecx", "edi", "edx", "eflags",
        "eip", "eiz", "es", "esi", "esp",
        "fpsw", "fs", "gs", "ip", "rax",
        "rbp", "rbx", "rcx", "rdi", "rdx",
        "rip", "riz", "rsi", "rsp", "si",
        "sil", "sp", "spl", "ss", "cr0",
        "cr1", "cr2", "cr3", "cr4", "cr5",
        "cr6", "cr7", "cr8", "cr9", "cr10",
        "cr11", "cr12", "cr13", "cr14", "cr15",
        "dr0", "dr1", "dr2", "dr3", "dr4",
        "dr5", "dr6", "dr7", "fp0", "fp1",
        "fp2", "fp3", "fp4", "fp5", "fp6", "fp7",
        "k0", "k1", "k2", "k3", "k4",
        "k5", "k6", "k7", "mm0", "mm1",
        "mm2", "mm3", "mm4", "mm5", "mm6",
        "mm7", "r8", "r9", "r10", "r11",
        "r12", "r13", "r14", "r15",
        "st0", "st1", "st2", "st3",
        "st4", "st5", "st6", "st7",
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4",
        "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
        "xmm10", "xmm11", "xmm12", "xmm13", "xmm14",
        "xmm15", "xmm16", "xmm17", "xmm18", "xmm19",
        "xmm20", "xmm21", "xmm22", "xmm23", "xmm24",
        "xmm25", "xmm26", "xmm27", "xmm28", "xmm29",
        "xmm30", "xmm31", "ymm0", "ymm1", "ymm2",
        "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
        "ymm8", "ymm9", "ymm10", "ymm11", "ymm12",
        "ymm13", "ymm14", "ymm15", "ymm16", "ymm17",
        "ymm18", "ymm19", "ymm20", "ymm21", "ymm22",
        "ymm23", "ymm24", "ymm25", "ymm26", "ymm27",
        "ymm28", "ymm29", "ymm30", "ymm31", "zmm0",
        "zmm1", "zmm2", "zmm3", "zmm4", "zmm5",
        "zmm6", "zmm7", "zmm8", "zmm9", "zmm10",
        "zmm11", "zmm12", "zmm13", "zmm14", "zmm15",
        "zmm16", "zmm17", "zmm18", "zmm19", "zmm20",
        "zmm21", "zmm22", "zmm23", "zmm24", "zmm25",
        "zmm26", "zmm27", "zmm28", "zmm29", "zmm30",
        "zmm31", "r8b", "r9b", "r10b", "r11b",
        "r12b", "r13b", "r14b", "r15b", "r8d",
        "r9d", "r10d", "r11d", "r12d", "r13d",
        "r14d", "r15d", "r8w", "r9w", "r10w",
        "r11w", "r12w", "r13w", "r14w", "r15w",
	NULL
};

static char *getarg(cs_insn *insn, int n, int set) {
	char buf[64];
	cs_x86_op op;
	if (!insn->detail)
		return NULL;
#if 0
	if (n<0 || n>INSOPS)
		return NULL;
#endif
	op = INSOP(n);
	switch (op.type) {
	case X86_OP_INVALID:
		return strdup ("invalid");
		break;
	case X86_OP_REG:
		// TODO: control boundaries
		return strdup (cs_x86_regnames[op.reg]);
	case X86_OP_IMM:
		snprintf (buf, sizeof (buf), "%"PFMT64d, (ut64)op.imm);
		return strdup (buf);
	case X86_OP_MEM:
		{
		const char *base = cs_x86_regnames[op.mem.base];
		//const char *index =  cs_x86_regnames[op.mem.index];
		int scale = op.mem.scale;
		st64 disp = op.mem.disp;
		if (scale>1) {
			if (set>1) {
				snprintf (buf, sizeof (buf),
						"%s,%d,+,%d,*",
						base, (int)disp, scale);
			} else {
				snprintf (buf, sizeof (buf),
						"%s,%d,+,%d,*,[%d]",
						base, (int)disp, scale, op.size);
			}
		} else {
			if (set>1) {
				snprintf (buf, sizeof (buf),
						"%s,%d,+",
						base, (int)disp);
			} else {
				snprintf (buf, sizeof (buf),
						"%s,%d,+,%s[%d]",
						base, (int)disp,
						set?"=":"", op.size);
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
	switch (a->bits) {
	case 64: regsz = 8; break;
	case 16: regsz = 2; break;
	default:
	case 32: regsz = 4; break;
	}
	memset (op, '\0', sizeof (RAnalOp));
	op->type = R_ANAL_OP_TYPE_NULL;
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->ptr = op->val = UT64_MAX;
	op->src[0] = NULL;
	op->src[1] = NULL;
	op->size = 0;
	op->delay = 0;
	r_strbuf_init (&op->esil);
	if (ret == CS_ERR_OK) {
		cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
		// capstone-next
#if USE_ITER_API
		{
			ut64 naddr = addr;
			size_t size = len;
			if (insn == NULL)
				insn = cs_malloc (handle);
			n = cs_disasm_iter (handle, (const uint8_t**)&buf, &size, (uint64_t*)&naddr, insn);
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
			op->prefix = 0;
			switch (insn->detail->x86.prefix[0]) {
			case X86_PREFIX_REPNE:
				op->prefix |= R_ANAL_OP_PREFIX_REPNE;
			case X86_PREFIX_REP:
				op->prefix |= R_ANAL_OP_PREFIX_REP;
			case X86_PREFIX_LOCK:
				op->prefix |= R_ANAL_OP_PREFIX_LOCK;
			}
			switch (insn->id) {
			case X86_INS_FNOP:
			case X86_INS_NOP:
				op->type = R_ANAL_OP_TYPE_NOP;
				if (a->decode)
					esilprintf (op, ",");
				break;
			case X86_INS_HLT:
				op->type = R_ANAL_OP_TYPE_TRAP;
				break;
			case X86_INS_CLI:
			case X86_INS_STI:
			case X86_INS_CLC:
			case X86_INS_STC:
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
						esilprintf (op, "%s,%s",
								getarg (insn, 1, 0),
								getarg (insn, 0, 1));
					}
					break;
				default:
					if (a->decode) {
						esilprintf (op, "%s,%s,=",
								getarg (insn, 1, 0),
								getarg (insn, 0, 0));
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
					char *src = getarg (insn, 1, 0);
					char *dst = getarg (insn, 0, 0);
					esilprintf (op, "%s,%s,<<=,cz,%%z,zf,=", src, dst);
					free (src);
					free (dst);
				}
				break;
			case X86_INS_SAR:
			case X86_INS_SARX:
				op->type = R_ANAL_OP_TYPE_SAR;
				if (a->decode) {
					char *src = getarg (insn, 1, 0);
					char *dst = getarg (insn, 0, 0);
					esilprintf (op, "%s,%s,>>=,%%z,zf,=", src, dst);
					free (src);
					free (dst);
				}
				break;
			case X86_INS_SAL:
			case X86_INS_SALC:
				op->type = R_ANAL_OP_TYPE_SAL;
				if (a->decode) {
					char *src = getarg (insn, 1, 0);
					char *dst = getarg (insn, 0, 0);
					esilprintf (op, "%s,%s,<<=,%%z,zf,=", src, dst);
					free (src);
					free (dst);
				}
				break;
			case X86_INS_SHR:
			case X86_INS_SHRD:
			case X86_INS_SHRX:
				op->type = R_ANAL_OP_TYPE_SHR;
				if (a->decode) {
					char *src = getarg (insn, 1, 0);
					char *dst = getarg (insn, 0, 0);
					esilprintf (op, "%s,%s,>>=,cz,%%z,zf,=", src, dst);
					free (src);
					free (dst);
				}
				break;
			case X86_INS_CMP:
			case X86_INS_VCMP:
			case X86_INS_CMPPD:
			case X86_INS_CMPPS:
			case X86_INS_CMPSW:
			case X86_INS_CMPSD:
			case X86_INS_CMPSQ:
			case X86_INS_CMPSB:
			case X86_INS_CMPSS:
			case X86_INS_TEST:
				op->type = R_ANAL_OP_TYPE_CMP;
				if (a->decode) {
					char *src = getarg (insn, 1, 0);
					char *dst = getarg (insn, 0, 0);
					esilprintf (op,  "%s,%s,==,%%z,zf,=", dst, src);
					free (src);
					free (dst);
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
					char *src = getarg (insn, 0, 0);
					char *dst = getarg (insn, 1, 2);
					esilprintf (op, "%s,%s,=", dst, src);
					free (src);
					free (dst);
				}
				switch (INSOP(1).type) {
				case X86_OP_MEM:
					op->ptr = INSOP(1).mem.disp;
					op->refptr = INSOP(1).size;
					if (INSOP(1).mem.base == X86_REG_RBP || INSOP(1).mem.base == X86_REG_EBP) {
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
				break;
			case X86_INS_ENTER:
			case X86_INS_PUSH:
			case X86_INS_PUSHAW:
			case X86_INS_PUSHAL:
			case X86_INS_PUSHF:
				{
					char *dst = getarg (insn, 0, 0);
					esilprintf (op,  "%d,%s,-=,%s,%s,=[%d]", rs, sp, dst, sp, rs);
					free (dst);
				}
				op->type = R_ANAL_OP_TYPE_PUSH;
				switch (INSOP(0).type) {
				case X86_OP_IMM:
					op->ptr = INSOP(0).imm;
				default:
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
			case X86_INS_POPAW:
			case X86_INS_POPAL:
			case X86_INS_POPF:
			case X86_INS_POPCNT:
				op->type = R_ANAL_OP_TYPE_POP;
				if (a->decode) {
					char *dst = getarg (insn, 0, 0);
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
					esilprintf (op, "%d,$", (int)INSOP(0).imm);
				op->type = R_ANAL_OP_TYPE_SWI;
				break;
			case X86_INS_INT1:
			case X86_INS_INT3:
			case X86_INS_INTO:
			case X86_INS_VMCALL:
			case X86_INS_VMMCALL:
			case X86_INS_SYSCALL:
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
					char *dst = getarg (insn, 0, 2);
					switch (insn->id) {
					case X86_INS_JL:
						esilprintf (op, "of,sf,^,?{,%s,%s,}", dst, pc);
						break;
					case X86_INS_JLE:
						esilprintf (op, "of,sf,^,zf,|,%s,%s,=", dst, pc);
						break;
					case X86_INS_JA:
						esilprintf (op, "cf,!,zf,!,&,?{,%s,%s,}",dst, pc);
						break;
					case X86_INS_JAE:
						esilprintf (op, "cf,?{,%s,%s,=,}", dst, pc);
						break;
					case X86_INS_JB:
						esilprintf (op, "cf,?{,%s,%s,=,}", dst, pc);
						break;
					case X86_INS_JO:
						esilprintf (op, "of,?{,%s,%s,=,}", dst, pc);
						break;
					case X86_INS_JNO:
						esilprintf (op, "of,!,?{,%s,%s,}", dst, pc);
						break;
					case X86_INS_JE:
						esilprintf (op, "zf,?{,%s,%s,=,}", dst, pc);
						break;
					case X86_INS_JGE:
						esilprintf (op, "of,!,sf,^,?{,%s,%s,}", dst, pc);
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
						esilprintf (op, "zf,cf,&,?{,%s,%s,=,}", dst, pc);
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
					if (INSOP(0).mem.base== 0) {
						op->ptr = INSOP(0).mem.disp;
					}
					break;
				default:
					op->type = R_ANAL_OP_TYPE_UCALL;
					op->jump = UT64_MAX;
					break;
				}
				if (a->decode) {
					esilprintf (op,
							"%d,%s,+,"
							"%d,%s,-=,%s,"
							"=[],"
							"%"PFMT64d",%s,=",
							op->size, pc,
							rs, sp, sp,
							op->jump, pc);
				}
				break;
			case X86_INS_JMP:
			case X86_INS_LJMP:
				if (a->decode) {
					char *src = getarg (insn, 0, 0);
					esilprintf (op, "%s,%s,=", src, pc);
					free (src);
				}
				// TODO: what if UJMP?
				if (INSOP(0).type == X86_OP_IMM) {
					op->jump = INSOP(0).imm;
					op->type = R_ANAL_OP_TYPE_JMP;
					if (a->decode) {
						ut64 dst = INSOP(0).imm;
						esilprintf (op, "0x%"PFMT64x",%s,=", dst, pc);
					}
				} else {
					op->type = R_ANAL_OP_TYPE_UJMP;
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
					char *src = getarg (insn, 1, 0);
					char *dst = getarg (insn, 0, 0);
					esilprintf (op, "%s,%s,^=", dst, src);
					free (src);
					free (dst);
				}
				break;
			case X86_INS_OR:
				op->type = R_ANAL_OP_TYPE_OR;
				if (a->decode) {
					char *src = getarg (insn, 1, 0);
					char *dst = getarg (insn, 0, 0);
					esilprintf (op, "%s,%s,|=", dst, src);
					free (src);
					free (dst);
				}
				break;
			case X86_INS_SUB:
			case X86_INS_DEC:
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
					char *src = getarg (insn, 1, 0);
					char *dst = getarg (insn, 0, 0);
					esilprintf (op, "%s,%s,-=,%%c,cf,=,%%z,zf,=,%%s,sf,=,%%o,of,=", src, dst); // TODO: update flags
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
			case X86_INS_AND:
			case X86_INS_ANDN:
			case X86_INS_ANDPD:
			case X86_INS_ANDPS:
			case X86_INS_ANDNPD:
			case X86_INS_ANDNPS:
				op->type = R_ANAL_OP_TYPE_AND;
				if (a->decode) {
					char *src = getarg (insn, 1, 0);
					char *dst = getarg (insn, 0, 0);
					esilprintf (op, "%s,%s,&=", dst, src);
					free (src);
					free (dst);
				}
				break;
			case X86_INS_DIV:
				op->type = R_ANAL_OP_TYPE_DIV;
				if (a->decode) {
					char *src = getarg (insn, 1, 0);
					char *dst = getarg (insn, 0, 0);
					esilprintf (op, "%s,%s,/=", dst, src);
					free (src);
					free (dst);
				}
				break;
			case X86_INS_MUL:
				op->type = R_ANAL_OP_TYPE_MUL;
				if (a->decode) {
					char *src = getarg (insn, 1, 0);
					char *dst = getarg (insn, 0, 0);
					esilprintf (op, "%s,%s,*=", dst, src);
					free (src);
					free (dst);
				}
				break;
			case X86_INS_INC:
				op->type = R_ANAL_OP_TYPE_ADD;
				if (a->decode) {
					char *dst = getarg (insn, 0, 0);
					esilprintf (op, "1,%s,+=", dst);
					free (dst);
				}
				break;
			case X86_INS_ADD:
			case X86_INS_FADD:
			case X86_INS_ADDPD:
				op->type = R_ANAL_OP_TYPE_ADD;
				if (a->decode) {
					char *src = getarg (insn, 1, 0);
					char *dst = getarg (insn, 0, 0);
					esilprintf (op, "%s,%s,+=", dst, src);
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
			}
		}
#if !USE_ITER_API
		cs_free (insn, n);
#endif
		cs_close (&handle);
	}
	return op->size;
}

RAnalPlugin r_anal_plugin_x86_cs = {
	.name = "x86",
	.desc = "Capstone X86 analysis",
	.esil = R_TRUE,
	.license = "BSD",
	.arch = R_SYS_ARCH_X86,
	.bits = 16|32|64,
	.op = &analop,
	//.set_reg_profile = &set_reg_profile,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_x86_cs
};
#endif
