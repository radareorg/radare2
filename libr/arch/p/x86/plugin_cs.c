
/* radare2 - LGPL - Copyright 2013-2025 - pancake */

#include <r_arch.h>
#include <r_anal.h>
#include <r_lib.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>

// clang-format off
#define r_anal_value_new() R_NEW0 (RAnalValue)
#define ARCH_HAVE_READ 1
#define GHOSTOPS 1

#if 0
CYCLES:
======
register access = 1
memory access = 2
jump = 3
call = 4
#endif

#define CYCLE_REG 0
#define CYCLE_MEM 1
#define CYCLE_JMP 2

#if CS_NEXT_VERSION > 0
#define HAVE_CSGRP_PRIVILEGE 1
#else
#define HAVE_CSGRP_PRIVILEGE 0
#endif

#define USE_ITER_API 1

#if CS_API_MAJOR < 2
#error Old Capstone not supported
#endif

#define CSINC X86
#define CSINC_MODE \
	R_SYS_BITS_CHECK (as->config->bits, 64)? CS_MODE_64: \
	R_SYS_BITS_CHECK (as->config->bits, 32)? CS_MODE_32: \
	R_SYS_BITS_CHECK (as->config->bits, 16)? CS_MODE_16: 0
#include "../capstone.inc.c"

typedef struct plugin_data_t {
	CapstonePluginData cpd;
	int bits;
	int syntax;
	int omode; // XXX unused?
// 	char *cpu;
} PluginData;

static bool init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}
	PluginData *pd = R_NEW0 (PluginData);
	if (!pd) {
		return false;
	}
	// pd->cpu = as->config->cpu? strdup (as->config->cpu): NULL;
	if (!r_arch_cs_init (as, &pd->cpd.cs_handle)) {
		R_LOG_ERROR ("Cannot initialize capstone");
		R_FREE (as->data);
		return false;
	}
	pd->bits = as->config->bits;
	pd->syntax = as->config->syntax;
	as->data = pd;
	return true;
}

static bool fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	PluginData *pd = as->data;
	cs_close (&pd->cpd.cs_handle);
	R_FREE (as->data);
	return true;
}

static csh cs_handle_for_session(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, 0);
	CapstonePluginData *pd = as->data;
	return pd->cs_handle;
}

static inline RAnalValue * R_NONNULL newvalue(int type, int access, const char *regname, int delta, int memref) {
	RAnalValue *val = R_NEW0 (RAnalValue);
	val->type = type;
	val->access = access;
	val->reg = regname;
	val->delta = delta;
	val->memref = memref;
	return val;
}

#define opexprintf(op, fmt, ...) r_strbuf_setf (&op->opex, fmt, ##__VA_ARGS__)
#define INSOP(n) insn->detail->x86.operands[n]
#define INSOPS insn->detail->x86.op_count
#define ISIMM(x) insn->detail->x86.operands[x].type == X86_OP_IMM
#define ISMEM(x) insn->detail->x86.operands[x].type == X86_OP_MEM

struct Getarg {
	csh handle;
	cs_insn *insn;
	int bits;
	int syntax; // R_ARCH_SYNTAX_ATT or R_ARCH_SYNTAX_INTEL
};

// TODO: get rid of this unnecessary wrapper
static void hidden_op(cs_insn *insn, cs_x86 *x, int mode) {
	unsigned int id = insn->id;
	int regsz = 4;
	switch (mode) {
	case CS_MODE_64:
		regsz = 8;
		break;
	case CS_MODE_16:
		regsz = 2;
		break;
	default:
		regsz = 4; //32 bit
		break;
	}

	switch (id) {
	case X86_INS_PUSHF:
	case X86_INS_POPF:
	case X86_INS_PUSHFD:
	case X86_INS_POPFD:
	case X86_INS_PUSHFQ:
	case X86_INS_POPFQ:
		x->op_count = 1;
		cs_x86_op *op = &x->operands[0];
		op->type = X86_OP_REG;
		op->reg = X86_REG_EFLAGS;
		op->size = regsz;
#if CS_API_MAJOR >= 4
		if (id == X86_INS_PUSHF || id == X86_INS_PUSHFD || id == X86_INS_PUSHFQ) {
			op->access = 1;
		} else {
			op->access = 2;
		}
#endif
		break;
	case X86_INS_PUSHAW:
	case X86_INS_PUSHAL:
	case X86_INS_POPAW:
	case X86_INS_POPAL:
	default:
		break;
	}
}

static void opex(RArchSession *as, RStrBuf *buf, cs_insn *insn, int mode) {
	csh handle = cs_handle_for_session (as);

	int i;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	cs_x86 *x = &insn->detail->x86;
	if (x->op_count == 0) {
		hidden_op (insn, x, mode);
	}
	pj_ka (pj, "operands");
	for (i = 0; i < x->op_count; i++) {
		cs_x86_op *op = x->operands + i;
		pj_o (pj);
		pj_ki (pj, "size", op->size);
#if CS_API_MAJOR >= 4
		pj_ki (pj, "rw", op->access); // read, write, read|write
#endif
		switch (op->type) {
		case X86_OP_REG:
			pj_ks (pj, "type", "reg");
			pj_ks (pj, "value", r_str_get (cs_reg_name (handle, op->reg)));
			break;
		case X86_OP_IMM:
			pj_ks (pj, "type", "imm");
			pj_kN (pj, "value", op->imm);
			break;
		case X86_OP_MEM:
			pj_ks (pj, "type", "mem");
			if (op->mem.segment != X86_REG_INVALID) {
				pj_ks (pj, "segment", r_str_get (cs_reg_name (handle, op->mem.segment)));
			}
			if (op->mem.base != X86_REG_INVALID) {
				pj_ks (pj, "base", r_str_get (cs_reg_name (handle, op->mem.base)));
			}
			if (op->mem.index != X86_REG_INVALID) {
				pj_ks (pj, "index", r_str_get (cs_reg_name (handle, op->mem.index)));
			}
			pj_ki (pj, "scale", op->mem.scale);
			pj_kN (pj, "disp", op->mem.disp);
			break;
		default:
			pj_ks (pj, "type", "invalid");
			break;
		}
		pj_end (pj); /* o operand */
	}
	pj_end (pj); /* a operands */
	if (x->rex) {
		pj_kb (pj, "rex", true);
	}
	if (x->modrm) {
		pj_kb (pj, "modrm", true);
	}
	if (x->sib) {
		pj_ki (pj, "sib", x->sib);
	}
	if (x->disp) {
		pj_kN (pj, "disp", x->disp);
	}
	if (x->sib_index != X86_REG_INVALID) {
		pj_ki (pj, "sib_scale", x->sib_scale);
		pj_ks (pj, "sib_index", r_str_get (cs_reg_name (handle, x->sib_index)));
	}
	if (x->sib_base != X86_REG_INVALID) {
		pj_ks (pj, "sib_base", r_str_get (cs_reg_name (handle, x->sib_base)));
	}
	pj_end (pj);

	r_strbuf_init (buf);
	r_strbuf_append (buf, pj_string (pj));
	pj_free (pj);
}

static bool is_xmm_reg(cs_x86_op op) {
	switch (op.reg) {
	case X86_REG_XMM0:
	case X86_REG_XMM1:
	case X86_REG_XMM2:
	case X86_REG_XMM3:
	case X86_REG_XMM4:
	case X86_REG_XMM5:
	case X86_REG_XMM6:
	case X86_REG_XMM7:
	case X86_REG_XMM8:
	case X86_REG_XMM9:
	case X86_REG_XMM10:
	case X86_REG_XMM11:
	case X86_REG_XMM12:
	case X86_REG_XMM13:
	case X86_REG_XMM14:
	case X86_REG_XMM15:
	case X86_REG_XMM16:
	case X86_REG_XMM17:
	case X86_REG_XMM18:
	case X86_REG_XMM19:
	case X86_REG_XMM20:
	case X86_REG_XMM21:
	case X86_REG_XMM22:
	case X86_REG_XMM23:
	case X86_REG_XMM24:
	case X86_REG_XMM25:
	case X86_REG_XMM26:
	case X86_REG_XMM27:
	case X86_REG_XMM28:
	case X86_REG_XMM29:
	case X86_REG_XMM30:
	case X86_REG_XMM31: return true;
	default: return false;
	}
}

/**
 * Get normalized operand index for AT&T syntax
 * In AT&T, operands are source,dest so we swap for 2-operand instructions
 */
static inline int norm_op(int n, int syntax, int op_count) {
	if (syntax == R_ARCH_SYNTAX_ATT && op_count == 2) {
		return 1 - n; // swap 0<->1
	}
	return n;
}

/**
 * Translates operand N to esil
 *
 * @param  handle  csh
 * @param  insn    cs_insn
 * @param  n       Operand index
 * @param  set     if 1 it adds set (=) to the operand
 * @param  setoper Extra operation for the set (^, -, +, etc...)
 * @param  sel     Selector for output buffer in staic array
 * @return         Pointer to esil operand in static array
 */
static char *getarg(struct Getarg* gop, int n, int set, char *setop, ut32 *bitsize) {
	const char *setarg = r_str_get (setop);
	cs_insn *insn = gop->insn;
	csh handle = gop->handle;

	if (bitsize) {
		// default blind bitsize which may be wrong
		*bitsize = 8;
	}
	// For AT&T syntax, capstone reports operands in source,dest order
	// We need to swap indices for 2-operand instructions to normalize
	int actual_n = n;
	if (gop->syntax == R_ARCH_SYNTAX_ATT && INSOPS == 2) {
		actual_n = 1 - n; // swap 0<->1
	}
	cs_x86_op op = INSOP (actual_n);
	if (!insn->detail) {
		return NULL;
	}
	if (actual_n < 0 || actual_n >= INSOPS) {
		return NULL;
	}
	if (bitsize) {
		size_t bs = op.size * 8;
		*bitsize = bs? bs: 8;
	}
	switch (op.type) {
#if CS_API_MAJOR == 3
	case X86_OP_FP:
		return strdup ("invalid");
#endif
	case X86_OP_INVALID:
		return strdup ("invalid");
	case X86_OP_REG:
		{
			const char *rn = cs_reg_name (handle, op.reg);
			if (rn) {
				if (set == 1) {
					return r_str_newf ("%s,%s=", rn, setarg);
				}
				return strdup (rn);
			}
			return NULL;
		}
	case X86_OP_IMM:
		if (set == 1) {
			return r_str_newf ("%"PFMT64u",%s=[%d]", (ut64)op.imm, setarg, op.size);
		}
		return r_str_newf ("%"PFMT64u, (ut64)op.imm);
	case X86_OP_MEM:
		{
		// address = (base + (index * scale) + offset)
		int component_count = 0;
		const char *base = cs_reg_name (handle, op.mem.base);
		const char *index = cs_reg_name (handle, op.mem.index);
		int scale = op.mem.scale;
		st64 disp = op.mem.disp;
		RStrBuf *sb = r_strbuf_new ("");
		if (disp != 0) {
			r_strbuf_setf (sb, "0x%"PFMT64x",", (disp < 0) ? -disp : disp); // out
			component_count++;
		}
		if (index) {
			if (scale > 1) {
				r_strbuf_appendf (sb, "%s,%d,*,", index, scale);
			} else {
				r_strbuf_appendf (sb, "%s,", index);
			}
			component_count++;
		}
		if (base) {
			r_strbuf_appendf (sb, "%s,", base);
			component_count++;
		}
		if (component_count > 1) {
			if (component_count > 2) {
				r_strbuf_append (sb, "+,");
			}
			if (disp < 0) {
				r_strbuf_append (sb, "-");
			} else {
				r_strbuf_append (sb, "+");
			}
		} else {
			size_t blen = r_strbuf_length (sb);
			if (blen > 0) {
				r_strbuf_slice (sb, 0, blen - 1);
			}
		}

		// set = 2 is reserved for lea, where the operand is a memory address,
		// but the corresponding memory is not loaded.
		if (set == 1) {
			size_t len = strlen (setarg);
			if (len > 0 && setarg[len - 1] == ',') {
				r_strbuf_appendf (sb, ",%s%s=[%d]", setarg,
					gop->bits == 32 ? "0xffffffff,&," : "", op.size == 10? 8: op.size);
			} else {
				r_strbuf_appendf (sb, ",%s=[%d]", setarg, op.size == 10? 8: op.size);
			}
		} else if (set == 0) {
			if (r_strbuf_length (sb) == 0) {
				r_strbuf_set (sb, "0");
			}
			r_strbuf_appendf (sb, ",[%d]", op.size == 10? 8: op.size);
		}
		return r_strbuf_drain (sb);
		}
	}
	return NULL;
}

static int cond_x862r2(int id) {
	switch (id) {
	case X86_INS_JE:
		return R_ANAL_CONDTYPE_EQ;
	case X86_INS_JNE:
		return R_ANAL_CONDTYPE_NE;
	case X86_INS_JB:
	case X86_INS_JL:
		return R_ANAL_CONDTYPE_LT;
	case X86_INS_JBE:
	case X86_INS_JLE:
		return R_ANAL_CONDTYPE_LE;
	case X86_INS_JG:
	case X86_INS_JA:
		return R_ANAL_CONDTYPE_GT;
	case X86_INS_JAE:
		return R_ANAL_CONDTYPE_GE;
	case X86_INS_JS:
	case X86_INS_JNS:
	case X86_INS_JO:
	case X86_INS_JNO:
	case X86_INS_JGE:
	case X86_INS_JP:
	case X86_INS_JNP:
	case X86_INS_JCXZ:
	case X86_INS_JECXZ:
		break;
	}
	return 0;
}

#if ARCH_HAVE_READ
/* reg indices are based on Intel doc for 32-bit ModR/M byte */
static const char *reg32_to_name(ut8 reg) {
	const char * const names[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
	return reg < R_ARRAY_SIZE (names) ? names[reg] : "unk";
}
#endif

static inline bool get64from32(const char *s, char *out, size_t outsz) {
	if (*s == 'e') {
		snprintf (out, outsz, "r%s", s + 1);
		return true;
	}
	if (*s == 'r' && isdigit (s[1])) {
		if (s[2] == 'd' || (s[2] != 0 && isdigit(s[2]) && s[3] == 'd')) {
			snprintf (out, outsz, "r%d", atoi (s + 1));
			return true;
		}
	}
	return false;
}

static void anop_esil(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh handle, cs_insn *insn) {
	RAnalValue *val = NULL;
	const int bits = as->config->bits;
	int rs = bits / 8;
	const char *pc, *sp, *bp, *si;
	switch (bits) {
	case 16:
		pc = "ip";
		sp = "sp";
		bp = "bp";
		si = "si";
		break;
	case 32:
		pc = "eip";
		sp = "esp";
		bp = "ebp";
		si = "esi";
		break;
	// case 64:
	default:
		pc = "rip";
		sp = "rsp";
		bp = "rbp";
		si = "rsi";
		break;
	}
	struct Getarg gop = {
		.handle = handle,
		.insn = insn,
		.bits = bits,
		.syntax = as->config->syntax
	};
	char *src = NULL;
	char *src2 = NULL;
	char *dst = NULL;
	char *dst2 = NULL;
	char *dst_r = NULL;
	char *dst_w = NULL;
	char *dstAdd = NULL;
	char *arg0 = NULL;
	char *arg1 = NULL;
	char *arg2 = NULL;

	// counter for rep prefix
	const char *counter = (bits == 16)?"cx": (bits == 32)? "ecx": "rcx";

	bool repe = false;

	switch (insn->id) {
	case X86_INS_FNOP:
	case X86_INS_NOP:
	case X86_INS_PAUSE:
		esilprintf (op, ",");
		break;
	case X86_INS_HLT:
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
		break;
	case X86_INS_FTST:
	case X86_INS_FUCOMI:
	case X86_INS_FUCOMPP:
	case X86_INS_FUCOMP:
	case X86_INS_FUCOM:
		break;
	case X86_INS_FABS:
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
		break;
	case X86_INS_FIST:
	case X86_INS_FISTP:
	case X86_INS_FST:
	case X86_INS_FSTP:
	case X86_INS_FSTPNCE:
	case X86_INS_FXRSTOR:
	case X86_INS_FXRSTOR64:
		break;
	case X86_INS_FIDIV:
	case X86_INS_FIDIVR:
	case X86_INS_FDIV:
	case X86_INS_FDIVP:
	case X86_INS_FDIVR:
	case X86_INS_FDIVRP:
		break;
	case X86_INS_FSUBR:
	case X86_INS_FISUBR:
	case X86_INS_FSUBRP:
	case X86_INS_FSUB:
	case X86_INS_FISUB:
	case X86_INS_FSUBP:
		break;
	case X86_INS_FMUL:
	case X86_INS_FIMUL:
	case X86_INS_FMULP:
		break;
	case X86_INS_CLI:
		esilprintf (op, "0,if,:=");
		break;
	case X86_INS_STI:
		esilprintf (op, "1,if,:=");
		break;
	case X86_INS_CLC:
		esilprintf (op, "0,cf,:=");
		break;
	case X86_INS_CMC:
		esilprintf (op, "cf,!,cf,=");
		break;
	case X86_INS_STC:
		esilprintf (op, "1,cf,:=");
		break;
	case X86_INS_CLAC:
	case X86_INS_CLGI:
	case X86_INS_CLTS:
#if CS_API_MAJOR >= 4
	case X86_INS_CLWB:
#endif
	case X86_INS_STAC:
	case X86_INS_STGI:
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
		{
			dst = getarg (&gop, 0, 1, NULL, NULL);
			switch (insn->id) {
			case X86_INS_SETE:  esilprintf (op, "zf,%s", dst); break;
			case X86_INS_SETNE: esilprintf (op, "zf,!,%s", dst); break;
			case X86_INS_SETO:  esilprintf (op, "of,%s", dst); break;
			case X86_INS_SETNO: esilprintf (op, "of,!,%s", dst); break;
			case X86_INS_SETP:  esilprintf (op, "pf,%s", dst); break;
			case X86_INS_SETNP: esilprintf (op, "pf,!,%s", dst); break;
			case X86_INS_SETS:  esilprintf (op, "sf,%s", dst); break;
			case X86_INS_SETNS: esilprintf (op, "sf,!,%s", dst); break;
			case X86_INS_SETB:  esilprintf (op, "cf,%s", dst); break;
			case X86_INS_SETAE: esilprintf (op, "cf,!,%s", dst); break;
			case X86_INS_SETL:  esilprintf (op, "sf,of,^,%s", dst); break;
			case X86_INS_SETLE: esilprintf (op, "zf,sf,of,^,|,%s", dst); break;
			case X86_INS_SETG:  esilprintf (op, "zf,!,sf,of,^,!,&,%s", dst); break;
			case X86_INS_SETGE: esilprintf (op, "sf,of,^,!,%s", dst); break;
			case X86_INS_SETA:  esilprintf (op, "cf,zf,|,!,%s", dst); break;
			case X86_INS_SETBE: esilprintf (op, "cf,zf,|,%s", dst); break;
			}
			R_FREE (dst);
		}
		break;
	// cmov
	case X86_INS_FCMOVBE:
	case X86_INS_FCMOVB:
	case X86_INS_FCMOVNBE:
	case X86_INS_FCMOVNB:
	case X86_INS_FCMOVE:
	case X86_INS_FCMOVNE:
	case X86_INS_FCMOVNU:
	case X86_INS_FCMOVU:
		break;
	case X86_INS_CMOVA:
	case X86_INS_CMOVAE:
	case X86_INS_CMOVB:
	case X86_INS_CMOVBE:
	case X86_INS_CMOVE:
	case X86_INS_CMOVG:
	case X86_INS_CMOVGE:
	case X86_INS_CMOVL:
	case X86_INS_CMOVLE:
	case X86_INS_CMOVNE:
	case X86_INS_CMOVNO:
	case X86_INS_CMOVNP:
	case X86_INS_CMOVNS:
	case X86_INS_CMOVO:
	case X86_INS_CMOVP:
	case X86_INS_CMOVS: {
		const char *conditional = NULL;
		src = getarg (&gop, 1, 0, NULL, NULL);
		dst = getarg (&gop, 0, 1, NULL, NULL);
		switch (insn->id) {
		case X86_INS_CMOVA:
			// mov if CF = 0 *AND* ZF = 0
			conditional = "cf,zf,|,!";
			break;
		case X86_INS_CMOVAE:
			// mov if CF = 0
			conditional = "cf,!";
			break;
		case X86_INS_CMOVB:
			// mov if CF = 1
			conditional = "cf";
			break;
		case X86_INS_CMOVBE:
			// mov if CF = 1 *OR* ZF = 1
			conditional = "cf,zf,|";
			break;
		case X86_INS_CMOVE:
			// mov if ZF = 1
			conditional = "zf";
			break;
		case X86_INS_CMOVG:
			// mov if ZF = 0 *AND* SF = OF
			conditional = "zf,!,sf,of,^,!,&";
			break;
		case X86_INS_CMOVGE:
			// mov if SF = OF
			conditional = "sf,of,^,!";
			break;
		case X86_INS_CMOVL:
			// mov if SF != OF
			conditional = "sf,of,^";
			break;
		case X86_INS_CMOVLE:
			// mov if ZF = 1 *OR* SF != OF
			conditional = "zf,sf,of,^,|";
			break;
		case X86_INS_CMOVNE:
			// mov if ZF = 0
			conditional = "zf,!";
			break;
		case X86_INS_CMOVNO:
			// mov if OF = 0
			conditional = "of,!";
			break;
		case X86_INS_CMOVNP:
			// mov if PF = 0
			conditional = "pf,!";
			break;
		case X86_INS_CMOVNS:
			// mov if SF = 0
			conditional = "sf,!";
			break;
		case X86_INS_CMOVO:
			// mov if OF = 1
			conditional = "of";
			break;
		case X86_INS_CMOVP:
			// mov if PF = 1
			conditional = "pf";
			break;
		case X86_INS_CMOVS:
			// mov if SF = 1
			conditional = "sf";
			break;
		}
		if (src && dst && conditional) {
			esilprintf (op, "%s,?{,%s,%s,}", conditional, src, dst);
		}
		R_FREE (src);
		R_FREE (dst);
	}
		break;
	case X86_INS_STOSB:
		if (bits < 32) {
			r_strbuf_append (&op->esil, "al,di,=[1],df,?{,1,di,-=,},df,!,?{,1,di,+=,}");
		} else {
			r_strbuf_append (&op->esil, "al,edi,=[1],df,?{,1,edi,-=,},df,!,?{,1,edi,+=,}");
		}
		break;
	case X86_INS_STOSW:
		if (bits < 32) {
			r_strbuf_append (&op->esil, "ax,di,=[2],df,?{,2,di,-=,},df,!,?{,2,di,+=,}");
		} else {
			r_strbuf_append (&op->esil, "ax,edi,=[2],df,?{,2,edi,-=,},df,!,?{,2,edi,+=,}");
		}
		break;
	case X86_INS_STOSD:
			r_strbuf_append (&op->esil, "eax,edi,=[4],df,?{,4,edi,-=,},df,!,?{,4,edi,+=,}");
		break;
	case X86_INS_STOSQ:
			r_strbuf_append (&op->esil, "rax,rdi,=[8],df,?{,8,edi,-=,},df,!,?{,8,edi,+=,}");
		break;
	case X86_INS_LODSB:
			r_strbuf_appendf (&op->esil, "%s,[1],al,=,df,?{,1,%s,-=,},df,!,?{,1,%s,+=,}", si, si, si);
		break;
	case X86_INS_LODSW:
			r_strbuf_appendf (&op->esil, "%s,[2],ax,=,df,?{,2,%s,-=,},df,!,?{,2,%s,+=,}", si, si, si);
		break;
	case X86_INS_LODSD:
		r_strbuf_append (&op->esil, "esi,[4],eax,=,df,?{,4,esi,-=,},df,!,?{,4,esi,+=,}");
		break;
	case X86_INS_LODSQ:
		r_strbuf_append (&op->esil, "rsi,[8],rax,=,df,?{,8,rsi,-=,},df,!,?{,8,rsi,+=,}");
		break;
	case X86_INS_PEXTRB:
		r_strbuf_append (&op->esil, "TODO");
		break;
	// string mov
	// PS: MOVSD can correspond to one of the two instruction (yes, intel x86
	// has the same pneumonic for two different opcodes!). We can decide which
	// of the two it is based on the operands.
	// For more information, see:
	// https://mudongliang.github.io/x86/html/file_module_x86_id_203.html
	//               (vs)
	// https://mudongliang.github.io/x86/html/file_module_x86_id_204.html
	case X86_INS_MOVSD:
		// Handle "Move Scalar Double-Precision Floating-Point Value"
		if (is_xmm_reg (INSOP (0)) || is_xmm_reg (INSOP (1))) {
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, NULL, NULL);
			if (src && dst) {
				esilprintf (op, "%s,%s", src, dst);
			}
			free (src);
			free (dst);
			break;
		}
	case X86_INS_MOVSB:
	case X86_INS_MOVSQ:
	case X86_INS_MOVSW:
		if (op->prefix & R_ANAL_OP_PREFIX_REP) {
			int width = INSOP(0).size;
			src = (char *)cs_reg_name (handle, INSOP(1).mem.base);
			dst = (char *)cs_reg_name (handle, INSOP(0).mem.base);
			r_strbuf_appendf (&op->esil,
					"%s,[%d],%s,=[%d],"\
					"df,?{,%d,%s,-=,%d,%s,-=,},"\
					"df,!,?{,%d,%s,+=,%d,%s,+=,}",
					src, width, dst, width,
					width, src, width, dst,
					width, src, width, dst);
		} else {
			int width = INSOP(0).size;
			src = (char *)cs_reg_name (handle, INSOP(1).mem.base);
			dst = (char *)cs_reg_name (handle, INSOP(0).mem.base);
			esilprintf (op, "%s,[%d],%s,=[%d],df,?{,%d,%s,-=,%d,%s,-=,},"\
					"df,!,?{,%d,%s,+=,%d,%s,+=,}",
					src, width, dst, width, width, src, width,
					dst, width, src, width, dst);
		}
		break;
	// mov
	case X86_INS_MOVSS:
	case X86_INS_MOV:
	case X86_INS_MOVAPS:
	case X86_INS_MOVAPD:
	case X86_INS_MOVZX:
	case X86_INS_MOVUPS:
	case X86_INS_MOVABS:
	case X86_INS_MOVHPD:
	case X86_INS_MOVHPS:
	case X86_INS_MOVLPD:
	case X86_INS_MOVLPS:
	case X86_INS_MOVBE:
	case X86_INS_MOVSX:
	case X86_INS_MOVSXD:
	case X86_INS_MOVQ:
	case X86_INS_MOVDQU:
	case X86_INS_MOVDQA:
	case X86_INS_MOVDQ2Q:
		{
		// Use normalized operand indices for AT&T syntax support
		int dst_idx = norm_op (0, gop.syntax, INSOPS);
		int src_idx = norm_op (1, gop.syntax, INSOPS);
		switch (INSOP (dst_idx).type) {
		case X86_OP_MEM:
			if (op->prefix & R_ANAL_OP_PREFIX_REP) {
				int width = INSOP (dst_idx).size;
				const char *src = cs_reg_name (handle, INSOP (src_idx).mem.base);
				const char *dst = cs_reg_name (handle, INSOP (dst_idx).mem.base);
				const char *counter = (bits == 16)?"cx": (bits==32)?"ecx":"rcx";
				esilprintf (op, "%s,!,?{,BREAK,},%s,NUM,%s,NUM,"\
						"%s,[%d],%s,=[%d],df,?{,%d,%s,-=,%d,%s,-=,},"\
						"df,!,?{,%d,%s,+=,%d,%s,+=,},%s,--=,%s," \
						"?{,8,GOTO,}",
						counter, src, dst, src, width, dst,
						width, width, src, width, dst, width, src,
						width, dst, counter, counter);
			} else {
				src = getarg (&gop, 1, 0, NULL, NULL);
				dst = getarg (&gop, 0, 1, NULL, NULL);
				esilprintf (op, "%s,%s", src, dst);
				free (src);
				free (dst);
			}
			break;
		case X86_OP_REG:
		default:
			if (INSOP (dst_idx).type == X86_OP_MEM) {
				op->direction = R_ANAL_OP_DIR_READ;
			}
			if (INSOP (src_idx).type == X86_OP_MEM) {
				// MOV REG, [PTR + IREG*SCALE]
				op->ireg = cs_reg_name (handle, INSOP (src_idx).mem.index);
				op->disp = INSOP (src_idx).mem.disp;
				op->scale = INSOP (src_idx).mem.scale;
			}
			{
				int width = INSOP (src_idx).size;

				src = getarg (&gop, 1, 0, NULL, NULL);
				// dst is name of register from instruction.
				dst = getarg (&gop, 0, 0, NULL, NULL);
				char dst64[16];
				const bool havedst = get64from32 (dst, dst64, sizeof (dst64));
				if (bits == 64 && havedst) {
					// Here it is still correct, because 'e** = X'
					// turns into 'r** = X' (first one will keep higher bytes,
					// second one will overwrite them with zeros).
					if (insn->id == X86_INS_MOVSX || insn->id == X86_INS_MOVSXD) {
						esilprintf (op, "%d,%s,~,%s,=", width*8, src, dst64);
					} else {
						esilprintf (op, "%s,%s,=", src, dst64);
					}

				} else {
					if (insn->id == X86_INS_MOVSX || insn->id == X86_INS_MOVSXD) {
						esilprintf (op, "%d,%s,~,%s,=", width*8, src, dst);
					} else {
						esilprintf (op, "%s,%s,=", src, dst);
					}
				}
				free (src);
				free (dst);
			}
			break;
		}
		}
		break;
	case X86_INS_MOVD:
		if (is_xmm_reg (INSOP (0))) {
			if (!is_xmm_reg (INSOP (1))) {
				src = getarg (&gop, 1, 0, NULL, NULL);
				dst = getarg (&gop, 0, 0, NULL, NULL);
				esilprintf (op, "%s,%sl,=", src, dst);
				free (src);
				free (dst);
			}
		}
		if (is_xmm_reg (INSOP (1))) {
			if (!is_xmm_reg (INSOP (0))) {
				src = getarg (&gop, 1, 0, NULL, NULL);
				dst = getarg (&gop, 0, 1, NULL, NULL);
				esilprintf (op, "%sl,%s", src, dst);
				free (src);
				free (dst);
			}
		}
		break;
	case X86_INS_ROL:
	case X86_INS_RCL:
		// TODO: RCL Still does not work as intended
		//  - Set flags
		{
			src = getarg (&gop, 1, 0, NULL, NULL);
			src2 = getarg (&gop, 0, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, NULL, NULL);
			esilprintf (op, "%s,%s,ROL,%s", src, src2, dst);
			free (src);
			free (src2);
			free (dst);
		}
		break;
	case X86_INS_ROR:
	case X86_INS_RCR:
		// TODO: RCR Still does not work as intended
		//  - Set flags
		{
			src = getarg (&gop, 1, 0, NULL, NULL);
			src2 = getarg (&gop, 0, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, NULL, NULL);
			esilprintf (op, "%s,%s,ROR,%s", src, src2, dst);
			free (src);
			free (src2);
			free (dst);
		}
		break;
	case X86_INS_CPUID:
		// https://c9x.me/x86/html/file_module_x86_id_45.html
		// GenuineIntel
		esilprintf (op, "0xa,eax,=,0x756E6547,ebx,=,0x6C65746E,ecx,=,0x49656E69,edx,=");
		break;
	case X86_INS_SHLD:
	case X86_INS_SHLX:
		// TODO: SHLD is not implemented yet.
		{
			ut32 bitsize;
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, "<<", &bitsize);
			esilprintf (op, "%s,%s,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=", src, dst, bitsize - 1);
			free (src);
			free (dst);
		}
		break;
	case X86_INS_SAR:
		// TODO: Set CF. See case X86_INS_SHL for more details.
		{
		ut32 bitsize;
		src = getarg (&gop, 1, 0, NULL, NULL);
		dst_r = getarg (&gop, 0, 0, NULL, NULL);
		dst_w = getarg (&gop, 0, 1, NULL, &bitsize);
		esilprintf (op, "0,cf,:=,1,%s,-,1,<<,%s,&,?{,1,cf,:=,},%s,%s,ASR,%s,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=",
			src, dst_r, src, dst_r, dst_w, bitsize - 1);
		free (src);
		free (dst_r);
		free (dst_w);
	}
	break;
	case X86_INS_SARX:
		{
			dst = getarg (&gop, 0, 1, NULL, NULL);
			src = getarg (&gop, 1, 0, NULL, NULL);
			src2 = getarg (&gop, 1, 0, NULL, NULL);
			esilprintf (op, "%s,%s,ASR,%s,=", src2, src, dst);
			free (src);
			free (src2);
			free (dst);
		}
		break;
	case X86_INS_SHL:
	case X86_INS_SAL:
		{
		ut32 bitsize;
		src = getarg (&gop, 1, 0, NULL, &bitsize);
		dst = getarg (&gop, 0, 0, NULL, NULL);
		// dst2 = getarg (&gop, 0, 1, "<<", &bitsize);
#if 0
	// https://c9x.me/x86/html/file_module_x86_id_285.html
	The CF flag contains the value of the last bit shifted out of the destination operand;
		it is undefined for SHL and SHR instructions where the count is greater than or equal to the size (in bits) of the destination operand.
	The OF flag is affected only for 1-bit shifts (see "Description" above); otherwise, it is undefined.
	The SF, ZF, and PF flags are set according to the result
	If the count is 0, the flags are not affected.
	For a non-zero count, the AF flag is undefined.
#endif
		ut64 val = 0;
		switch (gop.insn->detail->x86.operands[0].size) {
		case 1:
			val = 0x80;
			break;
		case 2:
			val = 0x8000;
			break;
		case 4:
			val = 0x80000000;
			break;
		case 8:
			val = (ut64)0x8000000000000000ULL;
			break;
		default:
			R_LOG_ERROR ("unknown operand size: %d", gop.insn->detail->x86.operands[0].size);
			val = 256;
		}
		// OLD: esilprintf (op, "0,%s,!,!,?{,1,%s,-,%s,<<,0x%"PFMT64x",&,!,!,^,},%s,%s,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=,cf,=", src, src, dst, val, src, dst2, bitsize - 1);
		esilprintf (op,
			"%s,0x%"PFMT64x",&,POP,$z,cf,:=,"
			"%s,%s,<<=,"
			"$z,zf,:=,"
			"$p,pf,:=,"
			"%d,$s,sf,:=",
			dst, val,
			src, dst,
			bitsize - 1);
		free (src);
		free (dst);
	   	}
		break;
	case X86_INS_SALC:
		esilprintf (op, "$z,DUP,zf,=,al,=");
		break;
	case X86_INS_SHR:
	case X86_INS_SHRX:
		// TODO: Set CF: See case X86_INS_SAL for more details.
		{
			ut32 bitsize;
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst_r = getarg (&gop, 0, 0, NULL, NULL);
			dst_w = getarg (&gop, 0, 1, NULL, &bitsize);
			if (src && dst_r && dst_w) {
				esilprintf (op, "0,cf,:=,1,%s,-,1,<<,%s,&,?{,1,cf,:=,},%s,%s,>>,%s,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=",
					src, dst_r, src, dst_r, dst_w, bitsize - 1);
			}
			free (src);
			free (dst_r);
			free (dst_w);
		}
		break;
	case X86_INS_SHRD:
		{
			ut32 bitsize;
			char shft[32];
			cs_x86_op operand = insn->detail->x86.operands[2];
			if (operand.type == X86_OP_IMM) {
				snprintf (shft, sizeof (shft), "%" PFMT64d, operand.imm);
			} else {
				snprintf (shft, sizeof (shft), "%s", "cl");
			}
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst_r = getarg (&gop, 0, 0, NULL, NULL);
			dst_w = getarg (&gop, 0, 1, NULL, &bitsize);
			esilprintf (op,  // set CF to last bit shifted out, OF if sign changes
				"%s,?{,1,1,%s,-,%s,>>,&,cf,:=,1,%s,-,!,%s,%d,%s,>>,^,!,&,of,:=,"
				"%s,%d,-,%s,<<,%s,%s,>>,|,1,%d,1,<<,-,&,%s,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=,}",
				shft, shft, dst_r, shft, src, bitsize-1, dst_r,
				shft, bitsize, src, shft, dst_r, bitsize, dst_w, bitsize-1);
			free (dst_r);
			free (dst_w);
			free (src);
		}
		break;
	case X86_INS_PSLLDQ:
		{
			ut32 shift;
			if (is_xmm_reg (INSOP(0))) {
				src = getarg (&gop, 0, 0, NULL, NULL);
				if (ISIMM (1)) {
					shift = INSOP (1).imm * 8;
					if (shift < 64) {
						esilprintf (op, "%d,%sh,<<,%d,64,-,%sl,>>,|,%sh,=,", shift, src, shift, src, src);
						r_strbuf_appendf (&op->esil, "%d,%sl,<<=", shift, src);
					} else {
						esilprintf (op, "64,%d,-,%sl,<<,%sh,=,", shift, src, src);
						r_strbuf_appendf (&op->esil, "0,%sl,=", src);
					}
				}
				free (src);
			}
		}
		break;
	case X86_INS_CBW:
		esilprintf (op, "al,ax,=,7,ax,>>,?{,0xff00,ax,|=,}");
		break;
	case X86_INS_CWDE:
		esilprintf (op, "ax,eax,=,15,eax,>>,?{,0xffff0000,eax,|=,}");
		break;
	case X86_INS_CWD:
		esilprintf (op, "0,dx,=,15,ax,>>,?{,0xffff,dx,=,}");
		break;
	case X86_INS_CDQ:
		esilprintf (op, "0,edx,=,31,eax,>>,?{,0xffffffff,edx,=,}");
		break;
	case X86_INS_CQO:
		esilprintf (op, "0,rdx,=,63,rax,>>,?{,-1,rdx,=,}");
		break;
	case X86_INS_CDQE:
		esilprintf (op, "eax,rax,=,31,rax,>>,?{,0xffffffff00000000,rax,|=,}");
		break;
	case X86_INS_AAA:
		esilprintf (op, "0,cf,:=,0,af,:=,9,al,>,?{,10,al,-=,1,ah,+=,1,cf,:=,1,af,:=,}");	//don't
		break;
	case X86_INS_AAD:
		arg0 = "0,zf,:=,0,sf,:=,0,pf,:=,10,ah,*,al,+,ax,=";
		arg1 = "0,al,==,?{,1,zf,:=,},2,al,%,0,==,?{,1,pf,:=,},7,al,>>,?{,1,sf,:=,}";
		esilprintf (op, "%s,%s", arg0, arg1);
		break;
	case X86_INS_AAM:
		arg0 = "0,zf,:=,0,sf,:=,0,pf,:=,10,al,/,ah,=,10,al,%,al,=";
		arg1 = "0,al,==,?{,1,zf,:=,},2,al,%,0,==,?{,1,pf,:=,},7,al,>>,?{,1,sf,:=,}";
		esilprintf (op, "%s,%s", arg0, arg1);
		break;
	// XXX: case X86_INS_AAS: too tough to implement. BCD is deprecated anyways
	case X86_INS_CMPPD:
	case X86_INS_CMPPS:
	case X86_INS_CMPSW:
	case X86_INS_CMPSD:
	case X86_INS_CMPSQ:
	case X86_INS_CMPSB:
	case X86_INS_CMPSS:
		repe = true;
	case X86_INS_CMP:
	case X86_INS_TEST:
		{
			ut32 bitsize;
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 0, NULL, &bitsize);

			if (!bitsize || bitsize > 64) {
				break;
			}

			if (insn->id == X86_INS_TEST) {
				esilprintf (op, "0,%s,%s,&,==,$z,zf,:=,$p,pf,:=,%u,$s,sf,:=,0,cf,:=,0,of,:=",
					src, dst, bitsize - 1);
			} else if (insn->id == X86_INS_CMP) {
				esilprintf (op,
					"%s,%s,==,$z,zf,:=,%u,$b,cf,:=,$p,pf,:=,%u,$s,sf,:=,"\
					"%s,0x%"PFMT64x",-,!,%u,$o,^,of,:=,3,$b,af,:=",
					src, dst, bitsize, bitsize - 1, src, (ut64)(1ULL << (bitsize - 1)), bitsize - 1);
			} else {
				char *rsrc = (char *)cs_reg_name (handle, INSOP(1).mem.base);
				char *rdst = (char *)cs_reg_name (handle, INSOP(0).mem.base);
				const int width = INSOP(0).size;
				esilprintf (op,
					"%s,%s,==,$z,zf,:=,%u,$b,cf,:=,$p,pf,:=,%u,$s,sf,:=,%s,0x%"PFMT64x","\
					"-,!,%u,$o,^,of,:=,3,$b,af,:=,df,?{,%d,%s,-=,%d,%s,-=,}{,%d,%s,+=,%d,%s,+=,}",
					src, dst, bitsize, bitsize - 1, src, (ut64)(1ULL << (bitsize - 1)), bitsize - 1,
					width, rsrc, width, rdst, width, rsrc, width, rdst);
			}
			free (src);
			free (dst);
		}
		break;
	case X86_INS_LEA:
		{
			src = getarg (&gop, 1, 2, NULL, NULL);
			dst = getarg (&gop, 0, 1, NULL, NULL);
			esilprintf (op, "%s,%s", src, dst);
			free (src);
			free (dst);
		}
		break;
	case X86_INS_LES:
		if (bits == 16) {
			src = getarg (&gop, 1, 2, NULL, NULL);
			dst = getarg (&gop, 0, 1, NULL, NULL);
			esilprintf (op, "%s,%s", src, dst);
			free (src);
			free (dst);
		}
		break;
	case X86_INS_LDS:
		if (bits == 16) {
			src = getarg (&gop, 1, 2, NULL, NULL);
			dst = getarg (&gop, 0, 1, NULL, NULL);
			esilprintf (op, "%s,%s", src, dst);
			R_FREE (src);
			R_FREE (dst);
		}
		break;
	case X86_INS_PUSHAW:
	// pushal, popal - push/pop EAX,EBX,ECX,EDX,ESP,EBP,ESI,EDI
	case X86_INS_PUSHAL:
		{
			esilprintf (op,
				"0,%s,+,"
				"%d,%s,-=,%s,%s,=[%d],"
				"%d,%s,-=,%s,%s,=[%d],"
				"%d,%s,-=,%s,%s,=[%d],"
				"%d,%s,-=,%s,%s,=[%d],"
				"%d,%s,-=,%s,=[%d],"
				"%d,%s,-=,%s,%s,=[%d],"
				"%d,%s,-=,%s,%s,=[%d],"
				"%d,%s,-=,%s,%s,=[%d]",
				sp,
				rs, sp, "eax", sp, rs,
				rs, sp, "ecx", sp, rs,
				rs, sp, "edx", sp, rs,
				rs, sp, "ebx", sp, rs,
				rs, sp, "esp", rs,
				rs, sp, "ebp", sp, rs,
				rs, sp, "esi", sp, rs,
				rs, sp, "edi", sp, rs
				);
		}
		break;
	case X86_INS_ENTER:
		{
			dst = getarg (&gop, 0, 0, NULL, NULL);
			esilprintf (op, "%s,%d,%s,-,=[%d],%d,%s,-=",
				r_str_get_fail (dst, "eax"), rs, sp, rs, rs, sp);
			free (dst);
		}
		break;
	case X86_INS_PUSH:
		{
			dst = getarg (&gop, 0, 0, NULL, NULL);
			int oprs = INSOP(0).size;
			esilprintf (op, "%s,%d,%s,-,=[%d],%d,%s,-=",
				r_str_get_fail (dst, "eax"), oprs, sp, rs, rs, sp);
			free (dst);
		}
		break;
	case X86_INS_PUSHF:
	case X86_INS_PUSHFD:
	case X86_INS_PUSHFQ:
		esilprintf (op, "%d,%s,-=,eflags,%s,=[%d]", rs, sp, sp, rs);
		break;
	case X86_INS_LEAVE:
		esilprintf (op, "%s,%s,=,%s,[%d],%s,=,%d,%s,+=",
			bp, sp, sp, rs, bp, rs, sp);
		break;
	case X86_INS_POPAW:
	case X86_INS_POPAL:
		{
			esilprintf (op,
				"%s,[%d],%d,%s,+=,%s,=,"
				"%s,[%d],%d,%s,+=,%s,=,"
				"%s,[%d],%d,%s,+=,%s,=,"
				"%s,[%d],%d,%s,+=,"
				"%s,[%d],%d,%s,+=,%s,=,"
				"%s,[%d],%d,%s,+=,%s,=,"
				"%s,[%d],%d,%s,+=,%s,=,"
				"%s,[%d],%d,%s,+=,%s,=,"
				"%s,=",
				sp, rs, rs, sp, "edi",
				sp, rs, rs, sp, "esi",
				sp, rs, rs, sp, "ebp",
				sp, rs, rs, sp,
				sp, rs, rs, sp, "ebx",
				sp, rs, rs, sp, "edx",
				sp, rs, rs, sp, "ecx",
				sp, rs, rs, sp, "eax",
				sp
				);
		}
		break;
	case X86_INS_POP:
		{
			switch (INSOP(0).type) {
			case X86_OP_MEM:
				{
					dst = getarg (&gop, 0, 1, NULL, NULL);
					// It is important that we calculate the address
					// of the destination operand AFTER we increased
					// the stack pointer.
					//
					// Quoting the Intel manual:
					//
					// If the ESP register is used as a base register
					// for addressing a destination operand in memory,
					// the POP instruction computes the effective address
					// of the operand after it increments the ESP register.
					esilprintf (op,
						"%s,[%d],%d,%s,+=,%s",
						sp, rs, rs, sp, dst);
					free (dst);
				}
				break;
			case X86_OP_REG:
#if ARCH_HAVE_READ
				// check if previous instruction was a call to here
				{
					// handle CALLPOP sequence: 'CALL $$ + 5; POP REG'
					ut8 buf[5] = {0};
					const ut8 data[] = { 0xe8, 0, 0, 0, 0 };
					RBin *bin = as->arch->binb.bin;
					if (bin && bin->iob.read_at (bin->iob.io, addr - 5, buf, sizeof (buf))) {
						if (!memcmp (buf, data, sizeof (buf))) {
							dst = getarg (&gop, 0, 0, NULL, NULL);
							esilprintf (op, "0x%"PFMT64x",%s,=", addr, dst);
							free (dst);
							break;
						}
					} else {
						R_LOG_DEBUG ("Missing read callback required for a POP");
					}
				}
				// dont break;
#endif
			default:
				{
					dst = getarg (&gop, 0, 0, NULL, NULL);
					rs = INSOP (0).size;
					// esilprintf (op, "%s,[%d],%s,=,%d,%s,+=", sp, rs, dst, rs, sp);
					esilprintf (op, "%s,[%d],%d,%s,+=,%s,=", sp, rs, rs, sp, dst);
					free (dst);
					break;
				}
			}
		}
		break;
	case X86_INS_POPF:
	case X86_INS_POPFD:
	case X86_INS_POPFQ:
		esilprintf (op, "%s,[%d],eflags,=,%d,%s,+=", sp, rs, rs, sp);
		break;
	case X86_INS_RET:
	case X86_INS_RETF:
	case X86_INS_RETFQ:
	case X86_INS_IRET:
	case X86_INS_IRETD:
	case X86_INS_IRETQ:
	case X86_INS_SYSRET:
		{
		int cleanup = 0;
		if (INSOPS > 0) {
			cleanup = (int)INSOP(0).imm;
		}
		esilprintf (op, "%s,[%d],%s,=,%d,%s,+=",
			sp, rs, pc, rs + cleanup, sp);
		}
		break;
	case X86_INS_INT3:
		esilprintf (op, "3,$");
		break;
	case X86_INS_INT1:
		esilprintf (op, "1,$");
		break;
	case X86_INS_INT:
		esilprintf (op, "%d,$",
			R_ABS((int)INSOP(0).imm));
		break;
	case X86_INS_SYSCALL:
		esilprintf (op, "rax,()");
		break;
	case X86_INS_SYSENTER:
	case X86_INS_SYSEXIT:
		break;
	case X86_INS_INTO:
	case X86_INS_VMCALL:
	case X86_INS_VMMCALL:
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
	case X86_INS_LOOPE:
	case X86_INS_LOOPNE:
		{
			const char *cnt = (bits == 16)? "cx": (bits == 32)?"ecx":"rcx";
			dst = getarg (&gop, 0, 2, NULL, NULL);
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
			case X86_INS_LOOP:
				esilprintf (op, "1,%s,-=,%s,?{,%s,%s,=,}", cnt, cnt, dst, pc);
				break;
			case X86_INS_LOOPE:
				esilprintf (op, "1,%s,-=,%s,?{,zf,?{,%s,%s,=,},}",
					cnt, cnt, dst, pc);
				break;
			case X86_INS_LOOPNE:
				esilprintf (op, "1,%s,-=,%s,?{,zf,!,?{,%s,%s,=,},}",
					cnt, cnt, dst, pc);
				break;
			}
			free (dst);
		}
		break;
	case X86_INS_CALL:
		{
			arg0 = getarg (&gop, 0, 0, NULL, NULL);
			if (bits != 16) {
				ut8 thunk[4] = {0};
#if ARCH_HAVE_READ
				RBin *bin = as->arch->binb.bin;
				if (bin && bin->iob.read_at (bin->iob.io, (ut64)INSOP (0).imm, thunk, sizeof (thunk))) {
					/* Handle CALL ebx_pc (callpop)
					   8b xx x4    mov <reg>, dword [esp]
					   c3          ret
					*/
					if (thunk[0] == 0x8b && thunk[3] == 0xc3
							&& (thunk[1] & 0xc7) == 4        /* 00rrr100 */
							&& (thunk[2] & 0x3f) == 0x24) {  /* --100100: ignore scale in SIB byte */
						ut8 reg = (thunk[1] & 0x38) >> 3;
						esilprintf (op, "0x%"PFMT64x",%s,=", addr + op->size, reg32_to_name (reg));
						free (arg0);
						break;
					}
				} else {
					R_LOG_DEBUG ("Missing read callback for CALLPOP");
				}
			}
			if (bits == 32) {
				ut8 b[4] = {0};
				const ut64 at = addr + op->size;
				ut64 n = r_num_get (NULL, arg0);
				if (n == at) {
					RBin *bin = as->arch->binb.bin;
					if (bin && bin->iob.read_at && bin->iob.read_at (bin->iob.io, at, b, sizeof (b))) {
						if (b[0] == 0x5b) { // pop ebx
							esilprintf (op, "0x%"PFMT64x",ebx,=", at);
							free (arg0);
							break;
						}
					} else {
						R_LOG_DEBUG ("Missing read callback for CALLPOP");
					}
				}
			}
#endif
			esilprintf (op,
					"%s,%s,"
					"%d,%s,-=,%s,"
					"=[%d],"
					"%s,=",
					arg0, pc, rs, sp, sp, rs, pc);
			free (arg0);
		}
		break;
	case X86_INS_LCALL:
		{
			arg0 = getarg (&gop, 0, 0, NULL, NULL);
			arg1 = getarg (&gop, 1, 0, NULL, NULL);
			if (arg1) {
				esilprintf (op,
						"2,%s,-=,cs,%s,=[2],"	// push CS
						"%d,%s,-=,%s,%s,=[%d],"	// push IP/EIP
						"%s,cs,=,"		// set CS
						"%s,%s,=",		// set IP/EIP
						sp, sp, rs, sp, pc, sp, rs, arg0, arg1, pc);
			} else {
				esilprintf (op,
						"%s,%s,-=,%d,%s,=[%d],"	// push IP/EIP
						"%s,%s,=",		// set IP/EIP
						sp, sp, rs, sp, rs, arg0, pc);
			}
			free (arg0);
			free (arg1);
		}
		break;
	case X86_INS_JMP:
	case X86_INS_LJMP:
		{
			src = getarg (&gop, 0, 0, NULL, NULL);
			esilprintf (op, "%s,%s,=", src, pc);
			free (src);
		}
		// TODO: what if UJMP?
		switch (INSOP(0).type) {
		case X86_OP_IMM:
			if (INSOP(1).type == X86_OP_IMM) {
				ut64 seg = INSOP(0).imm;
				ut64 off = INSOP(1).imm;
				esilprintf (
					op,
					"0x%"PFMT64x",cs,=,"
					"0x%"PFMT64x",%s,=",
					seg, off, pc);
			} else {
				ut64 dst = INSOP(0).imm;
				esilprintf (op, "0x%"PFMT64x",%s,=", dst, pc);
			}
			break;
		case X86_OP_MEM:
			if (INSOP(0).mem.base == X86_REG_RIP) {
				/* nothing here */
			} else {
				cs_x86_op in = INSOP (0);
				if (in.mem.index == 0 && in.mem.base == 0 && in.mem.scale == 1) {
					if (in.mem.segment != X86_REG_INVALID) {
						esilprintf (
							op,
							"4,%s,<<,0x%"PFMT64x",+,[%d],%s,=",
							INSOP(0).mem.segment == X86_REG_ES ? "es"
							: INSOP(0).mem.segment == X86_REG_CS ? "cs"
							: INSOP(0).mem.segment == X86_REG_DS ? "ds"
							: INSOP(0).mem.segment == X86_REG_FS ? "fs"
							: INSOP(0).mem.segment == X86_REG_GS ? "gs"
							: INSOP(0).mem.segment == X86_REG_SS ? "ss"
							: "unknown_segment_register",
							(ut64)INSOP (0).mem.disp,
							rs, pc);
					} else {
						esilprintf (
							op,
							"0x%"PFMT64x",[%d],%s,=",
							(ut64)INSOP (0).mem.disp, rs, pc);
					}
				}
			}
			break;
		case X86_OP_REG:
#if 0
			{
				src = getarg (&gop, 0, 0, NULL, NULL);
				val = RVecRArchValue_emplace_back (&op->srcs);
				val->reg = r_reg_get (a->reg, src, R_REG_TYPE_GPR);
				free (src);
			}
#else
			val = RVecRArchValue_emplace_back (&op->srcs);
			val->reg = cs_reg_name (handle, INSOP (0).reg);
#endif
			break;
		//case X86_OP_FP:
		default: // other?
			break;
		}
		break;
	case X86_INS_IN:
	case X86_INS_INSW:
	case X86_INS_INSD:
	case X86_INS_INSB:
		if (ISIMM (1)) {
			op->val = INSOP (1).imm;
		}
		break;
	case X86_INS_OUT:
	case X86_INS_OUTSB:
	case X86_INS_OUTSD:
	case X86_INS_OUTSW:
		if (ISIMM (0)) {
			op->val = INSOP (0).imm;
		}
		break;
	case X86_INS_VXORPD:
	case X86_INS_VXORPS:
	case X86_INS_VPXORD:
	case X86_INS_VPXORQ:
	case X86_INS_VPXOR:
	case X86_INS_KXORW:
	case X86_INS_XOR:
		{
			ut32 bitsize;
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, "^", &bitsize);
			dst2 = getarg (&gop, 0, 0, NULL, NULL);
			char dst_reg64[16];
			const bool havedst = get64from32 (dst2, dst_reg64, sizeof (dst_reg64));
			if (bits == 64 && havedst) {
				// (64-bit ^ 32-bit) & 0xFFFF FFFF -> 64-bit, it's alright, higher bytes will be eliminated
				// (consider this is operation with 32-bit regs in 64-bit environment).
				esilprintf (op, "%s,%s,^,0xffffffff,&,%s,=,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=,0,cf,:=,0,of,:=",
					src, dst_reg64, dst_reg64, bitsize - 1);
			} else {
				esilprintf (op, "%s,%s,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=,0,cf,:=,0,of,:=",
					src, dst, bitsize - 1);
			}
			R_FREE (src);
			R_FREE (dst);
			R_FREE (dst2);
		}
		break;
	case X86_INS_XORPS:
	case X86_INS_PXOR:
		{
			if (is_xmm_reg (INSOP(0)) && is_xmm_reg (INSOP(1))) {
				src = getarg (&gop, 1, 0, NULL, NULL);
				dst = getarg (&gop, 0, 0, NULL, NULL);
				esilprintf (op, "%sl,%sl,^=,%sh,%sh,^=", src, dst, src, dst);
				R_FREE (src);
				R_FREE (dst);
			}
		}
		break;
	case X86_INS_BSF:
		{
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 0, NULL, NULL);
			if (strcmp (src, dst)) {
				const ut32 commas = r_str_char_count (src, ',');
				esilprintf (op, "%s,!,zf,:=,zf,?{,BREAK,},"
						"0x%"PFMT64x",%s,:=,"
						"%s,++,%s,:=,%s,1,<<,%s,&,!,?{,%d,GOTO,}",
						src, UT64_MAX, dst, dst, dst, dst, src, 11 + commas * 2);
			} else {
				// unroll the loop to avoid use of DUP operation
				const ut32 bits = INSOP (0).size * 8;
				ut32 i = 0;
				esilprintf (op, "%s,!,zf,:=,zf,?{,BREAK,}", src);
				for (; i < bits - 1; i++) {
					r_strbuf_appendf (&op->esil, ",0x%"PFMT64x",%s,&,?{,%d,%s,:=,BREAK,}",
						((ut64)1) << i, src, i, dst);
				}
				r_strbuf_appendf (&op->esil, ",%d,%s,:=", i, dst);
			}
			R_FREE (src);
			R_FREE (dst);
		}
		break;
	case X86_INS_BSR:
		{
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 0, NULL, NULL);
			const ut32 bits = INSOP (0).size * 8;

			if (strcmp (src, dst)) {
				const ut32 commas = r_str_char_count (src, ',');
				esilprintf (op, "%s,!,zf,:=,zf,?{,BREAK,},"
						"%d,%s,:=,"
						"%s,--,%s,:=,%s,1,<<,%s,&,!,?{,%d,GOTO,}",
						src, bits, dst, dst, dst, dst, src, 11 + commas * 2);
			} else {
				// unroll the loop to avoid use of DUP operation
				ut32 i = bits - 1;
				esilprintf (op, "%s,!,zf,:=,zf,?{,BREAK,}", src);
				for (; i; i--) {
					r_strbuf_appendf (&op->esil, ",0x%"PFMT64x",%s,&,?{,%d,%s,:=,BREAK,}",
						((ut64)1) << i, src, i, dst);
				}
				r_strbuf_appendf (&op->esil, ",0,%s,:=", dst);
			}
			R_FREE (src);
			R_FREE (dst);
		}
		break;
	case X86_INS_BSWAP:
		{
			dst = getarg (&gop, 0, 0, NULL, NULL);
			if (INSOP(0).size == 4) {
				esilprintf (op, "0xff000000,24,%s,NUM,<<,&,24,%s,NUM,>>,|,"
						"8,0x00ff0000,%s,NUM,&,>>,|,"
						"8,0x0000ff00,%s,NUM,&,<<,|,"
						"%s,=", dst, dst, dst, dst, dst);
			} else {
				esilprintf (op, "0xff00000000000000,56,%s,NUM,<<,&,"
						"56,%s,NUM,>>,|,40,0xff000000000000,%s,NUM,&,>>,|,"
						"40,0xff00,%s,NUM,&,<<,|,24,0xff0000000000,%s,NUM,&,>>,|,"
						"24,0xff0000,%s,NUM,&,<<,|,8,0xff00000000,%s,NUM,&,>>,|,"
						"8,0xff000000,%s,NUM,&,<<,|,"
						"%s,=", dst, dst, dst, dst, dst, dst, dst, dst, dst);
			}
			R_FREE (dst);
		}
		break;
	case X86_INS_OR:
		// The OF and CF flags are cleared; the SF, ZF, and PF flags are
		// set according to the result. The state of the AF flag is
		// undefined.
		{
			ut32 bitsize;
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, "|", &bitsize);
			esilprintf (op, "%s,%s,%d,$s,sf,:=,$z,zf,:=,$p,pf,:=,0,of,:=,0,cf,:=",
					src, dst, bitsize - 1);
			free (src);
			free (dst);
		}
		break;
	case X86_INS_POR:
		{
			if (is_xmm_reg (INSOP(0)) && is_xmm_reg (INSOP(1))) {
				src = getarg (&gop, 1, 0, NULL, NULL);
				dst = getarg (&gop, 0, 0, NULL, NULL);
				esilprintf (op, "%sl,%sl,|=,%sh,%sh,|=", src, dst, src, dst);
				free (src);
				free (dst);
			}
		}
		break;
	case X86_INS_INC:
		// The CF flag is not affected. The OF, SF, ZF, AF, and PF flags
		// are set according to the result.
		{
			ut32 bitsize;
			src = getarg (&gop, 0, 1, "++", &bitsize);
			esilprintf (op, "%s,%d,$o,of,:=,%d,$s,sf,:=,$z,zf,:=,$p,pf,:=,3,$c,af,:=", src, bitsize - 1, bitsize - 1);
			free (src);
		}
		break;
	case X86_INS_DEC:
		// The CF flag is not affected. The OF, SF, ZF, AF, and PF flags
		// are set according to the result.
		{
			ut32 bitsize;
			src = getarg (&gop, 0, 1, "--", &bitsize);
			esilprintf (op, "%s,%d,$o,of,:=,%d,$s,sf,:=,$z,zf,:=,$p,pf,:=,3,$b,af,:=", src, bitsize - 1, bitsize - 1);
			free (src);
		}
		break;
	case X86_INS_PSUBB:
	case X86_INS_PSUBW:
	case X86_INS_PSUBD:
	case X86_INS_PSUBQ:
	case X86_INS_PSUBSB:
	case X86_INS_PSUBSW:
	case X86_INS_PSUBUSB:
	case X86_INS_PSUBUSW:
		{
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, "-", NULL);
			esilprintf (op, "%s,%s", src, dst);
			free (src);
			free (dst);
		}
		break;
	case X86_INS_SUB:
		{
			ut32 bitsize;
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, "-", &bitsize);

			if (!bitsize || bitsize > 64) {
				break;
			}

			// Set OF, SF, ZF, AF, PF, and CF flags.
			// We use $b rather than $c here as the carry flag really
			// represents a "borrow"
			esilprintf (op, "%s,%s,%s,0x%"PFMT64x",-,!,%u,$o,^,of,:=,%u,$s,sf,:=,$z,zf,:=,$p,pf,:=,%u,$b,cf,:=,3,$b,af,:=",
				src, dst, src, (uint64_t)(1ULL) << (bitsize - 1), bitsize - 1, bitsize - 1, bitsize);
			free (src);
			free (dst);
		}
		break;
	case X86_INS_SBB:
		// dst = dst - (src + cf)
		{
			ut32 bitsize;
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 0, NULL, &bitsize);
			esilprintf (op, "cf,%s,+,%s,-=,%d,$o,of,:=,%d,$s,sf,:=,$z,zf,:=,$p,pf,:=,%d,$b,cf,:=",
				src, dst, bitsize - 1, bitsize - 1, bitsize);
			free (src);
			free (dst);
		}
		break;
	case X86_INS_LIDT:
		break;
	case X86_INS_SIDT:
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
		break;
	case X86_INS_AND:
	case X86_INS_ANDPD:
	case X86_INS_ANDNPD:
		{
			ut32 bitsize;
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, "&", &bitsize);
			dst2 = getarg (&gop, 0, 0, NULL, NULL);
			char dst_reg64[16];
			const bool havedst = get64from32 (dst2, dst_reg64, sizeof (dst_reg64));
			if (bits == 64 && havedst) {
				// (64-bit & 32-bit) & 0xFFFF FFFF -> 64-bit, it's alright, higher bytes will be eliminated
				// (consider this is operation with 32-bit regs in 64-bit environment).
				esilprintf (op, "%s,%s,&,0xffffffff,&,%s,=,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=,0,cf,:=,0,of,:=",
						src, dst_reg64, dst_reg64, bitsize - 1);
			} else {
				esilprintf (op, "%s,%s,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=,0,cf,:=,0,of,:=", src, dst, bitsize - 1);
			}
			free (src);
			free (dst);
			free (dst2);
		}
		break;
	case X86_INS_ANDN:
		{
			ut32 bitsize;
			char *src1 = getarg (&gop, 1, 0, NULL, NULL);
			char *src2 = getarg (&gop, 2, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, NULL, &bitsize);
			esilprintf (op, "%s,%s,~,&,%s,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=,0,cf,:=,0,of,:=", src2, src1, dst, bitsize - 1);
			free (src1);
			free (src2);
			free (dst);
		}
		break;
	case X86_INS_PANDN:
	case X86_INS_ANDNPS:
		{
			if (is_xmm_reg (INSOP(0)) && is_xmm_reg (INSOP(1))) {
				src = getarg (&gop, 1, 0, NULL, NULL);
				dst = getarg (&gop, 0, 0, NULL, NULL);
				esilprintf (op, "-1,%sl,^,%sl,&,%sl,=,-1,%sh,^,%sh,&,%sh,=", dst, src, dst, dst, src, dst);
				free (src);
				free (dst);
			}
		}
		break;
	case X86_INS_PAND:
	case X86_INS_ANDPS:
		{
			if (is_xmm_reg (INSOP(0)) && is_xmm_reg (INSOP(1))) {
				src = getarg (&gop, 1, 0, NULL, NULL);
				dst = getarg (&gop, 0, 0, NULL, NULL);
				esilprintf (op, "%sl,%sl,&=,%sh,%sh,&=", src, dst, src, dst);
				free (src);
				free (dst);
			}
		}
		break;
	case X86_INS_IDIV:
		{
			arg0 = getarg (&gop, 0, 0, NULL, NULL);
			arg1 = getarg (&gop, 1, 0, NULL, NULL);
			arg2 = getarg (&gop, 2, 0, NULL, NULL);
			// DONE handle signedness
			// IDIV does not change flags
			op->sign = true;
			if (!arg2 && !arg1) {
				// TODO: IDIV rbx not implemented. this is just a workaround
				//
				// https://www.tptp.cc/mirrors/siyobik.info/instruction/IDIV.html
				// Divides (signed) the value in the AX, DX:AX, or EDX:EAX registers (dividend) by the source operand (divisor) and stores the result in the AX (AH:AL), DX:AX, or EDX:EAX registers. The source operand can be a general-purpose register or a memory location. The action of this instruction depends on the operand size (dividend/divisor), as shown in the following table:
				// IDIV RBX    ==   RDX:RAX /= RBX

				//
				if (arg0) {
					int width = INSOP(0).size;
					const char *r_quot = (width == 1)?"al": (width == 2)?"ax": (width == 4)?"eax":"rax";
					const char *r_rema = (width == 1)?"ah": (width == 2)?"dx": (width == 4)?"edx":"rdx";
					const char *r_nume = (width == 1)?"ax": r_quot;

					esilprintf (op, "%d,%s,~,%d,%s,<<,%s,+,~%%,%d,%s,~,%d,%s,<<,%s,+,~/,%s,=,%s,=",
							width*8, arg0, width*8, r_rema, r_nume, width*8, arg0, width*8, r_rema, r_nume, r_quot, r_rema);
				}
				else {
					/* should never happen */
				}
			} else {
				// does this instruction even exist?
				int width = INSOP(0).size;
				esilprintf (op, "%d,%s,~,%d,%s,~,~/,%s,=", width*8, arg2, width*8, arg1, arg0);
			}
			free (arg0);
			free (arg1);
			free (arg2);
		}
		break;
	case X86_INS_DIV:
		{
			int width = INSOP(0).size;
			dst = getarg (&gop, 0, 0, NULL, NULL);
			const char *r_quot = (width == 1)?"al": (width == 2)?"ax": (width == 4)?"eax":"rax";
			const char *r_rema = (width == 1)?"ah": (width == 2)?"dx": (width == 4)?"edx":"rdx";
			const char *r_nume = (width == 1)?"ax": r_quot;
			// DIV does not change flags and is unsigned

			esilprintf (op, "%s,%d,%s,<<,%s,+,%%,%s,%d,%s,<<,%s,+,/,%s,=,%s,=",
					dst, width*8, r_rema, r_nume, dst, width*8, r_rema, r_nume, r_quot, r_rema);
			free (dst);
		}
		break;
	case X86_INS_IMUL:
		{
			arg0 = getarg (&gop, 0, 0, NULL, NULL);
			arg1 = getarg (&gop, 1, 0, NULL, NULL);
			arg2 = getarg (&gop, 2, 0, NULL, NULL);
			op->sign = true;
			int width = INSOP(0).size;

			if (arg1) {
				char *multiplier = arg0;
				if (arg2) {
					multiplier = arg2;
				}
				esilprintf (op, "%d,%s,~,%d,%s,~,*,DUP,%s,=,%d,%s,~,-,!,!,DUP,cf,:=,of,:=",
					width*8, multiplier, width*8, arg1, arg0, width*8, arg0);
			} else {
				if (arg0) {
					const char *r_quot = (width == 1)?"al": (width==2)?"ax": (width==4)?"eax":"rax";
					const char *r_rema = (width == 1)?"ah": (width==2)?"dx": (width==4)?"edx":"rdx";
					const char *r_nume = (width == 1)?"ax": r_quot;

					if (width == 8) { // TODO still needs to be fixed to handle correct signed 128 bit value
						esilprintf (op, "%s,%s,L*,%s,=,DUP,%s,=,!,!,DUP,cf,:=,of,:=", // flags will be sometimes wrong
								arg0, r_nume, r_nume, r_rema);
					} else {
						esilprintf (op, "%d,%s,~,%d,%s,~,*,DUP,DUP,%s,=,%d,SWAP,>>,%s,=,%d,%s,~,-,!,!,DUP,cf,:=,of,:=",
								width*8, arg0, width*8, r_nume, r_nume, width*8, r_rema, width*8, r_nume);
					}
				}
			}
			free (arg0);
			free (arg1);
			free (arg2);
		}
		break;
	case X86_INS_MUL:
		{
			src = getarg (&gop, 0, 0, NULL, NULL);
			if (src) {
				int width = INSOP(0).size;
				const char *r_quot = (width == 1)?"al": (width == 2)?"ax": (width == 4)?"eax":"rax";
				const char *r_rema = (width == 1)?"ah": (width == 2)?"dx": (width == 4)?"edx":"rdx";
				const char *r_nume = (width == 1)?"ax": r_quot;

				if (width == 8 ) {
					esilprintf (op, "%s,%s,L*,%s,=,DUP,%s,=,!,!,DUP,cf,:=,of,:=",
							src, r_nume, r_nume, r_rema);
				} else {
					esilprintf (op, "%s,%s,*,DUP,%s,=,%d,SWAP,>>,DUP,%s,=,!,!,DUP,cf,:=,of,:=",
							src, r_nume, r_nume, width*8, r_rema); // this should be ok for width == 1 also
				}
				free (src);
			}
		}
		break;
	case X86_INS_MULX:
		{
			bool free_src = true;
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, "*", NULL);
			if (!src && dst) {
				switch (dst[0]) {
				case 'r':
					src = "rax";
					break;
				case 'e':
					src = "eax";
					break;
				default:
					src = "al";
					break;
				}
				free_src = false;
			}
			esilprintf (op, "%s,%s", src, dst);
			if (free_src) {
				free (src);
			}
			free (dst);
		}
		break;

	case X86_INS_NEG:
		{
			ut32 bitsize;
			src = getarg (&gop, 0, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, NULL, &bitsize);
			ut64 xor = 0;
			switch (bitsize) {
			case 8:
				xor = UT8_MAX;
				break;
			case 16:
				xor = UT16_MAX;
				break;
			case 32:
				xor = UT32_MAX;
				break;
			case 64:
				xor = UT64_MAX;
				break;
			default:
				R_LOG_ERROR ("Neg: Unhandled bitsize %d", bitsize);
			}
			esilprintf (op, "%s,!,!,cf,:=,%s,0x%"PFMT64x",^,1,+,%s,$z,zf,:=,0,of,:=,%d,$s,sf,:=,%d,$o,pf,:=",
				src, src, xor, dst, bitsize - 1, bitsize - 1);
			free (src);
			free (dst);
		}
		break;
	case X86_INS_NOT:
		{
			dst = getarg (&gop, 0, 1, "^", NULL);
			esilprintf (op, "-1,%s", dst);
			R_FREE (dst);
		}
		break;
	case X86_INS_PACKSSDW:
	case X86_INS_PACKSSWB:
	case X86_INS_PACKUSWB:
		break;
	case X86_INS_PADDB:
	case X86_INS_PADDD:
	case X86_INS_PADDW:
	case X86_INS_PADDSB:
	case X86_INS_PADDSW:
	case X86_INS_PADDUSB:
	case X86_INS_PADDUSW:
		break;
	case X86_INS_XCHG:
		{
			dst = getarg (&gop, 0, 0, NULL, NULL);
			src = getarg (&gop, 1, 0, NULL, NULL);
			if (!strcmp (src, dst)) {
				esilprintf (op, ",");
			} else if (INSOP(0).type == X86_OP_MEM) {
				dst2 = getarg (&gop, 0, 1, NULL, NULL);
				esilprintf (op,
					"%s,%s,^,%s,=,"
					"%s,%s,^,%s,"
					"%s,%s,^,%s,=",
					dst, src, src,	// x = x ^ y
					src, dst, dst2,	// y = y ^ x
					dst, src, src); // x = x ^ y
				free (dst2);
			} else {
				esilprintf (op,
					"%s,%s,^,%s,=,"
					"%s,%s,^,%s,=,"
					"%s,%s,^,%s,=",
					dst, src, src,  // x = x ^ y
					src, dst, dst,  // y = y ^ x
					dst, src, src); // x = x ^ y
				//esilprintf (op, "%s,%s,%s,=,%s", src, dst, src, dst);
			}
			R_FREE (dst);
			R_FREE (src);
		}
		break;
	case X86_INS_XADD: /* xchg + add */
		{
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 0, NULL, NULL);
			dstAdd = getarg (&gop, 0, 1, "+", NULL);
			if (INSOP(0).type == X86_OP_MEM) {
				dst2 = getarg (&gop, 0, 1, NULL, NULL);
				esilprintf (op,
					"%s,%s,^,%s,=,"
					"%s,%s,^,%s,"
					"%s,%s,^,%s,=,"
					"%s,%s",
					dst, src, src,	// x = x ^ y
					src, dst, dst2,	// y = y ^ x
					dst, src, src,  // x = x ^ y
					src, dstAdd);
				R_FREE (dst2);
			} else {
				esilprintf (op,
					"%s,%s,^,%s,=,"
					"%s,%s,^,%s,=,"
					"%s,%s,^,%s,=,"
					"%s,%s",
					dst, src, src,  // x = x ^ y
					src, dst, dst,  // y = y ^ x
					dst, src, src,  // x = x ^ y
					src, dstAdd);
				//esilprintf (op, "%s,%s,%s,=,%s", src, dst, src, dst);
			}
			free (src);
			free (dst);
			free (dstAdd);
		}
		break;
	case X86_INS_FADD:
#if CS_API_MAJOR > 4
	case X86_INS_PFADD:
#else
	case X86_INS_FADDP:
#endif
		{
			ut32 bitsize;
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 0, NULL, &bitsize);
			if (src && dst) {
				esilprintf (op, "%u,%u,%s,F2D,%u,%s,F2D,F+,D2F,%s,=",
					bitsize, bitsize, src, bitsize, dst, dst);
			}
			free (src);
			free (dst);
			break;
		}
		break;
	case X86_INS_ADDPS:
	case X86_INS_ADDSS:
	case X86_INS_ADDSUBPS:
	case X86_INS_SUBPS:
	case X86_INS_SUBSS:
	case X86_INS_MULPS:
	case X86_INS_MULSS:
	case X86_INS_DIVPS:
	case X86_INS_DIVSS:
		{
			char operator = '+';
			switch (insn->id) {
			case X86_INS_SUBSS:
			case X86_INS_SUBPS:
				operator = '-';
				break;
			case X86_INS_MULSS:
			case X86_INS_MULPS:
				operator = '*';
				break;
			case X86_INS_DIVSS:
			case X86_INS_DIVPS:
				operator = '/';
				break;
			case X86_INS_ADDSUBPS:
			case X86_INS_ADDSS:
			case X86_INS_ADDPS:
			default:
				operator = '+';
				break;
			}
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 0, NULL, NULL);
			if (src && dst) {
				esilprintf (op, "32,32,%s,F2D,32,%s,F2D,F%c,D2F,%s,=",
					src, dst, operator, dst);
			}
			free (src);
			free (dst);
		}
		break;
	case X86_INS_ADDSUBPD:
	case X86_INS_ADDSD:
	case X86_INS_ADDPD:
	case X86_INS_SUBSD:
	case X86_INS_SUBPD:
	case X86_INS_MULSD:
	case X86_INS_MULPD:
	case X86_INS_DIVSD:
	case X86_INS_DIVPD:
		{
			char operator = '+';
			switch (insn->id) {
				case X86_INS_SUBSD:
				case X86_INS_SUBPD:
					operator = '-';
					break;
				case X86_INS_MULSD:
				case X86_INS_MULPD:
					operator = '*';
					break;
				case X86_INS_DIVSD:
				case X86_INS_DIVPD:
					operator = '/';
					break;
				case X86_INS_ADDSUBPD:
				case X86_INS_ADDSD:
				case X86_INS_ADDPD:
				default:
					operator = '+';
					break;
			}
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 0, NULL, NULL);
			if (src && dst) {
				esilprintf (op, "%s,%s,F%c,%s,=", src, dst, operator, dst);
			}
			free (src);
			free (dst);
		}
		break;
	case X86_INS_RCPSS:
	case X86_INS_RCPPS:
		{
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, NULL, NULL);
			if (src && dst) {
				esilprintf (op, "32,32,%s,F2D,1,I2D,F/,D2F,%s", src, dst);
			}
			free (src);
			free (dst);
		}
		break;
	case X86_INS_SQRTSS:
	case X86_INS_SQRTPS:
		{
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, NULL, NULL);
			if (src && dst) {
				esilprintf (op, "32,32,%s,F2D,SQRT,D2F,%s", src, dst);
			}
			free (src);
			free (dst);
		}
		break;
	case X86_INS_RSQRTSS:
	case X86_INS_RSQRTPS:
		{
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, NULL, NULL);
			if (src && dst) {
				esilprintf (op, "32,32,%s,F2D,SQRT,1,I2D,F/,D2F,%s", src, dst);
			}
			free (src);
			free (dst);
		}
		break;
	case X86_INS_SQRTSD:
	case X86_INS_SQRTPD:
		{
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, NULL, NULL);
			if (src && dst) {
				esilprintf (op, "%s,SQRT,%s", src, dst);
			}
			free (src);
			free (dst);
		}
		break;
	case X86_INS_ADD:
		// The OF, SF, ZF, AF, CF, and PF flags are set according to the
		// result.
		{
			ut32 bitsize;
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, "+", &bitsize);
			if (src && dst) {
				esilprintf (op, "%s,%s,%d,$o,of,:=,%d,$s,sf,:=,$z,zf,:=,%d,$c,cf,:=,$p,pf,:=,3,$c,af,:=",
					src, dst, bitsize - 1, bitsize - 1, bitsize - 1);
			}
			free (src);
			free (dst);
		}
		break;
	case X86_INS_ADC:
		{
			ut32 bitsize;
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst = getarg (&gop, 0, 1, "+", &bitsize);
			// dst = dst + src + cf
			// NOTE: We would like to add the carry first before adding the
			// source to ensure that the flag computation from $c belongs
			// to the operation of adding dst += src rather than the one
			// that adds carry (as esil only keeps track of the last
			// addition to set the flags).
			if (src && dst) {
				esilprintf (op, "cf,%s,+,%s,%d,$o,of,:=,%d,$s,sf,:=,$z,zf,:=,%d,$c,cf,:=,$p,pf,:=,3,$c,af,:=",
					src, dst, bitsize - 1, bitsize - 1, bitsize - 1);
			}
			free (src);
			free (dst);
		}
		break;
		/* Direction flag */
	case X86_INS_CLD:
		esilprintf (op, "0,df,:=");
		break;
	case X86_INS_STD:
		esilprintf (op, "1,df,:=");
		break;
	case X86_INS_CVTSS2SI:
	case X86_INS_CVTSD2SI:
	case X86_INS_CVTSD2SS:
	case X86_INS_CVTSS2SD:
	case X86_INS_CVTSI2SS:
	case X86_INS_CVTSI2SD:
	case X86_INS_CVTPS2PI:
	case X86_INS_CVTPD2PI:
	case X86_INS_CVTPD2PS:
	case X86_INS_CVTPS2PD:
	case X86_INS_CVTPI2PS:
	case X86_INS_CVTPI2PD:
	{
		src = getarg (&gop, 1, 0, NULL, NULL);
		dst = getarg (&gop, 0, 1, NULL, NULL);

		switch (insn->id) {
		case X86_INS_CVTSS2SI:
		case X86_INS_CVTPS2PI:
			esilprintf (op, "32,%s,F2D,D2I,%s", src, dst);
			break;
		case X86_INS_CVTSD2SI:
		case X86_INS_CVTPD2PI:
			esilprintf (op, "%s,D2I,%s", src, dst);
			break;
		case X86_INS_CVTSD2SS:
		case X86_INS_CVTPD2PS:
			esilprintf (op, "32,%s,D2F,%s", src, dst);
			break;
		case X86_INS_CVTSS2SD:
		case X86_INS_CVTPS2PD:
			esilprintf (op, "32,%s,F2D,%s", src, dst);
			break;
		case X86_INS_CVTSI2SS:
		case X86_INS_CVTPI2PS:
			esilprintf (op, "32,%s,I2D,D2F,%s", src, dst);
			break;
		case X86_INS_CVTPI2PD:
		case X86_INS_CVTSI2SD:
		default:
			esilprintf (op, "%s,I2D,%s", src, dst);
			break;
		}
		free (src);
		free (dst);
		break;
	}
	case X86_INS_BT:
	case X86_INS_BTC:
	case X86_INS_BTR:
	case X86_INS_BTS:
		if (INSOP(0).type == X86_OP_MEM && INSOP(1).type == X86_OP_REG) {
			int width = INSOP(0).size;
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst_r = getarg (&gop, 0, 2 /* use the address without loading */, NULL, NULL);
			esilprintf (op, "0,cf,:=,%d,%s,%%,1,<<,%d,%s,/,%s,+,[%d],&,?{,1,cf,:=,}",
					width * 8, src, width * 8, src, dst_r, width);
			switch (insn->id) {
			case X86_INS_BTS:
			case X86_INS_BTC:
				r_strbuf_appendf (&op->esil, ",%d,%s,%%,1,<<,%d,%s,/,%s,+,%c=[%d]",
						width * 8, src, width * 8, src, dst_r,
						(insn->id == X86_INS_BTS)?'|':'^', width);
				break;
			case X86_INS_BTR:
				dst_w = getarg (&gop, 0, 1, "&", NULL);
				r_strbuf_appendf (&op->esil, ",%d,%s,%%,1,<<,-1,^,%d,%s,/,%s,+,&=[%d]",
						width * 8, src, width * 8, src, dst_r, width);
				free (dst_w);
				break;
			}
			free (src);
			free (dst_r);
		} else {
			int width = INSOP(0).size;
			src = getarg (&gop, 1, 0, NULL, NULL);
			dst_r = getarg (&gop, 0, 0, NULL, NULL);
			dst_w = NULL;
			esilprintf (op, "0,cf,:=,%d,%s,%%,1,<<,%s,&,?{,1,cf,:=,}",
					width * 8, src, dst_r);
			switch (insn->id) {
			case X86_INS_BTS:
			case X86_INS_BTC:
				dst_w = getarg (&gop, 0, 1, (insn->id == X86_INS_BTS)?"|":"^", NULL);
				r_strbuf_appendf (&op->esil, ",%d,%s,%%,1,<<,%s", width * 8, src, dst_w);
				free (dst_w);
				break;
			case X86_INS_BTR:
				dst_w = getarg (&gop, 0, 1, "&", NULL);
				r_strbuf_appendf (&op->esil, ",%d,%s,%%,1,<<,-1,^,%s", width * 8, src, dst_w);
				free (dst_w);
				break;
			}
			free (src);
			free (dst_r);
		}
		break;
	case X86_INS_VMOVDQU16:
	case X86_INS_VMOVDQU32:
	case X86_INS_VMOVDQU64:
	case X86_INS_VMOVDQU8:
	case X86_INS_VMOVDQU:
		{
			char *src = getarg (&gop, 1, 0, NULL, NULL);
			if (is_xmm_reg (INSOP (1))) {
				if (is_xmm_reg (INSOP (0))) {
					r_strbuf_appendf (&op->esil, "%sl,%sh", src, src);
				} else {
					r_strbuf_appendf (&op->esil, "%sh,%sl", src, src);
				}
			} else {
				r_strbuf_append (&op->esil, src);
			}
			char *dst = getarg (&gop, 0, 0, NULL, NULL);
			if (is_xmm_reg (INSOP (0))) {
				r_strbuf_appendf (&op->esil, ",%sh,:=,%sl,:=", dst, dst);
			} else {
				r_strbuf_appendf (&op->esil, ",%s", dst);
			}
			free (dst);
			free (src);
		}
		break;
	}

	// AMD K8 optimization lead some compilation to emit REPZ RET which should be treated as RET
	if (op->prefix & R_ANAL_OP_PREFIX_REP && op->type != R_ANAL_OP_TYPE_RET) {
		r_strbuf_prepend (&op->esil, ",!,?{,BREAK,},");
		r_strbuf_prepend (&op->esil, counter);
		if (repe) {
			r_strbuf_appendf (&op->esil, ",%s,--=,zf,!,?{,BREAK,},0,GOTO", counter);
		} else {
			r_strbuf_appendf (&op->esil, ",%s,--=,0,GOTO", counter);
		}
	}
	// Intel MPX changes the REPNE prefix to mean BND for jmps, etc
	// its barely used anymore so the best thing to do is ignore
	if (op->prefix & R_ANAL_OP_PREFIX_REPNE && (op->type == R_ANAL_OP_TYPE_MOV || op->type == R_ANAL_OP_TYPE_STORE)) {
		r_strbuf_prepend (&op->esil, ",!,?{,BREAK,},");
		r_strbuf_prepend (&op->esil, counter);
		r_strbuf_appendf (&op->esil, ",%s,--=,zf,?{,BREAK,},0,GOTO", counter);
	}
}

static void set_access_info(RArchSession *as, RAnalOp *op, csh handle, cs_insn *insn, int mode) {
	int i;
	int regsz;
	x86_reg sp;
	switch (mode) {
	case CS_MODE_64:
		regsz = 8;
		sp = X86_REG_RSP;
		break;
	case CS_MODE_32:
		regsz = 4;
		sp = X86_REG_ESP;
		break;
	case CS_MODE_16:
		regsz = 4;
		sp = X86_REG_ESP;
		break;
	default:
		regsz = 4;
		sp = X86_REG_ESP;
		break;
	}
	RList *ret = r_list_newf ((RListFree)r_anal_value_free);
	if (!ret) {
		return;
	}

	// PC register
	RAnalValue *val = r_anal_value_new ();
	if (val) {
		val->type = R_ANAL_VAL_REG;
		val->access = R_PERM_W;
		val->reg = cs_reg_name (handle, X86_REG_RIP);
		r_list_append (ret, val);
	}

#if CS_API_MAJOR >= 4
	// Register access info
	cs_regs regs_read, regs_write;
	ut8 read_count, write_count;
	if (cs_regs_access (handle, insn, regs_read, &read_count, regs_write, &write_count) == 0) {
		for (i = 0; i < read_count; i++) {
			val = r_anal_value_new ();
			if (val) {
				val->type = R_ANAL_VAL_REG;
				val->access = R_PERM_R;
				val->reg = cs_reg_name (handle, regs_read[i]);
				r_list_append (ret, val);
			}
		}
		for (i = 0; i < write_count; i++) {
			val = r_anal_value_new ();
			if (val) {
				val->type = R_ANAL_VAL_REG;
				val->access = R_PERM_W;
				val->reg = cs_reg_name (handle, regs_write[i]);
				r_list_append (ret, val);
			}
		}
	}
#endif

	switch (insn->id) {
	case X86_INS_PUSH:
		r_list_append (ret, newvalue (R_ANAL_VAL_MEM, R_PERM_W, cs_reg_name (handle, sp), -INSOP(0).size, INSOP(0).size));
		break;
	case X86_INS_PUSHAW:
		// AX, CX, DX, BX, SP, BP, SI, DI
		r_list_append (ret, newvalue (R_ANAL_VAL_MEM, R_PERM_W, cs_reg_name (handle, sp), -16, 16));
		break;
	case X86_INS_PUSHAL:
		// EAX, ECX, EDX, EBX, EBP, ESP, EBP, ESI, EDI
		r_list_append (ret, newvalue (R_ANAL_VAL_MEM, R_PERM_W, cs_reg_name (handle, sp), -32, 32));
		break;
	case X86_INS_PUSHF:
		r_list_append (ret, newvalue (R_ANAL_VAL_MEM, R_PERM_W, cs_reg_name (handle, sp), -2, 2));
		break;
	case X86_INS_PUSHFD:
		r_list_append (ret, newvalue (R_ANAL_VAL_MEM, R_PERM_W, cs_reg_name (handle, sp), -4, 4));
		break;
	case X86_INS_PUSHFQ:
		r_list_append (ret, newvalue (R_ANAL_VAL_MEM, R_PERM_W, cs_reg_name (handle, sp), -8, 8));
		break;
	case X86_INS_CALL:
	case X86_INS_LCALL:
		val = r_anal_value_new ();
		if (val) {
			val->type = R_ANAL_VAL_MEM;
			val->access = R_PERM_W;
			val->reg = cs_reg_name (handle, sp);
			val->delta = -regsz;
			val->memref = regsz;
			r_list_append (ret, val);
		}
		break;
	default:
		break;
	}

	// Memory access info based on operands
	for (i = 0; i < INSOPS; i++) {
		if (INSOP (i).type == X86_OP_MEM) {
			val = r_anal_value_new ();
			if (val) {
				val->type = R_ANAL_VAL_MEM;
#if CS_API_MAJOR >= 4
				switch (INSOP (i).access) {
				case CS_AC_READ:
				    val->access = R_PERM_R;
				    break;
				case CS_AC_WRITE:
				    val->access = R_PERM_W;
				    break;
				case CS_AC_INVALID:
				    val->access = 0;
				    break;
				}
#else
				val->access = 0;
#endif
				val->mul = INSOP (i).mem.scale;
				val->delta = INSOP (i).mem.disp;
				if (INSOP(0).mem.base == X86_REG_RIP ||
				  INSOP(0).mem.base == X86_REG_EIP) {
					val->delta += insn->size;
				}
				val->memref = INSOP (i).size;
				val->reg = cs_reg_name (handle, INSOP (i).mem.base);
				val->seg = cs_reg_name (handle, INSOP (i).mem.segment);
				val->regdelta = cs_reg_name (handle, INSOP (i).mem.index);
				r_list_append (ret, val);
			}
		}
	}

	op->access = ret;
}

#define CREATE_SRC_DST(op) \
	src0 = RVecRArchValue_emplace_back (&(op)->srcs); \
	src1 = RVecRArchValue_emplace_back (&(op)->srcs); \
	src2 = RVecRArchValue_emplace_back (&(op)->srcs); \
	dst = RVecRArchValue_emplace_back (&(op)->dsts);

static void set_src_dst(RArchSession *as, RAnalValue *val, csh handle, cs_insn *insn, int x) {
	if (!val) {
		return;
	}
	switch (INSOP (x).type) {
	case X86_OP_MEM:
		val->mul = INSOP (x).mem.scale;
		val->delta = INSOP (x).mem.disp;
		val->memref = INSOP (x).size;
		val->seg = cs_reg_name (handle, INSOP (x).mem.segment);
		val->reg = cs_reg_name (handle, INSOP (x).mem.base);
		val->regdelta = cs_reg_name (handle, INSOP (x).mem.index);
		break;
	case X86_OP_REG:
		val->reg = cs_reg_name (handle, INSOP (x).reg);
		break;
	case X86_OP_IMM:
		val->imm = INSOP (x).imm;
		break;
	default:
		break;
	}
}

static void op_fillval(RArchSession *a, RAnalOp *op, csh handle, cs_insn *insn, int mode) {
	RAnalValue *dst, *src0, *src1, *src2;
	set_access_info (a, op, handle, insn, mode);
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_CMP:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_CMOV:
	case R_ANAL_OP_TYPE_SHL:
	case R_ANAL_OP_TYPE_SHR:
	case R_ANAL_OP_TYPE_SAL:
	case R_ANAL_OP_TYPE_SAR:
	case R_ANAL_OP_TYPE_ROL:
	case R_ANAL_OP_TYPE_ROR:
	case R_ANAL_OP_TYPE_ADD:
	case R_ANAL_OP_TYPE_AND:
	case R_ANAL_OP_TYPE_OR:
	case R_ANAL_OP_TYPE_XOR:
	case R_ANAL_OP_TYPE_SUB:
	case R_ANAL_OP_TYPE_XCHG:
	case R_ANAL_OP_TYPE_POP:
	case R_ANAL_OP_TYPE_NOT:
	case R_ANAL_OP_TYPE_ACMP:
		CREATE_SRC_DST (op);
		set_src_dst (a, dst, handle, insn, 0);
		set_src_dst (a, src0, handle, insn, 1);
		set_src_dst (a, src1, handle, insn, 2);
		set_src_dst (a, src2, handle, insn, 3);
		break;
	case R_ANAL_OP_TYPE_UPUSH:
		if ((op->type & R_ANAL_OP_TYPE_REG)) {
			CREATE_SRC_DST (op);
			set_src_dst (a, src0, handle, insn, 0);
		}
		break;
	default:
		break;
	}
}

// Helper to find immediate operand regardless of position (handles AT&T operand order)
static int find_immop(cs_insn *insn) {
	int i;
	for (i = 0; i < INSOPS; i++) {
		if (INSOP (i).type == X86_OP_IMM) {
			return i;
		}
	}
	return -1;
}

static void op0_memimmhandle(RAnalOp *op, cs_insn *insn, ut64 addr, int regsz) {
	op->ptr = UT64_MAX;
	switch (INSOP (0).type) {
	case X86_OP_MEM:
		op->cycles = CYCLE_MEM;
		op->disp = INSOP (0).mem.disp;
		if (!op->disp) {
			op->disp = UT64_MAX;
		}
		op->refptr = INSOP (0).size;
		if (INSOP (0).mem.base == X86_REG_RIP) {
			op->ptr = addr + insn->size + op->disp;
		} else if (INSOP (0).mem.base == X86_REG_RBP || INSOP (0).mem.base == X86_REG_EBP) {
			op->type |= R_ANAL_OP_TYPE_REG;
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = regsz;
		} else if (INSOP (0).mem.segment == X86_REG_INVALID && INSOP (0).mem.base == X86_REG_INVALID
			   && INSOP (0).mem.index == X86_REG_INVALID && INSOP (0).mem.scale == 1) { // [<addr>]
			op->ptr = op->disp;
			if (op->ptr < 0x1000) {
				op->ptr = UT64_MAX;
			}
		} else if (op->disp > 1000) {
			op->ptr = op->disp;
			op->disp = UT64_MAX;
		}
		break;
	case X86_OP_REG:
		break;
	default:
		break;
	}
	// Set val from immediate operand if present (handles AT&T operand order)
	int immop = find_immop (insn);
	if (immop >= 0) {
		op->val = INSOP (immop).imm;
	}
}

// Helper to find register operand regardless of position (handles AT&T operand order)
static int find_regop(cs_insn *insn) {
	int i;
	for (i = 0; i < INSOPS; i++) {
		if (INSOP (i).type == X86_OP_REG) {
			return i;
		}
	}
	return -1;
}

static void op1_memimmhandle(RAnalOp *op, cs_insn *insn, ut64 addr, int regsz) {
	if (op->refptr < 1 || op->ptr == UT64_MAX) {
		switch (INSOP (1).type) {
		case X86_OP_MEM:
			op->disp = INSOP (1).mem.disp;
			op->refptr = INSOP (1).size;
			if (INSOP (1).mem.base == X86_REG_RIP) {
				op->ptr = addr + insn->size + op->disp;
			} else if (INSOP (1).mem.base == X86_REG_RBP || INSOP (1).mem.base == X86_REG_EBP) {
				op->stackop = R_ANAL_STACK_GET;
				op->stackptr = regsz;
			} else if (INSOP (1).mem.segment == X86_REG_INVALID && INSOP (1).mem.base == X86_REG_INVALID
					&& INSOP (1).mem.index == X86_REG_INVALID && INSOP (1).mem.scale == 1) { // [<addr>]
				op->ptr = op->disp;
			}
			break;
		case X86_OP_IMM:
			if ((INSOP (1).imm > 10) &&
				(INSOP (0).reg != X86_REG_RSP) && (INSOP (0).reg != X86_REG_ESP)) {
				op->ptr = INSOP (1).imm;
			}
			break;
		default:
			break;
		}
	}
	// Handle AT&T mode: if ptr not set and there's an immediate operand, use it
	if (op->ptr == UT64_MAX) {
		int immop = find_immop (insn);
		int regop = find_regop (insn);
		if (immop >= 0 && INSOP (immop).imm > 10) {
			bool is_stack_reg = false;
			if (regop >= 0) {
				x86_reg reg = INSOP (regop).reg;
				is_stack_reg = (reg == X86_REG_RSP || reg == X86_REG_ESP);
			}
			if (!is_stack_reg) {
				op->ptr = INSOP (immop).imm;
			}
		}
	}
}

static void op_stackidx(RAnalOp *op, cs_insn *insn, bool minus) {
	if (INSOP (0).type == X86_OP_REG && INSOP (1).type == X86_OP_IMM) {
		if (INSOP (0).reg == X86_REG_RSP || INSOP (0).reg == X86_REG_ESP) {
			op->stackop = R_ANAL_STACK_INC;
			if (minus) {
				op->stackptr = -INSOP (1).imm;
			} else {
				op->stackptr = INSOP (1).imm;
			}
		}
	}
}

static void set_opdir(RAnalOp *op, cs_insn *insn, int syntax) {
	// Use normalized operand indices for AT&T syntax support
	int dst_idx = norm_op (0, syntax, INSOPS);
	int src_idx = norm_op (1, syntax, INSOPS);
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_MOV:
		switch (INSOP (dst_idx).type) {
		case X86_OP_MEM:
			op->direction = R_ANAL_OP_DIR_WRITE;
			break;
		case X86_OP_REG:
			if (INSOP (src_idx).type == X86_OP_MEM) {
				op->direction = R_ANAL_OP_DIR_READ;
			}
			break;
		default:
			break;
		}
		break;
	case R_ANAL_OP_TYPE_LEA:
		op->direction = R_ANAL_OP_DIR_REF;
		break;
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_UCALL:
		op->direction = R_ANAL_OP_DIR_EXEC;
		break;
	default:
		break;
	}
}

static void inscmp(RAnalOp *op, ut64 addr, cs_insn *insn, int regsz) {
	switch (INSOP(0).type) {
	case X86_OP_MEM:
		op->disp = INSOP(0).mem.disp;
		op->refptr = INSOP(0).size;
		if (INSOP(0).mem.base == X86_REG_RIP) {
			op->ptr = addr + insn->size + op->disp;
		} else if (INSOP(0).mem.base == X86_REG_RBP || INSOP(0).mem.base == X86_REG_EBP) {
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = regsz;
			op->type |= R_ANAL_OP_TYPE_REG;
		} else if (INSOP(0).mem.segment == X86_REG_INVALID && INSOP(0).mem.base == X86_REG_INVALID
				&& INSOP(0).mem.index == X86_REG_INVALID && INSOP(0).mem.scale == 1) { // [<addr>]
			op->ptr = op->disp;
		}
		if (INSOP(1).type == X86_OP_IMM) {
			op->val = INSOP(1).imm;
		}
		break;
	default:
		switch (INSOP(1).type) {
		case X86_OP_MEM:
			op->disp = INSOP(1).mem.disp;
			op->refptr = INSOP(1).size;
			if (INSOP(1).mem.base == X86_REG_RIP) {
				op->ptr = addr + insn->size + op->disp;
			} else if (INSOP(1).mem.base == X86_REG_RBP || INSOP(1).mem.base == X86_REG_EBP) {
				op->type |= R_ANAL_OP_TYPE_REG;
				op->stackop = R_ANAL_STACK_SET;
				op->stackptr = regsz;
			} else if (INSOP(1).mem.segment == X86_REG_INVALID
					&& INSOP(1).mem.base == X86_REG_INVALID
					&& INSOP(1).mem.index == X86_REG_INVALID
					&& INSOP(1).mem.scale == 1) { // [<addr>]
				op->ptr = op->disp;
			}
			if (INSOP(0).type == X86_OP_IMM) {
				op->val = INSOP(0).imm;
			}
			break;
		case X86_OP_IMM:
			op->val = op->ptr = INSOP(1).imm;
			break;
		default:
			break;
		}
		break;
	}
}

static void anop(RArchSession *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn) {
	int bits = a->config->bits;
	struct Getarg gop = {
		.handle = *handle,
		.insn = insn,
		.bits = a->config->bits
	};
	int regsz = 4;
	switch (bits) {
	case 64: regsz = 8; break;
	case 16: regsz = 2; break;
	default: regsz = 4; break; // 32
	}
	switch (insn->id) {
	case X86_INS_FNOP:
		op->family = R_ANAL_OP_FAMILY_FPU;
		/* fallthru */
	case X86_INS_NOP:
	case X86_INS_PAUSE:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case X86_INS_HLT:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case X86_INS_VPINSRQ:
	case X86_INS_VPINSRD:
	case X86_INS_VPINSRW:
	case X86_INS_VPINSRB:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case X86_INS_FBLD:
	case X86_INS_FBSTP:
	case X86_INS_FINCSTP:
	case X86_INS_FNSTCW:
	case X86_INS_FNSTSW:
	case X86_INS_FRSTOR:
	case X86_INS_FNSAVE:
	case X86_INS_FNSTENV:
	case X86_INS_FXSAVE:
	case X86_INS_FXSAVE64:
	case X86_INS_FISTTP:
		op0_memimmhandle (op, insn, addr, regsz);
		/* fallthu */
	case X86_INS_FCOMPP:
	case X86_INS_FDECSTP:
	case X86_INS_FEMMS:
	case X86_INS_FFREE:
	case X86_INS_FICOM:
	case X86_INS_FICOMP:
	case X86_INS_FNCLEX:
	case X86_INS_FNINIT:
	case X86_INS_FPATAN:
	case X86_INS_FPREM:
	case X86_INS_FPREM1:
	case X86_INS_FPTAN:
#if CS_API_MAJOR >= 4
	case X86_INS_FFREEP:
#endif
	case X86_INS_FRNDINT:
	case X86_INS_FSCALE:
	case X86_INS_FSETPM:
	case X86_INS_FSINCOS:
	case X86_INS_FXAM:
	case X86_INS_FXTRACT:
	case X86_INS_FYL2X:
	case X86_INS_FYL2XP1:
	case X86_INS_FSQRT:
	case X86_INS_FXCH:
		op->family = R_ANAL_OP_FAMILY_FPU;
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case X86_INS_FTST:
	case X86_INS_FUCOMI:
	case X86_INS_FUCOMPP:
	case X86_INS_FUCOMP:
	case X86_INS_FUCOM:
		op->family = R_ANAL_OP_FAMILY_FPU;
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case X86_INS_BT:
	case X86_INS_BTC:
	case X86_INS_BTR:
	case X86_INS_BTS:
		op->type = R_ANAL_OP_TYPE_CMP;
		op0_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_FABS:
		op->type = R_ANAL_OP_TYPE_ABS;
		op->family = R_ANAL_OP_FAMILY_FPU;
		break;
	case X86_INS_FLDCW:
	case X86_INS_FLDENV:
		op0_memimmhandle (op, insn, addr, regsz);
		/* fallthru */
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
	case X86_INS_FXRSTOR:
	case X86_INS_FXRSTOR64:
		op0_memimmhandle (op, insn, addr, regsz);
		/* fallthru */
	case X86_INS_FSTPNCE:
		op->type = R_ANAL_OP_TYPE_STORE;
		op->family = R_ANAL_OP_FAMILY_FPU;
		break;
	case X86_INS_FDIV:
	case X86_INS_FIDIV:
		op0_memimmhandle (op, insn, addr, regsz);
		/* fallthru */
	case X86_INS_FDIVP:
	case X86_INS_FDIVR:
	case X86_INS_FIDIVR:
	case X86_INS_FDIVRP:
		op->type = R_ANAL_OP_TYPE_DIV;
		op->family = R_ANAL_OP_FAMILY_FPU;
		break;
	case X86_INS_FSUBR:
	case X86_INS_FISUBR:
	case X86_INS_FSUB:
	case X86_INS_FISUB:
		op0_memimmhandle (op, insn, addr, regsz);
		/* fallthru */
	case X86_INS_FSUBRP:
	case X86_INS_FSUBP:
		op->type = R_ANAL_OP_TYPE_SUB;
		op->family = R_ANAL_OP_FAMILY_FPU;
		break;
	case X86_INS_FMUL:
	case X86_INS_FIMUL:
		op0_memimmhandle (op, insn, addr, regsz);
		/* fallthru */
	case X86_INS_FMULP:
		op->type = R_ANAL_OP_TYPE_MUL;
		op->family = R_ANAL_OP_FAMILY_FPU;
		break;
	case X86_INS_CLI:
	case X86_INS_STI:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->family = R_ANAL_OP_FAMILY_PRIV;
		break;
	case X86_INS_CLC:
	case X86_INS_STC:
	case X86_INS_CLAC:
	case X86_INS_CLGI:
	case X86_INS_CLTS:
#if CS_API_MAJOR >= 4
	case X86_INS_CLWB:
#endif
	case X86_INS_STAC:
	case X86_INS_STGI:
		op->type = R_ANAL_OP_TYPE_MOV;
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
		break;
	// cmov
	case X86_INS_FCMOVBE:
	case X86_INS_FCMOVB:
	case X86_INS_FCMOVNBE:
	case X86_INS_FCMOVNB:
	case X86_INS_FCMOVE:
	case X86_INS_FCMOVNE:
	case X86_INS_FCMOVNU:
	case X86_INS_FCMOVU:
		op->family = R_ANAL_OP_FAMILY_FPU;
		op->type = R_ANAL_OP_TYPE_CMOV;
		break;
	case X86_INS_CMOVA:
	case X86_INS_CMOVAE:
	case X86_INS_CMOVB:
	case X86_INS_CMOVBE:
	case X86_INS_CMOVE:
	case X86_INS_CMOVG:
	case X86_INS_CMOVGE:
	case X86_INS_CMOVL:
	case X86_INS_CMOVLE:
	case X86_INS_CMOVNE:
	case X86_INS_CMOVNO:
	case X86_INS_CMOVNP:
	case X86_INS_CMOVNS:
	case X86_INS_CMOVO:
	case X86_INS_CMOVP:
	case X86_INS_CMOVS:
		op->type = R_ANAL_OP_TYPE_CMOV;
		op1_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_STOSB:
	case X86_INS_STOSD:
	case X86_INS_STOSQ:
	case X86_INS_STOSW:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case X86_INS_LODSB:
	case X86_INS_LODSD:
	case X86_INS_LODSQ:
	case X86_INS_LODSW:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case X86_INS_PALIGNR:
	case X86_INS_VALIGND:
	case X86_INS_VALIGNQ:
	case X86_INS_VPALIGNR:
		op->type = R_ANAL_OP_TYPE_AND;
		op->family = R_ANAL_OP_FAMILY_CPU;
		break;
	case X86_INS_CPUID:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->family = R_ANAL_OP_FAMILY_CPU;
		break;
	case X86_INS_SFENCE:
	case X86_INS_LFENCE:
	case X86_INS_MFENCE:
		op->type = R_ANAL_OP_TYPE_NOP;
		op->family = R_ANAL_OP_FAMILY_THREAD;
		break;
	// mov
	case X86_INS_MOVNTQ:
	case X86_INS_MOVNTDQA:
	case X86_INS_MOVNTDQ:
	case X86_INS_MOVNTI:
	case X86_INS_MOVNTPD:
	case X86_INS_MOVNTPS:
	case X86_INS_MOVNTSD:
	case X86_INS_MOVNTSS:
	case X86_INS_VMOVNTDQA:
	case X86_INS_VMOVNTDQ:
	case X86_INS_VMOVNTPD:
	case X86_INS_VMOVNTPS:
	case X86_INS_VMOVQ:
	case X86_INS_VMOVDDUP:
	case X86_INS_VMOVD:
	case X86_INS_VMOVDQA32:
	case X86_INS_VMOVDQA64:
	case X86_INS_VMOVDQA:
	case X86_INS_VMOVDQU16:
	case X86_INS_VMOVDQU32:
	case X86_INS_VMOVDQU64:
	case X86_INS_VMOVDQU8:
	case X86_INS_VMOVDQU:
	case X86_INS_VMOVHLPS:
	case X86_INS_VMOVHPD:
	case X86_INS_VMOVHPS:
	case X86_INS_VMOVLHPS:
	case X86_INS_VMOVLPD:
	case X86_INS_VMOVLPS:
	case X86_INS_VMOVMSKPD:
	case X86_INS_VMOVMSKPS:
	case X86_INS_VMOVSD:
	case X86_INS_VMOVSHDUP:
	case X86_INS_VMOVSLDUP:
	case X86_INS_VMOVSS:
	case X86_INS_VMOVUPD:
	case X86_INS_VMOVUPS:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->family = R_ANAL_OP_FAMILY_VEC;
		switch (INSOP(1).type) {
		case X86_OP_MEM:
			op->ptr = addr + op->size + op->disp;
			break;
		case X86_OP_IMM:
			if (INSOP(1).imm > 10) {
				op->ptr = INSOP(1).imm;
			}
			break;
		default:
			break;
		}
		break;
	case X86_INS_PCMPEQB:
	case X86_INS_PCMPEQD:
	case X86_INS_PCMPEQW:
	case X86_INS_PCMPGTB:
	case X86_INS_PCMPGTD:
	case X86_INS_PCMPGTW:
	case X86_INS_PCMPEQQ:
	case X86_INS_PCMPESTRI:
	case X86_INS_PCMPESTRM:
	case X86_INS_PCMPGTQ:
	case X86_INS_PCMPISTRI:
	case X86_INS_PCMPISTRM:
#if CS_API_MAJOR >= 4
	case X86_INS_VPCMPB:
#endif
	case X86_INS_VPCMPD:
	case X86_INS_VPCMPEQB:
	case X86_INS_VPCMPEQD:
	case X86_INS_VPCMPEQQ:
	case X86_INS_VPCMPEQW:
	case X86_INS_VPCMPESTRI:
	case X86_INS_VPCMPESTRM:
	case X86_INS_VPCMPGTB:
	case X86_INS_VPCMPGTD:
	case X86_INS_VPCMPGTQ:
	case X86_INS_VPCMPGTW:
	case X86_INS_VPCMPISTRI:
	case X86_INS_VPCMPISTRM:
	case X86_INS_VPCMPQ:
#if CS_API_MAJOR >= 4
	case X86_INS_VPCMPUB:
#endif
	case X86_INS_VPCMPUD:
	case X86_INS_VPCMPUQ:
#if CS_API_MAJOR >= 4
	case X86_INS_VPCMPUW:
	case X86_INS_VPCMPW:
#endif
		op->type = R_ANAL_OP_TYPE_CMP;
		op->family = R_ANAL_OP_FAMILY_VEC;
		break;
	case X86_INS_MOVSS:
	case X86_INS_MOV:
	case X86_INS_MOVAPS:
	case X86_INS_MOVAPD:
	case X86_INS_MOVZX:
	case X86_INS_MOVUPS:
	case X86_INS_MOVABS:
	case X86_INS_MOVHPD:
	case X86_INS_MOVHPS:
	case X86_INS_MOVLPD:
	case X86_INS_MOVLPS:
	case X86_INS_MOVBE:
	case X86_INS_MOVSB:
	case X86_INS_MOVSD:
	case X86_INS_MOVSQ:
	case X86_INS_MOVSX:
	case X86_INS_MOVSXD:
	case X86_INS_MOVSW:
	case X86_INS_MOVD:
	case X86_INS_MOVQ:
	case X86_INS_MOVDQU:
	case X86_INS_MOVDQA:
	case X86_INS_MOVDQ2Q:
		{
		op->type = R_ANAL_OP_TYPE_MOV;
		op0_memimmhandle (op, insn, addr, regsz);
		op1_memimmhandle (op, insn, addr, regsz);
		}
		break;
	// comiss
	case X86_INS_COMISS:
	case X86_INS_UCOMISD:
	case X86_INS_UCOMISS:
	case X86_INS_VCOMISS:
	case X86_INS_VUCOMISS:
		op->family = R_ANAL_OP_FAMILY_SIMD;
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case X86_INS_ROL:
	case X86_INS_RCL:
		// TODO: RCL Still does not work as intended
		//  - Set flags
		op->type = R_ANAL_OP_TYPE_ROL;
		op0_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_ROR:
	case X86_INS_RCR:
		// TODO: RCR Still does not work as intended
		//  - Set flags
		op->type = R_ANAL_OP_TYPE_ROR;
		op0_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_SHL:
	case X86_INS_SHLD:
	case X86_INS_SHLX:
		// TODO: Set CF: Carry flag is the last bit shifted out due to
		// this operation. It is undefined for SHL and SHR where the
		// number of bits shifted is greater than the size of the
		// destination.
		op->type = R_ANAL_OP_TYPE_SHL;
		op0_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_SAR:
	case X86_INS_SARX:
		// TODO: Set CF. See case X86_INS_SHL for more details.
		op->type = R_ANAL_OP_TYPE_SAR;
		op0_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_SAL:
		// TODO: Set CF: See case X86_INS_SAL for more details.
		op->type = R_ANAL_OP_TYPE_SAL;
		op0_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_SALC:
		op->type = R_ANAL_OP_TYPE_SAL;
		op0_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_SHR:
	case X86_INS_SHRD:
	case X86_INS_SHRX:
		// TODO: Set CF: See case X86_INS_SAL for more details.
		op->type = R_ANAL_OP_TYPE_SHR;
		op0_memimmhandle (op, insn, addr, regsz);
		op->val = INSOP(1).imm;
		// XXX this should be op->imm
		//op->src[0] = r_anal_value_new ();
		//op->src[0]->imm = INSOP(1).imm;
		break;
	case X86_INS_CMP:
	case X86_INS_CMPPD:
	case X86_INS_CMPPS:
	case X86_INS_CMPSW:
	case X86_INS_CMPSD:
	case X86_INS_CMPSQ:
	case X86_INS_CMPSB:
	case X86_INS_CMPSS:
		op->type = R_ANAL_OP_TYPE_CMP;
		inscmp (op, addr, insn, regsz);
		break;
	case X86_INS_TEST:
		op->type = R_ANAL_OP_TYPE_ACMP; // compare via and
		inscmp (op, addr, insn, regsz);
		break;
	case X86_INS_LEA:
		op->type = R_ANAL_OP_TYPE_LEA;
		switch (INSOP(1).type) {
		case X86_OP_MEM:
			// op->type = R_ANAL_OP_TYPE_ULEA;
			op->disp = INSOP(1).mem.disp;
			op->refptr = INSOP(1).size;
			switch (INSOP(1).mem.base) {
			case X86_REG_RIP:
				op->ptr = addr + op->size + op->disp;
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
			if (INSOP(1).imm > 10) {
				op->ptr = INSOP(1).imm;
			}
			break;
		default:
			break;
		}
		break;
	case X86_INS_PUSHAW:
	// pushal, popal - push/pop EAX,EBX,ECX,EDX,ESP,EBP,ESI,EDI
	case X86_INS_PUSHAL:
		op->ptr = UT64_MAX;
		op->type = R_ANAL_OP_TYPE_UPUSH;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = regsz * 8;
		break;
	case X86_INS_ENTER:
	case X86_INS_PUSH:
	case X86_INS_PUSHF:
	case X86_INS_PUSHFD:
	case X86_INS_PUSHFQ:
		switch (INSOP(0).type) {
		case X86_OP_MEM:
			if (INSOP(0).mem.disp && !INSOP(0).mem.base && !INSOP(0).mem.index) {
				op->val = op->ptr = INSOP(0).mem.disp;
				op->type = R_ANAL_OP_TYPE_PUSH;
			} else {
				op->type = R_ANAL_OP_TYPE_UPUSH;
			}
			op->cycles = CYCLE_REG + CYCLE_MEM;
			break;
		case X86_OP_IMM:
			op->val = op->ptr = INSOP(0).imm;
			op->type = R_ANAL_OP_TYPE_PUSH;
			op->cycles = CYCLE_REG + CYCLE_MEM;
			break;
		case X86_OP_REG:
			op->type = R_ANAL_OP_TYPE_RPUSH;
			op->cycles = CYCLE_REG + CYCLE_MEM;
			break;
		default:
			op->type = R_ANAL_OP_TYPE_UPUSH;
			op->cycles = CYCLE_MEM + CYCLE_MEM;
			break;
		}
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = regsz;
		break;
	case X86_INS_LEAVE:
		op->type = R_ANAL_OP_TYPE_POP;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -regsz;
		break;
	case X86_INS_POP:
	case X86_INS_POPF:
	case X86_INS_POPFD:
	case X86_INS_POPFQ:
		op->type = R_ANAL_OP_TYPE_POP;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -regsz;
		break;
	case X86_INS_POPAW:
	case X86_INS_POPAL:
		op->type = R_ANAL_OP_TYPE_POP;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -regsz * 8;
		break;
	case X86_INS_IRET:
	case X86_INS_IRETD:
	case X86_INS_IRETQ:
	case X86_INS_SYSRET:
		op->family = R_ANAL_OP_FAMILY_PRIV;
		/* fallthrough */
	case X86_INS_RET:
	case X86_INS_RETF:
	case X86_INS_RETFQ:
		op->type = R_ANAL_OP_TYPE_RET;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -regsz;
		op->cycles = CYCLE_MEM + CYCLE_JMP;
		break;
#if CS_API_MAJOR >= 4
	case X86_INS_UD0:
#endif
	case X86_INS_UD2:
#if CS_API_MAJOR == 4
	case X86_INS_UD2B:
#endif
	case X86_INS_INT3:
		op->type = R_ANAL_OP_TYPE_TRAP; // TRAP
		break;
	case X86_INS_INT1:
		op->type = R_ANAL_OP_TYPE_SWI;
		op->val = 1;
		break;
	case X86_INS_INT:
		op->type = R_ANAL_OP_TYPE_SWI;
		op->val = (int)INSOP(0).imm;
		if (a->config->bits == 16 && op->val == 0x20) {
			// TODO: Ccheck for >-config->os == "DOS"
			// "int 0x20" -> terminate program on DOS
			op->eob = true; // looks like eob is ignored if optype is not trap :?
			op->type = R_ANAL_OP_TYPE_TRAP;
		}
		break;
	case X86_INS_SYSCALL:
	case X86_INS_SYSENTER:
		op->type = R_ANAL_OP_TYPE_SWI;
		op->cycles = CYCLE_JMP;
		break;
	case X86_INS_SYSEXIT:
		op->type = R_ANAL_OP_TYPE_SWI;
		op->family = R_ANAL_OP_FAMILY_PRIV;
		break;
	case X86_INS_INTO:
		op->type = R_ANAL_OP_TYPE_SWI;
		// int4 if overflow bit is set , so this is an optional swi
		op->type |= R_ANAL_OP_TYPE_COND;
		break;
	case X86_INS_VMCALL:
	case X86_INS_VMMCALL:
		op->type = R_ANAL_OP_TYPE_TRAP;
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
	case X86_INS_LOOPE:
	case X86_INS_LOOPNE:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = INSOP(0).imm;
		op->fail = addr + op->size;
		op->cycles = CYCLE_JMP;
		switch (insn->id) {
		case X86_INS_JL:
		case X86_INS_JLE:
		case X86_INS_JS:
		case X86_INS_JG:
		case X86_INS_JGE:
			op->sign = true;
			break;
		}
		break;
	case X86_INS_CALL:
	case X86_INS_LCALL:
		op->cycles = CYCLE_JMP + CYCLE_MEM;
		switch (INSOP(0).type) {
		case X86_OP_IMM:
			op->type = R_ANAL_OP_TYPE_CALL;
			// TODO: what if UCALL?
			if (INSOP(1).type == X86_OP_IMM) {
				ut64 seg = INSOP(0).imm;
				ut64 off = INSOP(1).imm;
				op->ptr = INSOP (0).mem.disp;
				op->jump = (seg << a->config->seggrn) + off;
			} else {
				op->jump = INSOP(0).imm;
			}
			op->fail = addr + op->size;
			break;
		case X86_OP_MEM:
			op->type = R_ANAL_OP_TYPE_UCALL;
			op->jump = UT64_MAX;
			op->ptr = INSOP (0).mem.disp;
			op->disp = INSOP (0).mem.disp;
			op->reg = NULL;
			op->ireg = NULL;
			op->cycles += CYCLE_MEM;
			if (INSOP (0).mem.index == X86_REG_INVALID) {
				if (INSOP (0).mem.base != X86_REG_INVALID) {
					op->reg = cs_reg_name (*handle, INSOP (0).mem.base);
					op->type = R_ANAL_OP_TYPE_IRCALL;
				}
			} else {
				op->ireg = cs_reg_name (*handle, INSOP (0).mem.index);
				op->scale = INSOP(0).mem.scale;
			}
			if (INSOP (0).mem.base == X86_REG_RIP) {
				op->ptr += addr + insn->size;
				op->refptr = 8;
			}
			break;
		case X86_OP_REG:
			op->reg = cs_reg_name (*handle, INSOP (0).reg);
			op->type = R_ANAL_OP_TYPE_RCALL;
			op->ptr = UT64_MAX;
			op->cycles += CYCLE_REG;
			break;
		default:
			op->type = R_ANAL_OP_TYPE_UCALL;
			op->jump = UT64_MAX;
			break;
		}
		break;
	case X86_INS_JMP:
	case X86_INS_LJMP:
		// TODO: what if UJMP?
		switch (INSOP(0).type) {
		case X86_OP_IMM:
			if (INSOP(1).type == X86_OP_IMM) {
				ut64 seg = INSOP(0).imm;
				ut64 off = INSOP(1).imm;
				op->ptr = INSOP (0).mem.disp;
				op->jump = (seg << a->config->seggrn) + off;
			} else {
				op->jump = INSOP(0).imm;
			}
			op->type = R_ANAL_OP_TYPE_JMP;
			op->cycles = CYCLE_JMP;
			break;
		case X86_OP_MEM:
			// op->type = R_ANAL_OP_TYPE_UJMP;
			op->type = R_ANAL_OP_TYPE_MJMP;
			op->ptr = INSOP (0).mem.disp;
			op->disp = INSOP (0).mem.disp;
			op->reg = NULL;
			op->ireg = NULL;
			op->cycles = CYCLE_JMP + CYCLE_MEM;
			if (INSOP(0).mem.base != X86_REG_INVALID) {
				if (INSOP (0).mem.base != X86_REG_INVALID) {
					op->reg = cs_reg_name (*handle, INSOP (0).mem.base);
					op->type = R_ANAL_OP_TYPE_IRJMP;
				}
			}
			if (INSOP (0).mem.index == X86_REG_INVALID) {
				op->ireg = NULL;
			} else {
				op->type = R_ANAL_OP_TYPE_UJMP;
				op->ireg = cs_reg_name (*handle, INSOP (0).mem.index);
				op->scale = INSOP (0).mem.scale;
			}
			if (INSOP(0).mem.base == X86_REG_RIP) {
				op->ptr += addr + insn->size;
				op->refptr = 8;
			}
			break;
		case X86_OP_REG:
			{
			op->cycles = CYCLE_JMP + CYCLE_REG;
			op->reg = cs_reg_name (gop.handle, INSOP(0).reg);
			op->type = R_ANAL_OP_TYPE_RJMP;
			op->ptr = UT64_MAX;
			}
			break;
		//case X86_OP_FP:
		default: // other?
			op->type = R_ANAL_OP_TYPE_UJMP;
			op->ptr = UT64_MAX;
			break;
		}
		break;
	case X86_INS_IN:
	case X86_INS_INSW:
	case X86_INS_INSD:
	case X86_INS_INSB:
		op->type = R_ANAL_OP_TYPE_IO;
		op->type2 = 0;
		break;
	case X86_INS_OUT:
	case X86_INS_OUTSB:
	case X86_INS_OUTSD:
	case X86_INS_OUTSW:
		op->type = R_ANAL_OP_TYPE_IO;
		op->type2 = 1;
		break;
	case X86_INS_VXORPD:
	case X86_INS_VXORPS:
	case X86_INS_VPXORD:
	case X86_INS_VPXORQ:
	case X86_INS_VPXOR:
	case X86_INS_XORPS:
	case X86_INS_KXORW:
	case X86_INS_PXOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		if (INSOP(0).type == X86_OP_MEM) {
			op->direction = R_ANAL_OP_DIR_WRITE;
		} else if (INSOP(1).type == X86_OP_MEM) {
			op->direction = R_ANAL_OP_DIR_READ;
		}
		break;
	case X86_INS_XOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		if (INSOP(0).type == X86_OP_MEM) {
			op->direction = R_ANAL_OP_DIR_WRITE;
		} else if (INSOP(1).type == X86_OP_MEM) {
			op->direction = R_ANAL_OP_DIR_READ;
		}
		// TODO: Add stack indexing handling chang
		op0_memimmhandle (op, insn, addr, regsz);
		op1_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_OR:
		// The OF and CF flags are cleared; the SF, ZF, and PF flags are
		// set according to the result. The state of the AF flag is
		// undefined.
		op->type = R_ANAL_OP_TYPE_OR;
		// TODO: Add stack indexing handling chang
		op0_memimmhandle (op, insn, addr, regsz);
		op1_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_INC:
		// The CF flag is not affected. The OF, SF, ZF, AF, and PF flags
		// are set according to the result.
		op->type = R_ANAL_OP_TYPE_ADD;
		op0_memimmhandle (op, insn, addr, regsz);
		op->val = 1;
		break;
	case X86_INS_DEC:
		// The CF flag is not affected. The OF, SF, ZF, AF, and PF flags
		// are set according to the result.
		op->type = R_ANAL_OP_TYPE_SUB;
		op0_memimmhandle (op, insn, addr, regsz);
		op->val = 1;
		break;
	case X86_INS_NEG:
		op->type = R_ANAL_OP_TYPE_SUB;
		op->family = R_ANAL_OP_FAMILY_CPU;
		op0_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_NOT:
		op->type = R_ANAL_OP_TYPE_NOT;
		op->family = R_ANAL_OP_FAMILY_CPU;
		op0_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_PSUBB:
	case X86_INS_PSUBW:
	case X86_INS_PSUBD:
	case X86_INS_PSUBQ:
	case X86_INS_PSUBSB:
	case X86_INS_PSUBSW:
	case X86_INS_PSUBUSB:
	case X86_INS_PSUBUSW:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case X86_INS_SUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		op_stackidx (op, insn, false);
		op0_memimmhandle (op, insn, addr, regsz);
		op1_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_SBB:
		// dst = dst - (src + cf)
		op->type = R_ANAL_OP_TYPE_SUB;
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
	case X86_INS_ANDN:
	case X86_INS_ANDPD:
	case X86_INS_ANDPS:
	case X86_INS_ANDNPD:
	case X86_INS_ANDNPS:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case X86_INS_AND:
		op->type = R_ANAL_OP_TYPE_AND;
		// TODO: Add stack register change operation
		op0_memimmhandle (op, insn, addr, regsz);
		op1_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_IDIV:
		op->type = R_ANAL_OP_TYPE_DIV;
		op0_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_DIV:
		op->type = R_ANAL_OP_TYPE_DIV;
		op0_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_IMUL:
		op->type = R_ANAL_OP_TYPE_MUL;
		op->sign = true;
		op0_memimmhandle (op, insn, addr, regsz);
		op1_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_MUL:
		op0_memimmhandle (op, insn, addr, regsz);
		/* fallthru */
	case X86_INS_AAM:
	case X86_INS_MULX:
	case X86_INS_MULPD:
	case X86_INS_MULPS:
	case X86_INS_MULSD:
	case X86_INS_MULSS:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case X86_INS_PACKSSDW:
	case X86_INS_PACKSSWB:
	case X86_INS_PACKUSWB:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->family = R_ANAL_OP_FAMILY_VEC;
		break;
	case X86_INS_PADDB:
	case X86_INS_PADDD:
	case X86_INS_PADDW:
	case X86_INS_PADDSB:
	case X86_INS_PADDSW:
	case X86_INS_PADDUSB:
	case X86_INS_PADDUSW:
		op->type = R_ANAL_OP_TYPE_ADD;
		op->family = R_ANAL_OP_FAMILY_VEC;
		break;
	case X86_INS_XCHG:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->family = R_ANAL_OP_FAMILY_CPU;
		break;
	case X86_INS_XADD: /* xchg + add */
		op->type = R_ANAL_OP_TYPE_ADD;
		op->family = R_ANAL_OP_FAMILY_CPU;
		break;
	case X86_INS_FADD:
#if CS_API_MAJOR == 4
	case X86_INS_FADDP:
#endif
		op->family = R_ANAL_OP_FAMILY_FPU;
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case X86_INS_ADDPS:
	case X86_INS_ADDSD:
	case X86_INS_ADDSS:
	case X86_INS_ADDSUBPD:
	case X86_INS_ADDSUBPS:
	case X86_INS_ADDPD:
		// The OF, SF, ZF, AF, CF, and PF flags are set according to the
		// result.
		op->type = R_ANAL_OP_TYPE_ADD;
		op_stackidx (op, insn, true);
		op->val = INSOP(1).imm;
		break;
	case X86_INS_ADD:
		// The OF, SF, ZF, AF, CF, and PF flags are set according to the
		// result.
		op->type = R_ANAL_OP_TYPE_ADD;
		op_stackidx (op, insn, true);
		op0_memimmhandle (op, insn, addr, regsz);
		op1_memimmhandle (op, insn, addr, regsz);
		break;
	case X86_INS_ADC:
		op->type = R_ANAL_OP_TYPE_ADD;
		op0_memimmhandle (op, insn, addr, regsz);
		op1_memimmhandle (op, insn, addr, regsz);
		break;
		/* Direction flag */
	case X86_INS_CLD:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case X86_INS_STD:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case X86_INS_SUBSD:    //cvtss2sd
	case X86_INS_CVTSS2SD: //cvtss2sd
		break;
	}
	if (cs_insn_group (*handle, insn, X86_GRP_MMX)) {
		op->family = R_ANAL_OP_FAMILY_VEC;
	}
	// TODO: add SSE* families?
	if (cs_insn_group (*handle, insn, X86_GRP_SSE1)) {
		op->family = R_ANAL_OP_FAMILY_VEC;
	}
	if (cs_insn_group (*handle, insn, X86_GRP_SSE2)) {
		op->family = R_ANAL_OP_FAMILY_VEC;
	}
	if (cs_insn_group (*handle, insn, X86_GRP_SSE3)) {
		op->family = R_ANAL_OP_FAMILY_VEC;
	}
}

static int cs_len_prefix_opcode(uint8_t *item) {
	int i, len = 0;
	for (i = 0; i < 4; i++) {
		len += (item[i] != 0) ? 1 : 0;
	}
	return len;
}

static bool plugin_changed(RArchSession *as) {
	PluginData *cpd = as->data;
	if (as->config->bits != cpd->bits) {
		return true;
	}
	if (as->config->syntax != cpd->syntax) {
		return true;
	}
	return false;
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	csh handle = cs_handle_for_session (as);
	if (handle == 0) {
		return false;
	}
	int mode = as->config->bits;
	switch (mode) {
	case 16: mode = CS_MODE_16; break;
	case 32: mode = CS_MODE_32; break;
	case 64: mode = CS_MODE_64; break;
	}
	if (plugin_changed (as)) {
		fini (as);
		init (as);
		handle = cs_handle_for_session (as);
	}

	cs_insn *insn = NULL;
	int n;
#if GHOSTOPS
	if (op->size >= 2 && op->bytes[0] == 0x0f) {
		ut8 b1 = op->bytes[1];
		if (b1 == 0x1a || b1 == 0x1b) {
			op->type = R_ANAL_OP_TYPE_NOP;
			op->mnemonic = strdup ("nop2");
			op->size = 2;
			return true;
		}
	}
#endif

	op->cycles = 1; // aprox
	cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	// capstone-next
#if USE_ITER_API
	cs_detail insnack_detail = {{0}};
	cs_insn insnack = {0};
	insnack.detail = &insnack_detail;
	const ut64 addr = op->addr;
	const ut8 *buf = op->bytes;
	const int len = op->size;
	ut64 naddr = addr;
	size_t size = len;
	insn = &insnack;
	n = cs_disasm_iter (handle, (const uint8_t**)&buf, &size, (uint64_t*)&naddr, insn);
#else
	n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
#endif
	//XXX: capstone lcall seg:off workaround, remove when capstone will be fixed
	if (n >= 1 && mode == CS_MODE_16 && r_str_startswith (insn->mnemonic, "lcall")) {
		char *opstr = strdup (insn->op_str);
		opstr = r_str_replace (opstr, ", ", ":", 0);
		r_str_ncpy (insn->op_str, opstr, sizeof (insn->op_str));
		free (opstr);
	}
	if (n < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		op->size = 1;
	} else {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = r_str_newf ("%s%s%s",
				insn->mnemonic,
				insn->op_str[0]?" ":"",
				insn->op_str);
			if (op->mnemonic) {
				if (as->config->syntax != R_ARCH_SYNTAX_MASM) {
					op->mnemonic = r_str_replace (op->mnemonic, "ptr ", "", true);
				}
				if (as->config->syntax == R_ARCH_SYNTAX_JZ) {
					if (r_str_startswith (op->mnemonic, "je ")) {
						op->mnemonic[1] = 'z';
					} else if (r_str_startswith (op->mnemonic, "jne ")) {
						op->mnemonic[2] = 'z';
					}
				}
			}
		}
		op->nopcode = cs_len_prefix_opcode (insn->detail->x86.prefix)
			+ cs_len_prefix_opcode (insn->detail->x86.opcode);
		op->size = insn->size;
		op->id = insn->id;
		op->family = R_ANAL_OP_FAMILY_CPU; // almost everything is CPU
		op->prefix = 0;
		op->cond = cond_x862r2 (insn->id);
		switch (insn->detail->x86.prefix[0]) {
		case X86_PREFIX_REPNE:
			op->prefix |= R_ANAL_OP_PREFIX_REPNE;
			break;
		case X86_PREFIX_REP:
			op->prefix |= R_ANAL_OP_PREFIX_REP;
			break;
		case X86_PREFIX_LOCK:
			op->prefix |= R_ANAL_OP_PREFIX_LOCK;
			op->family = R_ANAL_OP_FAMILY_THREAD; // XXX ?
			break;
		}
		anop (as, op, addr, buf, len, &handle, insn);
		set_opdir (op, insn, as->config->syntax);
		if (mask & R_ARCH_OP_MASK_ESIL) {
			anop_esil (as, op, addr, buf, len, handle, insn);
		}
		if (mask & R_ARCH_OP_MASK_OPEX) {
			opex (as, &op->opex, insn, mode);
		}
		if (mask & R_ARCH_OP_MASK_VAL) {
			op_fillval (as, op, handle, insn, mode);
		}
	}
//#if X86_GRP_PRIVILEGE>0
	if (insn) {
#if HAVE_CSGRP_PRIVILEGE
		if (cs_insn_group (handle, insn, X86_GRP_PRIVILEGE)) {
			op->family = R_ANAL_OP_FAMILY_PRIV;
		}
#endif
#if !USE_ITER_API
		cs_free (insn, n);
#endif
	}
	return op->size > 0;
}

#if 0
static int x86_int_0x80(REsil *esil, int interrupt) {
	int syscall;
	ut64 eax, ebx, ecx, edx;
	if (!esil || (interrupt != 0x80))
		return false;
	r_esil_reg_read (esil, "eax", &eax, NULL);
	r_esil_reg_read (esil, "ebx", &ebx, NULL);
	r_esil_reg_read (esil, "ecx", &ecx, NULL);
	r_esil_reg_read (esil, "edx", &edx, NULL);
	syscall = (int) eax;
	switch (syscall) {
	case 3:
		{
			char *dst = calloc (1, (size_t)edx);
			(void)read ((ut32)ebx, dst, (size_t)edx);
			r_esil_mem_write (esil, ecx, (ut8 *)dst, (int)edx);
			free (dst);
			return true;
		}
	case 4:
		{
			char *src = malloc ((size_t)edx);
			r_esil_mem_read (esil, ecx, (ut8 *)src, (int)edx);
			write ((ut32)ebx, src, (size_t)edx);
			free (src);
			return true;
		}
	}
	R_LOG_ERROR ("syscall %d not implemented yet", syscall);
	return false;
}
#endif

#if 0
static int esil_x86_cs_intr(REsil *esil, int intr) {
	if (!esil) return false;
	R_LOG_DEBUG ("INTERRUPT 0x%02x HAPPENS", intr);
	return true;
}
#endif

#if 0
On 32 bit Windows GS is reserved for future use.
The FS segment points to the Thread information block.

In x64 mode the FS and GS segment registers have been swapped around.

In x86 mode FS:[0] points to the start of the TIB, in X64 its GS:[0].
The reason Win64 uses GS is that there the FS register is used in the 32 bit compatibility layer (confusingly called Wow64).
Because 32-bit apps use FS the bookkeeping for Win64 is simplified.
32 bit applications never cause GS to be altered and 64 bit applications never cause FS to be altered.

Note that the fact that GS is non-zero in Win64 and Wow64 can be used to detect if a 32-bit application is running in 64-bit Windows.
In a true 32 bit Windows GS is always zero.
#endif

static char *get_reg_profile(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->config, NULL);
	int bits = as->config->bits;
	switch (bits) {
	case 16:
	case 32:
	case 64:
		break;
	default:
		if (R_SYS_BITS_CHECK (bits, 64)) {
			bits = 64;
		} else {
			bits = 32;
		}
		break;
	}
	const char *p = NULL;
	switch (bits) {
	case 16: p =
		"=PC	ip\n"
		"=SP	sp\n"
		"=BP	bp\n"
		"=R0	ax\n"
		"=A0	ax\n"
		"=A1	bx\n"
		"=A2	cx\n"
		"=A3	dx\n"
		"=A4	si\n"
		"=A5	di\n"
		"=SN	ah\n"
		"=TR	fs\n" // can be %gs too, but well thats can be overriden with the cc abi scripts
		"gpr	ip	.16	48	0\n"
		"gpr	ax	.16	24	0\n"
		"gpr	ah	.8	25	0\n"
		"gpr	al	.8	24	0\n"
		"gpr	bx	.16	0	0\n"
		"gpr	bh	.8	1	0\n"
		"gpr	bl	.8	0	0\n"
		"gpr	cx	.16	4	0\n"
		"gpr	ch	.8	5	0\n"
		"gpr	cl	.8	4	0\n"
		"gpr	dx	.16	8	0\n"
		"gpr	dh	.8	9	0\n"
		"gpr	dl	.8	8	0\n"
		"gpr	sp	.16	60	0\n"
		"gpr	bp	.16	20	0\n"
		"gpr	si	.16	12	0\n"
		"gpr	di	.16	16	0\n"
		"seg	cs	.16	52	0\n"
		"seg	ss	.16	54	0\n"
		"seg	ds	.16	56	0\n"
		"seg	es	.16	58	0\n"
		"gpr	flags	.16	56	0\n"
		"flg	cf	.1	.448	0\n"
		"flg	pf	.1	.449	0\n"
		"flg	af	.1	.450	0\n"
		"flg	zf	.1	.451	0\n"
		"flg	sf	.1	.452	0\n"
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
	case 32: p =
		"=PC	eip\n"
		"=SP	esp\n"
		"=BP	ebp\n"
		"=R0	eax\n"
		"=A0	eax\n"
		"=A1	ebx\n"
		"=A2	ecx\n"
		"=A3	edx\n"
		"=A4	esi\n"
		"=A5	edi\n"
		"=SN	eax\n"
		"gpr	eiz	.32	?	0\n"
		"gpr	oeax	.32	44	0\n"
		"gpr	eax	.32	24	0\n"
		"gpr	ax	.16	24	0\n"
		"gpr	ah	.8	25	0\n"
		"gpr	al	.8	24	0\n"
		"gpr	ebx	.32	0	0\n"
		"gpr	bx	.16	0	0\n"
		"gpr	bh	.8	1	0\n"
		"gpr	bl	.8	0	0\n"
		"gpr	ecx	.32	4	0\n"
		"gpr	cx	.16	4	0\n"
		"gpr	ch	.8	5	0\n"
		"gpr	cl	.8	4	0\n"
		"gpr	edx	.32	8	0\n"
		"gpr	dx	.16	8	0\n"
		"gpr	dh	.8	9	0\n"
		"gpr	dl	.8	8	0\n"
		"gpr	esi	.32	12	0\n"
		"gpr	si	.16	12	0\n"
		"gpr	edi	.32	16	0\n"
		"gpr	di	.16	16	0\n"
		"gpr	esp	.32	60	0\n"
		"gpr	sp	.16	60	0\n"
		"gpr	ebp	.32	20	0\n"
		"gpr	bp	.16	20	0\n"
		"gpr	eip	.32	48	0\n"
		"gpr	ip	.16	48	0\n"
		"seg	xfs	.32	36	0\n"
		"seg	xgs	.32	40	0\n"
		"seg	xcs	.32	52	0\n"
		"seg	cs	.16	52	0\n"
		"seg	xss	.32	52	0\n"
		"flg	eflags	.32	.448	0	c1p.a.zstido.n.rv\n"
		"flg	flags	.16	.448	0\n"
		"flg	cf	.1	.448	0\n"
		"flg	pf	.1	.450	0\n"
		"flg	af	.1	.452	0\n"
		"flg	zf	.1	.454	0\n"
		"flg	sf	.1	.455	0\n"
		"flg	tf	.1	.456	0\n"
		"flg	if	.1	.457	0\n"
		"flg	df	.1	.458	0\n"
		"flg	of	.1	.459	0\n"
		"flg	nt	.1	.462	0\n"
		"flg	rf	.1	.464	0\n"
		"flg	vm	.1	.465	0\n"
		"drx	dr0	.32	0	0\n"
		"drx	dr1	.32	4	0\n"
		"drx	dr2	.32	8	0\n"
		"drx	dr3	.32	12	0\n"
		//"drx	dr4	.32	16	0\n"
		//"drx	dr5	.32	20	0\n"
		"drx	dr6	.32	24	0\n"
		"drx	dr7	.32	28	0\n"
		"vec128@fpu    xmm0  .128 160  4\n"
		"vec64@fpu    xmm0l .64 160  0\n"
		"vec64@fpu    xmm0h .64 168  0\n"

		"vec128@fpu    xmm1  .128 176  4\n"
		"fpu    xmm1l .64 176  0\n"
		"fpu    xmm1h .64 184  0\n"

		"vec128@fpu    xmm2  .128 192  4\n"
		"fpu    xmm2l .64 192  0\n"
		"fpu    xmm2h .64 200  0\n"

		"vec128@fpu    xmm3  .128 208  4\n"
		"fpu    xmm3l .64 208  0\n"
		"fpu    xmm3h .64 216  0\n"

		"vec128@fpu    xmm4  .128 224  4\n"
		"fpu    xmm4l .64 224  0\n"
		"fpu    xmm4h .64 232  0\n"

		"vec128@fpu    xmm5  .128 240  4\n"
		"fpu    vec1285l .64 240  0\n"
		"fpu    vec1285h .64 248  0\n"

		"vec128@fpu    xmm6  .128 256  4\n"
		"fpu    vec1286l .64 256  0\n"
		"fpu    vec1286h .64 264  0\n"

		"vec128@fpu    xmm7  .128 272  4\n"
		"fpu    xmm7l .64 272  0\n"
		"fpu    xmm7h .64 280  0\n";

		break;
	case 64:
	{
#if 0
		const char *cc = "cdecl"; // r_anal_cc_default (anal); // R2_590
		const char *args_prof = cc && !strcmp (cc, "ms")
		? // Microsoft x64 CC
		"# RAX     return value\n"
		"# RCX     argument 1\n"
		"# RDX     argument 2\n"
		"# R8      argument 3\n"
		"# R9      argument 4\n"
		"# R10-R11 syscall/sysret\n"
		"# R12-R15 GP preserved\n"
		"# RSI     preserved source\n"
		"# RDI     preserved destination\n"
		"# RSP     stack pointer\n"
		"=PC	rip\n"
		"=SP	rsp\n"
		"=R0	rax\n"
		"=F0	xmm0\n"
		"=BP	rbp\n"
		"=A0	rcx\n"
		"=A1	rdx\n"
		"=A2	r8\n"
		"=A3	r9\n"
		"=SN	rax\n"
		 : // System V AMD64 ABI
#endif
		// R2_590 - this info shouldnt be used as a calling convention if anal.cc is set
		const char *args_prof =
		"=PC	rip\n"
		"=SP	rsp\n"
		"=BP	rbp\n"
		"=R0	rax\n"
		"=A0	rdi\n"
		"=A1	rsi\n"
		"=A2	rdx\n"
		"=A3	rcx\n"
		"=A4	r8\n"
		"=A5	r9\n"
		"=A6	r10\n"
		"=A7	r11\n"
		"=SN	rax\n";
		char *prof = r_str_newf ("%s%s", args_prof,
		 "gpr	rax	.64	80	0\n"
		 "gpr	eax	.32	80	0\n"
		 "gpr	ax	.16	80	0\n"
		 "gpr	al	.8	80	0\n"
		 "gpr	ah	.8	81	0\n"
		 "gpr	rbx	.64	40	0\n"
		 "gpr	ebx	.32	40	0\n"
		 "gpr	bx	.16	40	0\n"
		 "gpr	bl	.8	40	0\n"
		 "gpr	bh	.8	41	0\n"
		 "gpr	rcx	.64	88	0\n"
		 "gpr	ecx	.32	88	0\n"
		 "gpr	cx	.16	88	0\n"
		 "gpr	cl	.8	88	0\n"
		 "gpr	ch	.8	89	0\n"
		 "gpr	rdx	.64	96	0\n"
		 "gpr	edx	.32	96	0\n"
		 "gpr	dx	.16	96	0\n"
		 "gpr	dl	.8	96	0\n"
		 "gpr	dh	.8	97	0\n"
		 "gpr	rsi	.64	104	0\n"
		 "gpr	esi	.32	104	0\n"
		 "gpr	si	.16	104	0\n"
		 "gpr	sil	.8	104	0\n"
		 "gpr	rdi	.64	112	0\n"
		 "gpr	edi	.32	112	0\n"
		 "gpr	di	.16	112	0\n"
		 "gpr	dil	.8	112	0\n"
		 "gpr	r8	.64	72	0\n"
		 "gpr	r8d	.32	72	0\n"
		 "gpr	r8w	.16	72	0\n"
		 "gpr	r8b	.8	72	0\n"
		 "gpr	r9	.64	64	0\n"
		 "gpr	r9d	.32	64	0\n"
		 "gpr	r9w	.16	64	0\n"
		 "gpr	r9b	.8	64	0\n"
		 "gpr	r10	.64	56	0\n"
		 "gpr	r10d	.32	56	0\n"
		 "gpr	r10w	.16	56	0\n"
		 "gpr	r10b	.8	56	0\n"
		 "gpr	r11	.64	48	0\n"
		 "gpr	r11d	.32	48	0\n"
		 "gpr	r11w	.16	48	0\n"
		 "gpr	r11b	.8	48	0\n"
		 "gpr	r12	.64	24	0\n"
		 "gpr	r12d	.32	24	0\n"
		 "gpr	r12w	.16	24	0\n"
		 "gpr	r12b	.8	24	0\n"
		 "gpr	r13	.64	16	0\n"
		 "gpr	r13d	.32	16	0\n"
		 "gpr	r13w	.16	16	0\n"
		 "gpr	r13b	.8	16	0\n"
		 "gpr	r14	.64	8	0\n"
		 "gpr	r14d	.32	8	0\n"
		 "gpr	r14w	.16	8	0\n"
		 "gpr	r14b	.8	8	0\n"
		 "gpr	r15	.64	0	0\n"
		 "gpr	r15d	.32	0	0\n"
		 "gpr	r15w	.16	0	0\n"
		 "gpr	r15b	.8	0	0\n"
		 "gpr	rip	.64	128	0\n"
		 "gpr	rbp	.64	32	0\n"
		 "gpr	ebp	.32	32	0\n"
		 "gpr	bp	.16	32	0\n"
		 "gpr	bpl	.8	32	0\n"
		 "seg	cs	.64	136	0\n"
		 "flg	rflags	.64	144	0	c1p.a.zstido.n.rv\n"
		 "flg	eflags	.32	144	0	c1p.a.zstido.n.rv\n"
		 "flg	cf	.1	144.0	0	carry\n"
		 "flg	pf	.1	144.2	0	parity\n"
		 //"gpr	cf	.1	.1152	0	carry\n"
		 //"gpr	pf	.1	.1154	0	parity\n"
		 "flg	af	.1	144.4	0	adjust\n"
		 "flg	zf	.1	144.6	0	zero\n"
		 "flg	sf	.1	144.7	0	sign\n"
		 "flg	tf	.1	.1160	0	trap\n"
		 "flg	if	.1	.1161	0	interrupt\n"
		 "flg	df	.1	.1162	0	direction\n"
		 "flg	of	.1	.1163	0	overflow\n"

		 "gpr	riz	.64	?	0\n"
		 "gpr	rsp	.64	152	0\n"
		 "gpr	esp	.32	152	0\n"
		 "gpr	sp	.16	152	0\n"
		 "gpr	spl	.8	152	0\n"
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

		 "vec128@fpu    xmm0  .128 160  4\n"
		 "fpu    xmm0l .64 160  0\n"
		 "fpu    xmm0h .64 168  0\n"

		 "vec128@fpu    xmm1  .128 176  4\n"
		 "fpu    xmm1l .64 176  0\n"
		 "fpu    xmm1h .64 184  0\n"

		 "vec128@fpu    xmm2  .128 192  4\n"
		 "fpu    xmm2l .64 192  0\n"
		 "fpu    xmm2h .64 200  0\n"

		 "vec128@fpu    xmm3  .128 208  4\n"
		 "fpu    xmm3l .64 208  0\n"
		 "fpu    xmm3h .64 216  0\n"

		 "vec128@fpu    xmm4  .128 224  4\n"
		 "fpu    xmm4l .64 224  0\n"
		 "fpu    xmm4h .64 232  0\n"

		 "vec128@fpu    xmm5  .128 240  4\n"
		 "fpu    xmm5l .64 240  0\n"
		 "fpu    xmm5h .64 248  0\n"

		 "vec128@fpu    xmm6  .128 256  4\n"
		 "fpu    xmm6l .64 256  0\n"
		 "fpu    xmm6h .64 264  0\n"

		 "vec128@fpu    xmm7  .128 272  4\n"
		 "fpu    xmm7l .64 272  0\n"
		 "fpu    xmm7h .64 280  0\n"
		 "fpu    x64   .64 288  0\n");
		return prof;
	}
	}
	return (R_STR_ISNOTEMPTY (p))? strdup (p): NULL;
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_CODE_ALIGN:
	case R_ARCH_INFO_DATA_ALIGN:
		return 0;
	case R_ARCH_INFO_FUNC_ALIGN:
		if (R_SYS_BITS_CHECK (as->config->bits, 64)) {
			return 4;
		}
		return 0;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 16;
	case R_ARCH_INFO_INVOP_SIZE:
		return 1;
	case R_ARCH_INFO_MINOP_SIZE:
		return 1;
	}
	return 0;
}

static RList *anal_preludes(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->config, NULL);
	RList *l = NULL;
	switch (as->config->bits) {
	case 32:
		l = r_list_newf (free);
		r_list_append (l, strdup ("8bff558bec"));
		r_list_append (l, strdup ("5589e5"));
		r_list_append (l, strdup ("558bec"));
		r_list_append (l, strdup ("f30f1efb")); // endbr32
		r_list_append (l, strdup ("55575653")); // push ebp, edi, esi, ebx
		break;
	case 64:
		l = r_list_newf (free);
		r_list_append (l, strdup ("554889e5"));
		r_list_append (l, strdup ("55488bec"));
		r_list_append (l, strdup ("f30f1efa")); // endbr64
		// r_list_append (l, strdup ("4157415653")); // push r15,r14,rbx
		r_list_append (l, strdup ("5541574156")); // push rbp,r15,r14
		r_list_append (l, strdup ("415741564154")); // push r15,r14,r13,r12
		r_list_append (l, strdup ("56534883"));
		break;
	default:
		// nothing to do on x86-16
		break;
	}
	return l;
}

static char *mnemonics(RArchSession *as, int id, bool json) {
	R_RETURN_VAL_IF_FAIL (as && as->data, NULL);
	CapstonePluginData *cpd = as->data;
	return r_arch_cs_mnemonics (as, cpd->cs_handle, id, json);
}
#include <r_core.h>

static bool tls_begin(REsil *esil) {
	// R_LOG_DEBUG ("tls:begin");
	RCoreBind *coreb = &esil->anal->coreb;
	coreb->cmdf (coreb->core, "omb fs");
	return true;
}

static bool tls_end(REsil *esil) {
	// R_LOG_DEBUG ("tls:end");
	RCoreBind *coreb = &esil->anal->coreb;
	coreb->cmdf (coreb->core, "omb default");
	return true;
}

static bool esilcb(RArchSession *as, RArchEsilAction action) {
	// R_LOG_DEBUG ("x86.cs.esil.action %d", action);
	RBin *bin = as->arch->binb.bin;
	if (!bin) {
		return false;
	}
	RIO *io = bin->iob.io;
	RCore *core = io->coreb.core;
	RAnal *anal = core->anal;
	REsil *esil = anal->esil;
	// not implemented
	if (!esil) {
		R_LOG_ERROR ("Failed to find an esil instance");
		return false;
	}
	r_esil_set_op (esil, "TLS_BEGIN", tls_begin, 0, 0, R_ESIL_OP_TYPE_CUSTOM, NULL);
	r_esil_set_op (esil, "TLS_END", tls_end, 0, 0, R_ESIL_OP_TYPE_CUSTOM, NULL);
	// XXX. this depends on kernel
	// r_esil_set_interrupt (esil, 0x80, x86_int_0x80);
	/* disable by default */
//	r_esil_set_interrupt (esil, 0x80, NULL);	// this is stupid, don't do this
	return true;
}

const RArchPlugin r_arch_plugin_x86_cs = {
	.meta = {
		.name = "x86",
		.desc = "Capstone X86 analysis",
		.license = "Apache-2.0",
	},
	.arch = "x86",
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.decode = &decode,
	.preludes = anal_preludes,
	.init = init,
	.fini = fini,
	.info = archinfo,
	.regs = &get_reg_profile,
	.esilcb = esilcb,
	.mnemonics = mnemonics,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_x86_cs,
	.version = R2_VERSION
};
#endif
// clang-format on
