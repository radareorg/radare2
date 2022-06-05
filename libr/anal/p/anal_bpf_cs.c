/* radare2 - LGPL - Copyright 2022 - terorie */

#include <r_anal.h>
#include <r_lib.h>

#include <capstone/capstone.h>
#if CS_API_MAJOR >= 5

// calculate jump address from immediate, the "& 0xffff" is for some weird CS bug in JMP
#define JUMP(n) (addr + insn->size * ((1 + insn->detail->bpf.operands[n].imm) & 0xffff))

static const char *ebpf_gpr_names[] = {
	"r0",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",
	"r8",
	"r9",
	"r10",
};

static const char *get_ebpf_gpr_name (uint8_t reg) {
	switch (reg) {
	// cbpf
	case BPF_REG_A: return "a";
	case BPF_REG_X: return "x";
	// ebpf
	case BPF_REG_R0: return ebpf_gpr_names[0];
	case BPF_REG_R1: return ebpf_gpr_names[1];
	case BPF_REG_R2: return ebpf_gpr_names[2];
	case BPF_REG_R3: return ebpf_gpr_names[3];
	case BPF_REG_R4: return ebpf_gpr_names[4];
	case BPF_REG_R5: return ebpf_gpr_names[5];
	case BPF_REG_R6: return ebpf_gpr_names[6];
	case BPF_REG_R7: return ebpf_gpr_names[7];
	case BPF_REG_R8: return ebpf_gpr_names[8];
	case BPF_REG_R9: return ebpf_gpr_names[9];
	case BPF_REG_R10: return ebpf_gpr_names[10];
	// invalid
	default: return NULL;
	}
}

static RRegItem *get_ebpf_gpr (RAnal *a, uint8_t reg) {
	return r_reg_get (a->reg, get_ebpf_gpr_name (reg), R_REG_TYPE_GPR);
}

static RAnalValue *new_ebpf_op (RAnal *a, cs_bpf_op *op) {
	RAnalValue *val = r_anal_value_new ();
	if (!val) {
		return NULL;
	}
	switch (op->type) {
	case CS_OP_REG:
		val->type = R_ANAL_VAL_REG;
		val->reg = get_ebpf_gpr (a, op->reg);
		if ((op->access & CS_AC_READ) != 0) {
			val->access |= R_ANAL_ACC_R;
		}
		if ((op->access & CS_AC_WRITE) != 0) {
			val->access |= R_ANAL_ACC_W;
		}
		return val;
	case CS_OP_IMM:
		val->type = R_ANAL_VAL_IMM;
		val->imm = op->imm;
		return val;
	default:
		R_LOG_WARN ("unsupported capstone op: %d", op->type);
		r_anal_value_free (val);
		return NULL;
	}
}

static RAnalValue *new_ebpf_dest (RAnal *a, cs_bpf *bpf) {
	if (bpf->op_count < 1) {
		return NULL;
	}
	return new_ebpf_op (a, &bpf->operands[0]);
}

static void new_ebpf_operands (RAnal *a, RAnalOp *op, cs_insn *insn) {
	cs_bpf *bpf = &insn->detail->bpf;

	// First Capstone operand is RAnalOp dest operand
	op->dst = new_ebpf_dest (a, bpf);
	if (!op->dst) {
		return;
	}

	// RAnalOp can currently only handle 3 source operands
	ut8 argc = insn->detail->bpf.op_count;
	ut8 max_argc = (ut8)(sizeof (op->src) / sizeof (RAnalValue *));
	if (argc > max_argc + 1) {
		argc = max_argc + 1;
	}
	for (ut8 i = 1; i < argc; i++) {
		op->src[i - 1] = new_ebpf_op (a, &bpf->operands[i]);
	}

	// Set immediate.
	if (op->src[0] != NULL && op->src[0]->type == R_ANAL_VAL_IMM) {
		op->val = op->src[0]->imm;
	}
}

#define OP_DST  (op->dst)
#define OP_SRC0 (op->src[0])

static void _esil_binary_op (RAnalOp *op, RAnalValue *arg1, RAnalValue *arg0, const char *opstr) {
	if (arg1->reg) {
		esilprintf (op, "%s", arg1->reg->name);
	} else {
		esilprintf (op, "%" PFMT64d, arg1->imm);
	}
	r_strbuf_appendf (&op->esil, ",%s,%s=", arg0->reg->name, opstr);
}

static bool check_esil_binary_op_args (RAnalValue *arg1, RAnalValue *arg0) {
	return arg0 && arg0->reg && arg1;
}

static void esil_binary_op_32 (RAnalOp *op, RAnalValue *arg1, RAnalValue *arg0, const char *opstr, bool ebpf) {
	if (!check_esil_binary_op_args (arg1, arg0)) {
		return;
	}
	if (ebpf) {
		// 32-bit compatibility mode on 64-bit arch.

		// Truncate return value to 32 bits (part 1).
		esilprintf (op, "0xffffffff");
		// Express second arg.
		if (arg1->reg) {
			r_strbuf_appendf (&op->esil, ",%s", arg1->reg->name);
		} else {
			r_strbuf_appendf (&op->esil, ",%" PFMT64d, arg1->imm);
		}
		r_strbuf_appendf (&op->esil,
			// Truncate second arg to 32 bits.
			",0xffffffff,&"
			// Truncate first arg to 32 bits.
			",%s,0xffffffff,&"
			// Execute operation
			",%s"
			// Truncate return value to 32 bits (part 2).
			",&"
			// Save to first arg
			",%s,=",
			arg0->reg->name,
			opstr,
			arg0->reg->name);
	} else {
		// Native 32-bit op.
		_esil_binary_op (op, arg1, arg0, opstr);
	}
}

static void esil_binary_op_64 (RAnalOp *op, RAnalValue *arg1, RAnalValue *arg0, const char *opstr) {
	if (!check_esil_binary_op_args (arg1, arg0)) {
		return;
	}
	_esil_binary_op (op, arg1, arg0, opstr);
}

static int analop (RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	static R_TH_LOCAL csh handle = 0;
	static R_TH_LOCAL int omode = -1;
	static R_TH_LOCAL int obits = 32;
	cs_insn *insn = NULL;
	bool ebpf = a->config->bits == 64;
	int mode = ebpf ? CS_MODE_BPF_EXTENDED : CS_MODE_BPF_CLASSIC;
	int n, ret;
	mode |= (a->config->big_endian) ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
	if (mode != omode || a->config->bits != obits) {
		if (handle != 0) {
			cs_close (&handle);
			handle = 0; // unnecessary
		}
		omode = mode;
		obits = a->config->bits;
	}
	op->size = 8;
	op->addr = addr;
	if (handle == 0) {
		ret = cs_open (CS_ARCH_BPF, mode, &handle);
		if (ret != CS_ERR_OK) {
			handle = 0;
			return -1;
		}
	}

	cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	n = cs_disasm (handle, (ut8 *)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ANAL_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
	} else {
		if (mask & R_ANAL_OP_MASK_DISASM) {
			op->mnemonic = r_str_newf ("%s%s%s",
				insn->mnemonic,
				insn->op_str[0] ? " " : "",
				insn->op_str);
		}
		if (insn->detail) {
			new_ebpf_operands (a, op, insn);
			switch (insn->id) {
			case BPF_INS_JMP:
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = JUMP (0);
				break;
			case BPF_INS_JEQ:
			case BPF_INS_JGT:
			case BPF_INS_JGE:
			case BPF_INS_JSET:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = JUMP (1);
				op->fail = (insn->detail->bpf.op_count == 3) ? JUMP (2) : addr + insn->size;
				break;
			case BPF_INS_JNE: ///< eBPF only
			case BPF_INS_JSGT: ///< eBPF only
			case BPF_INS_JSGE: ///< eBPF only
			case BPF_INS_JLT: ///< eBPF only
			case BPF_INS_JLE: ///< eBPF only
			case BPF_INS_JSLT: ///< eBPF only
			case BPF_INS_JSLE: ///< eBPF only
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = JUMP (2);
				op->fail = addr + insn->size;
				break;
			case BPF_INS_CALL: ///< eBPF only
				op->type = R_ANAL_OP_TYPE_CALL;
				break;
			case BPF_INS_EXIT: ///< eBPF only
				op->type = R_ANAL_OP_TYPE_TRAP;
				break;
			case BPF_INS_RET:
				op->type = R_ANAL_OP_TYPE_RET;
				break;
			case BPF_INS_TAX:
			case BPF_INS_TXA:
				op->type = R_ANAL_OP_TYPE_MOV;
				break;
			case BPF_INS_ADD:
				op->type = R_ANAL_OP_TYPE_ADD;
				esil_binary_op_32 (op, OP_SRC0, OP_DST, "+", ebpf);
				break;
			case BPF_INS_ADD64:
				op->type = R_ANAL_OP_TYPE_ADD;
				esil_binary_op_64 (op, OP_SRC0, OP_DST, "+");
				break;
			case BPF_INS_SUB:
				op->type = R_ANAL_OP_TYPE_SUB;
				esil_binary_op_32 (op, OP_SRC0, OP_DST, "-", ebpf);
				break;
			case BPF_INS_SUB64:
				op->type = R_ANAL_OP_TYPE_SUB;
				esil_binary_op_64 (op, OP_SRC0, OP_DST, "-");
				break;
			case BPF_INS_MUL:
				op->type = R_ANAL_OP_TYPE_MUL;
				esil_binary_op_32 (op, OP_SRC0, OP_DST, "*", ebpf);
				break;
			case BPF_INS_MUL64:
				op->type = R_ANAL_OP_TYPE_MUL;
				esil_binary_op_64 (op, OP_SRC0, OP_DST, "*");
				break;
			case BPF_INS_DIV:
				op->type = R_ANAL_OP_TYPE_DIV;
				esil_binary_op_32 (op, OP_SRC0, OP_DST, "/", ebpf);
				break;
			case BPF_INS_DIV64:
				op->type = R_ANAL_OP_TYPE_DIV;
				esil_binary_op_64 (op, OP_SRC0, OP_DST, "/");
				break;
			case BPF_INS_MOD:
				op->type = R_ANAL_OP_TYPE_DIV;
				esil_binary_op_32 (op, OP_SRC0, OP_DST, "%", ebpf);
				break;
			case BPF_INS_MOD64:
				op->type = R_ANAL_OP_TYPE_DIV;
				esil_binary_op_64 (op, OP_SRC0, OP_DST, "%");
				break;
			case BPF_INS_OR:
				op->type = R_ANAL_OP_TYPE_OR;
				esil_binary_op_32 (op, OP_SRC0, OP_DST, "|", ebpf);
				break;
			case BPF_INS_OR64:
				op->type = R_ANAL_OP_TYPE_OR;
				esil_binary_op_64 (op, OP_SRC0, OP_DST, "|");
				break;
			case BPF_INS_AND:
				op->type = R_ANAL_OP_TYPE_AND;
				esil_binary_op_32 (op, OP_SRC0, OP_DST, "&", ebpf);
				break;
			case BPF_INS_AND64:
				op->type = R_ANAL_OP_TYPE_AND;
				esil_binary_op_64 (op, OP_SRC0, OP_DST, "&");
				break;
			case BPF_INS_LSH:
				op->type = R_ANAL_OP_TYPE_SHL;
				esil_binary_op_32 (op, OP_SRC0, OP_DST, "<<", ebpf);
				break;
			case BPF_INS_LSH64:
				op->type = R_ANAL_OP_TYPE_SHL;
				esil_binary_op_64 (op, OP_SRC0, OP_DST, "<<");
				break;
			case BPF_INS_RSH:
				op->type = R_ANAL_OP_TYPE_SHR;
				esil_binary_op_32 (op, OP_SRC0, OP_DST, ">>", ebpf);
				break;
			case BPF_INS_RSH64:
				op->type = R_ANAL_OP_TYPE_SHR;
				esil_binary_op_64 (op, OP_SRC0, OP_DST, ">>");
				break;
			case BPF_INS_XOR:
				op->type = R_ANAL_OP_TYPE_XOR;
				esil_binary_op_32 (op, OP_SRC0, OP_DST, "^", ebpf);
				break;
			case BPF_INS_XOR64:
				op->type = R_ANAL_OP_TYPE_XOR;
				esil_binary_op_64 (op, OP_SRC0, OP_DST, "^");
				break;
			case BPF_INS_NEG:
			case BPF_INS_NEG64:
				op->type = R_ANAL_OP_TYPE_NOT;
				break;
			case BPF_INS_ARSH: ///< eBPF only
					   ///< ALU64: eBPF only
			case BPF_INS_ARSH64:
				op->type = R_ANAL_OP_TYPE_ADD;
				break;
			case BPF_INS_MOV: ///< eBPF only
			case BPF_INS_MOV64:
				op->type = R_ANAL_OP_TYPE_MOV;
				break;
				///< Byteswap: eBPF only
			case BPF_INS_LE16:
			case BPF_INS_LE32:
			case BPF_INS_LE64:
			case BPF_INS_BE16:
			case BPF_INS_BE32:
			case BPF_INS_BE64:
				op->type = R_ANAL_OP_TYPE_MOV;
				break;
				///< Load
			case BPF_INS_LDW: ///< eBPF only
			case BPF_INS_LDH:
			case BPF_INS_LDB:
			case BPF_INS_LDDW: ///< eBPF only: load 64-bit imm
				op->type = R_ANAL_OP_TYPE_MOV;
				break;
			case BPF_INS_LDXW: ///< eBPF only
			case BPF_INS_LDXH: ///< eBPF only
			case BPF_INS_LDXB: ///< eBPF only
			case BPF_INS_LDXDW: ///< eBPF only
				op->type = R_ANAL_OP_TYPE_LOAD;
				break;
				///< Store
			case BPF_INS_STW: ///< eBPF only
			case BPF_INS_STH: ///< eBPF only
			case BPF_INS_STB: ///< eBPF only
			case BPF_INS_STDW: ///< eBPF only
			case BPF_INS_STXW: ///< eBPF only
			case BPF_INS_STXH: ///< eBPF only
			case BPF_INS_STXB: ///< eBPF only
			case BPF_INS_STXDW: ///< eBPF only
			case BPF_INS_XADDW: ///< eBPF only
			case BPF_INS_XADDDW: ///< eBPF only
				op->type = R_ANAL_OP_TYPE_STORE;
				break;
			}
		}
		op->size = insn->size;
		op->id = insn->id;
		cs_free (insn, n);
	}
	return op->size;
}

static bool set_reg_profile (RAnal *anal) {
	if (anal->config->bits != 64) {
		return false;
	}
	const char *p =
		"=PC    pc\n"
		"=A0    r1\n"
		"=R0    r0\n"
		"=SP    sp\n"
		"gpr    z        .32 ?    0\n"
		"gpr    a        .32 0    0\n"
		"gpr    x        .32 4    0\n"
		"gpr    m[0]     .32 8    0\n"
		"gpr    m[1]     .32 12   0\n"
		"gpr    m[2]     .32 16   0\n"
		"gpr    m[3]     .32 20   0\n"
		"gpr    m[4]     .32 24   0\n"
		"gpr    m[5]     .32 28   0\n"
		"gpr    m[6]     .32 32   0\n"
		"gpr    m[7]     .32 36   0\n"
		"gpr    m[8]     .32 40   0\n"
		"gpr    m[9]     .32 44   0\n"
		"gpr    m[10]    .32 48   0\n"
		"gpr    m[11]    .32 52   0\n"
		"gpr    m[12]    .32 56   0\n"
		"gpr    m[13]    .32 60   0\n"
		"gpr    m[14]    .32 64   0\n"
		"gpr    m[15]    .32 68   0\n"
		"gpr    pc       .32 72   0\n"
		"gpr    sp       .32 76   0\n"
		"gpr    r0       .64 80   0\n" // eBPF registers are 64 bits
		"gpr    r1       .64 88   0\n"
		"gpr    r2       .64 96   0\n"
		"gpr    r3       .64 104  0\n"
		"gpr    r4       .64 112  0\n"
		"gpr    r5       .64 120  0\n"
		"gpr    r6       .64 128  0\n"
		"gpr    r7       .64 136  0\n"
		"gpr    r8       .64 144  0\n"
		"gpr    r9       .64 152  0\n";

	return r_reg_set_profile_string (anal->reg, p);
}

static int archinfo (RAnal *anal, int q) {
	const int bits = anal->config->bits;
	switch (q) {
	case R_ANAL_ARCHINFO_ALIGN:
	case R_ANAL_ARCHINFO_DATA_ALIGN:
		return 1;
	}
	// case R_ANAL_ARCHINFO_MAX_OP_SIZE:
	// case R_ANAL_ARCHINFO_MIN_OP_SIZE:
	return (bits == 64) ? 8 : 4;
}

RAnalPlugin r_anal_plugin_bpf_cs = {
	.name = "bpf",
	.desc = "Capstone BPF arch plugin",
	.license = "BSD",
	.author = "terorie",
	.esil = false, // TODO
	.arch = "bpf",
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.bits = 32 | 64,
	.archinfo = archinfo,
	.set_reg_profile = &set_reg_profile,
	.op = &analop,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_bpf_cs,
	.version = R2_VERSION
};
#endif

#else
RAnalPlugin r_anal_plugin_bpf_cs = { 0 };
#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.version = R2_VERSION
};
#endif
#endif
