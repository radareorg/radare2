/* radare2 - LGPL - Copyright 2022 - terorie */

#include <r_anal.h>
#include <r_lib.h>

#include <capstone/capstone.h>

#if CS_API_MAJOR >= 5

#define OP(n) insn->detail->bpf.operands[n]
// the "& 0xffffffff" is for some weird CS bug in JMP
#define IMM(n) (insn->detail->bpf.operands[n].imm & 0xffffffff)
#define OPCOUNT insn->detail->bpf.op_count

// calculate jump address from immediate
#define JUMP(n) (addr + insn->size * (1 + IMM (n)))

void analop_esil(RAnal *a, RAnalOp *op, cs_insn *insn, ut64 addr);

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	static R_TH_LOCAL csh handle = 0;
	static R_TH_LOCAL int omode = -1;
	static R_TH_LOCAL int obits = 32;

	cs_insn *insn = NULL;
	int mode = (a->config->bits == 32)? CS_MODE_BPF_CLASSIC: CS_MODE_BPF_EXTENDED;
	int n, ret;
	mode |= (a->config->big_endian)? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
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
			R_LOG_ERROR ("Capstone failed: cs_open(CS_ARCH_BPF, %x, ...): %s\n", mode, cs_strerror (ret));
			handle = 0;
			return -1;
		}
	}

	cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	n = cs_disasm (handle, (ut8*)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ANAL_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
	} else {
		if (mask & R_ANAL_OP_MASK_DISASM) {
			op->mnemonic = r_str_newf ("%s%s%s",
				insn->mnemonic,
				insn->op_str[0]? " ": "",
				insn->op_str);
		}
		if (insn->detail) {
			switch (insn->id) {
			case BPF_INS_JMP:
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = JUMP (0);
				break;
			case BPF_INS_JEQ:
			case BPF_INS_JGT:
			case BPF_INS_JGE:
			case BPF_INS_JSET:
			case BPF_INS_JNE:	///< eBPF only
			case BPF_INS_JSGT:	///< eBPF only
			case BPF_INS_JSGE:	///< eBPF only
			case BPF_INS_JLT:	///< eBPF only
			case BPF_INS_JLE:	///< eBPF only
			case BPF_INS_JSLT:	///< eBPF only
			case BPF_INS_JSLE:	///< eBPF only
				op->type = R_ANAL_OP_TYPE_CJMP;
				if (mode == CS_MODE_BPF_CLASSIC) {
					op->jump = JUMP (1);
					op->fail = (insn->detail->bpf.op_count == 3) ? JUMP(2) : addr + insn->size;
				} else {
					op->jump = JUMP (2);
					op->fail = addr + insn->size;
				}
				break;
			case BPF_INS_CALL:	///< eBPF only
				op->type = R_ANAL_OP_TYPE_CALL;
				break;
			case BPF_INS_EXIT:	///< eBPF only
				//op->type = R_ANAL_OP_TYPE_TRAP;
				op->type = R_ANAL_OP_TYPE_RET;
				break;
			case BPF_INS_RET:
				op->type = R_ANAL_OP_TYPE_RET;
				break;
			case BPF_INS_TAX:
			case BPF_INS_TXA:
				op->type = R_ANAL_OP_TYPE_MOV;
				break;
			case BPF_INS_ADD:
			case BPF_INS_ADD64:
				op->type = R_ANAL_OP_TYPE_ADD;
				break;
			case BPF_INS_SUB:
			case BPF_INS_SUB64:
				op->type = R_ANAL_OP_TYPE_SUB;
				break;
			case BPF_INS_MUL:
			case BPF_INS_MUL64:
				op->type = R_ANAL_OP_TYPE_MUL;
				break;
			case BPF_INS_DIV:
			case BPF_INS_DIV64:
			case BPF_INS_MOD:
			case BPF_INS_MOD64:
				op->type = R_ANAL_OP_TYPE_DIV;
				break;
			case BPF_INS_OR:
			case BPF_INS_OR64:
				op->type = R_ANAL_OP_TYPE_OR;
				break;
			case BPF_INS_AND:
			case BPF_INS_AND64:
				op->type = R_ANAL_OP_TYPE_AND;
				break;
			case BPF_INS_LSH:
			case BPF_INS_LSH64:
				op->type = R_ANAL_OP_TYPE_SHL;
				break;
			case BPF_INS_RSH:
			case BPF_INS_RSH64:
				op->type = R_ANAL_OP_TYPE_SHR;
				break;
			case BPF_INS_XOR:
			case BPF_INS_XOR64:
				op->type = R_ANAL_OP_TYPE_XOR;
				break;
			case BPF_INS_NEG:
			case BPF_INS_NEG64:
				op->type = R_ANAL_OP_TYPE_NOT;
				break;
			case BPF_INS_ARSH:	///< eBPF only
						///< ALU64: eBPF only
			case BPF_INS_ARSH64:
				op->type = R_ANAL_OP_TYPE_ADD;
				break;
			case BPF_INS_MOV:	///< eBPF only
			case BPF_INS_MOV64:
			case BPF_INS_LDDW:	///< eBPF only: load 64-bit imm
				op->type = R_ANAL_OP_TYPE_MOV;
				if (OPCOUNT > 1 && OP (1).type == BPF_OP_IMM) {
					op->val = OP (1).imm;
				} else if (insn->size == 16) { // lddw wtf
					op->val = r_read_ble64((insn->bytes)+8, 0) + IMM (0);
				}
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
			case BPF_INS_LDW:	///< eBPF only
			case BPF_INS_LDH:
			case BPF_INS_LDB:
			case BPF_INS_LDXW:	///< eBPF only
			case BPF_INS_LDXH:	///< eBPF only
			case BPF_INS_LDXB:	///< eBPF only
			case BPF_INS_LDXDW:	///< eBPF only
				op->type = R_ANAL_OP_TYPE_LOAD;
				break;
				///< Store
			case BPF_INS_STW:	///< eBPF only
			case BPF_INS_STH:	///< eBPF only
			case BPF_INS_STB:	///< eBPF only
			case BPF_INS_STDW:	///< eBPF only
			case BPF_INS_STXW:	///< eBPF only
			case BPF_INS_STXH:	///< eBPF only
			case BPF_INS_STXB:	///< eBPF only
			case BPF_INS_STXDW:	///< eBPF only
			case BPF_INS_XADDW:	///< eBPF only
			case BPF_INS_XADDDW:	///< eBPF only
				op->type = R_ANAL_OP_TYPE_STORE;
				break;
			}

			if (mask & R_ANAL_OP_MASK_ESIL) {
				analop_esil(a, op, insn, addr);
			}
		}

		op->size = insn->size;
		op->id = insn->id;
		cs_free (insn, n);
	}
	return op->size;
}

static char* regname(uint8_t reg) {
	switch (reg) {
	///< cBPF
	case BPF_REG_A:
		return "a";
	case BPF_REG_X:
		return "x";

	///< eBPF
	case BPF_REG_R0:
		return "r0";
	case BPF_REG_R1:
		return "r1";
	case BPF_REG_R2:
		return "r2";
	case BPF_REG_R3:
		return "r3";
	case BPF_REG_R4:
		return "r4";
	case BPF_REG_R5:
		return "r5";
	case BPF_REG_R6:
		return "r6";
	case BPF_REG_R7:
		return "r7";
	case BPF_REG_R8:
		return "r8";
	case BPF_REG_R9:
		return "r9";
	case BPF_REG_R10:
		return "r10";

	default:
		return "0"; // hax
	}
}

#define REG(n) (regname(OP(n).reg))
 
void bpf_alu(RAnal *a, RAnalOp *op, cs_insn *insn, const char* operation, int bits) {
	if (OPCOUNT == 2 && a->config->bits == 64) { // eBPF
		if (bits == 64) {
			if (OP (1).type == BPF_OP_IMM) {
				op->val = IMM (1);
				esilprintf (op, "%" PFMT64d ",%s,%s=", IMM (1), REG (0), operation);
			} else {
				esilprintf (op, "%s,%s,%s=", REG (1), REG (0), operation);
			}
		} else {
			if (OP (1).type == BPF_OP_IMM) {
				op->val = IMM (1);
				esilprintf (op, "%" PFMT64d ",%s,0xffffffff,&,%s,0xffffffff,&,%s,=", 
					IMM (1), REG (0), operation, REG (0));
			} else {
				esilprintf (op, "%s,%s,0xffffffff,&,%s,0xffffffff,&,%s,=", 
					REG (1), REG (0), operation, REG (0));
			}
		}
	} else { // cBPF
		if (OPCOUNT > 0 && OP (0).type == BPF_OP_IMM) {
			op->val = IMM (0);
			esilprintf (op, "%" PFMT64d ",a,%s=", IMM (0), operation);
		} else { 
			esilprintf (op, "x,a,%s=", operation);
		}
	}
}

void bpf_load(RAnal *a, RAnalOp *op, cs_insn *insn, char* reg, int size) {
	if (OPCOUNT > 1 && OP (0).type == BPF_OP_REG) {
		esilprintf (op, "%d,%s,+,[%d],%s,=", 
			OP (1).mem.disp, regname(OP (1).mem.base), size, REG (0));
	} else if (OPCOUNT > 0 && OP (0).type == BPF_OP_MMEM) { // cBPF
		esilprintf (op, "m[%d],%s,=", OP (0).mmem, reg);
	} else if (OPCOUNT > 0) {
		esilprintf (op, "%d,%s,+,[%d],%s,=", 
			OP (0).mem.disp, regname(OP (0).mem.base), size, reg);
	}
}

void bpf_store(RAnal *a, RAnalOp *op, cs_insn *insn, char *reg, int size) {
	if (OPCOUNT > 0 && a->config->bits == 32) { // cBPF
		esilprintf (op, "%s,m[%d],=", reg, OP (0).mmem);
	} else if (OPCOUNT > 1) { // eBPF
		if (OP (1).type == BPF_OP_IMM) {
			esilprintf (op, "%" PFMT64d ",%d,%s,+,=[%d]", 
				IMM (1), OP (0).mem.disp, regname(OP (0).mem.base), size);
		} else {
			esilprintf (op, "%s,%d,%s,+,=[%d]", 
				REG (1), OP (0).mem.disp, regname(OP (0).mem.base), size);
		}
	}
}

void bpf_jump(RAnal *a, RAnalOp *op, cs_insn *insn, char *condition) {
	if (OPCOUNT > 0 && a->config->bits == 32) { // cBPF
		if (OP (0).type == BPF_OP_IMM) {
			esilprintf (op, "%" PFMT64d ",a,NUM,%s,?{,0x%" PFMT64x ",}{,0x%" PFMT64x ",},pc,=", 
				IMM (0), condition, op->jump, op->fail);
		} else {
			esilprintf (op, "x,NUM,a,NUM,%s,?{,0x%" PFMT64x ",}{,0x%" PFMT64x ",},pc,=", 
				condition, op->jump, op->fail);
		}
	} else if (OPCOUNT > 1) { // eBPF
		if (OP (1).type == BPF_OP_IMM) {
			esilprintf (op, "%" PFMT64d ",%s,%s,?{,0x%" PFMT64x ",pc,=,}", 
				IMM (1), REG (0), condition, op->jump);
		} else {
			esilprintf (op, "%s,%s,%s,?{,0x%" PFMT64x ",pc,=,}", 
				REG (1), REG (0), condition, op->jump);
		}
	}
}

#define ALU(c, b) bpf_alu(a, op, insn, c, b)
#define LOAD(c, s) bpf_load(a, op, insn, c, s)
#define STORE(c, s) bpf_store(a, op, insn, c, s)
#define CJMP(c) bpf_jump(a, op, insn, c)

void analop_esil(RAnal *a, RAnalOp *op, cs_insn *insn, ut64 addr) {
	switch (insn->id) {
	case BPF_INS_JMP:
		esilprintf (op, "0x%" PFMT64x ",pc,=", op->jump);
		break;
	case BPF_INS_JEQ:
		CJMP ("==,$z");
		break;
	case BPF_INS_JGT:
		CJMP ("==,63,$c,$z,|,!");
		break;
	case BPF_INS_JGE:
		CJMP ("==,63,$c,!");
		break;
	case BPF_INS_JSET:
		CJMP ("&");
		break;
	case BPF_INS_JNE:	///< eBPF only
		CJMP ("-");
		break;
	case BPF_INS_JSGT:	///< eBPF only
		CJMP (">");
		break;
	case BPF_INS_JSGE:	///< eBPF only
		CJMP (">=");
		break;
	case BPF_INS_JLT:	///< eBPF only
		CJMP ("==,63,$c");
		break;
	case BPF_INS_JSLT:	///< eBPF only
		CJMP ("<");
		break;
	case BPF_INS_JLE:	///< eBPF only
		CJMP ("==,63,$c,$z,|");
		break;
	case BPF_INS_JSLE:	///< eBPF only
		CJMP ("<=");
		break;
	case BPF_INS_CALL:	///< eBPF only
		// the call immediate is almost never used as an addr so its an INT
		// maybe this will change in the future once the relocs are added?
		esilprintf (op, "pc,sp,=[8],8,sp,-=,0x%" PFMT64x ",$", IMM (0)); 
		break;
	case BPF_INS_EXIT:	///< eBPF only
		esilprintf (op, "8,sp,+=,sp,[8],pc,="); 
		break;
	case BPF_INS_RET:
		// cBPF shouldnt really need the stack, but gonna leave it
		esilprintf (op, "%" PFMT64d ",r0,=,8,sp,+=,sp,[8],pc,=", IMM (0)); 
		break;
	case BPF_INS_TAX:
		esilprintf (op, "a,x,="); 
		break;
	case BPF_INS_TXA:
		esilprintf (op, "x,a,="); 
		break;
	case BPF_INS_ADD:
		ALU ("+", 32);
		break;
	case BPF_INS_ADD64:
		ALU ("+", 64);
		break;
	case BPF_INS_SUB:
		ALU ("-", 32);
		break;
	case BPF_INS_SUB64:
		ALU ("-", 64);
		break;
	case BPF_INS_MUL:
		ALU ("*", 32);
		break;
	case BPF_INS_MUL64:
		ALU ("*", 64);
		break;
	case BPF_INS_DIV:
		ALU ("/", 32);
		break;
	case BPF_INS_DIV64:
		ALU ("/", 64);
		break;
	case BPF_INS_MOD:
		ALU ("%", 32);
		break;
	case BPF_INS_MOD64:
		ALU ("%", 64);
		break;
	case BPF_INS_OR:
		ALU ("|", 32);
		break;
	case BPF_INS_OR64:
		ALU ("|", 64);
		break;
	case BPF_INS_AND:
		ALU ("&", 32);
		break;
	case BPF_INS_AND64:
		ALU ("&", 64);
		break;
	case BPF_INS_LSH:
		ALU ("<<", 32);
		break;
	case BPF_INS_LSH64:
		ALU ("<<", 64);
		break;
	case BPF_INS_RSH:
		ALU (">>", 32);
		break;
	case BPF_INS_RSH64:
		ALU (">>", 64);
		break;
	case BPF_INS_XOR:
		ALU ("^", 32);
		break;
	case BPF_INS_XOR64:
		ALU ("^", 64);
		break;
	case BPF_INS_NEG:
		if (OPCOUNT == 1) {
			esilprintf (op, "-1,%s,*,0xffffffff,&,%s,=", REG (0), REG (0));
			break;
		} else {
			esilprintf (op, "-1,a,*=");
			break;
		}
	case BPF_INS_NEG64:
		esilprintf (op, "-1,%s,*=", REG (0));
		break;
	case BPF_INS_ARSH:	///< eBPF only
		ALU (">>>>", 32);
		break;
	case BPF_INS_ARSH64:
		ALU (">>>>", 64);
		break;
	case BPF_INS_MOV:	///< eBPF only
		if (OP (1).type == BPF_OP_IMM) {
			// i already truncate IMM to 32 bits
			esilprintf (op, "%" PFMT64d ",%s,=", IMM (1), REG (0));
		} else {
			esilprintf (op, "%s,0xffffffff,&,%s,=", REG (1), REG (0));
		}
		break;
	case BPF_INS_LDDW:	///< eBPF only: load 64-bit imm
	{
		char *reg = regname(insn->bytes[1]+3);
		ut64 val = r_read_ble64((insn->bytes)+8, 0) + IMM (0); // wtf
		esilprintf (op, "%" PFMT64d ",%s,=", val, reg);
		break;
	}
	case BPF_INS_MOV64:
		if (OP (1).type == BPF_OP_IMM) {
			esilprintf (op, "%" PFMT64d ",%s,=", IMM (1), REG (0));
		} else {
			esilprintf (op, "%s,%s,=", REG (1), REG (0));
		}
		break;
		///< Byteswap: eBPF only
	case BPF_INS_LE16:
	case BPF_INS_LE32:
	case BPF_INS_LE64:
		break; // TODO we are assuming host is LE right now and maybe forever
	case BPF_INS_BE16:
	{
		const char *r0 = REG (0);
		esilprintf (op, "8,%s,>>,0xff,&,8,%s,<<,0xffff,&,|,%s,=", r0, r0, r0);
		break;
	}
	case BPF_INS_BE32:
	{
		const char *r0 = REG (0);
		esilprintf (op,
				"0xffffffff,%s,&=,"
				"24,0xff,%s,&,<<,tmp,=,"
				"16,0xff,8,%s,>>,&,<<,tmp,|=,"
				"8,0xff,16,%s,>>,&,<<,tmp,|=,"
				"0xff,24,%s,>>,&,tmp,|=,tmp,%s,=",
				r0, r0, r0, r0, r0, r0);
		
		break;
	}
	case BPF_INS_BE64:	
	{
		const char *r0 = REG (0);
		esilprintf (op,
			"56,0xff,%s,&,<<,tmp,=,"
			"48,0xff,8,%s,>>,&,<<,tmp,|=,"
			"40,0xff,16,%s,>>,&,<<,tmp,|=,"
			"32,0xff,24,%s,>>,&,<<,tmp,|=,"
			"24,0xff,32,%s,>>,&,<<,tmp,|=,"
			"16,0xff,40,%s,>>,&,<<,tmp,|=,"
			"8,0xff,48,%s,>>,&,<<,tmp,|=,"
			"0xff,56,%s,>>,&,tmp,|=,tmp,%s,=",
			r0, r0, r0, r0, r0, r0, r0, r0, r0);

		break;
	}
		///< Load
	case BPF_INS_LDW:	///< eBPF only
		LOAD ("a", 4);
		break;
	case BPF_INS_LDXW:	///< eBPF only
		LOAD ("x", 4);
		break;
	case BPF_INS_LDH:
		LOAD ("a", 2);
		break;
	case BPF_INS_LDXH:	///< eBPF only
		LOAD ("x", 2);
		break;
	case BPF_INS_LDB:
		LOAD ("a", 1);
		break;
	case BPF_INS_LDXB:	///< eBPF only
		LOAD ("x", 1);
		break;
	case BPF_INS_LDXDW:	///< eBPF only
		LOAD ("a", 8); // reg never used here 
		break;

		///< Store
	case BPF_INS_STW:	///< eBPF only
		STORE ("a", 4);
		break;
	case BPF_INS_STXW:	///< eBPF only
		STORE ("x", 4);
		break;
	case BPF_INS_STH:	///< eBPF only
	case BPF_INS_STXH:	///< eBPF only
		STORE ("a", 2);
		break;
	case BPF_INS_STB:	///< eBPF only
	case BPF_INS_STXB:	///< eBPF only
		STORE ("a", 1);
		break;
	case BPF_INS_STDW:	///< eBPF only
	case BPF_INS_STXDW:	///< eBPF only
		STORE ("a", 8);
		break;

	case BPF_INS_XADDW:	///< eBPF only
		esilprintf (op, "%s,0xffffffff,&,%d,%s,+,[4],DUP,%s,=,+,%d,%s,+,=[4]", 
			REG (1), OP (0).mem.disp, regname(OP (0).mem.base), 
			REG (1), OP (0).mem.disp, regname(OP (0).mem.base));

		break;
	case BPF_INS_XADDDW: ///< eBPF only
		esilprintf (op, "%s,NUM,%d,%s,+,[8],DUP,%s,=,+,%d,%s,+,=[8]", 
			REG (1), OP (0).mem.disp, regname(OP (0).mem.base), 
			REG (1), OP (0).mem.disp, regname(OP (0).mem.base));

		break;
	}
}

static bool set_reg_profile(RAnal *anal) {
	const char *p =
		"=PC    pc\n"
		"=A0    r1\n"
		"=A1    r2\n"
		"=A2    r3\n"
		"=A3    r4\n"
		"=R0    r0\n"
		"=SP    sp\n"
		"=BP    sp\n"
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
		"gpr    pc       .64 72   0\n"
		"gpr    sp       .64 80   0\n" // eBPF registers are 64 bits
		"gpr    r0       .64 88   0\n"
		"gpr    r1       .64 96   0\n"
		"gpr    r2       .64 104  0\n"
		"gpr    r3       .64 112  0\n"
		"gpr    r4       .64 120  0\n"
		"gpr    r5       .64 128  0\n"
		"gpr    r6       .64 136  0\n"
		"gpr    r7       .64 144  0\n"
		"gpr    r8       .64 152  0\n"
		"gpr    r9       .64 160  0\n"
		"gpr    r10      .64 168  0\n"
		"gpr    tmp      .64 176  0\n";



	return r_reg_set_profile_string (anal->reg, p);
}

static int archinfo(RAnal *anal, int q) {
	const int bits = anal->config->bits;
	switch (q) {
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		return 8;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return (bits == 64)? 16: 8;
	case R_ANAL_ARCHINFO_INV_OP_SIZE:
		return 8;
	case R_ANAL_ARCHINFO_ALIGN:
		return 8;
	case R_ANAL_ARCHINFO_DATA_ALIGN:
		return 1;
	}
	return 0;
}

RAnalPlugin r_anal_plugin_bpf_cs = {
	.name = "bpf",
	.desc = "Capstone BPF arch plugin",
	.license = "BSD",
	.author = "terorie, aemmitt",
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
RAnalPlugin r_anal_plugin_bpf_cs = {0};
#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.version = R2_VERSION
};
#endif
#endif // CS_API_MAJOR
