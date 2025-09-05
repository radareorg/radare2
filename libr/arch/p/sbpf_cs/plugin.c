/* radare2 - LGPL - Copyright 2025 - Based on bpf_cs plugin, modified for Solana BPF */

#include <r_anal.h>
#include <r_esil.h>
#include <r_lib.h>
#include <r_arch.h>

#include <capstone/capstone.h>

#define SBPF_PROGRAM_ADDR 	0x100000000ULL
#define SBPF_STACK_ADDR 	0x200000000ULL
// Rust strings are not null-terminated
// We need to cap the string size to avoid reading garbage
#define SBPF_MAX_STRING_SIZE 0x100

#if CS_API_MAJOR >= 5

#define CSINC BPF
#define CSINC_MODE get_capstone_mode(as)

static int get_capstone_mode(RArchSession *as) {
	int mode = R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config)
		? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	// sBPF is always extended mode (64-bit)
	mode |= CS_MODE_BPF_EXTENDED;
	return mode;
}

#include "../capstone.inc.c"

#define OP(n) insn->detail->bpf.operands[n]
// the "& 0xffffffff" is for some weird CS bug in JMP
#define IMM(n) (insn->detail->bpf.operands[n].imm & UT32_MAX)
#define OPCOUNT insn->detail->bpf.op_count

// calculate jump address from immediate (sBPF uses 16-bit signed offsets in instruction units)
#define JUMP(n) (op->addr + insn->size + ((st16)(IMM(n) & 0xffff)) * 8)

// Solana syscall name mapping (retrieved from firedancer validator)
static struct {
	ut32 hash;
	const char *name;
} solana_syscalls[] = {
	{0xb6fc1a11U, "abort"},
	{0x686093bbU, "sol_panic_"},
	{0x207559bdU, "sol_log_"},
	{0x5c2a3178U, "sol_log_64_"},
	{0x52ba5096U, "sol_log_compute_units_"},
	{0x7ef088caU, "sol_log_pubkey"},
	{0x9377323cU, "sol_create_program_address"},
	{0x48504a38U, "sol_try_find_program_address"},
	{0x11f49d86U, "sol_sha256"},
	{0xd7793abbU, "sol_keccak256"},
	{0x17e40350U, "sol_secp256k1_recover"},
	{0x174c5122U, "sol_blake3"},
	{0xaa2607caU, "sol_curve_validate_point"},
	{0xdd1c41a6U, "sol_curve_group_op"},
	{0xd56b5fe9U, "sol_get_clock_sysvar"},
	{0x23a29a61U, "sol_get_epoch_schedule_sysvar"},
	{0xbf7188f6U, "sol_get_rent_sysvar"},
	{0x717cc4a3U, "sol_memcpy_"},
	{0x434371f8U, "sol_memmove_"},
	{0x5fdcde31U, "sol_memcmp_"},
	{0x3770fb22U, "sol_memset_"},
	{0xa22b9c85U, "sol_invoke_signed_c"},
	{0xd7449092U, "sol_invoke_signed_rust"},
	{0x83f00e8fU, "sol_alloc_free_"},
	{0xa226d3ebU, "sol_set_return_data"},
	{0x5d2245e4U, "sol_get_return_data"},
	{0x7317b434U, "sol_log_data"},
	{0xadb8efc8U, "sol_get_processed_sibling_instruction"},
	{0, NULL}
};

static const char *get_syscall_name(ut32 hash) {
	int i;
	for (i = 0; solana_syscalls[i].name; i++) {
		if (solana_syscalls[i].hash == hash) {
			return solana_syscalls[i].name;
		}
	}
	return NULL;
}

static void analop_esil(RArchSession *a, RAnalOp *op, cs_insn *insn, ut64 addr);
static void check_and_create_string_flag(RArchSession *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len);

static char *mnemonics(RArchSession *s, int id, bool json) {
	CapstonePluginData *cpd = (CapstonePluginData*)s->data;
	return r_arch_cs_mnemonics (s, cpd->cs_handle, id, json);
}

static bool decode(RArchSession *a, RAnalOp *op, RArchDecodeMask mask) {
	CapstonePluginData *cpd = (CapstonePluginData*)a->data;
	const ut8 *buf = op->bytes;
	const int len = op->size;
	op->size = 8;
	cs_insn *insn = NULL;
	int n = cs_disasm (cpd->cs_handle, (ut8*)buf, len, op->addr, 1, &insn);
	if (n < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
	} else {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			// Handle CALL instruction
			if (insn->id == BPF_INS_CALL && insn->detail && OPCOUNT > 0 && OP(0).type == BPF_OP_IMM) {
				st32 imm = IMM (0);
				// Check if this is a syscall first
				const char *syscall_name = get_syscall_name (imm);
				if (syscall_name) {
					op->mnemonic = r_str_newf ("call %s", syscall_name);
				} else {
					// PC-relative call
					st64 current_pc = op->addr / 8; 	 		// Current PC in instruction units
					st64 target_pc = current_pc + imm + 1;  	// Target PC in instruction units
					st64 target_addr = target_pc * 8;  			// Target address in bytes
					op->mnemonic = r_str_newf ("call 0x%"PFMT64x, (ut64)target_addr);
					// Set jump target for call instruction
					op->jump = target_addr;

					// Try to force function creation using hints
					op->hint.addr = target_addr;
					op->hint.jump = target_addr;

					// Mark operation to force function creation
					op->type = R_ANAL_OP_TYPE_CALL;
					op->family = R_ANAL_OP_FAMILY_CPU;
					op->size = insn->size;
				}
			} else {
				op->mnemonic = r_str_newf ("%s%s%s",
					insn->mnemonic,
					insn->op_str[0]? " ": "",
					insn->op_str);
			}
		}
		if (insn->detail) {
			switch (insn->id) {
#if CS_API_MAJOR > 5
			case BPF_INS_JAL:
#else
			case BPF_INS_JMP:
#endif
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
				if (a->config->bits == 32) {
					op->jump = JUMP (1);
					op->fail = (insn->detail->bpf.op_count == 3) ? JUMP (2) : op->addr + insn->size;
				} else {
					op->jump = JUMP (2);
					op->fail = op->addr + insn->size;
				}
				break;
			case BPF_INS_CALL: ///< eBPF only
				op->type = R_ANAL_OP_TYPE_CALL;
				// Enhanced call analysis for function detection
				if (OPCOUNT > 0 && OP(0).type == BPF_OP_IMM) {
					st32 imm = IMM(0);
					const char *syscall_name = get_syscall_name (imm);
					if (!syscall_name) {
						// PC-relative call - calculate target and force function creation
						st64 current_pc = op->addr / 8;
						st64 target_pc = current_pc + imm + 1;
						st64 target_addr = target_pc * 8;

						// Set jump target for call instruction
						op->jump = target_addr;

						// Set function hint
						op->hint.addr = target_addr;
						op->hint.jump = target_addr;

						// Mark this as a call to force function creation
						op->type = R_ANAL_OP_TYPE_CALL;
					}
				}
				break;
			case BPF_INS_EXIT: ///< eBPF only
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
				op->type = R_ANAL_OP_TYPE_MOV;
				if (OPCOUNT > 1 && OP (1).type == BPF_OP_IMM) {
					op->val = OP (1).imm;
				}
				break;
			case BPF_INS_LDDW:	///< eBPF only: load 64-bit imm
				op->type = R_ANAL_OP_TYPE_MOV;
				if (OPCOUNT > 1 && OP (1).type == BPF_OP_IMM) {
					op->val = OP (1).imm;
				} else if (insn->size == 16) { // lddw is a 16-byte instruction
					op->val = r_read_ble64 (insn->bytes + 8, 0) + IMM (0);
				}
				// Check if the loaded address might contain string data
				check_and_create_string_flag(a, op, op->val, buf + insn->size, len - insn->size);
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
			if (mask & R_ARCH_OP_MASK_ESIL) {
				analop_esil (a, op, insn, op->addr);
			}
		}
		op->size = insn->size;
		op->id = insn->id;
		cs_free (insn, n);
	}
	return true;
}

static ut32 detect_string_size_from_next_insn(RArchSession *a, RAnalOp *op, const ut8 *buf, int len, ut32 default_size) {
	if (!a || !a->data || !buf || len < 8) {
		return default_size;
	}
	CapstonePluginData *cpd = (CapstonePluginData*)a->data;
	if (!cpd || !cpd->cs_handle) {
		return default_size;
	}

	cs_insn *next_insn = NULL;
	ut64 next_addr = op->addr + op->size;
	int n = cs_disasm (cpd->cs_handle, buf, 8, next_addr, 1, &next_insn);

	if (n <= 0 || !next_insn) {
		return default_size;
	}

	ut32 string_size = default_size;

	// Check if it's a mov REG, IMM instruction
	bool is_mov_insn = (next_insn->id == BPF_INS_MOV || next_insn->id == BPF_INS_MOV64);
	bool has_detail = next_insn->detail && next_insn->detail->bpf.op_count > 1;

	if (is_mov_insn && has_detail) {
		bool is_reg_dest = next_insn->detail->bpf.operands[0].type == BPF_OP_REG;
		bool is_imm_src = next_insn->detail->bpf.operands[1].type == BPF_OP_IMM;
		if (is_reg_dest && is_imm_src) {
			ut32 imm_size = next_insn->detail->bpf.operands[1].imm;
			// Use the immediate value as string size if it's reasonable
			if (imm_size > 0 && imm_size <= SBPF_MAX_STRING_SIZE) {
				string_size = imm_size;
			}
		}
	}
	cs_free (next_insn, n);
	return string_size;
}

static void check_and_create_string_flag(RArchSession *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	if (!a || !a->arch) {
		return;
	}
	bool is_valid_program_range = false;
	// Check if it's in the main program range
	if (addr >= SBPF_PROGRAM_ADDR && addr < SBPF_STACK_ADDR) {
		is_valid_program_range = true;
	}
	if (!is_valid_program_range) {
		return;
	}

	op->ptr = addr;

	ut32 string_size = SBPF_MAX_STRING_SIZE;

	// check the next instruction(s) after a lddw instruction for a mov REG, IMM pattern
	string_size = detect_string_size_from_next_insn(a, op, buf, len, string_size);

	// Use the refptr field to indicate a fixed-size string reference
	op->refptr = string_size;

	op->hint.addr = addr;
	op->hint.type = R_ANAL_ADDR_HINT_TYPE_SIZE;
	op->hint.size = string_size;

	op->type |= R_ANAL_OP_TYPE_MEM;
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
void sbpf_alu(RArchSession *a, RAnalOp *op, cs_insn *insn, const char* operation, int bits) {
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
		if (OPCOUNT > 0) {
			switch (OP (0).type) {
			case BPF_OP_IMM:
				op->val = IMM (0);
				esilprintf (op, "%" PFMT64d ",%s=", IMM (0), operation);
				break;
			case BPF_OP_REG:
				op->val = IMM (1);
				esilprintf (op, "%" PFMT64d ",%s,%s=", IMM (1), REG (0), operation);
				break;
			default:
				R_LOG_ERROR ("oops");
				break;
			}
		} else {
			esilprintf (op, "x,a,%s=", operation);
		}
	}
}

void sbpf_load(RArchSession *a, RAnalOp *op, cs_insn *insn, char* reg, int size) {
	// For eBPF (64-bit mode), use proper register operands
	if (a->config->bits == 64 && OPCOUNT > 1 && OP(0).type == BPF_OP_REG && OP(1).type == BPF_OP_MEM) {
		esilprintf (op, "%d,%s,+,[%d],%s,=",
			OP(1).mem.disp, regname(OP(1).mem.base), size, REG(0));
	} else if (OPCOUNT > 0 && OP (0).type == BPF_OP_MMEM) { // cBPF
		esilprintf (op, "m[%d],%s,=", OP (0).mmem, reg);
	} else if (OPCOUNT > 0) {
		esilprintf (op, "%d,%s,+,[%d],%s,=",
			OP (0).mem.disp, regname(OP (0).mem.base), size, reg);
	}
}

void sbpf_store(RArchSession *a, RAnalOp *op, cs_insn *insn, char *reg, int size) {
	if (OPCOUNT > 0 && a->config->bits == 32) { // cBPF
		esilprintf (op, "%s,m[%d],=", reg, OP (0).mmem);
	} else if (OPCOUNT > 1 && OP(0).type == BPF_OP_MEM) { // eBPF
		if (OP (1).type == BPF_OP_IMM) {
			esilprintf (op, "%" PFMT64d ",%d,%s,+,=[%d]",
				IMM (1), OP (0).mem.disp, regname(OP (0).mem.base), size);
		} else if (OP (1).type == BPF_OP_REG) {
			esilprintf (op, "%s,%d,%s,+,=[%d]",
				REG (1), OP (0).mem.disp, regname(OP (0).mem.base), size);
		}
	}
}

void sbpf_jump(RArchSession *a, RAnalOp *op, cs_insn *insn, char *condition) {
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

#define ALU(c, b) sbpf_alu (a, op, insn, c, b)
#define LOAD(c, s) sbpf_load (a, op, insn, c, s)
#define STORE(c, s) sbpf_store (a, op, insn, c, s)
#define CJMP(c) sbpf_jump (a, op, insn, c)

static void analop_esil(RArchSession *a, RAnalOp *op, cs_insn *insn, ut64 addr) {
	switch (insn->id) {
#if CS_API_MAJOR > 5
	case BPF_INS_JAL:
#else
	case BPF_INS_JMP:
#endif
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
		if (OPCOUNT > 0 && OP(0).type == BPF_OP_IMM) {
			st32 imm = IMM(0);
			const char *syscall_name = get_syscall_name (imm);
			if (syscall_name) {
				// This is a syscall - trigger trap instead of setting PC
				esilprintf(op, "8,pc,+,sp,=[8],8,sp,-=,%" PFMT64d ",TRAP", (ut64)imm);
			} else {
				// This is a regular function call - use PC-relative addressing
				st64 current_pc = op->addr / 8;
				st64 target_pc = current_pc + imm + 1;
				st64 target_addr = target_pc * 8;
				esilprintf(op, "8,pc,+,sp,=[8],8,sp,-=,0x%" PFMT64x ",pc,=", target_addr);
			}
		} else {
			esilprintf (op, "pc,sp,=[8],8,sp,-=,0x%" PFMT64x ",$", IMM (0));
		}
		break;
	case BPF_INS_EXIT: ///< eBPF only
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
		if (OPCOUNT > 1 && OP(0).type == BPF_OP_REG && OP(1).type == BPF_OP_IMM) {
			// Get the full 64-bit immediate value from the 16-byte instruction
			ut64 val = r_read_ble64((insn->bytes)+8, 0) + IMM(1);
			esilprintf (op, "%" PFMT64d ",%s,=", val, REG(0));
		}
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
		if (OPCOUNT > 1 && OP(0).type == BPF_OP_REG && OP(1).type == BPF_OP_MEM) {
			esilprintf (op, "%d,%s,+,[4],%s,=",
				OP(1).mem.disp, regname(OP(1).mem.base), REG(0));
		}
		break;
	case BPF_INS_LDXW:	///< eBPF only
		if (OPCOUNT > 1 && OP(0).type == BPF_OP_REG && OP(1).type == BPF_OP_MEM) {
			esilprintf (op, "%d,%s,+,[4],%s,=",
				OP(1).mem.disp, regname(OP(1).mem.base), REG(0));
		}
		break;
	case BPF_INS_LDH:
		if (OPCOUNT > 1 && OP(0).type == BPF_OP_REG && OP(1).type == BPF_OP_MEM) {
			esilprintf (op, "%d,%s,+,[2],%s,=",
				OP(1).mem.disp, regname(OP(1).mem.base), REG(0));
		}
		break;
	case BPF_INS_LDXH:	///< eBPF only
		if (OPCOUNT > 1 && OP(0).type == BPF_OP_REG && OP(1).type == BPF_OP_MEM) {
			esilprintf (op, "%d,%s,+,[2],%s,=",
				OP(1).mem.disp, regname(OP(1).mem.base), REG(0));
		}
		break;
	case BPF_INS_LDB:
		if (OPCOUNT > 1 && OP(0).type == BPF_OP_REG && OP(1).type == BPF_OP_MEM) {
			esilprintf (op, "%d,%s,+,[1],%s,=",
				OP(1).mem.disp, regname(OP(1).mem.base), REG(0));
		}
		break;
	case BPF_INS_LDXB:	///< eBPF only
		if (OPCOUNT > 1 && OP(0).type == BPF_OP_REG && OP(1).type == BPF_OP_MEM) {
			esilprintf (op, "%d,%s,+,[1],%s,=",
				OP(1).mem.disp, regname(OP(1).mem.base), REG(0));
		}
		break;
	case BPF_INS_LDXDW:	///< eBPF only
		if (OPCOUNT > 1 && OP(0).type == BPF_OP_REG && OP(1).type == BPF_OP_MEM) {
			esilprintf (op, "%d,%s,+,[8],%s,=",
				OP(1).mem.disp, regname(OP(1).mem.base), REG(0));
		}
		break;
		///< Store
	case BPF_INS_STW:	///< eBPF only
		if (OPCOUNT > 1 && OP(0).type == BPF_OP_MEM && OP(1).type == BPF_OP_IMM) {
			esilprintf (op, "%" PFMT64d ",%d,%s,+,=[4]",
				IMM(1), OP(0).mem.disp, regname(OP(0).mem.base));
		}
		break;
	case BPF_INS_STXW:	///< eBPF only
		if (OPCOUNT > 1 && OP(0).type == BPF_OP_MEM && OP(1).type == BPF_OP_REG) {
			esilprintf (op, "%s,%d,%s,+,=[4]",
				REG(1), OP(0).mem.disp, regname(OP(0).mem.base));
		}
		break;
	case BPF_INS_STH:	///< eBPF only
		if (OPCOUNT > 1 && OP(0).type == BPF_OP_MEM && OP(1).type == BPF_OP_IMM) {
			esilprintf (op, "%" PFMT64d ",%d,%s,+,=[2]",
				IMM(1), OP(0).mem.disp, regname(OP(0).mem.base));
		}
		break;
	case BPF_INS_STXH:	///< eBPF only
		if (OPCOUNT > 1 && OP(0).type == BPF_OP_MEM && OP(1).type == BPF_OP_REG) {
			esilprintf (op, "%s,%d,%s,+,=[2]",
				REG(1), OP(0).mem.disp, regname(OP(0).mem.base));
		}
		break;
	case BPF_INS_STB:	///< eBPF only
		if (OPCOUNT > 1 && OP(0).type == BPF_OP_MEM && OP(1).type == BPF_OP_IMM) {
			esilprintf (op, "%" PFMT64d ",%d,%s,+,=[1]",
				IMM(1), OP(0).mem.disp, regname(OP(0).mem.base));
		}
		break;
	case BPF_INS_STXB:	///< eBPF only
		if (OPCOUNT > 1 && OP(0).type == BPF_OP_MEM && OP(1).type == BPF_OP_REG) {
			esilprintf (op, "%s,%d,%s,+,=[1]",
				REG(1), OP(0).mem.disp, regname(OP(0).mem.base));
		}
		break;
	case BPF_INS_STDW:	///< eBPF only
		if (OPCOUNT > 1 && OP(0).type == BPF_OP_MEM && OP(1).type == BPF_OP_IMM) {
			esilprintf (op, "%" PFMT64d ",%d,%s,+,=[8]",
				IMM(1), OP(0).mem.disp, regname(OP(0).mem.base));
		}
		break;
	case BPF_INS_STXDW:	///< eBPF only
		if (OPCOUNT > 1 && OP(0).type == BPF_OP_MEM && OP(1).type == BPF_OP_REG) {
			esilprintf (op, "%s,%d,%s,+,=[8]",
				REG(1), OP(0).mem.disp, regname(OP(0).mem.base));
		}
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

static char *regs(RArchSession *as) {
	const char *p =
		"=PC    pc\n"
		"=A0    r1\n"
		"=A1    r2\n"
		"=A2    r3\n"
		"=A3    r4\n"
		"=R0    r0\n"
		"=SP    sp\n"
		"=BP    r10\n"
		"=SN    r0\n"
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
		"gpr    r0       .64 80   0\n"
		"gpr    r1       .64 88   0\n"
		"gpr    r2       .64 96   0\n"
		"gpr    r3       .64 104  0\n"
		"gpr    r4       .64 112  0\n"
		"gpr    r5       .64 120  0\n"
		"gpr    r6       .64 128  0\n"
		"gpr    r7       .64 136  0\n"
		"gpr    r8       .64 144  0\n"
		"gpr    r9       .64 152  0\n"
		"gpr    r10      .64 160  0\n"
		"gpr    sp       .64 160  0\n"
		"gpr    tmp      .64 168  0\n";
	return strdup (p);
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
		// R_ARCH_INFO_MINOPSZ
	case R_ARCH_INFO_MINOP_SIZE:
		return 8;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 16; // LDDW is 16 bytes
	case R_ARCH_INFO_INVOP_SIZE:
		return 8;
	case R_ARCH_INFO_CODE_ALIGN:
		return 8;
	case R_ARCH_INFO_DATA_ALIGN:
		return 1;
	}
	return 0;
}

static bool init(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	if (s->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}
	s->data = R_NEW0 (CapstonePluginData);
	CapstonePluginData *cpd = (CapstonePluginData*)s->data;
	if (!r_arch_cs_init (s, &cpd->cs_handle)) {
		R_LOG_ERROR ("Cannot initialize capstone");
		R_FREE (s->data);
		return false;
	}
	return true;
}

static bool fini(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	CapstonePluginData *cpd = (CapstonePluginData*)s->data;
	cs_close (&cpd->cs_handle);
	R_FREE (s->data);
	return true;
}

const RArchPlugin r_arch_plugin_sbpf_cs = {
	.meta = {
		.name = "sbpf",
		.desc = "Capstone-based Solana Berkeley Packet Filtering bytecode",
		.license = "BSD-3-Clause",
		.author = "ulexec,radare,terori,",
	},
	.arch = "sbpf",
	.endian = R_SYS_ENDIAN_LITTLE,
	.bits = R_SYS_BITS_PACK1(64),
	.info = archinfo,
	.regs = &regs,
	.decode = &decode,
	.mnemonics = &mnemonics,
	.init = init,
	.fini = fini
};

#else
const RArchPlugin r_arch_plugin_sbpf_cs = {0};
#endif // CS_API_MAJOR

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
#if CS_API_MAJOR >= 5
	.data = &r_arch_plugin_sbpf_cs,
#endif
	.version = R2_VERSION
};
#endif
