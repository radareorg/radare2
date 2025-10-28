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

// sBPF Version Detection (from ELF e_flags field at offset 0x30)
#define SBPF_V0 0
#define SBPF_V1 1
#define SBPF_V2 2
#define SBPF_V3 3
#define SBPF_VERSION_COUNT 4
#define E_FLAGS_OFFSET 0x30
#define E_FLAGS_SBPF_V2 0x20U

// sBPF v1
#define SBPF_INS_ADD64_IMM 		0x07
#define SBPF_INS_CALLX			0x8d
// sBPF v2
#define SBPF_INS_STQ			0x97
#define SBPF_INS_LDXQ			0x9c
#define SBPF_INS_STXQ			0x9f
#define SBPF_INS_LDXB			0x2c
#define SBPF_INS_STXB			0x2f
#define SBPF_INS_STB			0x27
#define SBPF_INS_STH			0x37
#define SBPF_INS_LDXH			0x3c
#define SBPF_INS_STXH			0x3f
#define SBPF_INS_STW			0x87
#define SBPF_INS_LDXW			0x8c
#define SBPF_INS_LMUL32_IMM		0x86
#define SBPF_INS_STXW			0x8f
#define SBPF_INS_UHMUL64_IMM	0x36
#define SBPF_INS_UDIV32_IMM 	0x46
#define SBPF_INS_UDIV64_IMM 	0x56
#define SBPF_INS_UREM32_IMM 	0x66
#define SBPF_INS_UHMUL64_REG 	0x3e
#define SBPF_INS_LMUL64_IMM 	0x96
#define SBPF_INS_LMUL64_REG 	0x9e
#define SBPF_INS_HOR64			0xf7
// sBPF v3
#define SBPF_INS_EXIT_V3		0x9d

// Global variable to cache the detected sBPF version
static ut32 g_sbpf_version = SBPF_V0;
static bool g_version_detected = false;

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

// Solana syscall name mapping
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

static void print_sbpf_version(void) {
	const char *version_str = "unknown";
	switch (g_sbpf_version) {
	case SBPF_V0: version_str = "V0"; break;
	case SBPF_V1: version_str = "V1"; break;
	case SBPF_V2: version_str = "V2"; break;
	case SBPF_V3: version_str = "V3"; break;
	}
	R_LOG_INFO ("[sBPF] Detected sBPF version: %s\n", version_str);
}

static ut32 detect_sbpf_version(RArchSession *a) {
	// Return cached version if already detected
	if (g_version_detected) {
		return g_sbpf_version;
	}

	// Get version from RBin's info->abi which was set by the ELF parser
	if (!a || !a->arch || !a->arch->binb.bin) {
		return SBPF_V0;
	}

	RBin *bin = a->arch->binb.bin;
	if (!bin->cur || !bin->cur->bo || !bin->cur->bo->info || !bin->cur->bo->info->abi) {
		// Info not available yet, will try again later
		return SBPF_V0;
	}

	const char *abi = bin->cur->bo->info->abi;

	// Parse the version from the ABI string set by the ELF parser
	if (!strcmp (abi, "sbpfv0")) {
		g_sbpf_version = SBPF_V0;
	} else if (!strcmp (abi, "sbpfv1")) {
		g_sbpf_version = SBPF_V1;
	} else if (!strcmp (abi, "sbpfv2")) {
		g_sbpf_version = SBPF_V2;
	} else if (!strcmp (abi, "sbpfv3")) {
		g_sbpf_version = SBPF_V3;
	} else {
		// Default to v0 for unknown/missing ABI
		g_sbpf_version = SBPF_V0;
	}

	g_version_detected = true;
	print_sbpf_version ();

	return g_sbpf_version;
}

static void analop_esil(RArchSession *a, RAnalOp *op, cs_insn *insn, ut64 addr);

static char *mnemonics(RArchSession *s, int id, bool json) {
	CapstonePluginData *cpd = (CapstonePluginData*)s->data;
	return r_arch_cs_mnemonics (s, cpd->cs_handle, id, json);
}

static bool decode(RArchSession *a, RAnalOp *op, RArchDecodeMask mask) {
	CapstonePluginData *cpd = (CapstonePluginData*)a->data;
	const ut8 *buf = op->bytes;
	const int len = op->size;
	op->size = 8;

	// Detect sBPF version once at the start
	ut32 sbpf_version = detect_sbpf_version (a);

	cs_insn *insn = NULL;
	int n = cs_disasm (cpd->cs_handle, (ut8*)buf, len, op->addr, 1, &insn);
	if (n < 1) {
		// Check for instructions that Capstone doesn't decode correctly
		// In sBPF V3 opcodes for exit and syscall seems that are swapped
		if (len >= 8 && buf[0] == SBPF_INS_EXIT_V3 && sbpf_version >= SBPF_V3) {
			op->type = R_ANAL_OP_TYPE_RET;
			op->mnemonic = r_str_newf ("exit");
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_STQ && sbpf_version >= SBPF_V2) {
			// Opcode 0x97 = STQ (store quad word / 64-bit immediate to memory)
			ut8 dst_reg = buf[1] & 0x0F;
			st16 offset = r_read_le16 (buf + 2);
			st32 imm = r_read_le32 (buf + 4);

			op->type = R_ANAL_OP_TYPE_STORE;
			op->ptr = offset;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				if (offset >= 0) {
					op->mnemonic = r_str_newf ("stq [r%d+0x%x], 0x%x", dst_reg, offset, imm);
				} else {
					op->mnemonic = r_str_newf ("stq [r%d-0x%x], 0x%x", dst_reg, -offset, imm);
				}
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_LDXQ && sbpf_version >= SBPF_V2) {
			// Opcode 0x9c = LDXQ (load quad word / 64-bit from memory)
			ut8 dst_reg = buf[1] & 0x0F;
			ut8 src_reg = (buf[1] >> 4) & 0x0F;
			st16 offset = r_read_le16 (buf + 2);

			op->type = R_ANAL_OP_TYPE_LOAD;
			op->ptr = offset;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				if (offset >= 0) {
					op->mnemonic = r_str_newf ("ldxq r%d, [r%d+0x%x]", dst_reg, src_reg, offset);
				} else {
					op->mnemonic = r_str_newf ("ldxq r%d, [r%d-0x%x]", dst_reg, src_reg, -offset);
				}
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_STXQ && sbpf_version >= SBPF_V2) {
			// Opcode 0x9f = STXQ (store quad word / 64-bit register to memory)
			ut8 dst_reg = buf[1] & 0x0F;
			ut8 src_reg = (buf[1] >> 4) & 0x0F;
			st16 offset = r_read_le16 (buf + 2);

			op->type = R_ANAL_OP_TYPE_STORE;
			op->ptr = offset;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				if (offset >= 0) {
					op->mnemonic = r_str_newf ("stxq [r%d+0x%x], r%d", dst_reg, offset, src_reg);
				} else {
					op->mnemonic = r_str_newf ("stxq [r%d-0x%x], r%d", dst_reg, -offset, src_reg);
				}
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_LDXB && sbpf_version >= SBPF_V2) {
			// Opcode 0x2c = LDXB (load byte from memory to register) - v2+
			// Despite being class 0x7 in bit encoding, this is a memory operation in sBPF
			ut8 dst_reg = buf[1] & 0x0F;
			ut8 src_reg = (buf[1] >> 4) & 0x0F;
			st16 offset = r_read_le16 (buf + 2);

			op->type = R_ANAL_OP_TYPE_LOAD;
			op->ptr = offset;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				if (offset >= 0) {
					op->mnemonic = r_str_newf ("ldxb r%d, [r%d+0x%x]", dst_reg, src_reg, offset);
				} else {
					op->mnemonic = r_str_newf ("ldxb r%d, [r%d-0x%x]", dst_reg, src_reg, -offset);
				}
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_STXB && sbpf_version >= SBPF_V2) {
			// Opcode 0x2f = STXB (store byte from register to memory) - v2+
			// Despite being class 0x7 in bit encoding, this is a memory operation in sBPF
			ut8 dst_reg = buf[1] & 0x0F;
			ut8 src_reg = (buf[1] >> 4) & 0x0F;
			st16 offset = r_read_le16 (buf + 2);

			op->type = R_ANAL_OP_TYPE_STORE;
			op->ptr = offset;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				if (offset >= 0) {
					op->mnemonic = r_str_newf ("stxb [r%d+0x%x], r%d", dst_reg, offset, src_reg);
				} else {
					op->mnemonic = r_str_newf ("stxb [r%d-0x%x], r%d", dst_reg, -offset, src_reg);
				}
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_STB && sbpf_version >= SBPF_V2) {
			// Opcode 0x27 = STB (store byte immediate to memory) - v2+
			// Despite being class 0x7 in bit encoding, this is a memory operation in sBPF
			ut8 dst_reg = buf[1] & 0x0F;
			st16 offset = r_read_le16 (buf + 2);
			st32 imm = r_read_le32 (buf + 4);

			op->type = R_ANAL_OP_TYPE_STORE;
			op->ptr = offset;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				if (offset >= 0) {
					op->mnemonic = r_str_newf ("stb [r%d+0x%x], 0x%x", dst_reg, offset, imm & 0xFF);
				} else {
					op->mnemonic = r_str_newf ("stb [r%d-0x%x], 0x%x", dst_reg, -offset, imm & 0xFF);
				}
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_STH && sbpf_version >= SBPF_V2) {
			// Opcode 0x37 = STH (store half-word immediate) - v2+
			ut8 dst_reg = buf[1] & 0x0F;
			st16 offset = r_read_le16 (buf + 2);
			st32 imm = r_read_le32 (buf + 4);

			op->type = R_ANAL_OP_TYPE_STORE;
			op->ptr = offset;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				if (offset >= 0) {
					op->mnemonic = r_str_newf ("sth [r%d+0x%x], 0x%x", dst_reg, offset, imm & 0xFFFF);
				} else {
					op->mnemonic = r_str_newf ("sth [r%d-0x%x], 0x%x", dst_reg, -offset, imm & 0xFFFF);
				}
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_LDXH && sbpf_version >= SBPF_V2) {
			// Opcode 0x3c = LDXH (load half-word from register) - v2+
			ut8 dst_reg = buf[1] & 0x0F;
			ut8 src_reg = (buf[1] >> 4) & 0x0F;
			st16 offset = r_read_le16 (buf + 2);

			op->type = R_ANAL_OP_TYPE_LOAD;
			op->ptr = offset;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				if (offset >= 0) {
					op->mnemonic = r_str_newf ("ldxh r%d, [r%d+0x%x]", dst_reg, src_reg, offset);
				} else {
					op->mnemonic = r_str_newf ("ldxh r%d, [r%d-0x%x]", dst_reg, src_reg, -offset);
				}
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_STXH && sbpf_version >= SBPF_V2) {
			// Opcode 0x3f = STXH (store half-word from register) - v2+
			ut8 dst_reg = buf[1] & 0x0F;
			ut8 src_reg = (buf[1] >> 4) & 0x0F;
			st16 offset = r_read_le16 (buf + 2);

			op->type = R_ANAL_OP_TYPE_STORE;
			op->ptr = offset;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				if (offset >= 0) {
					op->mnemonic = r_str_newf ("stxh [r%d+0x%x], r%d", dst_reg, offset, src_reg);
				} else {
					op->mnemonic = r_str_newf ("stxh [r%d-0x%x], r%d", dst_reg, -offset, src_reg);
				}
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_STW && sbpf_version >= SBPF_V2) {
			// Opcode 0x87 = STW (store word immediate) - v2+
			ut8 dst_reg = buf[1] & 0x0F;
			st16 offset = r_read_le16 (buf + 2);
			st32 imm = r_read_le32 (buf + 4);

			op->type = R_ANAL_OP_TYPE_STORE;
			op->ptr = offset;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				if (offset >= 0) {
					op->mnemonic = r_str_newf ("stw [r%d+0x%x], 0x%x", dst_reg, offset, imm);
				} else {
					op->mnemonic = r_str_newf ("stw [r%d-0x%x], 0x%x", dst_reg, -offset, imm);
				}
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_LDXW && sbpf_version >= SBPF_V2) {
			// Opcode 0x8c = LDXW (load word from register) - v2+
			ut8 dst_reg = buf[1] & 0x0F;
			ut8 src_reg = (buf[1] >> 4) & 0x0F;
			st16 offset = r_read_le16 (buf + 2);

			op->type = R_ANAL_OP_TYPE_LOAD;
			op->ptr = offset;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				if (offset >= 0) {
					op->mnemonic = r_str_newf ("ldxw r%d, [r%d+0x%x]", dst_reg, src_reg, offset);
				} else {
					op->mnemonic = r_str_newf ("ldxw r%d, [r%d-0x%x]", dst_reg, src_reg, -offset);
				}
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_LMUL32_IMM && sbpf_version >= SBPF_V2) {
			// Opcode 0x86 = LMUL32_IMM (lower half of 32×32 multiply with immediate) - v2+
			ut8 dst_reg = buf[1] & 0x0F;
			st32 imm = r_read_le32 (buf + 4);

			op->type = R_ANAL_OP_TYPE_MUL;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = r_str_newf ("lmul32 r%d, 0x%x", dst_reg, imm);
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_STXW && sbpf_version >= SBPF_V2) {
			// Opcode 0x8f = STXW (store word from register) - v2+
			ut8 dst_reg = buf[1] & 0x0F;
			ut8 src_reg = (buf[1] >> 4) & 0x0F;
			st16 offset = r_read_le16 (buf + 2);

			op->type = R_ANAL_OP_TYPE_STORE;
			op->ptr = offset;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				if (offset >= 0) {
					op->mnemonic = r_str_newf ("stxw [r%d+0x%x], r%d", dst_reg, offset, src_reg);
				} else {
					op->mnemonic = r_str_newf ("stxw [r%d-0x%x], r%d", dst_reg, -offset, src_reg);
				}
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_UHMUL64_IMM && sbpf_version >= SBPF_V2) {
			// Opcode 0x36 = UHMUL64_IMM (upper half of unsigned 64×64 multiply with immediate) - v2+
			ut8 dst_reg = buf[1] & 0x0F;
			st32 imm = r_read_le32 (buf + 4);

			op->type = R_ANAL_OP_TYPE_MUL;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = r_str_newf ("uhmul64 r%d, 0x%x", dst_reg, imm);
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_UDIV32_IMM && sbpf_version >= SBPF_V2) {
			// Opcode 0x46 = UDIV32_IMM (unsigned 32-bit divide by immediate) - v2+
			ut8 dst_reg = buf[1] & 0x0F;
			st32 imm = r_read_le32 (buf + 4);

			op->type = R_ANAL_OP_TYPE_DIV;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = r_str_newf ("udiv32 r%d, 0x%x", dst_reg, imm);
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_UDIV64_IMM && sbpf_version >= SBPF_V2) {
			// Opcode 0x56 = UDIV64_IMM (unsigned 64-bit divide by immediate) - v2+
			ut8 dst_reg = buf[1] & 0x0F;
			st32 imm = r_read_le32 (buf + 4);

			op->type = R_ANAL_OP_TYPE_DIV;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = r_str_newf ("udiv64 r%d, 0x%x", dst_reg, imm);
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_UREM32_IMM && sbpf_version >= SBPF_V2) {
			// Opcode 0x66 = UREM32_IMM (unsigned 32-bit remainder by immediate) - v2+
			ut8 dst_reg = buf[1] & 0x0F;
			st32 imm = r_read_le32 (buf + 4);

			op->type = R_ANAL_OP_TYPE_MOD;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = r_str_newf ("urem32 r%d, 0x%x", dst_reg, imm);
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_UHMUL64_REG && sbpf_version >= SBPF_V2) {
			// Opcode 0x3e = UHMUL64_REG (upper half of unsigned 64×64 multiply) - v2+
			ut8 dst_reg = buf[1] & 0x0F;
			ut8 src_reg = (buf[1] >> 4) & 0x0F;

			op->type = R_ANAL_OP_TYPE_MUL;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = r_str_newf ("uhmul64 r%d, r%d", dst_reg, src_reg);
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_LMUL64_IMM && sbpf_version >= SBPF_V2) {
			// Opcode 0x96 = LMUL64_IMM (lower half of 64×64 multiply with immediate) - v2+
			ut8 dst_reg = buf[1] & 0x0F;
			st32 imm = r_read_le32 (buf + 4);

			op->type = R_ANAL_OP_TYPE_MUL;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = r_str_newf ("lmul64 r%d, 0x%x", dst_reg, imm);
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_LMUL64_REG && sbpf_version >= SBPF_V2) {
			// Opcode 0x9e = LMUL64_REG (lower half of signed 64×64 multiply) - v2+
			ut8 dst_reg = buf[1] & 0x0F;
			ut8 src_reg = (buf[1] >> 4) & 0x0F;

			op->type = R_ANAL_OP_TYPE_MUL;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = r_str_newf ("lmul64 r%d, r%d", dst_reg, src_reg);
			}
			return true;
		} else if (len >= 8 && buf[0] == SBPF_INS_HOR64 && sbpf_version >= SBPF_V2) {
			// Opcode 0xf7 = HOR64 (horizontal or) - v2+ only
			ut8 dst_reg = buf[1] & 0x0F;
			st32 imm = r_read_le32 (buf + 4);

			op->type = R_ANAL_OP_TYPE_OR;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = r_str_newf ("hor64 r%d, 0x%x", dst_reg, imm);
			}
		} else if (len >= 8 && buf[0] == SBPF_INS_ADD64_IMM && sbpf_version >= SBPF_V1) {
			// Opcode 0x07 = ADD64_IMM (usually used with r10 for dynamic stack frames in v1+)
			ut8 dst_reg = buf[1] & 0x0F;
			st32 imm = r_read_le32 (buf + 4);

			if (sbpf_version >= SBPF_V1 && (imm % 64) == 0) {
				// Valid stack frame allocation in v1+
				op->type = R_ANAL_OP_TYPE_ADD;
				if (mask & R_ARCH_OP_MASK_DISASM) {
					op->mnemonic = r_str_newf ("add64 r%d, 0x%x", dst_reg, imm);
				}
			} else {
				op->type = R_ANAL_OP_TYPE_ILL;
				if (mask & R_ARCH_OP_MASK_DISASM) {
					op->mnemonic = strdup ("invalid");
				}
			}
		}  else { 
			op->type = R_ANAL_OP_TYPE_ILL;
			if (mask & R_ARCH_OP_MASK_DISASM) {
				op->mnemonic = strdup ("invalid");
			}
		}
	} else {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			if (insn->id == BPF_INS_CALLX) {
				op->type = R_ANAL_OP_TYPE_UCALL;

				if (sbpf_version >= SBPF_V2) {
					// v2+: src field (SIMD-0174)
					ut8 src_reg = (buf[1] >> 4) & 0x0F;
					if (mask & R_ARCH_OP_MASK_DISASM) {
						op->mnemonic = r_str_newf ("callx r%d", src_reg);
					}
				} else {
					// v0/v1: imm field
					st32 reg_num = IMM (0);
					if (mask & R_ARCH_OP_MASK_DISASM) {
						op->mnemonic = r_str_newf ("callx r%d", reg_num);
					}
				}
			} else if (insn->id ==  BPF_INS_EXIT ) {
				if (sbpf_version >= SBPF_V3) {
					op->type = R_ANAL_OP_TYPE_CALL;
				
					st32 imm = r_read_le32 (buf + 4);
					const char *syscall_name = get_syscall_name (imm);
					if (syscall_name) {
						op->mnemonic = r_str_newf ("syscall %s", syscall_name);
					} else {
						op->mnemonic = r_str_newf ("syscall (invalid)");
					}
				} else {
					op->type = R_ANAL_OP_TYPE_RET;
					op->mnemonic = r_str_newf ("exit");
				}
			// Handle SUB instruction - operands swapped in v2+ (SIMD-0174)
			} else if ((insn->id == BPF_INS_SUB || insn->id == BPF_INS_SUB64) && insn->detail && OPCOUNT > 1) {
				const char *suffix = (insn->id == BPF_INS_SUB64) ? "64" : "";
				if (OP(1).type == BPF_OP_IMM && sbpf_version >= SBPF_V2) {
					// v2+: dst = imm - dst (swapped)
					op->mnemonic = r_str_newf ("sub%s r%d, 0x%x",
						suffix, OP(0).reg, (int)IMM(1));
				} else {
					// v0/v1: normal eBPF disassembly (dst = dst - src/imm)
					op->mnemonic = r_str_newf ("%s%s%s",
						insn->mnemonic,
						insn->op_str[0]? " ": "",
						insn->op_str);
				}
			// Handle LDDW instruction - disabled in v2+ (SIMD-0173)
			} else if (insn->id == BPF_INS_LDDW) {
				if (sbpf_version >= SBPF_V2) {
					op->mnemonic = r_str_newf ("%s%s%s ; DISABLED in v%d",
						insn->mnemonic,
						insn->op_str[0]? " ": "",
						insn->op_str,
						sbpf_version);
				} else {
					op->mnemonic = r_str_newf ("%s%s%s",
						insn->mnemonic,
						insn->op_str[0]? " ": "",
						insn->op_str);
				}
			// Handle CALL instruction
			} else if (insn->id == BPF_INS_CALL && insn->detail && OPCOUNT > 0 && OP(0).type == BPF_OP_IMM) {
				st32 imm = IMM (0);
				// Check if this is a syscall first
				const char *syscall_name = get_syscall_name (imm);
				if (syscall_name) {
					op->mnemonic = r_str_newf ("syscall %s", syscall_name);
				} else {
					// PC-relative call
					st64 current_pc = op->addr / 8;        // Current PC in instruction units
					st64 target_pc = current_pc + imm + 1; // Target PC in instruction units
					st64 target_addr = target_pc * 8;      // Target address in bytes
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
				switch (insn->id) {
				case BPF_INS_JEQ:
				case BPF_INS_JGT:
				case BPF_INS_JGE:
				case BPF_INS_JSET:
				case BPF_INS_JNE:
				case BPF_INS_JSGT:
				case BPF_INS_JSGE:
				case BPF_INS_JLT:
				case BPF_INS_JLE:
				case BPF_INS_JSLT:
				case BPF_INS_JSLE:
					{
						char *opstr = strdup (insn->op_str);
						char *comma = strchr (opstr, ',');
						if (comma) {
							comma = strchr (comma + 1, ',');
							if (comma) {
								*comma = 0;
							}
						}
						op->mnemonic = r_str_newf ("%s %s, 0x%08"PFMT64x,
								insn->mnemonic, opstr, JUMP (2));
						free (opstr);
					}
					break;
#if CS_VERSION_MAJOR > 5
				case BPF_INS_JAL:
#else
				case BPF_INS_JMP:
#endif
					op->mnemonic = r_str_newf ("%s 0x%08"PFMT64x,
							insn->mnemonic, JUMP (0));
					break;
				default:
					op->mnemonic = r_str_newf ("%s%s%s",
							insn->mnemonic,
							insn->op_str[0]? " ": "",
							insn->op_str);
					break;
				}
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
			// case BPF_INS_EXIT: ///< eBPF only
			// 	//op->type = R_ANAL_OP_TYPE_TRAP;
			// 	op->type = R_ANAL_OP_TYPE_CALL;
			// 	op->type = R_ANAL_OP_TYPE_RET;
			// 	break;
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
				esilprintf (op, "8,pc,+,sp,=[8],8,sp,-=,%" PFMT64d ",TRAP", (ut64)imm);
			} else {
				// This is a regular function call - use PC-relative addressing
				st64 current_pc = op->addr / 8;
				st64 target_pc = current_pc + imm + 1;
				st64 target_addr = target_pc * 8;
				esilprintf (op, "8,pc,+,sp,=[8],8,sp,-=,0x%" PFMT64x ",pc,=", target_addr);
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
		"gpr    r0       .64 0    0\n"
		"gpr    r1       .64 8    0\n"
		"gpr    r2       .64 16   0\n"
		"gpr    r3       .64 24   0\n"
		"gpr    r4       .64 32   0\n"
		"gpr    r5       .64 40   0\n"
		"gpr    r6       .64 48   0\n"
		"gpr    r7       .64 56   0\n"
		"gpr    r8       .64 64   0\n"
		"gpr    r9       .64 72   0\n"
		"gpr    r10      .64 80   0\n"
		"gpr    sp       .64 80   0\n"
		"gpr    pc       .64 88   0\n";
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
		.desc = "Solana Berkeley Packet Filtering Bytecode",
		.license = "BSD-3-Clause",
		.author = "ulexec,radare",
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
