/* radare - LGPL - Copyright 2015 - qnix */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../../asm/arch/riscv/riscv-opc.c"
#include "../../asm/arch/riscv/riscv.h"

#define NARGS_SEQ(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,\
_14,_15,_16,_17,_18,_19,_20, N,...) N
#define NARGS(...) NARGS_SEQ(__VA_ARGS__,20,19,18,17,16,15,14,\
13,12,11,10,9,8,7,6,5,4,3,2,1)

static int init = 0;

static int _is_any(int n, const char *str, ...) {
	char *cur;
	va_list va;
	va_start (va, str);

	while (n-- > 0) {
		cur = va_arg (va, char *);
		if (!strcmp (str, cur)) {
			va_end (va);
			return 1;
		}
	}

	va_end (va);

	return 0;
}

static struct riscv_opcode *get_opcode (insn_t word) {
	struct riscv_opcode *op = NULL;
	static const struct riscv_opcode *riscv_hash[OP_MASK_OP + 1] = {0};

#define OP_HASH_IDX(i) ((i) & (riscv_insn_length (i) == 2 ? 0x3 : OP_MASK_OP))

	if (!init) {
		for (op=riscv_opcodes; op < &riscv_opcodes[NUMOPCODES]; op++) {
			if (!riscv_hash[OP_HASH_IDX (op->match)]) {
				riscv_hash[OP_HASH_IDX (op->match)] = op;
			}
		}
		init = 1;
	}

	return (struct riscv_opcode *)riscv_hash[OP_HASH_IDX (word)];
}

static int riscv_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len)
{
	const int no_alias = 1;
	struct riscv_opcode *o = NULL;
	insn_t word = 0;
	int xlen = anal->bits;

	op->size = 4;
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;

	memcpy (&word, data, 4);
	o = get_opcode (word);
	if (o == NULL) {
		return op->size;
	}

	for(; o < &riscv_opcodes[NUMOPCODES]; o++) {
		if ( !(o->match_func)(o, word) ) continue;
		if ( no_alias && (o->pinfo & INSN_ALIAS) ) continue;
		if ( isdigit (o->subset[0]) && atoi (o->subset) != xlen) continue;
		else break;
	}
#define is_any(...) _is_any(NARGS(__VA_ARGS__), o->name, __VA_ARGS__)

// branch/jumps/calls/rets
	if (is_any ("jal")) {
		// decide wether it's ret or call
		int rd = (word >> OP_SH_RD) & OP_MASK_RD;
		op->type = (rd == 0) ? R_ANAL_OP_TYPE_RET : R_ANAL_OP_TYPE_CALL;
		op->jump = EXTRACT_UJTYPE_IMM (word) + addr;
		op->fail = addr + 4;
	} else if(is_any ("jr")) {
		op->type = R_ANAL_OP_TYPE_JMP;
	} else if(is_any ("j", "jump")) {
		op->type = R_ANAL_OP_TYPE_JMP;
	} else if(is_any ("jalr", "ret")) { // ?
		op->type = R_ANAL_OP_TYPE_UCALL;
	} else if(is_any ("beqz", "beq", "blez", "bgez", "ble",
			"bleu", "bge", "bgeu", "bltz", "bgtz", "blt", "bltu",
			"bgt", "bgtu", "bnez", "bne")) {
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = EXTRACT_SBTYPE_IMM (word) + addr;
		op->fail = addr + 4;
// math
	} else if(is_any ("addi", "addw", "addiw", "add")) {
		op->type = R_ANAL_OP_TYPE_ADD;
	} else if(is_any ("subi", "subw", "sub")) {
		op->type = R_ANAL_OP_TYPE_SUB;
	} else if(is_any ("xori", "xor")) {
		op->type = R_ANAL_OP_TYPE_XOR;
	} else if(is_any ("andi", "and")) {
		op->type = R_ANAL_OP_TYPE_AND;
	} else if(is_any ("ori", "or")) {
		op->type = R_ANAL_OP_TYPE_OR;
	} else if(is_any ("not")) {
		op->type = R_ANAL_OP_TYPE_NOT;
	} else if(is_any ("mul", "mulh", "mulhu", "mulhsu", "mulw")) {
		op->type = R_ANAL_OP_TYPE_MUL;
	} else if(is_any ("div", "divu", "divw", "divuw")) {
		op->type = R_ANAL_OP_TYPE_DIV;
// memory
	} else if (is_any ("sd", "sb", "sh", "sw")) {
		op->type = R_ANAL_OP_TYPE_STORE;
	} else if (is_any ("ld", "lw", "lwu", "lui", "li",
			"lb", "lbu", "lh", "lhu", "la", "lla")) {
		op->type = R_ANAL_OP_TYPE_LOAD;
	}

	return op->size;
}

#if 0
static int set_reg_profile(RAnal *anal) {
	char *p =
		"=pc	pc\n"
		"=sp	sp\n"

		"gpr	a	.8	0	0\n"
		"gpr	x	.8	1	0\n"
		"gpr	y	.8	2	0\n"

		"gpr	flags	.8	3	0\n"
		"gpr	C	.1	.24	0\n"
		"gpr	Z	.1	.25	0\n"
		"gpr	I	.1	.26	0\n"
		"gpr	D	.1	.27	0\n"
		// bit 4 (.28) is NOT a real flag.
		// "gpr	B	.1	.28	0\n"
		// bit 5 (.29) is not used
		"gpr	V	.1	.30	0\n"
		"gpr	N	.1	.31	0\n"

		"gpr	sp	.8	4	0\n"

		"gpr	pc	.16	5	0\n";

	return r_reg_set_profile_string (anal->reg, p);
}
#endif

struct r_anal_plugin_t r_anal_plugin_riscv = {
	.name = "riscv",
	.desc = "RISC-V analysis plugin",
	.license = "GPL",
	.arch = "riscv",
	.bits = 16|32,
	.op = &riscv_op,
	//.set_reg_profile = &set_reg_profile,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_riscv,
	.version = R2_VERSION
};
#endif
