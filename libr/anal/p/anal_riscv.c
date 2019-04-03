/* radare - LGPL - Copyright 2015 - qnix */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../../asm/arch/riscv/riscv-opc.c"
#include "../../asm/arch/riscv/riscv.h"

static bool init = false;

#define is_any(...) _is_any(o->name, __VA_ARGS__, NULL)
static bool _is_any(const char *str, ...) {
	char *cur;
	va_list va;
	va_start (va, str);
	while (true) {
		cur = va_arg (va, char *);
		if (!cur) {
			break;
		}
		if (!strcmp (str, cur)) {
			va_end (va);
			return true;
		}
	}
	va_end (va);
	return false;
}

static struct riscv_opcode *get_opcode (insn_t word) {
	struct riscv_opcode *op = NULL;
	static const struct riscv_opcode *riscv_hash[OP_MASK_OP + 1] = {0};

#define OP_HASH_IDX(i) ((i) & (riscv_insn_length (i) == 2 ? 3 : OP_MASK_OP))

	if (!init) {
		int i;
		for (i=0;i<OP_MASK_OP+1; i++) {
			riscv_hash[i] = 0;
		}
		for (op=riscv_opcodes; op < &riscv_opcodes[NUMOPCODES]; op++) {
			if (!riscv_hash[OP_HASH_IDX (op->match)]) {
				riscv_hash[OP_HASH_IDX (op->match)] = op;
			}
		}
		init = true;
	}
	return (struct riscv_opcode *)riscv_hash[OP_HASH_IDX (word)];
}

static int riscv_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	const int no_alias = 1;
	struct riscv_opcode *o = NULL;
	ut64 word = 0;
	int xlen = anal->bits;

	op->size = 4;
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;

	if (len >= sizeof (ut64)) {
		word = r_read_ble64 (data, anal->big_endian);
	} else if (len >= sizeof (ut32)) {
		word = r_read_ble16 (data, anal->big_endian);
	} else {
		op->type = R_ANAL_OP_TYPE_ILL;
		return -1;
	}

	o = get_opcode (word);
	if (word == UT64_MAX) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return -1;
	}
	if (!o || !o->name) {
		return op->size;
	}

	for (; o < &riscv_opcodes[NUMOPCODES]; o++) {
		// XXX ASAN segfault if ( !(o->match_func)(o, word) ) continue;
		if (no_alias && (o->pinfo & INSN_ALIAS)) {
			continue;
		}
		if (isdigit ((ut8)(o->subset[0])) && atoi (o->subset) != xlen) {
			continue;
		} else {
			break;
		}
	}

	if (!o || !o->name) {
		return -1;
	}
// branch/jumps/calls/rets
	if (is_any ("jal")) {
		// decide wether it's ret or call
		int rd = (word >> OP_SH_RD) & OP_MASK_RD;
		op->type = (rd == 0) ? R_ANAL_OP_TYPE_RET: R_ANAL_OP_TYPE_CALL;
		op->jump = EXTRACT_UJTYPE_IMM (word) + addr;
		op->fail = addr + 4;
	} else if (is_any ("jr")) {
		op->type = R_ANAL_OP_TYPE_JMP;
	} else if (is_any ("j", "jump")) {
		op->type = R_ANAL_OP_TYPE_JMP;
	} else if (is_any ("jalr", "ret")) { // ?
		op->type = R_ANAL_OP_TYPE_UCALL;
	} else if (is_any ("ret")) {
		op->type = R_ANAL_OP_TYPE_RET;
	} else if (is_any ("beqz", "beq", "blez", "bgez", "ble",
			"bleu", "bge", "bgeu", "bltz", "bgtz", "blt", "bltu",
			"bgt", "bgtu", "bnez", "bne")) {
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = EXTRACT_SBTYPE_IMM (word) + addr;
		op->fail = addr + 4;
// math
	} else if (is_any ("addi", "addw", "addiw", "add", "auipc")) {
		op->type = R_ANAL_OP_TYPE_ADD;
	} else if (is_any ("subi", "subw", "sub")) {
		op->type = R_ANAL_OP_TYPE_SUB;
	} else if (is_any ("xori", "xor")) {
		op->type = R_ANAL_OP_TYPE_XOR;
	} else if (is_any ("andi", "and")) {
		op->type = R_ANAL_OP_TYPE_AND;
	} else if (is_any ("ori", "or")) {
		op->type = R_ANAL_OP_TYPE_OR;
	} else if (is_any ("not")) {
		op->type = R_ANAL_OP_TYPE_NOT;
	} else if (is_any ("mul", "mulh", "mulhu", "mulhsu", "mulw")) {
		op->type = R_ANAL_OP_TYPE_MUL;
	} else if (is_any ("div", "divu", "divw", "divuw")) {
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

static char *get_reg_profile(RAnal *anal) {
	const char *p = NULL;
	switch (anal->bits) {
	case 32: p =
		"=PC	pc\n"
		"=SP	sp\n" // ABI: stack pointer
		"=LR	ra\n" // ABI: return address
		"=BP	s0\n" // ABI: frame pointer

		"gpr	pc	.32	0	0\n"
		// RV32I regs (ABI names)
		// From user-Level ISA Specification, section 2.1
		// "zero" has been left out as it ignores writes and always reads as zero
		"gpr	ra	.32	4	0\n" // =x1
		"gpr	sp	.32	8	0\n" // =x2
		"gpr	gp	.32	12	0\n" // =x3
		"gpr	tp	.32	16	0\n" // =x4
		"gpr	t0	.32	20	0\n" // =x5
		"gpr	t1	.32	24	0\n" // =x6
		"gpr	t2	.32	28	0\n" // =x7
		"gpr	s0	.32	32	0\n" // =x8
		"gpr	s1	.32	36	0\n" // =x9
		"gpr	a0	.32	40	0\n" // =x10
		"gpr	a1	.32	44	0\n" // =x11
		"gpr	a2	.32	48	0\n" // =x12
		"gpr	a3	.32	52	0\n" // =x13
		"gpr	a4	.32	56	0\n" // =x14
		"gpr	a5	.32	60	0\n" // =x15
		"gpr	a6	.32	64	0\n" // =x16
		"gpr	a7	.32	68	0\n" // =x17
		"gpr	s2	.32	72	0\n" // =x18
		"gpr	s3	.32	76	0\n" // =x19
		"gpr	s4	.32	80	0\n" // =x20
		"gpr	s5	.32	84	0\n" // =x21
		"gpr	s6	.32	88	0\n" // =x22
		"gpr	s7	.32	92	0\n" // =x23
		"gpr	s8	.32	96	0\n" // =x24
		"gpr	s9	.32	100	0\n" // =x25
		"gpr	s10	.32	104	0\n" // =x26
		"gpr	s11	.32	108	0\n" // =x27
		"gpr	t3	.32	112	0\n" // =x28
		"gpr	t4	.32	116	0\n" // =x29
		"gpr	t5	.32	120	0\n" // =x30
		"gpr	t6	.32	124	0\n" // =x31
		// RV32F/D regs (ABI names)
		// From user-Level ISA Specification, section 8.1 and 9.1
		"gpr	ft0	.64	128	0\n" // =f0
		"gpr	ft1	.64	136	0\n" // =f1
		"gpr	ft2	.64	144	0\n" // =f2
		"gpr	ft3	.64	152	0\n" // =f3
		"gpr	ft4	.64	160	0\n" // =f4
		"gpr	ft5	.64	168	0\n" // =f5
		"gpr	ft6	.64	176	0\n" // =f6
		"gpr	ft7	.64	184	0\n" // =f7
		"gpr	fs0	.64	192	0\n" // =f8
		"gpr	fs1	.64	200	0\n" // =f9
		"gpr	fa0	.64	208	0\n" // =f10
		"gpr	fa1	.64	216	0\n" // =f11
		"gpr	fa2	.64	224	0\n" // =f12
		"gpr	fa3	.64	232	0\n" // =f13
		"gpr	fa4	.64	240	0\n" // =f14
		"gpr	fa5	.64	248	0\n" // =f15
		"gpr	fa6	.64	256	0\n" // =f16
		"gpr	fa7	.64	264	0\n" // =f17
		"gpr	fs2	.64	272	0\n" // =f18
		"gpr	fs3	.64	280	0\n" // =f19
		"gpr	fs4	.64	288	0\n" // =f20
		"gpr	fs5	.64	296	0\n" // =f21
		"gpr	fs6	.64	304	0\n" // =f22
		"gpr	fs7	.64	312	0\n" // =f23
		"gpr	fs8	.64	320	0\n" // =f24
		"gpr	fs9	.64	328	0\n" // =f25
		"gpr	fs10	.64	336	0\n" // =f26
		"gpr	fs11	.64	344	0\n" // =f27
		"gpr	ft8	.64	352	0\n" // =f28
		"gpr	ft9	.64	360	0\n" // =f29
		"gpr	ft10	.64	368	0\n" // =f30
		"gpr	ft11	.64	376	0\n" // =f31
		"gpr	fcsr	.32	384	0\n"
		"flg	nx	.1	3072	0\n"
		"flg	uf	.1	3073	0\n"
		"flg	of	.1	3074	0\n"
		"flg	dz	.1	3075	0\n"
		"flg	nv	.1	3076	0\n"
		"flg	frm	.3	3077	0\n"
		;

		break;
	case 64: p =
		"=PC	pc\n"
		"=SP	sp\n" // ABI: stack pointer
		"=LR	ra\n" // ABI: return address
		"=BP	s0\n" // ABI: frame pointer

		"gpr	pc	.64	0	0\n"
		// RV64I regs (ABI names)
		// From user-Level ISA Specification, section 2.1 and 4.1
		// "zero" has been left out as it ignores writes and always reads as zero
		"gpr	ra	.64	8	0\n" // =x1
		"gpr	sp	.64	16	0\n" // =x2
		"gpr	gp	.64	24	0\n" // =x3
		"gpr	tp	.64	32	0\n" // =x4
		"gpr	t0	.64	40	0\n" // =x5
		"gpr	t1	.64	48	0\n" // =x6
		"gpr	t2	.64	56	0\n" // =x7
		"gpr	s0	.64	64	0\n" // =x8
		"gpr	s1	.64	72	0\n" // =x9
		"gpr	a0	.64	80	0\n" // =x10
		"gpr	a1	.64	88	0\n" // =x11
		"gpr	a2	.64	96	0\n" // =x12
		"gpr	a3	.64	104	0\n" // =x13
		"gpr	a4	.64	112	0\n" // =x14
		"gpr	a5	.64	120	0\n" // =x15
		"gpr	a6	.64	128	0\n" // =x16
		"gpr	a7	.64	136	0\n" // =x17
		"gpr	s2	.64	144	0\n" // =x18
		"gpr	s3	.64	152	0\n" // =x19
		"gpr	s4	.64	160	0\n" // =x20
		"gpr	s5	.64	168	0\n" // =x21
		"gpr	s6	.64	176	0\n" // =x22
		"gpr	s7	.64	184	0\n" // =x23
		"gpr	s8	.64	192	0\n" // =x24
		"gpr	s9	.64	200	0\n" // =x25
		"gpr	s10	.64	208	0\n" // =x26
		"gpr	s11	.64	216	0\n" // =x27
		"gpr	t3	.64	224	0\n" // =x28
		"gpr	t4	.64	232	0\n" // =x29
		"gpr	t5	.64	240	0\n" // =x30
		"gpr	t6	.64	248	0\n" // =x31
		// RV64F/D regs (ABI names)
		"gpr	ft0	.64	256	0\n" // =f0
		"gpr	ft1	.64	264	0\n" // =f1
		"gpr	ft2	.64	272	0\n" // =f2
		"gpr	ft3	.64	280	0\n" // =f3
		"gpr	ft4	.64	288	0\n" // =f4
		"gpr	ft5	.64	296	0\n" // =f5
		"gpr	ft6	.64	304	0\n" // =f6
		"gpr	ft7	.64	312	0\n" // =f7
		"gpr	fs0	.64	320	0\n" // =f8
		"gpr	fs1	.64	328	0\n" // =f9
		"gpr	fa0	.64	336	0\n" // =f10
		"gpr	fa1	.64	344	0\n" // =f11
		"gpr	fa2	.64	352	0\n" // =f12
		"gpr	fa3	.64	360	0\n" // =f13
		"gpr	fa4	.64	368	0\n" // =f14
		"gpr	fa5	.64	376	0\n" // =f15
		"gpr	fa6	.64	384	0\n" // =f16
		"gpr	fa7	.64	392	0\n" // =f17
		"gpr	fs2	.64	400	0\n" // =f18
		"gpr	fs3	.64	408	0\n" // =f19
		"gpr	fs4	.64	416	0\n" // =f20
		"gpr	fs5	.64	424	0\n" // =f21
		"gpr	fs6	.64	432	0\n" // =f22
		"gpr	fs7	.64	440	0\n" // =f23
		"gpr	fs8	.64	448	0\n" // =f24
		"gpr	fs9	.64	456	0\n" // =f25
		"gpr	fs10	.64	464	0\n" // =f26
		"gpr	fs11	.64	472	0\n" // =f27
		"gpr	ft8	.64	480	0\n" // =f28
		"gpr	ft9	.64	488	0\n" // =f29
		"gpr	ft10	.64	496	0\n" // =f30
		"gpr	ft11	.64	504	0\n" // =f31
		"gpr	fcsr	.32	512	0\n"
		"flg	nx	.1	4096	0\n"
		"flg	uf	.1	4097	0\n"
		"flg	of	.1	4098	0\n"
		"flg	dz	.1	4099	0\n"
		"flg	nv	.1	4100	0\n"
		"flg	frm	.3	4101	0\n"
		;

		break;
	}
	return (p && *p)? strdup (p): NULL;
}

RAnalPlugin r_anal_plugin_riscv = {
	.name = "riscv",
	.desc = "RISC-V analysis plugin",
	.license = "GPL",
	.arch = "riscv",
	.bits = 32|64,
	.op = &riscv_op,
	.get_reg_profile = &get_reg_profile,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_riscv,
	.version = R2_VERSION
};
#endif
