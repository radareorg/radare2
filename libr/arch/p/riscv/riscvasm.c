/* radare - Copyright 2021-2023 - pancake */
// inspired by https://www.csl.cornell.edu/courses/ece5745/handouts/ece5745-tinyrv-isa.txt

#include <r_util.h>

#if 0
// hello world writing into the serial console. that should compile
addi a0, x0, 0x68
li a1, 0x10000000
sb a0,(a1) # 'h'
loop:
j loop
#endif

static const char *const regs[33] = {
	"x0",
	"x1",
	"x2",
	"x3",
	"x4",
	"x5",
	"x6",
	"x7",
	"x8",
	"x9",
	"x10",
	"x11",
	"x12",
	"x13",
	"x14",
	"x15",
	"x16",
	"x17",
	"x18",
	"x19",
	"x20",
	"x21",
	"x22",
	"x23",
	"x24",
	"x25",
	"x26",
	"x27",
	"x28",
	"x29",
	"x30",
	"x31",
	NULL
};

// alias
static const char *const aregs[33] = {
	"zero",
	"ra",
	"sp",
	"gp",
	"tp",
	"t0",
	"t1",
	"t2",
	"s0",
	"s1",
	"a0",
	"a1",
	"a2",
	"a3",
	"a4",
	"a5",
	"a6",
	"a7",
	"s2",
	"s3",
	"s4",
	"s5",
	"s6",
	"s7",
	"s8",
	"s9",
	"s10",
	"s11",
	"t3",
	"t4",
	"t5",
	"t6",
	NULL
};

static struct {
	ut32 op;
	const char *name;
	char type;
	int args;
	int n;
	int x;
} ops[] = {
	{ 0x1, "c.nop", 'N', 0, 0, 0 }, // c.nop
	{ 0x13, "nop", 'N', 0, 0, 0 }, // addi x0, x0, 0 // 13010100 (mov sp, sp)
	{ 0x37, "lui", 'I', 2, 0, 0 }, // lui x0, 33
	// TODO { 0x37, "li", 'I', 2, 0, 0 }, // lui x0, 33
	{ 0x13, "addi", 'I', 3, 0, 0 }, // addi x1, x3, 33
	{ 0x7013, "andi", 'I', 3, 0, 0 }, // andi x1, x3, 33
	{ 0x6013, "ori", 'I', 3, 0, 0 }, // ori x1, x3, 33
	{ 0x4013, "xori", 'I', 3, 0, 0 }, // xori x1, x3, 33
	{ 0x17, "auipc", 'I', 2, 0, 0 }, // auipc t0, 0x0
	{ 0x2013, "slti", 'I', 3, 0, 0 },
	{ 0x3013, "sltiu", 'I', 3, 0, 0 },
	{ 0x1013, "slli", 'H', 3, 0, 0 },
	{ 0x5013, "srli", 'H', 3, 0, 0 },
	{ 0x40005013, "srai", 'H', 3, 0, 0 },
	{ 0x0003, "lb", 'I', 3, 0, 0 },
	{ 0x1003, "lh", 'I', 3, 0, 0 },
	{ 0x2003, "lw", 'I', 3, 0, 0 },
	{ 0x3003, "ld", 'I', 3, 0, 0 },
	{ 0x4003, "lbu", 'I', 3, 0, 0 },
	{ 0x5003, "lhu", 'I', 3, 0, 0 },
	{ 0x6003, "lwu", 'I', 3, 0, 0 },
	{ 0x0023, "sb", 'S', 3, 0, 0 },
	{ 0x1023, "sh", 'S', 3, 0, 0 },
	{ 0x2023, "sw", 'S', 3, 0, 0 },
	{ 0x3023, "sd", 'S', 3, 0, 0 },
	// Type 'J' not yet implemented
	{ 0x67, "jr", 'R', 3, 0, 0 }, // alias for jalr zero, rX
	{ 0x67, "jalr", 'R', 3, 0, 0 },
	{ 0 }
};

// lui
static int riscv_ri(ut8 *b, int op, int rt, int imm) {
	ut32 *insn = (ut32 *)b;
	*insn |= op;
	*insn |= (rt << 7);
	*insn |= ((ut32) (imm & 0xfffff) << 12);
	return 4;
}

static int riscv_rri(ut8 *b, ut32 op, int rs, int rt, int imm) {
	if (rs < 0 || rt < 0 || imm < -2048 || imm > 2047) {
		return -1;
	}
	ut32 *insn = (ut32 *)b;
	*insn |= op;
	*insn |= (rt << 7);
	*insn |= (rs << 15);
	*insn |= ((ut32)imm & 0xfff) << 20;
	return 4;
}

// sw rs2, imm(rs1)
static int riscv_store(ut8 *b, ut32 op, int rs1, int rs2, int imm) {
	if (rs1 < 0 || rs2 < 0 || imm < -2048 || imm > 2047) {
		return -1;
	}
	ut32 *insn = (ut32 *)b;
	*insn |= op;
	*insn |= ((ut32)imm & 0x1f) << 7;
	*insn |= rs1 << 15;
	*insn |= rs2 << 20;
	*insn |= (((ut32)imm >> 5) & 0x7f) << 25;
	return 4;
}

static int getreg(const char *p) {
	int n;
	if (R_STR_ISEMPTY (p)) {
		R_LOG_ERROR ("Missing argument");
		return -1;
	}
	/* check if it's a register */
	for (n = 0; regs[n]; n++) {
		if (!strcmp (p, regs[n])) {
			return n;
		}
	}
	/* check if it's a register alias */
	for (n = 0; aregs[n]; n++) {
		if (!strcmp (p, aregs[n])) {
			return n;
		}
	}
	/* try to convert it into a number */
	if (p[0] == '-') {
		n = (int)r_num_get (NULL, p + 1);
		n = -n;
	} else {
		n = (int)r_num_get (NULL, p);
	}
	if (n != 0 || p[0] == '0') {
		return n;
	}
	R_LOG_ERROR ("Invalid reg name (%s) at pos %d", p, n);
	return -1;
}

R_IPI int riscv_assemble(const char *str, ut64 pc, ut8 *out) {
	int i, hasp;
	char w0[32], w1[32], w2[32], w3[32];
	char *s = strdup (str);
	if (!s) {
		return -1;
	}

	r_str_replace_char (s, ',', ' ');
	hasp = r_str_replace_char (s, '(', ' ');
	r_str_replace_char (s, ')', ' ');

	*out = 0;
	*w0 = 0;
	*w1 = 0;
	*w2 = 0;
	*w3 = 0;
	sscanf (s, "%31s", w0);
	if (*w0) {
		// alias for 'j $$' which is an alias for 'addi pc, pc, -2
		if (!strcmp (w0, "jinf")) {
			out[0] = 0x01;
			out[1] = 0xa0;
			return 2;
		}
		for (i = 0; ops[i].name; i++) {
			if (strcmp (ops[i].name, w0)) {
				continue;
			}
			switch (ops[i].args) {
			case 3: sscanf (s, "%31s %31s %31s %31s", w0, w1, w2, w3); break;
			case 2: sscanf (s, "%31s %31s %31s", w0, w1, w2); break;
			case 1: sscanf (s, "%31s %31s", w0, w1); break;
			case 0: sscanf (s, "%31s", w0); break;
			}
			if (ops[i].type == 'R') {
				// jalr rs, jalr rd, rs, jalr rd, imm(rs), jr rs or jr imm(rs)
				const bool jr = !strcmp (w0, "jr");
				const int n = (*w1 != 0) + (*w2 != 0) + (*w3 != 0);
				int rd = jr? 0: 1;
				int rs = -1;
				int imm = 0;
				if (n == 1) {
					rs = getreg (w1);
				} else if (n == 2 && hasp) {
					imm = getreg (w1);
					rs = getreg (w2);
				} else if (n == 2 && !jr) {
					rd = getreg (w1);
					rs = getreg (w2);
				} else if (n == 3 && !jr) {
					rd = getreg (w1);
					rs = getreg (hasp? w3: w2);
					imm = getreg (hasp? w2: w3);
				}
				free (s);
				return riscv_rri (out, ops[i].op, rs, rd, imm);
			}
			if (hasp) {
				char tmp[32];
				strcpy (tmp, w2);
				strcpy (w2, w3);
				strcpy (w3, tmp);
			}
			switch (ops[i].type) {
			case 'I':
				{
					int op = 0, rs = 0, rt = 0, imm = 0;
					switch (ops[i].args) {
					case 2: // lui x0, 33
						rt = getreg (w1);
						imm = getreg (w2);
						free (s);
						return riscv_ri (out, ops[i].op, rt, imm);
					case 3: // addi x1, x2, 3
						rs = getreg (w2);
						rt = getreg (w1);
						imm = getreg (w3);
						free (s);
						return riscv_rri (out, ops[i].op, rs, rt, imm);
					default:
						// invalid
						op = ops[i].op;
						free (s);
						return riscv_ri (out, op, rs, imm);
					}
					break;
				}
			case 'H': // slli rd, rs, shamt
				{
					const int rt = getreg (w1);
					const int rs = getreg (w2);
					const int shamt = getreg (w3);
					free (s);
					if (shamt < 0 || shamt > 63) {
						return -1;
					}
					return riscv_rri (out, ops[i].op, rs, rt, shamt);
				}
			case 'S': // sw rs2, imm(rs1)
				{
					const int rs2 = getreg (w1);
					const int rs1 = getreg (w2);
					const int imm = getreg (w3);
					free (s);
					return riscv_store (out, ops[i].op, rs1, rs2, imm);
				}
			case 'N': // nop
				memset (out, 0, 4);
				out[0] = ops[i].op;
				free (s);
				if (r_str_startswith (ops[i].name, "c.")) {
					return 2;
				}
				return 4;
			default:
				R_LOG_ERROR ("Unknown type");
				break;
			}
			free (s);
			return -1;
		}
	}
	free (s);
	return -1;
}
