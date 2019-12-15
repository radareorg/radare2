/* radare - Copyright 2012-2018 - pancake */

#include <r_types.h>
#include <r_util.h>

static const char *const regs[33] = {
	"zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
	"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
	"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
	"t8", "t9", "k0", "k1", "gp", "sp", "s8", "ra",
	NULL
};

static struct {
	const char *name;
	int type;
	int args;
	int n;
	int x;
} ops[] = {
	{ "nop", 'N', 0, 0, 0 },
	{ "lui", 'I', 2, 15, 0 },
	{ "sw", 'I', 3, 43, 0 },
	{ "sh", 'I', 3, 41, 0 },
	{ "sb", 'I', 3, 40, 0 },
	{ "lw", 'I', 3, 35, 0 },
	{ "lh", 'I', 3, 33, 0 },
	{ "lb", 'I', 3, 32, 0 },
	{ "ori", 'I', 3, 13, 0 },
	{ "andi", 'I', 3, 12, 0 },
	{ "xori", 'I', 3, 14, 0 },
	{ "addi", 'I', 3, 8, 0 },
	{ "addiu", 'I', 3, 9, 0 },
	{ "b", 'B', -1, 4, 0 },
	{ "bnez", 'B', 2, 5, 0 },
	{ "bal", 'B', -1, -1, 17 },
	{ "bne", 'B', 3, 5, 0 },
	{ "beq", 'B', 3, 4, 0 },
	{ "bgez", 'B', -2, -1, 1 },
	{ "bgezal", 'B', -2, -1, 17 },
	{ "bltzal", 'B', -2, -1, 16 },
	{ "bgtz", 'B', -2, 7, 0 },
	{ "blez", 'B', -2, 6, 0 },
	{ "bltz", 'B', -2, 1, 0 },
	{ "syscall", 'R', 0, 12, 0 },
	{ "break", 'R', 0, 13, 0 },
	{ "nor", 'R', 3, 39, 0 },
	{ "or", 'R', 3, 37, 0 },
	{ "xor", 'R', 3, 38, 0 },
	{ "and", 'R', 3, 36, 0 },
	{ "sll", 'R', -3, 0, 0 },
	{ "sllv", 'R', 3, 4, 0 },
	{ "slt", 'R', 3, 42, 0 },
	{ "sltu", 'R', 3, 43, 0 },
	{ "sra", 'R', -3, 3, 0 },
	{ "srl", 'R', -3, 2, 0 },
	{ "srlv", 'R', 3, 6, 0 },
	{ "srav", 'R', 3, 7, 0 },
	{ "add", 'R', 3, 32, 0 },
	{ "move", 'R', -2, 32, 0 },
	{ "addu", 'R', 3, 33, 0 },
	{ "sub", 'R', 3, 34, 0 },
	{ "subu", 'R', 3, 35, 0 },
	{ "mult", 'R', 2, 24, 0 },
	{ "multu", 'R', 2, 25, 0 },
	{ "div", 'R', 2, 26, 0 },
	{ "divu", 'R', 2, 27, 0 },
	{ "mfhi", 'R', 1, 16, 0 },
	{ "mflo", 'R', 1, 18, 0 },
	{ "mthi", 'R', 1, 17, 0 },
	{ "mtlo", 'R', 1, 19, 0 },
	{ "jalr", 'R', -2, 9, 0 },
	{ "jr", 'R', 1, 8, 0 },
	{ "jal", 'J', 1, 3, 0 },
	{ "j", 'J', 1, 2, 0 },
	{ NULL }
};

static int mips_r(ut8 *b, int op, int rs, int rt, int rd, int sa, int fun) {
//^this will keep the below mips_r fuctions working
// diff instructions use a diff arg order (add is rd, rs, rt - sll is rd, rt, sa - sllv is rd, rt, rs
//static int mips_r (ut8 *b, int op, int rd, int rs, int rt, int sa, int fun) {
	if (rs == -1 || rt == -1) {
		return -1;
	}
	b[3] = ((op<<2)&0xfc) | ((rs>>3)&3); // 2
	b[2] = (rs<<5) | (rt&0x1f); // 1
	b[1] = ((rd<<3)&0xff) | (sa>>2); // 0
	b[0] = (fun&0x3f) | ((sa&3)<<6);
	return 4;
}

static int mips_i(ut8 *b, int op, int rs, int rt, int imm, int is_branch) {
	if (rs == -1 || rt == -1) {
		return -1;
	}
	if (is_branch) {
		if (imm > 4) {
			imm /= 4;
			imm--;
		} else {
			imm = 0;
		}
	}
	b[3] = ((op<<2)&0xfc) | ((rs>>3)&3);
	b[2] = (rs<<5) | (rt);
	b[1] = (imm>>8) &0xff;
	b[0] = imm & 0xff;
	return 4;
}

static int mips_j(ut8 *b, int op, int addr) {
	addr /= 4;
	b[3] = ((op<<2)&0xfc) | ((addr>>24)&3);
	b[2] = (addr>>16)&0xff;
	b[1] = (addr>>8) &0xff;
	b[0] = addr & 0xff;
	return 4;
}

static int getreg(const char *p) {
	int n;
	if (!p || !*p) {
		eprintf ("Missing argument\n");
		return -1;
	}
	/* check if it's a register */
	for (n = 0; regs[n]; n++) {
		if (!strcmp (p, regs[n])) {
			return n;
		}
	}
	/* try to convert it into a number */
	if (p[0] == '-') {
		n = (int) r_num_get (NULL, &p[1]);
		n = -n;
	} else {
		n = (int) r_num_get (NULL, p);
	}
	if (n != 0 || p[0] == '0') {
		return n;
	}
	eprintf ("Invalid reg name (%s) at pos %d\n", p, n);
	return -1;
}

R_IPI int mips_assemble(const char *str, ut64 pc, ut8 *out) {
	int i, hasp, is_branch;
	char *s = strdup (str);
	char w0[32], w1[32], w2[32], w3[32];
	r_str_replace_char (s, ',', ' ');
	hasp = r_str_replace_char (s, '(', ' ');
	r_str_replace_char (s, ')', ' ');
	*out = 0;
	*w0=*w1=*w2=*w3=0;

	if (!strncmp (s, "jalr", 4) && !strchr (s, ',')) {
		char opstr[32];
		const char *arg = strchr (s, ' ');
		if (arg) {
			snprintf (opstr, sizeof (opstr), "jalr ra ra %s", arg + 1);
			free (s);
			s = strdup (opstr);
		}
	}

	sscanf (s, "%31s", w0);
	if (*w0) {
		for (i = 0; ops[i].name; i++) {
			if (!strcmp (ops[i].name, w0)) {
				switch (ops[i].args) {
				case 3: sscanf (s, "%31s %31s %31s %31s", w0, w1, w2, w3); break;
				case -3: sscanf (s, "%31s %31s %31s %31s", w0, w1, w2, w3); break;
				case 2: sscanf (s, "%31s %31s %31s", w0, w1, w2); break;
				case -2: sscanf (s, "%31s %31s %31s", w0, w1, w2); break;
				case 1: sscanf (s, "%31s %31s", w0, w1); break;
				case -1: sscanf (s, "%31s %31s", w0, w1); break;
				case 0: sscanf (s, "%31s", w0); break;
				}
				if (hasp) {
					char tmp[32];
					strcpy (tmp, w2);
					strcpy (w2, w3);
					strcpy (w3, tmp);
				}
				switch (ops[i].type) {
				case 'R': //reg order diff per instruction 'group' - ordered to number of likelyhood to call (add > mfhi)
					switch (ops[i].args) {
					case 3: return mips_r (out, 0, getreg (w2), getreg (w3), getreg (w1), 0, ops[i].n); break;
					case -3:
						if (ops[i].n > -1) {
							return mips_r (out, 0, 0, getreg (w2), getreg (w1), getreg (w3), ops[i].n);
							break;
						} else {
							return mips_r (out, 0, getreg (w3), getreg (w2), getreg (w1), 0, (-1 * ops[i].n));
							break;
						}
					case 2: return mips_r (out, 0, getreg (w1), getreg (w2), 0, 0, ops[i].n); break;
					case 1: return mips_r (out, 0, getreg (w1), 0, 0, 0, ops[i].n);
					case -2: return mips_r (out, 0, getreg (w2), 0, getreg (w1), 0, ops[i].n); break;
					case -1: return mips_r (out, 0, 0, 0, getreg (w1), 0, ops[i].n);
					case 0: return mips_r (out, 0, 0, 0, 0, 0, ops[i].n);
					}
					break;
				case 'I':
				case 'B':
					is_branch = ops[i].type == 'B';
					switch (ops[i].args) {
					case 2: return mips_i (out, ops[i].n, 0, getreg (w1), getreg (w2), is_branch); break;
					case 3: return mips_i (out, ops[i].n, getreg (w2), getreg (w1), getreg (w3), is_branch); break;
					case -2:
						if (ops[i].n > 0) {
							return mips_i (out, ops[i].n, getreg (w1), 0, getreg (w2), is_branch);
							break;
						} else {
							return mips_i (out, (-1 * ops[i].n), getreg (w1), ops[i].x, getreg (w2), is_branch);
							break;
						}

					case -1:
						if (ops[i].n > 0) {
							return mips_i (out, ops[i].n, 0, 0, getreg (w1), is_branch);
							break;
						} else {
							return mips_i (out, (-1 * ops[i].n), 0, ops[i].x, getreg (w1), is_branch);
							break;
						}
					}
					break;
				case 'J':
					switch (ops[i].args) {
					case 1: return mips_j (out, ops[i].n, getreg (w1)); break;
					}
					break;
				case 'N': // nop
					memset (out, 0, 4);
					free (s);
					return 4;
				}
				free (s);
				return -1;
			}
		}
	}
	free (s);
	return -1;
}
