/* radare - Copyright 2012 - pancake */

#include <r_types.h>

static const char * const regs[32] = {
  "zero", "at",   "v0",   "v1",   "a0",   "a1",   "a2",   "a3",
  "a4",   "a5",   "a6",   "a7",   "t0",   "t1",   "t2",   "t3",
  "s0",   "s1",   "s2",   "s3",   "s4",   "s5",   "s6",   "s7",
  "t8",   "t9",   "k0",   "k1",   "gp",   "sp",   "s8",   "ra",
  NULL
};

static struct {
	const char *name;
	int type;
	int args;
	int n;
} ops[] = {
	{ "nop", 'N', 0, NULL },
	{ "lui", 'I', 2, 15 },
	{ "sw", 'I', 3, 43 },
	{ "sh", 'I', 3, 41 },
	{ "sb", 'I', 3, 40 },
	{ "lw", 'I', 3, 35 },
	{ "lh", 'I', 3, 33 },
	{ "lb", 'I', 3, 32 },
	{ "ori", 'I', 3, 13 },
	{ "andi", 'I', 3, 12 },
	{ "xori", 'I', 3, 14 },
	{ "addi", 'I', 3, 8 },
	{ "addiu", 'I', 3, 9 },
	{ "bnez", 'I', 2, 5 },
	{ "jalr", 'R', 1, 9 },
	{ "jr", 'R', 1, 8 },
	{ "jal", 'J', 1, 3 },
	{ "j",   'J', 1, 2 },
	{ NULL }
};

static int mips_r (ut8 *b, int op, int rs, int rt, int rd, int sa, int fun) {
	if (rs == -1 || rt == -1) return -1;
	b[3] = ((op<<2)&0xfc) | ((rs>>3)&3);
	b[2] = (rs<<5) | (rt&0x1f);
	b[1] = ((rd<<3)&0xff) | (sa>>2);
	b[0] = (fun&0x3f) | ((sa&3)<<5);
	return 4;
}

static int mips_i (ut8 *b, int op, int rs, int rt, int imm) {
	if (rs == -1 || rt == -1) return -1;
	b[3] = ((op<<2)&0xfc) | ((rs>>3)&3);
	b[2] = (rs<<5) | (rt);
	b[1] = (imm>>8) &0xff;
	b[0] = imm & 0xff;
	return 4;
}

static int mips_j (ut8 *b, int op, int addr) {
	addr /= 4;
	b[3] = ((op<<2)&0xfc) | ((addr>>24)&3);
	b[2] = (addr>>16)&0xff;
	b[1] = (addr>>8) &0xff;
	b[0] = addr & 0xff;
	return 4;
}

static int getreg (const char *p) {
	int n = (int) r_num_get (NULL, p);
	if (n==0) {
		if (strcmp (p, "0")) {
			for (n=0; regs[n]; n++) {
				if (!strcmp (p, regs[n]))
					return n;
			}
		} else n = -1;
	}
	return n;
}

int mips_assemble(const char *str, ut64 pc, ut8 *out) {
	int i, hasp;
	char *s = strdup (str);
	char w0[32], w1[32], w2[32], w3[32];
	r_str_replace_char (s, ',', ' ');
	hasp = r_str_replace_char (s, '(', ' ');
	r_str_replace_char (s, ')', ' ');
	*out = 0;
	*w0=*w1=*w2=*w3=0;
	sscanf (s, "%31s", w0); 
	if (*w0)
	for (i=0; ops[i].name; i++) {
		if (!strcmp (ops[i].name, w0)) {
			switch (ops[i].args) {
			case 1: sscanf (s, "%31s %31s", w0, w1); break;
			case 2: sscanf (s, "%31s %31s %31s", w0, w1, w2); break;
			case 3: sscanf (s, "%31s %31s %31s %31s", w0, w1, w2, w3); break;
			}
			if (hasp) {
				char tmp[32];
				strcpy (tmp, w2);
				strcpy (w2, w3);
				strcpy (w3, tmp);
			}
			switch (ops[i].type) {
			case 'N': // nop
				memset (out, 0, 4);
				break;
			case 'R':
				switch (ops[i].args) {
				case 1: return mips_r (out, 0, getreg (w1), getreg (w2), getreg (w3), 0, ops[i].n);
				case 2: return mips_i (out, ops[i].n, 0, getreg (w1), getreg (w2)); break;
				case 3: return mips_i (out, ops[i].n, getreg (w1), getreg (w2), getreg (w3)); break;
				}
				break;
			case 'I':
				switch (ops[i].args) {
				case 2: return mips_i (out, ops[i].n, 0, getreg (w1), getreg (w2)); break;
				case 3: return mips_i (out, ops[i].n, getreg (w2), getreg (w1), getreg (w3)); break;
				}
				break;
			case 'J':
				switch (ops[i].args) {
				case 1: return mips_j (out, ops[i].n, getreg (w1)); break;
				}
				break;
			}
			return -1;
		}
	}
	free (s);
	return -1;
}
