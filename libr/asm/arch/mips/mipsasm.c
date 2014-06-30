/* radare - Copyright 2012 - pancake */

#include <r_types.h>
#include <r_util.h>

#ifndef R_IPI
#define R_IPI
#endif

static const char * const regs[33] = {
  "zero", "at",   "v0",   "v1",   "a0",   "a1",   "a2",   "a3",
  "t0",   "t1",   "t2",   "t3",   "t4",   "t5",   "t6",   "t7",
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
	{ "nop", 'N', 0, 0 },
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
	{ "bne", 'I', 3, 5 },
	{ "beq", 'I', 3, 4 },
	{ "bgez", 'I', -2, -1 },
	{ "bgtz", 'I', -2, 7 },
	{ "blez", 'I', -2, 6 },
	{ "bltz", 'I', -2, 1 },
	{ "syscall", 'R', 0, 12 },
	{ "break", 'R', 0, 13 },
	{ "nor", 'R', 3, 39 },
	{ "or", 'R', 3, 37 },
	{ "xor", 'R', 3, 38 },
	{ "and", 'R', 3, 36 },
	{ "sll", 'R', -3, 0 },
	{ "sllv", 'R', 3, 4 },
	{ "slt", 'R', 3, 42 },
	{ "sltu", 'R', 3, 43 },
	{ "sra", 'R', -3, 3 },
	{ "srl", 'R', -3, 2 },
	{ "srlv", 'R', 3, 6 },
	{ "srav", 'R', 3, 7 },
	{ "add", 'R', 3, 32 },
	{ "addu", 'R', 3, 33 },
	{ "sub", 'R', 3, 34 },
	{ "subu", 'R', 3, 35 },
	{ "mult", 'R', 2, 24 },
	{ "multu", 'R', 2, 25 },
	{ "div", 'R', 2, 26 },
	{ "divu", 'R', 2, 27 },
	{ "mfhi", 'R', 1, 16 },
	{ "mflo", 'R', 1, 18 },
	{ "mthi", 'R', 1, 17 },
	{ "mtlo", 'R', 1, 19 },
	{ "jalr", 'R', -2, 9 },
	{ "jr", 'R', 1, 8 },
	{ "jal", 'J', 1, 3 },
	{ "j",   'J', 1, 2 },
	{ NULL }
};

static int mips_r (ut8 *b, int op, int rs, int rt, int rd, int sa, int fun) {
//^this will keep the below mips_r fuctions working
// diff instructions use a diff arg order (add is rd, rs, rt - sll is rd, rt, sa - sllv is rd, rt, rs
//static int mips_r (ut8 *b, int op, int rd, int rs, int rt, int sa, int fun) {
	if (rs == -1 || rt == -1) return -1;
	b[3] = ((op<<2)&0xfc) | ((rs>>3)&3); // 2
	b[2] = (rs<<5) | (rt&0x1f); // 1
	b[1] = ((rd<<3)&0xff) | (sa>>2); // 0
	b[0] = (fun&0x3f) | ((sa&3)<<6);
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

R_IPI int mips_assemble(const char *str, ut64 pc, ut8 *out) {
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
			case 3: sscanf (s, "%31s %31s %31s %31s", w0, w1, w2, w3); break;
			case -3: sscanf (s, "%31s %31s %31s %31s", w0, w1, w2, w3); break;
			case 2: sscanf (s, "%31s %31s %31s", w0, w1, w2); break;
			case -2:sscanf (s, "%31s %31s %31s", w0, w1, w2); break;
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
			case 'R'://reg order diff per instruction 'group' - ordered to number of likelyhood to call (add > mfhi)
				switch (ops[i].args) {
				case 3: return mips_r (out, 0, getreg (w2), getreg (w3), getreg (w1), 0, ops[i].n); break;
				case -3:
					if(ops[i].n > -1) {
						return mips_r (out, 0, 0, getreg (w2), getreg (w1), getreg (w3), ops[i].n); break;
					}
					else {
						return mips_r (out, 0, getreg (w3), getreg (w2), getreg (w1), 0, (-1 * ops[i].n) ); break;
					}
				case 2: return mips_r (out, 0, getreg (w1), getreg (w2), 0, 0, ops[i].n); break;
				case 1: return mips_r (out, 0, getreg (w1), 0, 0, 0, ops[i].n);
				case -2: return mips_r (out, 0, getreg (w2), 0, getreg (w1), 0, ops[i].n); break;
				case -1: return mips_r (out, 0, 0, 0, getreg (w1), 0, ops[i].n);
				case 0: return mips_r (out, 0, 0, 0, 0, 0, ops[i].n);
				}
				break;
			case 'I':
				switch (ops[i].args) {
				case 2: return mips_i (out, ops[i].n, 0, getreg (w1), getreg (w2)); break;
				case 3: return mips_i (out, ops[i].n, getreg (w2), getreg (w1), getreg (w3)); break;
                    case -2:
                         if (ops[i].n > 0) {
                              return mips_i (out, ops[i].n, getreg (w1), 0, getreg (w2)); break;
                         }
					else {
                              return mips_i (out, (-1 * ops[i].n), getreg (w1), 1, getreg (w2)); break;
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
				break;
			}
			return -1;
		}
	}
	free (s);
	return -1;
}
