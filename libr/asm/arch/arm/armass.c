/* radare - LGPL - Copyright 2010 pancake<@nopcode.org> */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// TODO: only lo registers accessible in thumb arm
// TODO: add support for ldrb, ldrh, strb, strh

typedef struct {
	unsigned long off;
	int o;
	char op[32];
	char *a0, *a1, *a2;
} ArmOpcode;

typedef struct {
	const char *name;
	int code;
	int type;
} ArmOp;

enum {
	TYPE_MOV = 1,
	TYPE_TST = 2,
	TYPE_SWI = 3,
	TYPE_BRA = 4,
	TYPE_BRR = 5,
	TYPE_ARI = 6,
	TYPE_IMM = 7,
	TYPE_MEM = 8,
};

// static const char *const arm_shift[] = {"lsl", "lsr", "asr", "ror"};

static ArmOp ops[] = {
	{ "adc", 0xa000, TYPE_ARI },
	{ "adcs", 0xb000, TYPE_ARI },
	{ "adds", 0x9000, TYPE_ARI },
	{ "add", 0x8000, TYPE_ARI },
	{ "subs", 0x5000, TYPE_ARI },
	{ "sub", 0x4000, TYPE_ARI },
	{ "sbc", 0xc000, TYPE_ARI },
	{ "sbcs", 0xd000, TYPE_ARI },
	{ "rsb", 0x6000, TYPE_ARI },
	{ "rsbs", 0x7000, TYPE_ARI },
	{ "rsc", 0xe000, TYPE_ARI },
	{ "rscs", 0xf000, TYPE_ARI },

	{ "push", 0x2d09, TYPE_IMM },
	{ "pop", 0xbd08, TYPE_IMM },

	{ "cps", 0xb1, TYPE_IMM },
	{ "nop", 0xa0e1, -1 },

	{ "ldr", 0x9000, TYPE_MEM },
	{ "str", 0x8000, TYPE_MEM },

	{ "blx", 0x30ff2fe1, TYPE_BRR },
	{ "bx", 0x10ff2fe1, TYPE_BRR },

	{ "bl", 0xb, TYPE_BRA },
// bx/blx - to register, b, bne,.. justjust  offset
//    2220:       e12fff1e        bx      lr
//    2224:       e12fff12        bx      r2
//    2228:       e12fff13        bx      r3

	//{ "bx", 0xb, TYPE_BRA },
	{ "b", 0xa, TYPE_BRA },

	//{ "mov", 0x3, TYPE_MOV },
	//{ "mov", 0x0a3, TYPE_MOV },
	{ "mov", 0xa001, TYPE_MOV },
	{ "mvn", 0, TYPE_MOV },
	{ "svc", 0xf, TYPE_SWI }, // ???

	{ "and", 0x0, TYPE_TST },
	{ "ands", 0x1000, TYPE_TST },
	{ "eor", 0x2000, TYPE_TST },
	{ "eors", 0x3000, TYPE_TST },
	{ "orr", 0x0, TYPE_TST },
	{ "bic", 0x0, TYPE_TST },

	{ "cmp", 0x4001, TYPE_TST },
	{ "cmn", 0x0, TYPE_TST },
	{ "teq", 0x0, TYPE_TST },
	{ "tst", 0xe1, TYPE_TST },
	{ NULL }
};

static int getnum(const char *str) {
	if (!str)
		return 0;
	while (*str=='$' || *str=='#')
		str++;
	if (*str=='0' && str[1]=='x') {
		int x;
		if (sscanf (str+2, "%x", &x))
			return x;
	}
	return atoi(str);
}

static char *getrange(char *s) {
	char *p = NULL;
	while (s && *s) {
		if (*s==',') {
			p = s+1;
			*p=0;
		}
		if (*s=='[' || *s==']')
			strcpy (s, s+1);
		if (*s=='}')
			*s=0;
		s++;
	}
	while (p && *p==' ') p++;
	return p;
}

static int getreg(const char *str) {
	int i;
	const char *aliases[] = { "sl", "fp", "ip", "sp", "lr", "pc", NULL };
	if (!str)
		return -1;
	if (*str=='r')
		return atoi (str+1);
	for (i=0; aliases[i]; i++)
		if (!strcmp (str, aliases[i]))
			return 10+i;
	return -1;
}

static int getshift(const char *str) {
	if (!str) return 0;
	while (str && *str&&!atoi (str))
		str++;
	return atoi(str)/2;
}

static void arm_opcode_parse(ArmOpcode *ao, const char *str) {
	memset (ao, 0, sizeof (ArmOpcode));
	strncpy (ao->op, str, sizeof (ao->op));
	ao->a0 = strchr (ao->op, ' ');
	if (ao->a0) {
		*ao->a0 = 0;
		ao->a1 = strchr (++ao->a0, ',');
		if (ao->a1) {
			*ao->a1 = 0;
			ao->a2 = strchr (++ao->a1, ',');
			if (ao->a2) {
				*ao->a2 = 0;
				ao->a2++;
			}
		}
	}
	while (ao->a0&&*ao->a0==' ') ao->a0++;
	while (ao->a1&&*ao->a1==' ') ao->a1++;
	while (ao->a2&&*ao->a2==' ') ao->a2++;
}

static inline int arm_opcode_cond(ArmOpcode *ao, int delta) {
	const char *conds[] = {
		"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
		"hi", "ls", "ge", "lt", "gt", "le", "al", "nv", 0
	};
	int i, cond = 14; // 'always' is default
	char *c = ao->op+delta;
	for (i=0; conds[i]; i++) {
		if (!strcmp (c, conds[i])) {
			cond = i; 
			break;
		}
	}
	ao->o |= cond<<4;
	return cond;
}

// str, ldr
// TODO: group similar instructions like for non-thumb
static int thumb_assemble(ArmOpcode *ao, const char *str) {
	// TODO: Add thumb mode
	// mov r, n = 2[r0-7][nn]
	// mov r, r = 46[7bits,7bits]
	// cmp r, n = 2[r(8-f)-8][nn]
	// cmp r, r = 45[7bits,7bits]
	// subs r, n = 3[r(8-f)-8][nn]
	//
	// and r, r = 40[7bits=r][7bits=r] 
	//     asrs = 41
	// tst r, r = 42[7bits,7bits]
	//      orr = 43
	//     
	// b[cond] n = d[cond][nn]
	// b.n = e0[nn] = 
	// bx rN = 47[7bits(regidx)][7bits(ignored)]
	// bl = 4 bytes = f0[nn][????]
	// add r0, pc, n = a[r0-7][nn]
	// add r0, sp, n = a[r(8-f)-8][nn]
	// rasm2 -b 16 -a arm -e -d 2700 // movs r7, #0

	if (!strcmp (ao->op, "nop")) {
		ao->o = 0xbf;
	} else
	if (!strcmp (ao->op, "and")) {
		ao->o = 0x40;
		ao->o |= (0xff & getreg (ao->a0)) << 8;
		ao->o |= (0xff & getreg (ao->a1)) << 11;
	} else
	if (!strcmp (ao->op, "svc")) {
		ao->o = 0xdf;
		ao->o |= (0xff & getnum (ao->a0)) << 8;
	} else
	if (!strcmp (ao->op, "b") || !strcmp (ao->op, "b.n")) {
		ao->o = 0xe0;
		ao->o |= getnum (ao->a0)<<8;
	} else
	if (!strcmp (ao->op, "bx")) {
		ao->o = 0x47;
		ao->o |= getreg (ao->a0)<<11;
	} else
	if (!strcmp (ao->op, "bl")) {
		ao->o = 0x47;
		ao->o |= getnum (ao->a0)<<8;
		// XXX: length = 4
	} else
	if (*ao->op == 'b') { // conditional branch
		ao->o = 0xd0 | arm_opcode_cond (ao, 1);
		ao->o |= getnum (ao->a0)<<8;
	} else
	if (!strcmp (ao->op, "mov")) {
		int reg = getreg (ao->a1);
		if (reg!=-1) {
			ao->o = 0x46;
			ao->o |= (getreg (ao->a0))<<8;
			ao->o |= reg<<11;
		} else {
			ao->o = 0x20;
			ao->o |= (getreg (ao->a0));
			ao->o |= (getnum (ao->a1)&0xff)<<8;
		}
	} else
	if (!strcmp (ao->op, "ldr")) {
		getrange (ao->a1);
		getrange (ao->a2);
		if (!strcmp (ao->a1, "sp")) {
			// ldr r0, [sp, n] = a[r0-7][nn]
			if (getreg (ao->a2) == -1) {
				// ldr r0, [sp, n]
				ao->o = 0x98 + (0xf & getreg (ao->a0));
				ao->o |= (0xff & getnum (ao->a2)/4)<<8;
			} else return 0;
		} else
		if (!strcmp (ao->a1, "pc")) {
			// ldr r0, [pc, n] = 4[r0-8][nn*4]
			if (getreg (ao->a2) == -1) {
				ao->o = 0x40 | 8+(0xf & getreg (ao->a0));
				ao->o |= (0xff & getnum (ao->a2)/4)<<8;
			} else return 0;
		} else {
			// ldr r0, [rN, rN] = 58[7bits:basereg + 7bits:destreg]
			int a0 = getreg (ao->a0);
			int a1 = getreg (ao->a1);
			int a2 = getreg (ao->a2);
			ao->o = 0x58; // | (8+(0xf & a0));
			ao->o |= (7&a0)<<8;
			ao->o |= (7&a1)<<11;
			ao->o |= (7&a2)<<14;
		}
		// [0379] ldrb r3, [r0, #4]
		// [0188] ldrh r1, [r0, #0]

	} else
	if (!strcmp (ao->op, "str")) {
		// TODO
		// str r0, [sp, n] = a[r(8-f)-8][nn]
		//  " strh = 9
		//  " strb = 8
		// str r0, [rN, n] = 6[n*16][7bits:basereg + 7bits:destreg]
		// str r0, [rN, rN] = 50[7bits:basereg + 7bits:destreg]
//   0:   6191            str     r1, [r2, #24]
//   2:   50d1            str     r1, [r2, r3]
		getrange (ao->a1);
		getrange (ao->a2);
		if (!strcmp (ao->a1, "sp")) {
			// ldr r0, [sp, n] = a[r0-7][nn]
			if (getreg (ao->a2) == -1) {
				int ret = getnum (ao->a2);
				if (ret%4) {
					fprintf (stderr, "ldr index must be aligned to 4");
					return 0;
				}
				ao->o = 0x90 + (0xf & getreg (ao->a0));
				ao->o |= (0xff & getnum (ao->a2)/4)<<8;
			} else return 0;
		} else
		if (!strcmp (ao->a1, "pc")) {
			return 0;
		} else {
			// str
			int a0 = getreg (ao->a0);
			int a1 = getreg (ao->a1);
			int a2 = getreg (ao->a2);
			if (a2 == -1) {
				a2 = getnum (ao->a2)>>1;
				ao->o = 0x60; // | (8+(0xf & a0));
				ao->o |= (7&a0)<<8;
				ao->o |= (7&a1)<<11;
				if (a2<0||a2>12) {
					fprintf (stderr, "Invalid range in str\n");
					return 0;
				}
				ao->o |= (3&(a2/4))<<14; // XXX: must limit delta in 12
			} else {
				ao->o = 0x50; // | (8+(0xf & a0));
				ao->o |= (7&a0)<<8;
				ao->o |= (7&a1)<<11;
				ao->o |= (3&a2)<<14;
			}
		}
	} else
	if (!strcmp (ao->op, "tst")) {
		ao->o = 0x42;
		ao->o |= (getreg (ao->a0))<<8;
		ao->o |= getreg (ao->a1)<<11;
	} else
	if (!strcmp (ao->op, "cmp")) {
		int reg = getreg (ao->a1);
		if (reg!=-1) {
			ao->o = 0x45;
			ao->o |= (getreg (ao->a0))<<8;
			ao->o |= reg<<11;
		} else {
			ao->o = 0x20;
			ao->o |= 8+(getreg (ao->a0));
			ao->o |= (getnum (ao->a1)&0xff)<<8;
		}
	} else
	if (!strcmp (ao->op, "add")) {
		// XXX: signed unsigned ??
		// add r, r = 44[7bits,7bits]
		// adds r, n = 3[r0-7][nn]
		int reg = getreg (ao->a1);
		if (reg!=-1) {
			ao->o = 0x44;
			ao->o |= (getreg (ao->a0))<<8;
			ao->o |= reg<<11;
		} else {
			ao->o = 0x30;
			ao->o |= (getreg (ao->a0));
			ao->o |= (getnum (ao->a1)&0xff)<<8;
		}
	} else
	if (!strcmp (ao->op, "sub")) {
		// TODO
		int reg = getreg (ao->a1);
		if (reg!=-1) {
			ao->o = 0x1e;
			ao->o |= (getreg (ao->a0))<<8;
			ao->o |= reg<<11;
			// TODO: ao->o |= getnum(ao->a2)<<11;
		} else {
			ao->o = 0x30;
			ao->o |= 8+(getreg (ao->a0));
			ao->o |= (getnum (ao->a1)&0xff)<<8;
		}
	} else return 0;
	return 1;
}

static int arm_assemble(ArmOpcode *ao, const char *str) {
	int i, ret;
	for (i=0;ops[i].name;i++) {
		if (!memcmp(ao->op, ops[i].name, strlen (ops[i].name))) {
			ao->o = ops[i].code;
			arm_opcode_cond (ao, strlen(ops[i].name));
			switch(ops[i].type) {
			case TYPE_MEM:
				getrange (ao->a0);
				getrange (ao->a1);
				getrange (ao->a2);
				//printf("a0(%s) a1(%s) a2(%s)\n", ao->a0, ao->a1, ao->a2);
				ao->o |= getreg(ao->a0)<<20;
				ao->o |= getreg(ao->a1)<<8; // delta
				ret = getreg(ao->a2);
				if (ret != -1) {
					ao->o |= (strstr(str,"],"))?6:7;
					ao->o |= (ret&0x0f)<<24;//(getreg(ao->a2)&0x0f);
				} else {
					ao->o |= (strstr(str,"],"))?4:5;
					ao->o |= (getnum (ao->a2)&0x7f)<<24; // delta
				}
				break;
			case TYPE_IMM:
				if (*ao->a0=='{') {
					int reg, regmask, reg2;
					getrange (ao->a0+1); // XXX filter regname string
					reg = getreg (ao->a0+1);
					regmask = (reg>7)? 1<<(reg-8): 1<<(reg+8);
					if (reg>=0 && reg<=0xf)
						ao->o |= regmask<<16;
					if (ao->a1 && *ao->a1) {
						getrange (ao->a1);
						reg2 = getreg (ao->a1);
						if (reg2 != -1)
							ao->o |= (reg2-reg+1)<<20;
					}
					if (ao->a2)
						fprintf (stderr, "XXX: push/pop with more than 2 regs is broken\n");
					// char *r1 = getrange (ao->a0+1); // XXX: its a bitmask?
					//if (r1) ao->o |= getreg(r1)<<24;
				} else ao->o |= getnum(ao->a0)<<24; // ???
				break;
			case TYPE_BRA:
				if ((ret = getreg(ao->a0)) == -1) {
					// TODO: control if branch out of range
					ret = (getnum(ao->a0)-ao->off-8)/4;
					ao->o |= ((ret>>8)&0xff)<<16;
					ao->o |= ((ret)&0xff)<<24;
				} else {
					printf("This branch does not accept reg as arg\n");
					return 0;
				}
				break;
			case TYPE_BRR:
				if ((ret = getreg(ao->a0)) == -1) {
					printf("This branch does not accept off as arg\n");
					return 0;
				} else ao->o |= (getreg (ao->a0)<<24);
				break;
			case TYPE_SWI:
				ao->o |= (getnum (ao->a0)&0xff)<<24;
				ao->o |= ((getnum (ao->a0)>>8)&0xff)<<16;
				ao->o |= ((getnum (ao->a0)>>16)&0xff)<<8;
				break;
			case TYPE_ARI:
				if (!ao->a2) {
					ao->a2 = ao->a1;
					ao->a1 = ao->a0;
				}
				ao->o |= getreg (ao->a0)<<20;
				ao->o |= getreg (ao->a1)<<8;
				ret = getreg (ao->a2);
				ao->o |= (ret!=-1)? ret<<24 : 2 | getnum(ao->a2)<<24;
				break;
			case TYPE_MOV:
				ao->o |= getreg (ao->a0)<<20;
				ret = getreg (ao->a1);
				if (ret!=-1) ao->o |= ret<<24;
				else ao->o |= 0xa003 | getnum (ao->a1)<<24;
				break;
			case TYPE_TST:
				//ao->o |= getreg(ao->a0)<<20; // ??? 
				ao->o |= getreg (ao->a0)<<8;
				ao->o |= getreg (ao->a1)<<24;
				ao->o |= getshift (ao->a2)<<16; // shift
				break;
			}
			return 1;
		}
	}
	return 0;
}

typedef int (*AssembleFunction)(ArmOpcode *, const char *);
static AssembleFunction assemble[2] = { &arm_assemble, &thumb_assemble };

int armass_assemble(const char *str, unsigned long off, int thumb) {
	ArmOpcode aop = {0};
	aop.off = off;
	arm_opcode_parse (&aop, str);
	if (!assemble[thumb] (&aop, str)) {
		printf ("armass: Unknown opcode (%s)\n", str);
		return -1;
	}
	////printf ("PARSE (%s) (%s)(%s)(%s)\n", aop.op, aop.a0, aop.a1, aop.a2);
	return aop.o;
}

#ifdef MAIN
void thisplay(const char *str) {
	char cmd[32];
	int op = armass_assemble (str, 0x1000, 1);
	printf ("[%04x] %s\n", op, str);
	snprintf (cmd, sizeof(cmd), "rasm2 -d -b 16 -a arm %04x", op);
	system (cmd);
}

void display(const char *str) {
	char cmd[32];
	int op = armass_assemble (str, 0x1000, 0);
	printf ("[%08x] %s\n", op, str);
	snprintf (cmd, sizeof(cmd), "rasm2 -d -a arm %08x", op);
	system (cmd);
}

int main() {
#if 0
	thisplay("mov r0, 11");
	thisplay("mov r0, r2");
	thisplay("mov r1, r4");
	thisplay("cmp r1, r2");
	thisplay("cmp r3, 44");
	thisplay("nop");
	thisplay("svc 15");
	thisplay("add r1, r2");
	thisplay("add r3, 44");
	thisplay("sub r1, r2, 3");
	thisplay("sub r3, 44");
	thisplay("tst r3,r4");
	thisplay("bx r3");
	thisplay("b 33");
	thisplay("b 0");
	thisplay("bne 44");
	thisplay("and r2,r3");
#endif
	// INVALID thisplay("ldr r1, [pc, r2]");
	// INVALID thisplay("ldr r1, [sp, r2]");
#if 0
	thisplay("ldr r1, [pc, 12]");
	thisplay("ldr r1, [sp, 24]");
	thisplay("ldr r1, [r2, r3]");
#endif
	// INVALID thisplay("str r1, [pc, 22]");
	// INVALID thisplay("str r1, [pc, r2]");
	// INVALID thisplay("str r1, [sp, r2]");

	thisplay("str r1, [sp, 20]"); // aligned to 4
	thisplay("str r1, [r2, 12]"); // OK
	thisplay("str r1, [r2, r3]");
return 0;
#if 0
	display("mov r0, 33");
	display("mov r1, 33");
	display("movne r0, 33");
	display("tst r0, r1, lsl #2");
	display("svc 0x80");
	display("sub r3, r1, r2");
	display("add r0, r1, r2");
	display("mov fp, 0");
	display("pop {pc}");
	display("pop {r3}");
	display("bx r1");
	display("bx r3");
	display("bx pc");
	display("blx fp");
	display("pop {pc}");
	display("add lr, pc, lr");
	display("adds r3, #8");
	display("adds r3, r2, #8");
	display("subs r2, #1");
	display("cmp r0, r4");
	display("cmp r7, pc");
	display("cmp r1, r3");
	display("mov pc, 44");
	display("mov pc, r3");
	display("push {pc}");
	display("pop {pc}");
	display("nop");
	display("ldr r1, [r2, 33]");
	display("ldr r1, [r2, r3]");
	display("ldr r3, [r4, r6]");
	display("str r1, [pc, 33]");
	display("str r1, [pc], 2");
	display("str r1, [pc, 3]");
	display("str r1, [pc, r4]");
	display("bx r3");
	display("bcc 33");
	display("blx r3");
	display("bne 0x1200");
	display("str r0, [r1]");
	display("push {fp,lr}");
	display("pop {fp,lr}");
	display("pop {pc}");
#endif

   //10ab4:       00047e30        andeq   r7, r4, r0, lsr lr
   //10ab8:       00036e70        andeq   r6, r3, r0, ror lr

	display("andeq r7, r4, r0, lsr lr");
	display("andeq r6, r3, r0, ror lr");
//  c4:   e8bd80f0        pop     {r4, r5, r6, r7, pc}
	display("pop {r4,r5,r6,r7,pc}");


#if 0
	display("blx r1");
	display("blx 0x8048");
#endif

#if 0
	display("b 0x123");
	display("bl 0x123");
	display("blt 0x123"); // XXX: not supported
#endif
	return 0;
}
#endif
