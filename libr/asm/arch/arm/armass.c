/* radare - LGPL - Copyright 2010-2014 - pancake */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <r_util.h>

// TODO: only lo registers accessible in thumb arm

typedef struct {
	ut64 off;
	ut32 o;
	char op[128];
	char opstr[128];
	char *a[16]; /* only 15 arguments can be used! */
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
	TYPE_HLT = 4,
	TYPE_BRA = 5,
	TYPE_BRR = 6,
	TYPE_ARI = 7,
	TYPE_IMM = 8,
	TYPE_MEM = 9,
	TYPE_BKP = 10,
	TYPE_SWP = 11,
};

// static const char *const arm_shift[] = {"lsl", "lsr", "asr", "ror"};

static ArmOp ops[] = {
	{ "adc", 0xa000, TYPE_ARI },
	{ "adcs", 0xb000, TYPE_ARI },
	{ "adds", 0x9000, TYPE_ARI },
	{ "add", 0x8000, TYPE_ARI },
	{ "bkpt", 0x2001, TYPE_BKP },
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
	{ "mvn", 0xe000, TYPE_MOV },
	{ "svc", 0xf, TYPE_SWI }, // ???
	{ "hlt", 0x70000001, TYPE_HLT }, // ???

	{ "and", 0x0000, TYPE_ARI },
	{ "ands", 0x1000, TYPE_ARI },
	{ "eor", 0x2000, TYPE_ARI },
	{ "eors", 0x3000, TYPE_ARI },
	{ "orr", 0x0, TYPE_ARI },
	{ "bic", 0x0, TYPE_ARI },

	{ "cmp", 0x5001, TYPE_TST },
	{ "swp", 0xe1, TYPE_SWP },
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

#if 0
static int getshift_unused (const char *s) {
	int i;
	const char *shifts[] = { "lsl", "lsr", "asr", "ror", NULL };
	for (i=0; shifts[i]; i++)
		if (!strcmp (s, shifts[i]))
			return i * 0x20;
	return 0;
}
#endif

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

static int thumb_getreg(const char *str) {
	if (!str)
		return -1;
	if (*str=='r')
		return atoi (str+1);
	//FIXME Note that pc is only allowed un pop, lr in push in Thumb1 mode.
	if (!strcmp (str, "pc") || !strcmp(str,"lr"))
		return 8;
	return -1;
}

static int getlist(char *op) {
	int reg, list = 0;
	char *ptr = strchr (op, '{');
	if (ptr) {
		do {
			ptr++;
			while (*ptr && *ptr == ' ') ptr++;
			reg = getreg (ptr);
			if (reg == -1)
				break;
			list |= (1<<reg);
			while (*ptr && *ptr!=',') ptr++;
		} while (*ptr && *ptr==',');
	}
	return list;
}

static ut32 getshift(const char *str) {
	char type[128];
	char arg[128];
	char *space;
	ut32 i=0, shift=0;
	const char *shifts[] = {
		"LSL", "LSR", "ASR", "ROR",
		0, "RRX" // alias for ROR #0
	};

	strncpy (type, str, sizeof (type)-1);

	// XXX strcaecmp is probably unportable
	if (!strcasecmp (type, shifts[5])) {
		// handle RRX alias case
		shift = 6;
	} else { // all other shift types
		space = strchr (type, ' ');
		if (!space)
			return 0;
		*space = 0;
		strncpy (arg, ++space, sizeof(arg)-1);

		for (i=0; shifts[i]; i++) {
			if (!strcasecmp (type, shifts[i])) {
				shift = 1;
				break;
			}
		}
		if (!shift)
			return 0;
		shift = (i*2);

		if ((i = getreg (arg)) != -1) {
			i<<=8; // set reg
//			i|=1; // use reg
			i |= (1<<4); // bitshift
			i|=shift<<4; // set shift mode
			if (shift == 6) i|=(1<<20);
		} else {
			i = getnum (arg);
			// ensure only the bottom 5 bits are used
			i &= 0x1f;
			if (!i) i = 32;
			i = (i*8);
			i |= shift; // lsl, ror, ...
			i = i << 4;
		}
	}

	r_mem_copyendian ((ut8*)&shift, (const ut8*)&i, sizeof (ut32), 0);

	return shift;
}

static void arm_opcode_parse(ArmOpcode *ao, const char *str) {
	int i;
	memset (ao, 0, sizeof (ArmOpcode));
	if (strlen (str)+1>=sizeof (ao->op))
		return;
	strncpy (ao->op, str, sizeof (ao->op)-1);
	strcpy (ao->opstr, ao->op);
	ao->a[0] = strchr (ao->op, ' ');
	for (i=0; i<15; i++) {
		if (ao->a[i]) {
			*ao->a[i] = 0;
			ao->a[i+1] = strchr (++ao->a[i], ',');
		} else break;
	}
	if (ao->a[i]) {
		*ao->a[i] = 0;
		ao->a[i]++;
	}
	for (i=0; i<16; i++)
		while (ao->a[i] && *ao->a[i]==' ')
			ao->a[i]++;
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

// TODO: group similar instructions like for non-thumb
static int thumb_assemble(ArmOpcode *ao, const char *str) {
	int reg, j;
	ao->o = UT32_MAX;
	if (!strcmp (ao->op, "pop") && ao->a[0]) {
		ao->o = 0xbc;
		if (*ao->a[0]++=='{') {
			// XXX: inverse order?
			for (j=0; j<16; j++) {
				if (ao->a[j] && *ao->a[j]) {
					getrange (ao->a[j]); // XXX filter regname string
					reg = thumb_getreg (ao->a[j]);
					if (reg != -1) {
						if (reg<8)
							ao->o |= 1<<(8+reg);
						if (reg==8){
							ao->o |= 1;
						}
					//	else ignore...
					}
				}
			}
		} else ao->o |= getnum (ao->a[0])<<24; // ???
		return 2;
	} else
	if (!strcmp (ao->op, "push") && ao->a[0]) {
		ao->o = 0xb4;
		if (*ao->a[0]++=='{') {
			for (j=0; j<16; j++) {
				if (ao->a[j] && *ao->a[j]) {
					getrange (ao->a[j]); // XXX filter regname string
					reg = thumb_getreg (ao->a[j]);
					if (reg != -1) {
						if (reg<8)
							ao->o |= 1<<(8+reg);
						if (reg==8)
							ao->o |= 1;
					//	else ignore...
					}
				}
			}
		} else ao->o |= getnum (ao->a[0])<<24; // ???
		return 2;
	} else
	if (!strcmp (ao->op, "ldmia")) {
		ao->o = 0xc8 + getreg (ao->a[0]);
		ao->o |= getlist(ao->opstr) << 8;
		return 2;
	} else
	if (!strcmp (ao->op, "stmia")) {
		ao->o = 0xc0 + getreg (ao->a[0]);
		ao->o |= getlist(ao->opstr) << 8;
		return 2;
	} else
	if (!strcmp (ao->op, "nop")) {
		ao->o = 0xbf;
		return 2;
	} else
	if (!strcmp (ao->op, "yield")) {
		ao->o = 0x10bf;
		return 2;
	} else
	if (!strcmp (ao->op, "wfe")) {
		ao->o = 0x20bf;
		return 2;
	} else
	if (!strcmp (ao->op, "wfi")) {
		ao->o = 0x30bf;
		return 2;
	} else
	if (!strcmp (ao->op, "sev")) {
		ao->o = 0x40bf;
		return 2;
	} else
	if (!strcmp (ao->op, "bkpt")) {
		ao->o = 0xbe;
		ao->o |= (0xff & getnum (ao->a[0]))<<8;
		return 2;
	} else
#if 0
	if (!strcmp (ao->op, "and")) {
		ao->o = 0x40;
		ao->o |= (0xff & getreg (ao->a[0])) << 8;
		ao->o |= (0xff & getreg (ao->a[1])) << 11;
	} else
#endif
	if (!strcmp (ao->op, "svc")) {
		ao->o = 0xdf;
		ao->o |= (0xff & getnum (ao->a[0])) << 8;
		return 2;
	} else
	if (!strcmp (ao->op, "b") || !strcmp (ao->op, "b.n")) {
		ao->o = 0xe0;
		ao->o |= getnum (ao->a[0])<<8;
		return 2;
	} else
	if (!strcmp (ao->op, "bx")) {
		ao->o = 0x47;
		ao->o |= getreg (ao->a[0])<<11;
		return 2;
	} else
	if (!strcmp (ao->op, "bl")) {
		int reg = getreg (ao->a[0]);
		ao->o = 0x47;
		if (reg == -1) {
			ao->o |= getnum (ao->a[0])<<8;
		} else {
			return 0;
		}
		// XXX: length = 4
		return 4;
	} else
	if (*ao->op == 'b') { // conditional branch
		ao->o = 0xd0 | arm_opcode_cond (ao, 1);
		ao->o |= getnum (ao->a[0])<<8;
		return 2;
	} else
	if (!strcmp (ao->op, "mov")) {
		int reg = getreg (ao->a[1]);
		if (reg!=-1) {
			ao->o = 0x46;
			ao->o |= (getreg (ao->a[0]))<<8;
			ao->o |= reg<<11;
		} else {
			ao->o = 0x20;
			ao->o |= (getreg (ao->a[0]));
			ao->o |= (getnum (ao->a[1])&0xff)<<8;
		}
		return 2;
	} else
	if (!memcmp (ao->op, "ldr", 3)) {
		getrange (ao->a[1]);
		getrange (ao->a[2]);
		if (ao->op[3]=='h') {
			int a0 = getreg (ao->a[0]);
			int a1 = getreg (ao->a[1]);
			int a2 = getreg (ao->a[2]);
			if (a2 ==-1) {
				a2 = getnum (ao->a[2])/8;
				ao->o = 0x88; // | (8+(0xf & a0));
				ao->o |= (7&a0)<<8;
				ao->o |= (7&a1)<<11;
				ao->o += (7&a2);
				return 2;
			} else return 0;
		} else
		if (ao->op[3]=='b') {
			int a0 = getreg (ao->a[0]);
			int a1 = getreg (ao->a[1]);
			int a2 = getreg (ao->a[2]);
			if (a2 ==-1) {
				a2 = getnum (ao->a[2])/8;
				ao->o = 0x78; // | (8+(0xf & a0));
				ao->o |= (7&a0)<<8;
				ao->o |= (7&a1)<<11;
				ao->o |= (7&a2);
				return 2;
			} else return 0;
		} else {
			if (!strcmp (ao->a[1], "sp")) {
				// ldr r0, [sp, n] = a[r0-7][nn]
				if (getreg (ao->a[2]) == -1) {
					// ldr r0, [sp, n]
					ao->o = 0x98 + (0xf & getreg (ao->a[0]));
					ao->o |= (0xff & getnum (ao->a[2])/4)<<8;
					return 2;
				} else return 0;
			} else
			if (!strcmp (ao->a[1], "pc")) {
				// ldr r0, [pc, n] = 4[r0-8][nn*4]
				if (getreg (ao->a[2]) == -1) {
					ao->o = 0x40 | (8+(0xf & getreg (ao->a[0])));
					ao->o |= (0xff & getnum (ao->a[2])/4)<<8;
					return 2;
				} else return 0;
			} else {
				// ldr r0, [rN, rN] = 58[7bits:basereg + 7bits:destreg]
				int a0 = getreg (ao->a[0]);
				int a1 = getreg (ao->a[1]);
				int a2 = getreg (ao->a[2]);
				ao->o = 0x58; // | (8+(0xf & a0));
				ao->o |= (7&a0)<<8;
				ao->o |= (7&a1)<<11;
				ao->o |= (7&a2)<<14;
				return 2;
			}
		}
	} else
	if (!memcmp (ao->op, "str", 3)) {
		getrange (ao->a[1]);
		getrange (ao->a[2]);
		if (ao->op[3]=='h') {
			int a0 = getreg (ao->a[0]);
			int a1 = getreg (ao->a[1]);
			int a2 = getreg (ao->a[2]);
			if (a2 ==-1) {
				a2 = getnum (ao->a[2]);
				ao->o = 0x80; // | (8+(0xf & a0));
				ao->o |= (7&a0)<<8;
				ao->o |= (7&a1)<<11;
				ao->o |= (7&(a2>>1));
				return 2;
			}
		} else
		if (ao->op[3]=='b') {
			int a0 = getreg (ao->a[0]);
			int a1 = getreg (ao->a[1]);
			int a2 = getreg (ao->a[2]);
			if (a2 ==-1) {
				a2 = getnum (ao->a[2]);
				ao->o = 0x70; // | (8+(0xf & a0));
				ao->o |= (7&a0)<<8;
				ao->o |= (7&a1)<<11;
				ao->o |= (7&a2);
				return 2;
			}
		} else {
			if (!strcmp (ao->a[1], "sp")) {
				// ldr r0, [sp, n] = a[r0-7][nn]
				if (getreg (ao->a[2]) == -1) {
					int ret = getnum (ao->a[2]);
					if (ret%4) {
						eprintf ("ldr index must be aligned to 4");
						return 0;
					}
					ao->o = 0x90 + (0xf & getreg (ao->a[0]));
					ao->o |= (0xff & getnum (ao->a[2])/4)<<8;
					return 2;
				}
			} else
			if (!strcmp (ao->a[1], "pc")) {
				return 0;
			} else {
				int a0 = getreg (ao->a[0]);
				int a1 = getreg (ao->a[1]);
				int a2 = getreg (ao->a[2]);
				if (a2 == -1) {
					a2 = getnum (ao->a[2]);
					ao->o = 0x60;
					ao->o |= (7&a0)<<8;
					ao->o |= (7&a1)<<11;
					ao->o |= (3&(a2/4))<<14;
				} else {
					ao->o = 0x50;
					ao->o |= (7&a0)<<8;
					ao->o |= (7&a1)<<11;
					ao->o |= (3&a2)<<14;
				}
				return 2;
			}
		}
	} else
	if (!strcmp (ao->op, "tst")) {
		ao->o = 0x42;
		ao->o |= (getreg (ao->a[0]))<<8;
		ao->o |= getreg (ao->a[1])<<11;
		return 2;
	} else
	if (!strcmp (ao->op, "cmp")) {
		int reg = getreg (ao->a[1]);
		if (reg!=-1) {
			ao->o = 0x45;
			ao->o |= (getreg (ao->a[0]))<<8;
			ao->o |= reg<<11;
		} else {
			ao->o = 0x20;
			ao->o |= 8+(getreg (ao->a[0]));
			ao->o |= (getnum (ao->a[1])&0xff)<<8;
		}
		return 2;
	} else
	if (!strcmp (ao->op, "and") || !strcmp (ao->op, "and.w")) {
		int reg0 = getreg (ao->a[0]);
		int reg1 = getreg (ao->a[1]);
		int reg2 = getreg (ao->a[2]);
		if (reg0!=-1 && reg1 != -1) {
			if (reg2 == -1) {
				reg0 = getreg (ao->a[0]);
				reg1 = getreg (ao->a[0]);
				reg2 = getreg (ao->a[1]);
			}
			ao->o = 0;
			ao->o |= 0x00 | reg1;
			ao->o <<= 8;
			ao->o |= 0xea;
			ao->o <<= 8;
			ao->o |= 0x00 | reg2;
			ao->o <<= 8;
			ao->o |= 0xf0 | reg0;
			return 4;
		}
	} else
	if (!strcmp (ao->op, "mul") || !strcmp (ao->op, "mul.w")) {
		int reg0 = getreg (ao->a[0]);
		int reg1 = getreg (ao->a[1]);
		int reg2 = getreg (ao->a[2]);
		if (reg0!=-1 && reg1 != -1) {
			if (reg2 == -1) {
				reg0 = getreg (ao->a[0]);
				reg1 = getreg (ao->a[0]);
				reg2 = getreg (ao->a[1]);
			}
			ao->o = 0;
			ao->o |= 0x00 | reg1;
			ao->o <<= 8;
			ao->o |= 0xfb;
			ao->o <<= 8;
			ao->o |= 0x00 | reg2;
			ao->o <<= 8;
			ao->o |= 0xf0 | reg0;
			return 4;
		}
	} else
	if (!strcmp (ao->op, "add")) {
		// XXX: signed unsigned ??
		// add r, r = 44[7bits,7bits]
		// adds r, n = 3[r0-7][nn]
		int reg = getreg (ao->a[1]);
		if (reg!=-1) {
			ao->o = 0x44;
			ao->o |= (getreg (ao->a[0]))<<8;
			ao->o |= reg<<11;
		} else {
			ao->o = 0x30;
			ao->o |= (getreg (ao->a[0]));
			ao->o |= (getnum (ao->a[1])&0xff)<<8;
		}
		return 2;
	} else
	if (!strcmp (ao->op, "sub")) {
		int reg = getreg (ao->a[1]);
		if (reg!=-1) {
			int n = getnum (ao->a[2]); // TODO: add limit
			ao->o = 0x1e;
			ao->o |= (getreg (ao->a[0]))<<8;
			ao->o |= reg<<11;
			ao->o |= n/4 | ((n%4)<<14);
		} else {
			ao->o = 0x30;
			ao->o |= 8+(getreg (ao->a[0]));
			ao->o |= (getnum (ao->a[1])&0xff)<<8;
		}
		return 2;
	}
	return 0;
}

static int findyz(int x, int *y, int *z) {
        int i, j;
        for (i=0;i<0xff; i++) {
                for (j=0;j<0xf;j++) {
                        int v = i<<j;
                        if (v>x) continue;
                        if (v==x) {
                                *y = i;
                                *z = 16-(j/2);
                                return 1;
                        }
                }
        }
        return 0;
}

static int arm_assemble(ArmOpcode *ao, const char *str) {
	int i, j, ret, reg, a, b;
	for (i=0; ops[i].name; i++) {
		if (!memcmp (ao->op, ops[i].name, strlen (ops[i].name))) {
			ao->o = ops[i].code;
			arm_opcode_cond (ao, strlen(ops[i].name));
			if (ao->a[0] || ops[i].type == TYPE_BKP)
			switch (ops[i].type) {
			case TYPE_MEM:
				getrange (ao->a[0]);
				getrange (ao->a[1]);
				getrange (ao->a[2]);
				ao->o |= getreg (ao->a[0])<<20;
				ao->o |= getreg (ao->a[1])<<8; // delta
				ret = getreg (ao->a[2]);
				if (ret != -1) {
					ao->o |= (strstr (str,"],"))?6:7;
					ao->o |= (ret&0x0f)<<24;//(getreg(ao->a[2])&0x0f);
				} else {
					ao->o |= (strstr (str,"],"))?4:5;
					ao->o |= (getnum (ao->a[2])&0x7f)<<24; // delta
				}
				break;
			case TYPE_IMM:
				if (*ao->a[0]++=='{') {
					for (j=0; j<16; j++) {
						if (ao->a[j] && *ao->a[j]) {
							getrange (ao->a[j]); // XXX filter regname string
							reg = getreg (ao->a[j]);
							if (reg != -1) {
								if (reg<8)
									ao->o |= 1<<(24+reg);
								else
									ao->o |= 1<<(8+reg);
							}
						}
					}
				} else ao->o |= getnum (ao->a[0])<<24; // ???
				break;
			case TYPE_BRA:
				if ((ret = getreg (ao->a[0])) == -1) {
					// TODO: control if branch out of range
					ret = (getnum(ao->a[0])-(int)ao->off-8)/4;
					if (ret >= 0x00800000 || ret < (int)0xff800000) {
						eprintf("Branch into out of range\n");
						return 0;
					}
					ao->o |= ((ret>>16)&0xff)<<8;
					ao->o |= ((ret>>8)&0xff)<<16;
					ao->o |= ((ret)&0xff)<<24;
				} else {
					eprintf("This branch does not accept reg as arg\n");
					return 0;
				}
				break;
			case TYPE_BKP:
				ao->o |= 0x70<<24;
				if (ao->a[0]) {
					int n = getnum (ao->a[0]);
					ao->o |= ((n&0xf)<<24);
					ao->o |= (((n>>4)&0xff)<<16);
				}
				break;
			case TYPE_BRR:
				if ((ret = getreg(ao->a[0])) == -1) {
					eprintf("This branch does not accept off as arg\n");
					return 0;
				} else ao->o |= (getreg (ao->a[0])<<24);
				break;
			case TYPE_HLT:
				{
					ut32 o = 0, n = getnum (ao->a[0]);
					o |= ((n>>12)&0xf)<<8;
					o |= ((n>>8)&0xf)<<20;
					o |= ((n>>4)&0xf)<<16;
					o |= ((n)&0xf)<<24;
					ao->o |=o;
				}
				break;
			case TYPE_SWI:
				ao->o |= (getnum (ao->a[0])&0xff)<<24;
				ao->o |= ((getnum (ao->a[0])>>8)&0xff)<<16;
				ao->o |= ((getnum (ao->a[0])>>16)&0xff)<<8;
				break;
			case TYPE_ARI:
				if (!ao->a[2]) {
					ao->a[2] = ao->a[1];
					ao->a[1] = ao->a[0];
				}
				ao->o |= getreg (ao->a[0])<<20;
				ao->o |= getreg (ao->a[1])<<8;
				ret = getreg (ao->a[2]);
				ao->o |= (ret!=-1)? ret<<24 : 2 | getnum(ao->a[2])<<24;
				if (ao->a[3])
					ao->o |= getshift (ao->a[3]);
				break;
			case TYPE_SWP:
				ao->o = 0xe1;
				ao->o |= (getreg(ao->a[0])<<4)<<16;
				ao->o |= (0x90+getreg(ao->a[1]))<<24;
				ao->o |= (getreg(ao->a[2]+1))<<8;
				if (0xff==((ao->o>>16)&0xff))
					return 0;
				break;
			case TYPE_MOV:
				if (!strcmp (ao->op, "movs"))
					ao->o = 0xb0e1;
				ao->o |= getreg (ao->a[0])<<20;
				ret = getreg (ao->a[1]);
				if (ret!=-1) ao->o |= ret<<24;
				else ao->o |= 0xa003 | getnum (ao->a[1])<<24;
				break;
			case TYPE_TST:
				a = getreg (ao->a[0]);
				b = getreg (ao->a[1]);
				if (b == -1) {
					int y, z;
					b = getnum (ao->a[1]);
					if (b>=0 && b<=0xff) {
						ao->o = 0x50e3;
						// TODO: if (b>255) -> automatic multiplier
						ao->o |= (a<<8);
						ao->o |= ((b&0xff)<<24);
					} else
					if (findyz (b, &y, &z)) {
						ao->o = 0x50e3;
						ao->o |= (y<<24);
						ao->o |= (z<<16);
					} else {
						eprintf ("Parameter %d out of range (0-255)\n", (int)b);
						return 0;
					}
				} else {
					ao->o |= (a<<8);
					ao->o |= (b<<24);
					if (ao->a[2])
						ao->o |= getshift (ao->a[2]);
				}
				if (ao->a[2]) {
					int n = getnum (ao->a[2]);
					if (n&1) {
						eprintf ("Invalid multiplier\n");
						return 0;
					}
					ao->o |= (n>>1)<<16;
				}
				break;
			}
			return 1;
		}
	}
	return 0;
}

typedef int (*AssembleFunction)(ArmOpcode *, const char *);
static AssembleFunction assemble[2] = { &arm_assemble, &thumb_assemble };

ut32 armass_assemble(const char *str, ut64 off, int thumb) {
	int i, j;
	char buf[128];
	ArmOpcode aop = {.off = off};
	for (i=j=0; i<sizeof (buf)-1 && str[i]; i++, j++) {
		if (str[j]=='#') { i--; continue; }
		buf[i] = tolower ((const unsigned char)str[j]);
	}
	buf[i] = 0;
	arm_opcode_parse (&aop, buf);
	aop.off = off;
	if (thumb <0 || thumb>1 || !assemble[thumb] (&aop, buf)) {
	//	printf ("armass: Unknown opcode (%s)\n", buf);
		return -1;
	}
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
	thisplay ("ldmia r1!, {r3, r4, r5}");
	thisplay ("stmia r1!, {r3, r4, r5}");
	thisplay ("bkpt 12");
return 0;
	thisplay("sub r1, r2, 0");
	thisplay("sub r1, r2, 4");
	thisplay("sub r1, r2, 5");
	thisplay("sub r1, r2, 7");
	thisplay("sub r3, 44");
return 0;
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
#if 0
   0:   8991            ldrh    r1, [r2, #12]
   2:   7b11            ldrb    r1, [r2, #12]
   4:   8191            strh    r1, [r2, #12]
   6:   7311            strb    r1, [r2, #12]
#endif
	thisplay("ldrh r1, [r2, 8]"); // aligned to 4
	thisplay("ldrh r1, [r3, 8]"); // aligned to 4
	thisplay("ldrh r1, [r4, 16]"); // aligned to 4
	thisplay("ldrh r1, [r2, 32]"); // aligned to 4
	thisplay("ldrb r1, [r2, 20]"); // aligned to 4
	thisplay("strh r1, [r2, 20]"); // aligned to 4
	thisplay("strb r1, [r2, 20]"); // aligned to 4
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
