/* radare - LGPL - Copyright 2010 pancake<@nopcode.org> */

// TODO: Add thumb mode
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


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
	while (*str=='$'||*str=='#')
		str++;
	if (*str=='0'&&str[1]=='x') {
		int x;
		if (sscanf (str+2, "%x", &x))
			return x;
	}
	return atoi(str);
}

static char *getrange(char *s) {
	char *p = NULL;
	while(s&&*s) {
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
	while (p&&*p==' ') p++;
	return p;
}

static int getreg(const char *str) {
	int i;
	const char *aliases[] = { "sl", "fp", "ip", "sp", "lr", "pc", NULL };
	if (!str)
		return -1;
	if (*str=='r')
		return atoi (str+1);
	for(i=0;aliases[i];i++)
		if (!strcmp (str, aliases[i]))
			return 10+i;
	return -1;
}

static int getshift(const char *str) {
	if(!str) return 0;
	while (str&&*str&&!atoi (str))
		str++;
	return atoi(str)/2;
}

static void arm_opcode_parse(ArmOpcode *ao, const char *str) {
	memset (ao, 0, sizeof (ArmOpcode));
	strncpy (ao->op, str, sizeof(ao->op));
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

static void arm_opcode_cond(ArmOpcode *ao, int delta) {
	const char *conds[] = {
		"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
		"hi", "ls", "ge", "lt", "gt", "le", "al", "nv", 0
	};
	int i, cond = 14; // 'always' is default
	char *c = ao->op+delta;
	for (i=0;conds[i];i++) {
		if (!strcmp (c, conds[i])) {
			cond = i;
			break;
		}
	}
	ao->o |= cond<<4;
}

static int arm_opcode_name(ArmOpcode *ao, const char *str) {
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
					int reg, regmask;
					getrange (ao->a0+1); // XXX filter regname string
					reg = getreg(ao->a0+1);
					regmask = (reg>7)? 1<<(reg-8): 1<<(reg+8);
					if (reg>=0 && reg<=0xf)
						ao->o |= regmask<<16;
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
				if ((ret = getreg(ao->a0)) != -1) {
					ao->o |= (getreg (ao->a0)<<24);
				} else {
					printf("This branch does not accept off as arg\n");
					return 0;
				}
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

int armass_assemble(const char *str, unsigned long off) {
	ArmOpcode aop = {0};
	aop.off = off;
	arm_opcode_parse (&aop, str);
	if (!arm_opcode_name (&aop, str)) {
		printf ("armass: Unknown opcode (%s)\n", str);
		return -1;
	}
	////printf ("PARSE (%s) (%s)(%s)(%s)\n", aop.op, aop.a0, aop.a1, aop.a2);
	return aop.o;
}

#ifdef MAIN
void display(const char *str) {
	char cmd[32];
	int op = armass_assemble (str, 0x1000);
	printf ("%08x %s\n", op, str);
	snprintf (cmd, sizeof(cmd), "rasm2 -d -a arm %08x", op);
	system (cmd);
}

main() {
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
#endif

   //10ab4:       00047e30        andeq   r7, r4, r0, lsr lr
   //10ab8:       00036e70        andeq   r6, r3, r0, ror lr

	display("andeq r7, r4, r0, lsr lr");
	display("andeq r6, r3, r0, ror lr");
	display("push {fp,lr}");
	display("pop {fp,lr}");


#if 0
	display("blx r1");
	display("blx 0x8048");
#endif

#if 0
	display("b 0x123");
	display("bl 0x123");
	display("blt 0x123"); // XXX: not supported
#endif
}
#endif
