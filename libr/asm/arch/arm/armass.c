/* radare - LGPL - Copyright 2010 pancake<@nopcode.org> */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


typedef struct {
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
	TYPE_ARI = 5,
	TYPE_IMM = 6,
};

static ArmOp ops[] = {
	{ "adc", 0xa000, TYPE_ARI },
	{ "adcs", 0xb000, TYPE_ARI },
	{ "add", 0x8000, TYPE_ARI },
	{ "adds", 0x9000, TYPE_ARI },
	{ "sub", 0x4000, TYPE_ARI },
	{ "subs", 0x5000, TYPE_ARI },
	{ "sbc", 0xc000, TYPE_ARI },
	{ "sbcs", 0xd000, TYPE_ARI },
	{ "rsb", 0x6000, TYPE_ARI },
	{ "rsbs", 0x7000, TYPE_ARI },
	{ "rsc", 0xe000, TYPE_ARI },
	{ "rscs", 0xf000, TYPE_ARI },

	{ "cps", 0xb1, TYPE_IMM },

	{ "blx", 0x30ff2fe1, TYPE_BRA },
	{ "bl", 0xb, TYPE_BRA },
	{ "bx", 0x10ff2fe1, TYPE_BRA },
	//{ "bx", 0xb, TYPE_BRA },
	{ "b", 0xa, TYPE_BRA },

	{ "str", 0x4, TYPE_MOV },

	{ "mov", 0x3, TYPE_MOV },
	{ "mvn", 0, TYPE_MOV },
	{ "svc", 0xf, TYPE_SWI }, // ???

	{ "and", 0x0, TYPE_TST },
	{ "ands", 0x1000, TYPE_TST },
	{ "eor", 0x2000, TYPE_TST },
	{ "eors", 0x3000, TYPE_TST },
	{ "orr", 0x0, TYPE_TST },
	{ "bic", 0x0, TYPE_TST },

	{ "cmp", 0x0, TYPE_TST },
	{ "cmn", 0x0, TYPE_TST },
	{ "teq", 0x0, TYPE_TST },
	{ "tst", 0xe1, TYPE_TST },
	NULL
};

static int getnum(const char *str) {
	while (str&&(*str=='$'||*str=='#'))
		str++;
	if (*str=='0'&&str[1]=='x') {
		int x;
		if(sscanf(str+2, "%x", &x))
			return x;
	}
	return atoi(str);
}

static int getreg(const char *str) {
	if (!str)
		return 0;
	if (!strcmp(str, "pc"))
		return 15;
	if (!strcmp(str, "lr"))
		return 14;
	if (!strcmp(str, "sp"))
		return 13;
	if (!strcmp(str, "ip"))
		return 12;
	if (!strcmp(str, "fp"))
		return 11;
	if (!strcmp(str, "sl"))
		return 10;
	if (*str=='r')
		return atoi (str+1);
	return 0; // XXX
}

static int getshift(const char *str) {
	if(!str) return 0;
	while (str&&*str&&!atoi(str))
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

static int arm_opcode_cond(ArmOpcode *ao, int delta) {
	const char *conds[] = {
		"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
		"hi", "ls", "ge", "lt", "gt", "le", "al", "nv", 0
	};
	int i, cond = 14; // 'always' is default
	char *c = ao->op+delta;
	for(i=0;conds[i];i++) {
		if (!strcmp(c, conds[i])) {
			cond = i;
			break;
		}
	}
	ao->o |= cond<<4;
}

static int arm_opcode_name(ArmOpcode *ao) {
	int i, ret;
	for (i=0;ops[i].name;i++) {
		if (!memcmp(ao->op, ops[i].name, strlen (ops[i].name))) {
			ao->o = (ops[i].code);//<<24;
			arm_opcode_cond(ao, strlen(ops[i].name));
			switch(ops[i].type) {
			case TYPE_IMM:
				ao->o |= getnum(ao->a0)<<24; // ???
				break;
			case TYPE_BRA:
				if (!(ret = getreg(ao->a0)<<24)) {
				// XXX: Needs to calc (eip-off-8)>>2
			arm_opcode_cond(ao, strlen(ops[i].name));
					ao->o = ao->o&0x70 | 0xb | getnum(ao->a0)<<24;
				} else ao->o |= ret;
				printf("---> %s\n", ao->a0);
				break;
			case TYPE_SWI:
				ao->o |= getnum(ao->a0)<<24;
				break;
			case TYPE_ARI:
				ao->o |= getreg(ao->a0)<<20;
				ao->o |= getreg(ao->a1)<<8;
				ao->o |= getreg(ao->a2)<<24;
				break;
			case TYPE_MOV:
				ao->o |= getreg(ao->a0)<<20;
				ao->o |= getnum(ao->a1)<<24;
				break;
			case TYPE_TST:
				ao->o |= getreg(ao->a0)<<20;
				ao->o |= getreg(ao->a1)<<24;
				ao->o |= getshift(ao->a2)<<16; // shift
				break;
			}
			return 1;
		}
	}
	return 0;
}

// XXX: check endian stuff
int armass_assemble(const char *str) {
	ArmOpcode aop = {0};
	arm_opcode_parse (&aop, str);
	if (!arm_opcode_name (&aop)) {
		printf ("Unknown opcode\n");
		return -1;
	}
	////printf ("PARSE (%s) (%s)(%s)(%s)\n", aop.op, aop.a0, aop.a1, aop.a2);
	return aop.o;
}

#ifdef MAIN
void display(const char *str) {
	char cmd[32];
	int op = armass_assemble(str);
	printf("%08x %s\n", op, str);
	snprintf(cmd, sizeof(cmd), "rasm2 -d -a arm %08x", op);
	system(cmd);
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
#endif
	display("adds r3, #8");
	display("subs r2, #1");
	display("bne r3");
	display("str r1, 33");
	display("cmp r1, r3");
	display("bcc 33");
	display("blx r1");
	display("bx r1");
	display("blx 0x8048");
#if 0
	display("b 0x123");
	display("bl 0x123");
	display("blt 0x123"); // XXX: not supported
#endif
}
#endif
