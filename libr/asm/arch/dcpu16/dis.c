/* copypasted from http://pastie.org/3732465 */
/* adapted by pancake // public license */
/* known bugs: some (%s, NULL) happen */

#include <stdio.h>
#include <stdlib.h>
#include "dcpu16.h"


struct op_code {
	ut8 opcode;
};

struct op_basic {
	ut8 opcode;
	ut8 a_type;
	ut8 b_type;

	ut16 a;
	ut16 b;
};

struct op_nbasic {
	ut8 __empty;
	ut8 a_type;
	ut8 opcode;
	ut16 a;
};

typedef union {
	struct op_code code;
	struct op_basic b;
	struct op_nbasic n;
} op;

static const int opCycle[] = {
	0, 1, 2, 2, 2, 3, 3, 2, 2, 1, 1, 1, 2, 2, 2, 2
};
static const int opCycleB[] = { 0, 2 };

static const char* opName[] = {
	"", "set",
	"add", "sub", "mul", "div", "mod",
	"shl", "shr", "and", "bor", "xor",
	"ife", "ifn", "ifg", "ifb"
};

static const char* opNameB[] = { "reserved", "jsr" };

static const char* regs[] = {
	"a", "b", "c", "x", "y", "z", "i", "j",
	"pop", "peek", "push", "sp", "pc", "o"
};

static inline int needWord(ut8 type) {
	return ((type <= 0x17) && (type > 0x0f)) \
		|| (type == 0x1e) || (type == 0x1f);
}

static int valPrint(char *out, ut8 type, ut16 value) {
	if (type <= 0x07) return sprintf(out, "%s", regs[type]);
	if (type <= 0x0f) return sprintf(out, "[%s]", regs[type - 0x08]);
	if (type <= 0x17) return sprintf(out, "[%s + %#hx]", regs[type - 0x10], value);
	if (type <= 0x1d) return sprintf(out, "%s", regs[type - 0x18 + 0x08]);
	if (type == 0x1e) return sprintf(out, "[%#hx]", value);
	if (type == 0x1f) return sprintf(out, "%#hx", value);
	return sprintf(out, "%#hx", (short)(type - 0x20));
}

static int instrPrint(char *out, const op* o) {
	char arg[32], arg2[32];
	if (o->code.opcode == 0) {
		valPrint (arg, o->n.a_type, o->n.a);
		return sprintf(out, "%s %s",
			opNameB[o->n.opcode], arg);
	}
	valPrint (arg, o->b.a_type, o->b.a);
	valPrint (arg2, o->b.b_type, o->b.b);
	return sprintf(out, "%s %s, %s", opName[o->b.opcode], arg, arg2);
}

static int instrGet(ut16 in, op* o, ut16 a, ut16 b) {
	int ret = 1;
	o->code.opcode = in & 0xF;
	if (!(o->code.opcode = in & 0xF)) {
		/* Non basic op code */
		o->n.opcode = (in >> 4) & 0x3F;
		o->n.a_type = (in >> 10) & 0x3F;

		if (needWord(o->n.a_type)) {
			o->n.a = a;
			ret++;
		}
	} else {
		o->b.a_type = (in >> 4) & 0x3F;
		o->b.b_type = (in >> 10) & 0x3F;
		if (needWord(o->b.a_type)) {
			o->b.a = a;
			ret++;
			if (needWord (o->b.b_type)) {
				o->b.b = b;
				ret++;
			}
		} else if (needWord(o->b.b_type)) {
			o->b.b = a;
			ret++;
		}
	}
	return ret;
}

static int instrGetCycles(const op* o) {
	if (o->code.opcode == 0)
		return opCycleB[o->n.opcode] + needWord(o->n.a_type);
	return opCycle[o->b.opcode] + needWord(o->b.a_type)
		+ needWord(o->b.b_type);
}

int dcpu16_disasm(char *out, const ut16* inp, int len, int *cost) {
	op o;
	int delta = instrGet (inp[0], &o, inp[1], inp[2]);
	if (cost) *cost = instrGetCycles(&o) + ((o.b.opcode >= 0xc)?1:0);
	instrPrint (out, &o);
	//ind = (o.b.opcode >= 0xC);
	return delta<<1;
}
