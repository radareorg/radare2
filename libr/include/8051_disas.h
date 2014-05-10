#ifndef R2_8051_DISASM_H
#define R2_8051_DISASM_H

typedef struct op {
	const char *name;
	int length;
	int operand;
	ut32 addr;
	const char *arg;
	const ut8 *buf;
} r_8051_op;

enum {
	NONE = 0,
	ADDR11, // 8 bits from argument + 3 high bits from opcode
	ADDR16, // A 16-bit address destination. Used by LCALL and LJMP
	DIRECT, // An internal data RAM location (0-127) or SFR (128-255).
	OFFSET, // same as direct?
	ARG,    // register
};

r_8051_op r_8051_decode(const ut8 *buf, int len);
char *r_8051_disasm(r_8051_op op, ut32 addr, char *str, int len);

#endif /* 8051_DISASM_H */

