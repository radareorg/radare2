#if 0

http://www.keil.com/support/man/docs/is51/is51_instructions.htm
http://www.keil.com/support/man/docs/is51/is51_opcodes.htm

// TODO: extend support for 251

The classic 8051 provides 4 register banks of 8 registers each.
These register banks are mapped into the DATA memory area at
address 0 – 0x1F. In addition the CPU provides a 8-bit A
(accumulator) and B register and a 16-bit DPTR (data pointer)
for addressing XDATA and CODE memory. These registers are also
mapped into the SFR space as special function registers.

|-----------------------|
 r0 r1 r2 r3 r4 r5 r6 r7  0x00
 r0 r1 r2 r3 r4 r5 r6 r7  0x08
 r0 r1 r2 r3 r4 r5 r6 r7  0x10
 r0 r1 r2 r3 r4 r5 r6 r7  0x18

A = acumulator
B = general purpose
DPTR = 16 bit pointer to data

PSW1 - status word register

Bit 7	Bit 6	Bit 5	Bit 4	Bit 3	Bit 2	Bit 1	Bit 0
CY	AC	N	RS1	RS0	OV	Z	—

The following table describes the status bits in the PSW:

RS1 RS0 Working Register Bank and Address
0 0 Bank0 (D:0x00 - D:0x07)
0 1 Bank1 (D:0x08 - D:0x0F)
1 0 Bank2 (D:0x10 - D:0x17)
1 1 Bank3 (D:0x18H - D:0x1F)

#endif

#include <r_types.h>

typedef struct op {
	const char *name;
	int length;
	int operand;
	ut32 addr;
	const char *arg;
	const ut8 *buf;
} Op8051;

enum {
	NONE = 0,
	ADDR11, // 8 bits from argument + 3 high bits from opcode
	ADDR16, // A 16-bit address destination. Used by LCALL and LJMP
	DIRECT, // An internal data RAM location (0-127) or SFR (128-255).
	OFFSET, // same as direct?
	ARG,    // register
};

#undef _
#define _ (Op8051)
#define _ARG(x) ARG, 0, x, buf
#define _ADDR11(x) ADDR11, ((x[1])+((x[0]>>5)<<8)), NULL, buf
#define _ADDR16(x) ADDR16, ((x[1])<<8)+((x[2])), NULL, buf
#define _OFFSET(x) OFFSET, ((x[1])), NULL, buf
#define _DIRECT(x) DIRECT, (x[1]), NULL, x

static const char *arg[] = { "#immed", "direct", "@r0", "@r1", "r0",
	"r1", "r1", "r2", "r3", "r4", "r5", "r6", "r7" };
static const char *ops[] = {
	"inc",         // 0.   04 : immed=a
	"dec",         // 1.   14 : immed=a
	"add a,",      // 2.
	"addc a,",     // 3.
	"orl a,",      // 4.
	"anl a,",      // 5.
	"xrl a,",      // 6.
	"+#immed;mov", // 7.    74 == immed=a
	"mov direct,", // 8.    84 == DIV AB
	"subb a,",     // 9.
	"+direct;mov", // A.    A4 == MUL AB
	"+, $1, $2;cjne",
		// B4, B4 = {cjne a, {#immed,direct}, offset}
		// cjne arg, #immed, offset
	"xch a,",       // C.   C4 == SWAP A
	"+offset;djnz", // D.   D4 = DA
			//      D5 = DJNZ d,off
			//      D6,7 = XCHD A, r0,1
	"mov a,",       // E.   E4 == CLR A
	"+, a;mov"      // F.   F4 == CPL A
};

Op8051 do8051struct(const ut8 *buf, int len) {
	ut8 op = buf[0];
	if (!op) return _{ "nop", 1, NONE, 0 };
	if ((op&0xf)==1)
		return _{((op>>4)%2)? "acall": "ajmp", 2, _ADDR11(buf)};
	switch (op) {
	case 0x10: return _{ "jbc bit,", 3, _ADDR16(buf) };
	case 0x20: return _{ "jb bit,", 3, _ADDR16(buf) };
	case 0x30: return _{ "jnb bit,", 3, _ADDR16(buf) };
	case 0x40: return _{ "jc", 2, _OFFSET(buf) };
	case 0x50: return _{ "jnc", 2, _OFFSET(buf) };
	case 0x60: return _{ "jz", 2, _OFFSET(buf) };
	case 0x70: return _{ "jnz", 2, _OFFSET(buf) };
	case 0x80: return _{ "sjmp", 2, _OFFSET(buf) };

	case 0x90: return _{ "mov dptr, #immed", 3, _ADDR16(buf) }; // XXX
	case 0xa0: return _{ "orl c, /bin", 2, NONE };
	case 0xb0: return _{ "anl c, /bin", 2, NONE };

	case 0xc0: return _{ "push direct", 2, NONE };
	case 0xd0: return _{ "pop direct", 2, NONE };

	case 0x02: return _{ "ljmp", 3, _ADDR16(buf) };
	case 0x12: return _{ "lcall", 3, _ADDR16(buf) };
	case 0x22: return _{ "ret", 1, NONE };
	case 0x32: return _{ "reti", 1, NONE };
	case 0x42: return _{ "orl direct, a", 2, _DIRECT (buf)};
	case 0x92: return _{ "+, c;mov", 2, _DIRECT (buf) };
	case 0xc2: return _{ "clr  c", 1, _DIRECT (buf) };
	case 0xd2: return _{ "setb", 2, _DIRECT (buf) };
	case 0xa2: return _{ "mov c,", 2, _DIRECT (buf) };

	case 0x03: return _{ "rr a", 1, NONE };
	case 0x13: return _{ "rrc a", 1, NONE };
	case 0x23: return _{ "rl a", 1, NONE };
	case 0x33: return _{ "rlc a", 1, NONE };
	case 0x43: return _{ "orl direct, #imm", 3, NONE };
	case 0x73: return _{ "jmp @a+dptr", 1, NONE };
	case 0x83: return _{ "movc a, @a+pc", 1, NONE };
	case 0x93: return _{ "movc a, @a+dptr", 1, NONE };
	case 0xa3: return _{ "inc dptr", 1, NONE };
	case 0xb3: return _{ "cpl c", 1, NONE };
	case 0xc3: return _{ "clr c", 1, NONE };
	case 0xd3: return _{ "setb c", 1, NONE };

	case 0xe0: return _{ "movx a, @dptr", 1, NONE };
	case 0xe2: return _{ "movx a, @r0", 1, NONE };
	case 0xe3: return _{ "movx a, @r1", 1, NONE };
	case 0xf0: return _{ "movx @dptr, a", 1, NONE };
	case 0xf2: return _{ "movx @r0, a", 1, NONE };
	case 0xf3: return _{ "movx @r1, a", 1, NONE };
	}
	// general opcodes
	if ((op&0xf)>=4) {
		int opidx = (op>>4);
		int argidx = (op&0xf)-4;
		const char *opstr = ops[opidx];
		const char *argstr = arg[argidx];
		int length = ((op&0xf)<6)? 2: 1;
		/* exceptions */
		switch (op) {
		case 0x04: length = 1; opstr = "inc a"; break;
		case 0x14: length = 1; opstr = "dec a"; break;
		case 0x74: opstr = "mov a,"; break;
		case 0xa4: opstr = "mul ab"; break;
		case 0xa5: opstr = "reserved"; break;
		case 0x75: length = 3; break;
		case 0xc4: opstr = "swap a"; break;
		case 0xd4: opstr = "da a"; break;
		case 0xd5: opstr = "djnz d, "; break;
		case 0xd6: opstr = "xchd a, r0"; break;
		case 0xd7: opstr = "xchd a, r1"; break;
		case 0xe4: opstr = "clr a"; break;
		case 0xf4: opstr = "cpl a"; break;
		}
		/* exceptions */
		if (op==0x06) length = 2;
		else if (op==0x84) length = 1;
		else if (op==0x85) length = 3;
		else if (op==0x85) length = 3;
		return _{ opstr, length, _ARG (argstr) };
	}
	return _{ "xxx", 0 }; // XXX
}

static char *strdup_filter (const char *str, const ut8 *buf) {
	int i, j, len = strlen (str);
	char *o = malloc (1+len*4);
	for (i=j=0; i<len; i++) {
		if (str[i] == '$') {
			int n = str[i+1];
			if (n>='0' && n<='9') {
				n -= '0';
				i++;
				j += sprintf (o+j, "0x%02x", buf[n]);
			} else eprintf ("strdup_filter: Internal bug\n");
		} else o[j++] = str[i];
	}
	o[j] = 0;
	return o;
}

char *do8051disasm(Op8051 op, char *str, int len) {
	char *tmp, *eof, *out = str? str: malloc ((len=32));
	switch (op.operand) {
	case NONE: strcpy (out, op.name); break;
	case ARG: snprintf (out, len, "%s %s", op.name, op.arg); break;
	case ADDR11:
	case ADDR16: snprintf (out, len, "%s %d", op.name, op.addr); break;
	}
	if (*out == '+') {
		eof = strchr (out+1, ';');
		if (eof) {
			*eof = 0;
			tmp = strdup_filter (out+1, (const ut8*)op.buf);
			strcpy (out, eof+1);
			strcat (out, tmp);
			free (tmp);
		} else eprintf ("do8051disasm: Internal bug\n");
	}
	return out;
}

Op8051 do8051assemble(const char *str) {
	return _{"TODO"};
}

#if MAIN

int main() {
	char *str;
	ut8 buf[3] = {0xb3, 0x11, 0x22};
	Op8051 op = do8051struct (buf, sizeof (buf));
	str = do8051disasm (op, NULL, 0);
	eprintf ("%s\n", str);
	free (str);
	return 0;
}

#endif
