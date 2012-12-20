/* RAR-VM assembler/disassembler by pancake for radare with love */
/* this implementation is licensed under LGPLv3 - 2012 */

#include <stdio.h>
#include <string.h>

// XXX little endian only?

/* helpers */
#define eprintf(x,y...) fprintf(stderr,x,##y)
#define SKIPSPACES(x) if (x) while (*x==' '||*x=='\t') x++
static const char *skipspaces(const char *x) { SKIPSPACES(x); return x; }
//static const char *regs = "r0\x00r1\x00r2\x00r3\x00r4\x00r5\x00r6\x00r7";
//static const char *getregi(int n) { return (n>=0&&n<=7)? regs+(3*n): "r?"; }
static int getreg(const char *s) {
	if (s[0]=='r' && s[2]=='\0') {
		int n = s[1]-'0';
		if (n<8) return n;
	}
	return -1;
}

// ugly global vars
typedef struct {
	int bits;
	unsigned char *out;
} Bitbuf;

//static void clrbit(Bitbuf *bb) { memset (bb->out, 0, 1+(bb->bits/8)); }

static int bitget(Bitbuf *bb, int bit) {
	if (bit>=bb->bits) return -1;
	return (bb->out[bit/8] & (1<<((bit%8))))? 1: 0;
}

static void bitadd(Bitbuf *bb, unsigned int v, int n) {
	int i, b, bit;
	for (i=0; i<n; i++, bb->bits++) {
		b = (bb->bits+i)/8;
		bit = (bb->bits+i)%8;
//printf ("[%d].%d = %d\n", b, bit, v& (1<<(n-i-1)));
		if (!bit) bb->out[b] = 0;
//printf ("BIT (%d)\n", n-i-1);
		//if (v&(1<<(n-i-1))) bb->out[b] |= 1<<bit;
		if (v&(1<<(n-i-1))) bb->out[b] |= 1<<bit;
	//	printf ("%d", oz);
	}
	//printf ("\n");
}

#define T_BYTE (1<<2)
#define T_JUMP (1<<3)
#define T_PROC (1<<4)

#define NOPS 53
static struct {
	const char *name;
	int flags;
} opcodes [NOPS] = {
	{ "mov",  3|T_BYTE },
	{ "cmp",  3|T_BYTE },
	{ "add",  3|T_BYTE },
	{ "sub",  1|T_BYTE },
	{ "jz",   1|T_JUMP },
	{ "jnz",  1|T_JUMP },
	{ "inc",  1|T_BYTE },
	{ "dec",  1|T_BYTE },
	{ "jmp",  1|T_JUMP },
	{ "xor",  3|T_BYTE },
	{ "and",  3|T_BYTE },
	{ "or",   3|T_BYTE },
	{ "test", 3|T_BYTE },
	{ "js",   1|T_JUMP },
	{ "jb",   1|T_JUMP },
	{ "jbe",  1|T_JUMP },
	{ "ja",   1|T_JUMP },
	{ "jae",  1|T_JUMP },
	{ "push", 1 },
	{ "pop",  1 },
	{ "call", 1|T_PROC },
	{ "ret",    T_PROC },
	{ "not",  1|T_BYTE },
	{ "shl",  3|T_BYTE },
	{ "shr",  3|T_BYTE },
	{ "sar",  3|T_BYTE },
	{ "neg",  1|T_BYTE },
	{ "pusha",0 },
	{ "popa", 0 },
	{ "pushf",0 },
	{ "popf", 0 },
	{ "movzx",3 },
	{ "movsx",3 },
	{ "xchg", 3|T_BYTE },
	{ "mul",  3|T_BYTE },
	{ "div",  3|T_BYTE },
	{ "adc",  3|T_BYTE },
	{ "sbb",  3|T_BYTE },
	{ "print",0 },
	{ "movb", 0 },
	{ "movd", 0 },
	{ "cmpb", 0 },
	{ "cmpd", 0 },
	{ "addb", 0 },
	{ "addd", 0 },
	{ "subb", 0 },
	{ "subd", 0 },
	{ "incb", 0 },
	{ "incd", 0 },
	{ "decb", 0 },
	{ "decd", 0 },
	{ "negb", 0 },
	{ "negd", 0 },
};

#if 0
static int bitnum (Bitbuf *bb, int n, int c) {
	int i, ret = 0;
	if (n<bb->bits)
		for (i=0; i<c; i++)
			if (bitget (bb, n+i)>0)
				ret |= (1<<i);
	return ret;
}
#else
static int bitnum (Bitbuf *bb, int n, int c) {
	int i, ret = 0;
	if (n<bb->bits)
		for (i=0; i<c; i++)
			if (bitget (bb, n+i)>0)
				ret |= (1<<(c-i-1));
	return ret;
}

#endif
static inline const char *opcode_str (int n) {
	if (n>=0 && n<NOPS)
		return opcodes[n].name;
	return NULL;
}
static inline int opcode_num (const char *s) {
	int i;
	for (i=0; opcodes[i].name; i++)
		if (!strcmp (s, opcodes[i].name))
			return i;
	return -1;
}
