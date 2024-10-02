/* radare2 - PD - Copyright 2024 - pancake */

#include <r_util.h>

#define MAX_INSTRUCTION_LEN 16
#define NUM_INSTRUCTIONS 256

typedef struct {
	uint8_t opcode;
	int operand;
} Instruction;

static const char* instruction_mnemonics[NUM_INSTRUCTIONS] = {
	"brk", "inc", "pop", "nip", "swp", "rot", "dup", "ovr",
	"equ", "neq", "gth", "lth", "jmp", "jcn", "jsr", "sth",
	"ldz", "stz", "ldr", "str", "lda", "sta", "dei", "deo",
	"add", "sub", "mul", "div", "and", "ora", "eor", "sft",
	"jci", "inc2", "pop2", "nip2", "swp2", "rot2", "dup2", "ovr2",
	"equ2", "neq2", "gth2", "lth2", "jmp2", "jcn2", "jsr2", "sth2",
	"ldz2", "stz2", "ldr2", "str2", "lda2", "sta2", "dei2", "deo2",
	"add2", "sub2", "mul2", "div2", "and2", "ora2", "eor2", "sft2",
	"jmi", "incr", "popr", "nipr", "swpr", "rotr", "dupr", "ovrr",
	"equr", "neqr", "gthr", "lthr", "jmpr", "jcnr", "jsrr", "sthr",
	"ldzr", "stzr", "ldrr", "strr", "ldar", "star", "deir", "deor",
	"addr", "subr", "mulr", "divr", "andr", "orar", "eorr", "sftr",
	"jsi", "inc2r", "pop2r", "nip2r", "swp2r", "rot2r", "dup2r", "ovr2r",
	"equ2r", "neq2r", "gth2r", "lth2r", "jmp2r", "jcn2r", "jsr2r", "sth2r",
	"ldz2r", "stz2r", "ldr2r", "str2r", "lda2r", "sta2r", "dei2r", "deo2r",
	"add2r", "sub2r", "mul2r", "div2r", "and2r", "ora2r", "eor2r", "sft2r",
	"lit", "inck", "popk", "nipk", "swpk", "rotk", "dupk", "ovrk",
	"equk", "neqk", "gthk", "lthk", "jmpk", "jcnk", "jsrk", "sthk",
	"ldzk", "stzk", "ldrk", "strk", "ldak", "stak", "deik", "deok",
	"addk", "subk", "mulk", "divk", "andk", "orak", "eork", "sftk",
	"lit2", "inc2k", "pop2k", "nip2k", "swp2k", "rot2k", "dup2k", "ovr2k",
	"equ2k", "neq2k", "gth2k", "lth2k", "jmp2k", "jcn2k", "jsr2k", "sth2k",
	"ldz2k", "stz2k", "ldr2k", "str2k", "lda2k", "sta2k", "dei2k", "deo2k",
	"add2k", "sub2k", "mul2k", "div2k", "and2k", "ora2k", "eor2k", "sft2k",
	"litr", "inckr", "popkr", "nipkr", "swpkr", "rotkr", "dupkr", "ovrkr",
	"equkr", "neqkr", "gthkr", "lthkr", "jmpkr", "jcnkr", "jsrkr", "sthkr",
	"ldzkr", "stzkr", "ldrkr", "strkr", "ldakr", "stakr", "deikr", "deokr",
	"addkr", "subkr", "mulkr", "divkr", "andkr", "orakr", "eorkr", "sftkr",
	"lit2r", "inc2kr", "pop2kr", "nip2kr", "swp2kr", "rot2kr", "dup2kr", "ovr2kr",
	"equ2kr", "neq2kr", "gth2kr", "lth2kr", "jmp2kr", "jcn2kr", "jsr2kr", "sth2kr",
	"ldz2kr", "stz2kr", "ldr2kr", "str2kr", "lda2kr", "sta2kr", "dei2kr", "deo2kr",
	"add2kr", "sub2kr", "mul2kr", "div2kr", "and2kr", "ora2kr", "eor2kr", "sft2kr"
};

static int find_opcode(const char* mnemonic) {
	char upper_mnemonic[MAX_INSTRUCTION_LEN];
	r_str_ncpy (upper_mnemonic, mnemonic, sizeof (upper_mnemonic));
	r_str_case (upper_mnemonic, false);
	int i;

	for (i = 0; i < NUM_INSTRUCTIONS; i++) {
		if (!strcmp (instruction_mnemonics[i], upper_mnemonic)) {
			return i;
		}
	}
	return -1;
}

int uxn_assemble(const char* mnemonic, uint8_t* code, size_t code_size) {
	int code_len = 0;
	if (code_size < 3) {
		return -1;
	}
	Instruction instr = {0};
	char op[MAX_INSTRUCTION_LEN];
	r_str_ncpy (op, mnemonic, sizeof (op));
	char *arg = strchr (op, ' ');
	int args = 0;
	if (arg) {
		*arg++ = 0;
		instr.operand = atoi (arg);
		args++;
	}

	int opcode = find_opcode (op);
	if (opcode == -1) {
		return -1;
	}

	instr.opcode = opcode;

	code[code_len++] = instr.opcode;
	if (args > 1) {
		if (instr.opcode == 0x80
		|| (instr.opcode >= 0xA0 && instr.opcode <= 0xBF)
		|| instr.opcode == 0x2C
		|| instr.opcode == 0x2D
		|| instr.opcode == 0x2E) {
			// LIT2, JMP2, JCN2, JSR2, and their variations
			code[code_len++] = (instr.operand >> 8) & 0xFF;
			code[code_len++] = instr.operand & 0xFF;
		} else if (instr.opcode == 0x60) { // JSI
			code[code_len++] = instr.operand & 0xFF;
		} else if (instr.opcode > 0x80) {
			code[code_len++] = instr.operand & 0xFF;
		}
	}

	return code_len;
}

R_IPI int uxn_disassemble(const uint8_t* code, size_t code_size, char *text, size_t text_size) {
	Instruction instr = {
		.opcode = code[0]
	};

	const char* op = instruction_mnemonics[instr.opcode];
	if (!op) {
		op = "invalid";
	}

	size_t len = 1;
	if (instr.opcode == 0x80 || (instr.opcode >= 0xA0 && instr.opcode <= 0xBF) ||
			instr.opcode == 0x2C || instr.opcode == 0x2D || instr.opcode == 0x2E) {
		// LIT2, JMP2, JCN2, JSR2, and their variations
		instr.operand = (code[1] << 8) | code[2];
		snprintf(text, text_size, "%s 0x%04x", op, instr.operand);
		len = 3;
	} else if (instr.opcode == 0x60) { // JSI
		instr.operand = code[1];
		snprintf(text, text_size, "%s 0x%02x", op, instr.operand);
		len = 2;
	} else if (instr.opcode >= 0x80) {
		instr.operand = code[1];
		snprintf(text, text_size, "%s 0x%02x", op, instr.operand);
		len = 2;
	} else {
		snprintf(text, text_size, "%s", op);
	}

	return len;
}

#if 0
const char* test_instructions[] = {
	"BRK", "INC", "POP", "NIP", "SWP", "ROT", "DUP", "OVR",
	"EQU", "NEQ", "GTH", "LTH", "JMP", "JCN", "JSR", "STH",
	"LDZ", "STZ", "LDR", "STR", "LDA", "STA", "DEI", "DEO",
	"ADD", "SUB", "MUL", "DIV", "AND", "ORA", "EOR", "SFT",
	"LIT 42", "LIT2 1234", "JMP2 0x1000", "JSI 0x20",
	"inc2r", "pop2k", "jsr2kr 0x3000"
		"BRK", "INC", "POP", "NIP", "SWP", "ROT", "DUP", "OVR",
	"EQU", "NEQ", "GTH", "LTH", "JMP", "JCN", "JSR", "STH",
	"LDZ", "STZ", "LDR", "STR", "LDA", "STA", "DEI", "DEO",
	"ADD", "SUB", "MUL", "DIV", "AND", "ORA", "EOR", "SFT",
	"LIT 42", "LIT2 1234", "JMP2 0x1000", "JSI 0x20",
	"inc2r", "pop2k", "jsr2kr 0x3000",
	"JCN2 0x2000", "JSR2 0x3000",
	"LIT2r 0xABCD", "JMP2k 0x4000", "JCN2k 0x5000", "JSR2k 0x6000"
};
#endif
