/* radare2 - MIT - Copyright 2024 - pancake */

#include <r_arch.h>

#define NONE	0
#define SHORTBR 1
#define LONGBR  2
#define ABSVAL  3
#define CONTVAL 4
#define IGNORE	5
#define END	6
#define LONGSKIP 7

struct opcode {
	unsigned char opcode;
	char mnemonic[16];
	int argc;
	int argt;
	const char *desc;
	ut64 type;
	const char *esil;
};

static const struct opcode opcodes[256] = {
	{ 0x00, "idl", 0, END ,"Idle or wait for interrupt or DMA request"},
	{ 0x01, "ldn r1", 0, NONE ,"Load D with (R1)"},
	{ 0x02, "ldn r2", 0, NONE ,"Load D with (R2)"},
	{ 0x03, "ldn r3", 0, NONE ,"Load D with (R3)"},
	{ 0x04, "ldn r4", 0, NONE ,"Load D with (R4)"},
	{ 0x05, "ldn r5", 0, NONE ,"Load D with (R5)"},
	{ 0x06, "ldn r6", 0, NONE ,"Load D with (R6)"},
	{ 0x07, "ldn r7", 0, NONE ,"Load D with (R7)"},
	{ 0x08, "ldn r8", 0, NONE ,"Load D with (R8)"},
	{ 0x09, "ldn r9", 0, NONE ,"Load D with (R9)"},
	{ 0x0a, "ldn ra", 0, NONE ,"Load D with (RA)"},
	{ 0x0b, "ldn rb", 0, NONE ,"Load D with (RB)"},
	{ 0x0c, "ldn rc", 0, NONE ,"Load D with (RC)"},
	{ 0x0d, "ldn rd", 0, NONE ,"Load D with (RD)"},
	{ 0x0e, "ldn re", 0, NONE ,"Load D with (RE)"},
	{ 0x0f, "ldn rf", 0, NONE ,"Load D with (RF)"},

	{ 0x10, "inc r0", 0, NONE ,"Increment (R0)", R_ANAL_OP_TYPE_ADD, "1,r0,+,r0,:="},
	{ 0x11, "inc r1", 0, NONE ,"Increment (R1)", R_ANAL_OP_TYPE_ADD, "1,r1,+,r1,:="},
	{ 0x12, "inc r2", 0, NONE ,"Increment (R2)", R_ANAL_OP_TYPE_ADD, "1,r2,+,r2,:="},
	{ 0x13, "inc r3", 0, NONE ,"Increment (R3)", R_ANAL_OP_TYPE_ADD},
	{ 0x14, "inc r4", 0, NONE ,"Increment (R4)", R_ANAL_OP_TYPE_ADD},
	{ 0x15, "inc r5", 0, NONE ,"Increment (R5)", R_ANAL_OP_TYPE_ADD},
	{ 0x16, "inc r6", 0, NONE ,"Increment (R6)", R_ANAL_OP_TYPE_ADD},
	{ 0x17, "inc r7", 0, NONE ,"Increment (R7)", R_ANAL_OP_TYPE_ADD},
	{ 0x18, "inc r8", 0, NONE ,"Increment (R8)", R_ANAL_OP_TYPE_ADD},
	{ 0x19, "inc r9", 0, NONE ,"Increment (R9)", R_ANAL_OP_TYPE_ADD},
	{ 0x1a, "inc ra", 0, NONE ,"Increment (RA)", R_ANAL_OP_TYPE_ADD},
	{ 0x1b, "inc rb", 0, NONE ,"Increment (RB)", R_ANAL_OP_TYPE_ADD},
	{ 0x1c, "inc rc", 0, NONE ,"Increment (RC)", R_ANAL_OP_TYPE_ADD},
	{ 0x1d, "inc rd", 0, NONE ,"Increment (RD)", R_ANAL_OP_TYPE_ADD},
	{ 0x1e, "inc re", 0, NONE ,"Increment (RE)", R_ANAL_OP_TYPE_ADD},
	{ 0x1f, "inc rf", 0, NONE ,"Increment (RF)", R_ANAL_OP_TYPE_ADD},

	{ 0x20, "dec r0", 0, NONE ,"Decrement (R0)", R_ANAL_OP_TYPE_SUB},
	{ 0x21, "dec r1", 0, NONE ,"Decrement (R1)", R_ANAL_OP_TYPE_SUB},
	{ 0x22, "dec r2", 0, NONE ,"Decrement (R2)", R_ANAL_OP_TYPE_SUB},
	{ 0x23, "dec r3", 0, NONE ,"Decrement (R3)", R_ANAL_OP_TYPE_SUB},
	{ 0x24, "dec r4", 0, NONE ,"Decrement (R4)", R_ANAL_OP_TYPE_SUB},
	{ 0x25, "dec r5", 0, NONE ,"Decrement (R5)", R_ANAL_OP_TYPE_SUB},
	{ 0x26, "dec r6", 0, NONE ,"Decrement (R6)", R_ANAL_OP_TYPE_SUB},
	{ 0x27, "dec r7", 0, NONE ,"Decrement (R7)", R_ANAL_OP_TYPE_SUB},
	{ 0x28, "dec r8", 0, NONE ,"Decrement (R8)", R_ANAL_OP_TYPE_SUB},
	{ 0x29, "dec r9", 0, NONE ,"Decrement (R9)", R_ANAL_OP_TYPE_SUB},
	{ 0x2a, "dec ra", 0, NONE ,"Decrement (RA)", R_ANAL_OP_TYPE_SUB},
	{ 0x2b, "dec rb", 0, NONE ,"Decrement (RB)", R_ANAL_OP_TYPE_SUB},
	{ 0x2c, "dec rc", 0, NONE ,"Decrement (RC)", R_ANAL_OP_TYPE_SUB},
	{ 0x2d, "dec rd", 0, NONE ,"Decrement (RD)", R_ANAL_OP_TYPE_SUB},
	{ 0x2e, "dec re", 0, NONE ,"Decrement (RE)", R_ANAL_OP_TYPE_SUB},
	{ 0x2f, "dec rf", 0, NONE ,"Decrement (RF)", R_ANAL_OP_TYPE_SUB},

	{ 0x30, "br", 1 ,SHORTBR, "Short branch", R_ANAL_OP_TYPE_JMP },
	{ 0x31, "bq", 1 ,SHORTBR, "Short branch on Q=1", R_ANAL_OP_TYPE_CJMP},
	{ 0x32, "bz", 1 ,SHORTBR, "Short branch on D=0", R_ANAL_OP_TYPE_CJMP},
	{ 0x33, "bdf", 1 ,SHORTBR, "Short branch on DF=1", R_ANAL_OP_TYPE_CJMP},
	{ 0x34, "b1", 1 ,SHORTBR, "Short branch on EF1=1", R_ANAL_OP_TYPE_CJMP},
	{ 0x35, "b2", 1 ,SHORTBR, "Short branch on EF2=1", R_ANAL_OP_TYPE_CJMP},
	{ 0x36, "b3", 1 ,SHORTBR, "Short branch on EF3=1", R_ANAL_OP_TYPE_CJMP},
	{ 0x37, "b4", 1 ,SHORTBR, "Short branch on EF4=1", R_ANAL_OP_TYPE_CJMP},
	{ 0x38, "skp", 1 ,IGNORE, "Skip next byte"},
	{ 0x39, "bnq", 1 ,SHORTBR, "Short branch on Q=0", R_ANAL_OP_TYPE_CJMP},
	{ 0x3a, "bnz", 1 ,SHORTBR, "Short branch on D!=0", R_ANAL_OP_TYPE_CJMP},
	{ 0x3b, "bnf", 1 ,SHORTBR, "Short branch on DF=0", R_ANAL_OP_TYPE_CJMP},
	{ 0x3c, "bn1", 1 ,SHORTBR, "Short branch on EF1=0", R_ANAL_OP_TYPE_CJMP},
	{ 0x3d, "bn2", 1 ,SHORTBR, "Short branch on EF2=0", R_ANAL_OP_TYPE_CJMP},
	{ 0x3e, "bn3", 1 ,SHORTBR, "Short branch on EF3=0", R_ANAL_OP_TYPE_CJMP},
	{ 0x3f, "bn4", 1 ,SHORTBR, "Short branch on EF4=0", R_ANAL_OP_TYPE_CJMP},

	{ 0x40, "lda r0", 0, NONE, "Load D from (R0), increment R0", R_ANAL_OP_TYPE_LOAD},
	{ 0x41, "lda r1", 0, NONE, "Load D from (R1), increment R1", R_ANAL_OP_TYPE_LOAD},
	{ 0x42, "lda r2", 0, NONE, "Load D from (R2), increment R2", R_ANAL_OP_TYPE_LOAD},
	{ 0x43, "lda r3", 0, NONE, "Load D from (R3), increment R3", R_ANAL_OP_TYPE_LOAD},
	{ 0x44, "lda r4", 0, NONE, "Load D from (R4), increment R4", R_ANAL_OP_TYPE_LOAD},
	{ 0x45, "lda r5", 0, NONE, "Load D from (R5), increment R5", R_ANAL_OP_TYPE_LOAD},
	{ 0x46, "lda r6", 0, NONE, "Load D from (R6), increment R6", R_ANAL_OP_TYPE_LOAD},
	{ 0x47, "lda r7", 0, NONE, "Load D from (R7), increment R7", R_ANAL_OP_TYPE_LOAD},
	{ 0x48, "lda r8", 0, NONE, "Load D from (R8), increment R8", R_ANAL_OP_TYPE_LOAD},
	{ 0x49, "lda r9", 0, NONE, "Load D from (R9), increment R9", R_ANAL_OP_TYPE_LOAD},
	{ 0x4a, "lda ra", 0, NONE, "Load D from (RA), increment RA", R_ANAL_OP_TYPE_LOAD},
	{ 0x4b, "lda rb", 0, NONE, "Load D from (RB), increment RB", R_ANAL_OP_TYPE_LOAD},
	{ 0x4c, "lda rc", 0, NONE, "Load D from (RC), increment RC", R_ANAL_OP_TYPE_LOAD},
	{ 0x4d, "lda rd", 0, NONE, "Load D from (RD), increment RD", R_ANAL_OP_TYPE_LOAD},
	{ 0x4e, "lda re", 0, NONE, "Load D from (RE), increment RE", R_ANAL_OP_TYPE_LOAD},
	{ 0x4f, "lda rf", 0, NONE, "Load D from (RF), increment RF", R_ANAL_OP_TYPE_LOAD},

	{ 0x50, "str r0", 0, NONE, "Store D to (R0)", R_ANAL_OP_TYPE_STORE},
	{ 0x51, "str r1", 0, NONE, "Store D to (R1)", R_ANAL_OP_TYPE_STORE},
	{ 0x52, "str r2", 0, NONE, "Store D to (R2)", R_ANAL_OP_TYPE_STORE},
	{ 0x53, "str r3", 0, NONE, "Store D to (R3)", R_ANAL_OP_TYPE_STORE},
	{ 0x54, "str r4", 0, NONE, "Store D to (R4)", R_ANAL_OP_TYPE_STORE},
	{ 0x55, "str r5", 0, NONE, "Store D to (R5)", R_ANAL_OP_TYPE_STORE},
	{ 0x56, "str r6", 0, NONE, "Store D to (R6)", R_ANAL_OP_TYPE_STORE},
	{ 0x57, "str r7", 0, NONE, "Store D to (R7)", R_ANAL_OP_TYPE_STORE},
	{ 0x58, "str r8", 0, NONE, "Store D to (R8)", R_ANAL_OP_TYPE_STORE},
	{ 0x59, "str r9", 0, NONE, "Store D to (R9)", R_ANAL_OP_TYPE_STORE},
	{ 0x5a, "str ra", 0, NONE, "Store D to (RA)", R_ANAL_OP_TYPE_STORE},
	{ 0x5b, "str rb", 0, NONE, "Store D to (RB)", R_ANAL_OP_TYPE_STORE},
	{ 0x5c, "str rc", 0, NONE, "Store D to (RC)", R_ANAL_OP_TYPE_STORE},
	{ 0x5d, "str rd", 0, NONE, "Store D to (RD)", R_ANAL_OP_TYPE_STORE},
	{ 0x5e, "str re", 0, NONE, "Store D to (RE)", R_ANAL_OP_TYPE_STORE},
	{ 0x5f, "str rf", 0, NONE, "Store D to (RF)", R_ANAL_OP_TYPE_STORE},

	{ 0x60, "irx", 0, NONE, "Increment register X"},
	{ 0x61, "out 1", 0, NONE, "Output (R(X)); Increment R(X), N=001"},
	{ 0x62, "out 2", 0, NONE, "Output (R(X)); Increment R(X), N=010"},
	{ 0x63, "out 3", 0, NONE, "Output (R(X)); Increment R(X), N=011"},
	{ 0x64, "out 4", 0, NONE, "Output (R(X)); Increment R(X), N=100"},
	{ 0x65, "out 5", 0, NONE, "Output (R(X)); Increment R(X), N=101"},
	{ 0x66, "out 6", 0, NONE, "Output (R(X)); Increment R(X), N=110"},
	{ 0x67, "out 7", 0, NONE, "Output (R(X)); Increment R(X), N=111"},
	{ 0x68, "doublefetch", 1, NONE, "Opcode for double fetched instructions"},
	{ 0x69, "inp 1", 0, NONE, "Input to (R(X)) and D, N=001"},
	{ 0x6a, "inp 2", 0, NONE, "Input to (R(X)) and D, N=010"},
	{ 0x6b, "inp 3", 0, NONE, "Input to (R(X)) and D, N=011"},
	{ 0x6c, "inp 4", 0, NONE, "Input to (R(X)) and D, N=100"},
	{ 0x6d, "inp 5", 0, NONE, "Input to (R(X)) and D, N=101"},
	{ 0x6e, "inp 6", 0, NONE, "Input to (R(X)) and D, N=110"},
	{ 0x6f, "inp 7", 0, NONE, "Input to (R(X)) and D, N=111"},

	{ 0x70, "ret", 0, END, "Return from interrupt, set IE=1", R_ANAL_OP_TYPE_RET},
	{ 0x71, "dis", 0, END, "Disable. Return from interrupt, set IE=0", R_ANAL_OP_TYPE_MOV},
	{ 0x72, "ldxa", 0, NONE, "Load via X and advance", R_ANAL_OP_TYPE_LOAD},
	{ 0x73, "stxd", 0, NONE, "Store via X and devrement", R_ANAL_OP_TYPE_STORE},
	{ 0x74, "adc", 0, NONE, "Add with carry", R_ANAL_OP_TYPE_ADD},
	{ 0x75, "sdb", 0, NONE, "Substract D with borrow", R_ANAL_OP_TYPE_SUB},
	{ 0x76, "shrc", 0, NONE, "Shift right with carry", R_ANAL_OP_TYPE_SHR},
	{ 0x77, "smb", 0, NONE, "Substract memory with borrow"},
	{ 0x78, "sav", 0, NONE, "Save"},
	{ 0x79, "mark", 0, NONE, "Push X,P; mark subroutine call", R_ANAL_OP_TYPE_PUSH},
	{ 0x7a, "req", 0, NONE, "Reset Q=0", R_ANAL_OP_TYPE_MOV},
	{ 0x7b, "seq", 0, NONE, "Set Q=1", R_ANAL_OP_TYPE_MOV},
	{ 0x7c, "adci", 1, ABSVAL, "Add with carry immediate", R_ANAL_OP_TYPE_ADD},
	{ 0x7d, "sdbi", 1, ABSVAL, "Substract D with borrow immediate", R_ANAL_OP_TYPE_SUB},
	{ 0x7e, "shlc", 0, NONE, "Shift left with carry", R_ANAL_OP_TYPE_SHL},
	{ 0x7f, "smbi", 0, NONE, "Substract memory toh borrow, immediate", R_ANAL_OP_TYPE_SUB},

	{ 0x80, "glo r0", 0, NONE, "Get low register R0"},
	{ 0x81, "glo r1", 0, NONE, "Get low register R1"},
	{ 0x82, "glo r2", 0, NONE, "Get low register R2"},
	{ 0x83, "glo r3", 0, NONE, "Get low register R3"},
	{ 0x84, "glo r4", 0, NONE, "Get low register R4"},
	{ 0x85, "glo r5", 0, NONE, "Get low register R5"},
	{ 0x86, "glo r6", 0, NONE, "Get low register R6"},
	{ 0x87, "glo r7", 0, NONE, "Get low register R7"},
	{ 0x88, "glo r8", 0, NONE, "Get low register R8"},
	{ 0x89, "glo r9", 0, NONE, "Get low register R9"},
	{ 0x8a, "glo ra", 0, NONE, "Get low register RA"},
	{ 0x8b, "glo rb", 0, NONE, "Get low register RB"},
	{ 0x8c, "glo rc", 0, NONE, "Get low register RC"},
	{ 0x8d, "glo rd", 0, NONE, "Get low register RD"},
	{ 0x8e, "glo re", 0, NONE, "Get low register RE"},
	{ 0x8f, "glo rf", 0, NONE, "Get low register RF"},

	{ 0x90, "ghi r0", 0, NONE, "Get high register R0"},
	{ 0x91, "ghi r1", 0, NONE, "Get high register R1"},
	{ 0x92, "ghi r2", 0, NONE, "Get high register R2"},
	{ 0x93, "ghi r3", 0, NONE, "Get high register R3"},
	{ 0x94, "ghi r4", 0, NONE, "Get high register R4"},
	{ 0x95, "ghi r5", 0, NONE, "Get high register R5"},
	{ 0x96, "ghi r6", 0, NONE, "Get high register R6"},
	{ 0x97, "ghi r7", 0, NONE, "Get high register R7"},
	{ 0x98, "ghi r8", 0, NONE, "Get high register R8"},
	{ 0x99, "ghi r9", 0, NONE, "Get high register R9"},
	{ 0x9a, "ghi ra", 0, NONE, "Get high register RA"},
	{ 0x9b, "ghi rb", 0, NONE, "Get high register RB"},
	{ 0x9c, "ghi rc", 0, NONE, "Get high register RC"},
	{ 0x9d, "ghi rd", 0, NONE, "Get high register RD"},
	{ 0x9e, "ghi re", 0, NONE, "Get high register RE"},
	{ 0x9f, "ghi rf", 0, NONE, "Get high register RF"},

	{ 0xa0, "plo r0", 0, NONE, "Put low register R0"},
	{ 0xa1, "plo r1", 0, NONE, "Put low register R1"},
	{ 0xa2, "plo r2", 0, NONE, "Put low register R2"},
	{ 0xa3, "plo r3", 0, NONE, "Put low register R3"},
	{ 0xa4, "plo r4", 0, NONE, "Put low register R4"},
	{ 0xa5, "plo r5", 0, NONE, "Put low register R5"},
	{ 0xa6, "plo r6", 0, NONE, "Put low register R6"},
	{ 0xa7, "plo r7", 0, NONE, "Put low register R7"},
	{ 0xa8, "plo r8", 0, NONE, "Put low register R8"},
	{ 0xa9, "plo r9", 0, NONE, "Put low register R9"},
	{ 0xaa, "plo ra", 0, NONE, "Put low register RA"},
	{ 0xab, "plo rb", 0, NONE, "Put low register RB"},
	{ 0xac, "plo rc", 0, NONE, "Put low register RC"},
	{ 0xad, "plo rd", 0, NONE, "Put low register RD"},
	{ 0xae, "plo re", 0, NONE, "Put low register RE"},
	{ 0xaf, "plo rf", 0, NONE, "Put low register RF"},

	{ 0xb0, "phi r0", 0, NONE, "Put high register R0"},
	{ 0xb1, "phi r1", 0, NONE, "Put high register R1"},
	{ 0xb2, "phi r2", 0, NONE, "Put high register R2"},
	{ 0xb3, "phi r3", 0, NONE, "Put high register R3"},
	{ 0xb4, "phi r4", 0, NONE, "Put high register R4"},
	{ 0xb5, "phi r5", 0, NONE, "Put high register R5"},
	{ 0xb6, "phi r6", 0, NONE, "Put high register R6"},
	{ 0xb7, "phi r7", 0, NONE, "Put high register R7"},
	{ 0xb8, "phi r8", 0, NONE, "Put high register R8"},
	{ 0xb9, "phi r9", 0, NONE, "Put high register R9"},
	{ 0xba, "phi ra", 0, NONE, "Put high register RA"},
	{ 0xbb, "phi rb", 0, NONE, "Put high register RB"},
	{ 0xbc, "phi rc", 0, NONE, "Put high register RC"},
	{ 0xbd, "phi rd", 0, NONE, "Put high register RD"},
	{ 0xbe, "phi re", 0, NONE, "Put high register RE"},
	{ 0xbf, "phi rf", 0, NONE, "Put high register RF"},


	{ 0xc0, "lbr", 2, LONGBR, "Long branch", R_ANAL_OP_TYPE_JMP},
	{ 0xc1, "lbq", 2, LONGBR, "Long branch on Q=1", R_ANAL_OP_TYPE_CJMP},
	{ 0xc2, "lbz", 2, LONGBR, "Long branch on D=0", R_ANAL_OP_TYPE_CJMP},
	{ 0xc3, "lbdf", 2, LONGBR, "Long branch on DF=1", R_ANAL_OP_TYPE_CJMP},
	{ 0xc4, "nop", 0, NONE, "No operation", R_ANAL_OP_TYPE_NOP},
	{ 0xc5, "lsnq", 0, LONGSKIP, "Long skip on Q=0", R_ANAL_OP_TYPE_CJMP},
	{ 0xc6, "lsnz", 0, LONGSKIP, "Long skip on D!=0", R_ANAL_OP_TYPE_CJMP},
	{ 0xc7, "lsnf", 0, LONGSKIP, "Long skip on DF=0", R_ANAL_OP_TYPE_CJMP},
	{ 0xc8, "lskp", 2, NONE, "Long skip", R_ANAL_OP_TYPE_JMP},
	{ 0xc9, "lbnq", 2, LONGBR, "Long branch on Q=0", R_ANAL_OP_TYPE_CJMP},
	{ 0xca, "lbnz", 2, LONGBR, "Long branch on D!=0", R_ANAL_OP_TYPE_CJMP},
	{ 0xcb, "lbnf", 2, LONGBR, "Long branch on DF=0", R_ANAL_OP_TYPE_CJMP},
	{ 0xcc, "lsie", 0, LONGSKIP, "Long skip on IE=1", R_ANAL_OP_TYPE_CJMP},
	{ 0xcd, "lsq", 0, LONGSKIP, "Long skip on Q=1", R_ANAL_OP_TYPE_CJMP},
	{ 0xce, "lsz", 0, LONGSKIP, "Long skip on D=0", R_ANAL_OP_TYPE_CJMP},
	{ 0xcf, "lsdf", 0, LONGSKIP, "Long skip on DF=1", R_ANAL_OP_TYPE_CJMP},


	{ 0xd0, "sep r0", 0, NONE, "Set P=R0 as program counter", R_ANAL_OP_TYPE_RCALL, "r0,PC,r="},
	{ 0xd1, "sep r1", 0, NONE, "Set P=R1 as program counter", R_ANAL_OP_TYPE_RCALL, "r1,PC,r="},
	{ 0xd2, "sep r2", 0, NONE, "Set P=R2 as program counter", R_ANAL_OP_TYPE_RCALL, "r2,PC,r="},
	{ 0xd3, "sep r3", 0, NONE, "Set P=R3 as program counter", R_ANAL_OP_TYPE_RCALL, "r3,PC,r="},
	{ 0xd4, "sep r4", 0, NONE, "Set P=R4 as program counter", R_ANAL_OP_TYPE_RCALL, "r4,PC,r="},
	{ 0xd5, "sep r5", 0, NONE, "Set P=R5 as program counter", R_ANAL_OP_TYPE_RCALL, "r5,PC,r="},
	{ 0xd6, "sep r6", 0, NONE, "Set P=R6 as program counter", R_ANAL_OP_TYPE_RCALL, "r6,PC,r="},
	{ 0xd7, "sep r7", 0, NONE, "Set P=R7 as program counter", R_ANAL_OP_TYPE_RCALL, "r7,PC,r="},
	{ 0xd8, "sep r8", 0, NONE, "Set P=R8 as program counter", R_ANAL_OP_TYPE_RCALL, "r8,PC,r="},
	{ 0xd9, "sep r9", 0, NONE, "Set P=R9 as program counter", R_ANAL_OP_TYPE_RCALL, "r9,PC,r="},
	{ 0xda, "sep ra", 0, NONE, "Set P=RA as program counter", R_ANAL_OP_TYPE_RCALL, "ra,PC,r="},
	{ 0xdb, "sep rb", 0, NONE, "Set P=RB as program counter", R_ANAL_OP_TYPE_RCALL, "rb,PC,r="},
	{ 0xdc, "sep rc", 0, NONE, "Set P=RC as program counter", R_ANAL_OP_TYPE_RCALL, "rc,PC,r="},
	{ 0xdd, "sep rd", 0, NONE, "Set P=RD as program counter", R_ANAL_OP_TYPE_RCALL, "rd,PC,r="},
	{ 0xde, "sep re", 0, NONE, "Set P=RE as program counter", R_ANAL_OP_TYPE_RCALL, "re,PC,r="},
	{ 0xdf, "sep rf", 0, NONE, "Set P=RF as program counter", R_ANAL_OP_TYPE_RCALL, "rf,PC,r="},

	{ 0xe0, "sex r0", 0, NONE, "Set P=R0 as datapointer"},
	{ 0xe1, "sex r1", 0, NONE, "Set P=R1 as datapointer"},
	{ 0xe2, "sex r2", 0, NONE, "Set P=R2 as datapointer"},
	{ 0xe3, "sex r3", 0, NONE, "Set P=R3 as datapointer"},
	{ 0xe4, "sex r4", 0, NONE, "Set P=R4 as datapointer"},
	{ 0xe5, "sex r5", 0, NONE, "Set P=R5 as datapointer"},
	{ 0xe6, "sex r6", 0, NONE, "Set P=R6 as datapointer"},
	{ 0xe7, "sex r7", 0, NONE, "Set P=R7 as datapointer"},
	{ 0xe8, "sex r8", 0, NONE, "Set P=R8 as datapointer"},
	{ 0xe9, "sex r9", 0, NONE, "Set P=R9 as datapointer"},
	{ 0xea, "sex ra", 0, NONE, "Set P=RA as datapointer"},
	{ 0xeb, "sex rb", 0, NONE, "Set P=RB as datapointer"},
	{ 0xec, "sex rc", 0, NONE, "Set P=RC as datapointer"},
	{ 0xed, "sex rd", 0, NONE, "Set P=RD as datapointer"},
	{ 0xee, "sex re", 0, NONE, "Set P=RE as datapointer"},
	{ 0xef, "sex rf", 0, NONE, "Set P=RF as datapointer"},

	{ 0xf0, "ldx", 0, NONE, "Pop stack. Place value in D register", R_ANAL_OP_TYPE_POP},
	{ 0xf1, "or", 0, NONE, "Logical OR  D with (R(X))", R_ANAL_OP_TYPE_OR},
	{ 0xf2, "and", 0, NONE, "Logical AND: D with (R(X))", R_ANAL_OP_TYPE_AND},
	{ 0xf3, "xor", 0, NONE, "Logical exclusive OR  D with (R(X))", R_ANAL_OP_TYPE_XOR},
	{ 0xf4, "add", 0, NONE, "Add D: D,DF= D+(R(X))", R_ANAL_OP_TYPE_AND},
	{ 0xf5, "sd", 0, NONE, "Substract D: D,DF=(R(X))-D", R_ANAL_OP_TYPE_SUB},
	{ 0xf6, "shr", 0, NONE, "Shift right D", R_ANAL_OP_TYPE_SHR},
	{ 0xf7, "sm", 0, NONE, "Substract memory: DF,D=D-(R(X))"},
	{ 0xf8, "ldi", 1, ABSVAL, "Load D immediate", R_ANAL_OP_TYPE_LOAD},
	{ 0xf9, "ori", 1, ABSVAL, "Logical OR D with value", R_ANAL_OP_TYPE_OR},
	{ 0xfa, "ani", 1, ABSVAL, "Logical AND D with value", R_ANAL_OP_TYPE_AND},
	{ 0xfb, "xri", 1, ABSVAL, "Logical XOR D with value", R_ANAL_OP_TYPE_XOR},
	{ 0xfc, "adi", 1, ABSVAL, "Add D,DF with value", R_ANAL_OP_TYPE_ADD},
	{ 0xfd, "sdi", 1, ABSVAL, "Substract D,DF from value", R_ANAL_OP_TYPE_SUB},
	{ 0xfe, "shl", 0, NONE, "Shift left D", R_ANAL_OP_TYPE_SHL},
	{ 0xff, "smi", 1, ABSVAL, "Substract D,DF to value", R_ANAL_OP_TYPE_SUB},
};

static const struct opcode opcodes2[256] = {
	{ 0x00, "stpc", 0, NONE ,"stop counter", R_ANAL_OP_TYPE_MOV},
	{ 0x01, "dtc", 0, NONE ,"decrement timer/counter", R_ANAL_OP_TYPE_SUB},
	{ 0x02, "spm2", 0, NONE ,"set pulse width mode 2 and start"},
	{ 0x03, "scm2", 0, NONE ,"set counter mode 2 and start"},
	{ 0x04, "spm1", 0, NONE ,"set pulse width mode 1 and start"},
	{ 0x05, "scm1", 0, NONE ,"set counter mode 1 and start"},
	{ 0x06, "ldc", 0, NONE ,"load counter", R_ANAL_OP_TYPE_LOAD},
	{ 0x07, "stm", 0, NONE ,"set timer mode and start"},
	{ 0x08, "gec", 0, NONE ,"get counter", R_ANAL_OP_TYPE_MOV},
	{ 0x09, "etq", 0, NONE ,"enable toggle Q"},
	{ 0x0a, "xie", 0, NONE ,"external interrupt enable"},
	{ 0x0b, "xid", 0, NONE ,"external interrupt disable"},
	{ 0x0c, "cie", 0, NONE ,"counter interrupt enable"},
	{ 0x0d, "cid", 0, NONE ,"counter interrupt disable"},
	{ 0x0e, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x0f, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},

	{ 0x10, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x11, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x12, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x13, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x14, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x15, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x16, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x17, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x18, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x19, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x1a, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x1b, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x1c, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x1d, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x1e, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x1f, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},

	{ 0x20, "dbnz r0,", 2, LONGBR, "decrement R0 and long branch if not 0", R_ANAL_OP_TYPE_CJMP},
	{ 0x21, "dbnz r1,", 2, LONGBR, "decrement R1 and long branch if not 0", R_ANAL_OP_TYPE_CJMP},
	{ 0x22, "dbnz r2,", 2, LONGBR, "decrement R2 and long branch if not 0", R_ANAL_OP_TYPE_CJMP},
	{ 0x23, "dbnz r3,", 2, LONGBR, "decrement R3 and long branch if not 0", R_ANAL_OP_TYPE_CJMP},
	{ 0x24, "dbnz r4,", 2, LONGBR, "decrement R4 and long branch if not 0", R_ANAL_OP_TYPE_CJMP},
	{ 0x25, "dbnz r5,", 2, LONGBR, "decrement R5 and long branch if not 0", R_ANAL_OP_TYPE_CJMP},
	{ 0x26, "dbnz r6,", 2, LONGBR, "decrement R6 and long branch if not 0", R_ANAL_OP_TYPE_CJMP},
	{ 0x27, "dbnz r7,", 2, LONGBR, "decrement R7 and long branch if not 0", R_ANAL_OP_TYPE_CJMP},
	{ 0x28, "dbnz r8,", 2, LONGBR, "decrement R8 and long branch if not 0", R_ANAL_OP_TYPE_CJMP},
	{ 0x29, "dbnz r9,", 2, LONGBR, "decrement R9 and long branch if not 0", R_ANAL_OP_TYPE_CJMP},
	{ 0x2a, "dbnz ra,", 2, LONGBR, "decrement RA and long branch if not 0", R_ANAL_OP_TYPE_CJMP},
	{ 0x2b, "dbnz rb,", 2, LONGBR, "decrement RB and long branch if not 0", R_ANAL_OP_TYPE_CJMP},
	{ 0x2c, "dbnz rc,", 2, LONGBR, "decrement RC and long branch if not 0", R_ANAL_OP_TYPE_CJMP},
	{ 0x2d, "dbnz rd,", 2, LONGBR, "decrement RD and long branch if not 0", R_ANAL_OP_TYPE_CJMP},
	{ 0x2e, "dbnz re,", 2, LONGBR, "decrement RE and long branch if not 0", R_ANAL_OP_TYPE_CJMP},
	{ 0x2f, "dbnz rf,", 2, LONGBR, "decrement RF and long branch if not 0", R_ANAL_OP_TYPE_CJMP},

	{ 0x30, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x31, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x32, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x33, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x34, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x35, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x36, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x37, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x38, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x39, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x3a, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x3b, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x3c, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x3d, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x3e, "bci", 0, NONE ,"short branch on counter interrupt", R_ANAL_OP_TYPE_CJMP},
	{ 0x3f, "bxi", 0, NONE ,"short branch on external interrupt", R_ANAL_OP_TYPE_CJMP},

	{ 0x40, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x41, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x42, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x43, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x44, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x45, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x46, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x47, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x48, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x49, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x4a, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x4b, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x4c, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x4d, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x4e, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x4f, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},

	{ 0x50, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x51, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x52, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x53, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x54, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x55, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x56, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x57, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x58, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x59, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x5a, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x5b, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x5c, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x5d, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x5e, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x5f, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},

	{ 0x60, "rlxa r0,", 2, NONE, "load memory to R0"},
	{ 0x61, "rlxa r1,", 2, NONE, "load memory to R1"},
	{ 0x62, "rlxa r2,", 2, NONE, "load memory to R2"},
	{ 0x63, "rlxa r3,", 2, NONE, "load memory to R3"},
	{ 0x64, "rlxa r4,", 2, NONE, "load memory to R4"},
	{ 0x65, "rlxa r5,", 2, NONE, "load memory to R5"},
	{ 0x66, "rlxa r6,", 2, NONE, "load memory to R6"},
	{ 0x67, "rlxa r7,", 2, NONE, "load memory to R7"},
	{ 0x68, "rlxa r8,", 2, NONE, "load memory to R8"},
	{ 0x69, "rlxa r9,", 2, NONE, "load memory to R9"},
	{ 0x6a, "rlxa ra,", 2, NONE, "load memory to RA"},
	{ 0x6b, "rlxa rb,", 2, NONE, "load memory to RB"},
	{ 0x6c, "rlxa rc,", 2, NONE, "load memory to RC"},
	{ 0x6d, "rlxa rd,", 2, NONE, "load memory to RD"},
	{ 0x6e, "rlxa re,", 2, NONE, "load memory to RE"},
	{ 0x6f, "rlxa rf,", 2, NONE, "load memory to RF"},

	{ 0x70, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x71, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x72, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x73, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x74, "dadc", 0, NONE ,"decimal add with carry", R_ANAL_OP_TYPE_ADD},
	{ 0x75, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x76, "dsav", 0, NONE ,"save T,D,DF"},
	{ 0x77, "dsmb", 0, NONE ,"decimal substract memory with borrow", R_ANAL_OP_TYPE_SUB},
	{ 0x78, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x79, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x7a, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x7b, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x7c, "daci", 1, ABSVAL ,"decimal add with carry immediate", R_ANAL_OP_TYPE_ADD},
	{ 0x7d, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x7e, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0x7f, "dsbi", 1, ABSVAL ,"decimal substract memory with borrow, immediate", R_ANAL_OP_TYPE_SUB},

	{ 0x80, "scal r0", 0, NONE, "standard call to (R0)", R_ANAL_OP_TYPE_RCALL},
	{ 0x81, "scal r1", 0, NONE, "standard call to (R1)", R_ANAL_OP_TYPE_RCALL},
	{ 0x82, "scal r2", 0, NONE, "standard call to (R2)", R_ANAL_OP_TYPE_RCALL},
	{ 0x83, "scal r3", 0, NONE, "standard call to (R3)", R_ANAL_OP_TYPE_RCALL},
	{ 0x84, "scal r4", 0, NONE, "standard call to (R4)", R_ANAL_OP_TYPE_RCALL},
	{ 0x85, "scal r5", 0, NONE, "standard call to (R5)", R_ANAL_OP_TYPE_RCALL},
	{ 0x86, "scal r6", 0, NONE, "standard call to (R6)", R_ANAL_OP_TYPE_RCALL},
	{ 0x87, "scal r7", 0, NONE, "standard call to (R7)", R_ANAL_OP_TYPE_RCALL},
	{ 0x88, "scal r8", 0, NONE, "standard call to (R8)", R_ANAL_OP_TYPE_RCALL},
	{ 0x89, "scal r9", 0, NONE, "standard call to (R9)", R_ANAL_OP_TYPE_RCALL},
	{ 0x8a, "scal ra", 0, NONE, "standard call to (RA)", R_ANAL_OP_TYPE_RCALL},
	{ 0x8b, "scal rb", 0, NONE, "standard call to (RB)", R_ANAL_OP_TYPE_RCALL},
	{ 0x8c, "scal rc", 0, NONE, "standard call to (RC)", R_ANAL_OP_TYPE_RCALL},
	{ 0x8d, "scal rd", 0, NONE, "standard call to (RD)", R_ANAL_OP_TYPE_RCALL},
	{ 0x8e, "scal re", 0, NONE, "standard call to (RE)", R_ANAL_OP_TYPE_RCALL},
	{ 0x8f, "scal rf", 0, NONE, "standard call to (RF)", R_ANAL_OP_TYPE_RCALL},

	{ 0x90, "sret r0", 0, NONE, "standard return to (R0)", R_ANAL_OP_TYPE_RET},
	{ 0x91, "sret r1", 0, NONE, "standard return to (R1)", R_ANAL_OP_TYPE_RET},
	{ 0x92, "sret r2", 0, NONE, "standard return to (R2)", R_ANAL_OP_TYPE_RET},
	{ 0x93, "sret r3", 0, NONE, "standard return to (R3)", R_ANAL_OP_TYPE_RET},
	{ 0x94, "sret r4", 0, NONE, "standard return to (R4)", R_ANAL_OP_TYPE_RET},
	{ 0x95, "sret r5", 0, NONE, "standard return to (R5)", R_ANAL_OP_TYPE_RET},
	{ 0x96, "sret r6", 0, NONE, "standard return to (R6)", R_ANAL_OP_TYPE_RET},
	{ 0x97, "sret r7", 0, NONE, "standard return to (R7)", R_ANAL_OP_TYPE_RET},
	{ 0x98, "sret r8", 0, NONE, "standard return to (R8)", R_ANAL_OP_TYPE_RET},
	{ 0x99, "sret r9", 0, NONE, "standard return to (R9)", R_ANAL_OP_TYPE_RET},
	{ 0x9a, "sret ra", 0, NONE, "standard return to (RA)", R_ANAL_OP_TYPE_RET},
	{ 0x9b, "sret rb", 0, NONE, "standard return to (RB)", R_ANAL_OP_TYPE_RET},
	{ 0x9c, "sret rc", 0, NONE, "standard return to (RC)", R_ANAL_OP_TYPE_RET},
	{ 0x9d, "sret rd", 0, NONE, "standard return to (RD)", R_ANAL_OP_TYPE_RET},
	{ 0x9e, "sret re", 0, NONE, "standard return to (RE)", R_ANAL_OP_TYPE_RET},
	{ 0x9f, "sret rf", 0, NONE, "standard return to (RF)", R_ANAL_OP_TYPE_RET},

	{ 0xa0, "rsxd r0", 0, NONE, "store register R0 in memory", R_ANAL_OP_TYPE_STORE},
	{ 0xa1, "rsxd r1", 0, NONE, "store register R1 in memory", R_ANAL_OP_TYPE_STORE},
	{ 0xa2, "rsxd r2", 0, NONE, "store register R2 in memory", R_ANAL_OP_TYPE_STORE},
	{ 0xa3, "rsxd r3", 0, NONE, "store register R3 in memory", R_ANAL_OP_TYPE_STORE},
	{ 0xa4, "rsxd r4", 0, NONE, "store register R4 in memory", R_ANAL_OP_TYPE_STORE},
	{ 0xa5, "rsxd r5", 0, NONE, "store register R5 in memory", R_ANAL_OP_TYPE_STORE},
	{ 0xa6, "rsxd r6", 0, NONE, "store register R6 in memory", R_ANAL_OP_TYPE_STORE},
	{ 0xa7, "rsxd r7", 0, NONE, "store register R7 in memory", R_ANAL_OP_TYPE_STORE},
	{ 0xa8, "rsxd r8", 0, NONE, "store register R8 in memory", R_ANAL_OP_TYPE_STORE},
	{ 0xa9, "rsxd r9", 0, NONE, "store register R9 in memory", R_ANAL_OP_TYPE_STORE},
	{ 0xaa, "rsxd ra", 0, NONE, "store register RA in memory", R_ANAL_OP_TYPE_STORE},
	{ 0xab, "rsxd rb", 0, NONE, "store register RB in memory", R_ANAL_OP_TYPE_STORE},
	{ 0xac, "rsxd rc", 0, NONE, "store register RC in memory", R_ANAL_OP_TYPE_STORE},
	{ 0xad, "rsxd rd", 0, NONE, "store register RD in memory", R_ANAL_OP_TYPE_STORE},
	{ 0xae, "rsxd re", 0, NONE, "store register RE in memory", R_ANAL_OP_TYPE_STORE},
	{ 0xaf, "rsxd rf", 0, NONE, "store register RF in memory", R_ANAL_OP_TYPE_STORE},

	{ 0xb0, "rnx r0", 0, NONE, "copy register R0 to R(X)"},
	{ 0xb1, "rnx r1", 0, NONE, "copy register R1 to R(X)"},
	{ 0xb2, "rnx r2", 0, NONE, "copy register R2 to R(X)"},
	{ 0xb3, "rnx r3", 0, NONE, "copy register R3 to R(X)"},
	{ 0xb4, "rnx r4", 0, NONE, "copy register R4 to R(X)"},
	{ 0xb5, "rnx r5", 0, NONE, "copy register R5 to R(X)"},
	{ 0xb6, "rnx r6", 0, NONE, "copy register R6 to R(X)"},
	{ 0xb7, "rnx r7", 0, NONE, "copy register R7 to R(X)"},
	{ 0xb8, "rnx r8", 0, NONE, "copy register R8 to R(X)"},
	{ 0xb9, "rnx r9", 0, NONE, "copy register R9 to R(X)"},
	{ 0xba, "rnx ra", 0, NONE, "copy register RA to R(X)"},
	{ 0xbb, "rnx rb", 0, NONE, "copy register RB to R(X)"},
	{ 0xbc, "rnx rc", 0, NONE, "copy register RC to R(X)"},
	{ 0xbd, "rnx rd", 0, NONE, "copy register RD to R(X)"},
	{ 0xbe, "rnx re", 0, NONE, "copy register RE to R(X)"},
	{ 0xbf, "rnx rf", 0, NONE, "copy register RF to R(X)"},

	{ 0xc0, "rldi r0,", 2, ABSVAL, "register load immediate R0"},
	{ 0xc1, "rldi r1,", 2, ABSVAL, "register load immediate R1"},
	{ 0xc2, "rldi r2,", 2, ABSVAL, "register load immediate R2"},
	{ 0xc3, "rldi r3,", 2, ABSVAL, "register load immediate R3"},
	{ 0xc4, "rldi r4,", 2, ABSVAL, "register load immediate R4"},
	{ 0xc5, "rldi r5,", 2, ABSVAL, "register load immediate R5"},
	{ 0xc6, "rldi r6,", 2, ABSVAL, "register load immediate R6"},
	{ 0xc7, "rldi r7,", 2, ABSVAL, "register load immediate R7"},
	{ 0xc8, "rldi r8,", 2, ABSVAL, "register load immediate R8"},
	{ 0xc9, "rldi r9,", 2, ABSVAL, "register load immediate R9"},
	{ 0xca, "rldi ra,", 2, ABSVAL, "register load immediate RA"},
	{ 0xcb, "rldi rb,", 2, ABSVAL, "register load immediate RB"},
	{ 0xcc, "rldi rc,", 2, ABSVAL, "register load immediate RC"},
	{ 0xcd, "rldi rd,", 2, ABSVAL, "register load immediate RD"},
	{ 0xce, "rldi re,", 2, ABSVAL, "register load immediate RE"},
	{ 0xcf, "rldi rf,", 2, ABSVAL, "register load immediate RF"},

	{ 0xd0, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xd1, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xd2, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xd3, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xd4, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xd5, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xd6, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xd7, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xd8, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xd9, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xda, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xdb, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xdc, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xdd, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xde, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xdf, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},

	{ 0xe0, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xe1, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xe2, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xe3, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xe4, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xe5, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xe6, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xe7, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xe8, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xe9, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xea, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xeb, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xec, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xed, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xee, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xef, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},

	{ 0xf0, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xf1, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xf2, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xf3, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xf4, "dadd", 0, NONE ,"decimal add", R_ANAL_OP_TYPE_ADD},
	{ 0xf5, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xf6, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xf7, "dsm", 0, NONE ,"decimal substract memory", R_ANAL_OP_TYPE_SUB},
	{ 0xf8, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xf9, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xfa, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xfb, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xfc, "dadi", 1, ABSVAL ,"decimal add immediate", R_ANAL_OP_TYPE_ADD},
	{ 0xfd, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xfe, "invalid", 0, NONE ,"INVALID INSTRUCTION", R_ANAL_OP_TYPE_ILL},
	{ 0xff, "dsmi", 1, ABSVAL ,"decimal substract memory, immediate", R_ANAL_OP_TYPE_SUB}
};

static int cdp_disasm(RAnalOp *aop, RArchDecodeMask mask) {
	const ut8 *buf = aop->bytes;
	ut8 b0 = buf[0];
	struct opcode op = opcodes[b0];
	int size = op.argc + 1;
	if (b0 == 0x68) {
		buf++;
		size = op.argc + 2;
		op = opcodes2[buf[0]];
	}

	switch (op.argc) {
	case 1:
		aop->mnemonic = r_str_newf ("%s 0x%02x", op.mnemonic, buf[1]);
		switch (op.type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			aop->jump = buf[1];
			aop->fail = aop->addr + size;
			break;
		}
		break;
	case 2:
		aop->mnemonic = r_str_newf ("%s 0x%02x%02x", op.mnemonic, buf[1], buf[2]);
		switch (op.type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			aop->jump = ((ut16)buf[1] << 8) | buf[2];
			aop->fail = aop->addr + size;
			break;
		}
		break;
	default:
		aop->mnemonic = r_str_newf ("%s", op.mnemonic);
		switch (op.type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			{
				// longskip
				struct opcode nextop = opcodes[buf[size]];
				aop->jump = aop->addr + size + nextop.argc + 1;
				aop->fail = aop->addr + size;
			}
			break;
		}
		break;
	}
	if (mask & R_ARCH_OP_MASK_ESIL) {
		r_strbuf_initf (&aop->esil, "%s", op.esil);
	}
#if 0
	Most instructions execute in 2 machine cycles. Some in 3. The 1804 and
	1805 also have instructions which take up to 10 machine cycles.
	Every machine cycle requires 8 clock cycles, which obviously results in a
	less than average performance of the processor. Most instructions take 16
	clock cycles to execute. The 1804 and 1805 use slightly less clock cycles,
	making them just a little bit less slow.
#endif
	if (buf[0] >= 0xc0 && buf[0] <= 0xcf) {
		aop->cycles = 3;
	} else {
		aop->cycles = 2;
	}
	aop->size = size;
	aop->type = op.type;
	return size;
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	// const char *cpu = as->config->cpu;
	op->size = cdp_disasm (op, mask);
	if (mask & R_ARCH_OP_MASK_DISASM) {
	//	op->size = cdp_disasm (op);
		if (R_STR_ISEMPTY (op->mnemonic)) {
			op->type = R_ANAL_OP_TYPE_ILL;
			op->mnemonic = strdup ("invalid");
		}
	}
	return op->size > 0;
}

static char *getregs(RArchSession *as) {
	const char *const p =
		"=PC	r0\n"
		"=SP	r1\n"
		"=A0	r2\n"
		"=A1	r3\n"
		"gpr	r0	.16	0	0\n"
		"gpr	r1	.16	2	0\n"
		"gpr	r2	.16	4	0\n"
		"gpr	r3	.16	6	0\n"
		"gpr	r4	.16	8	0\n"
		"gpr	r5	.16	10	0\n"
		"gpr	r6	.16	12	0\n"
		"gpr	r7	.16	14	0\n"
		"gpr	r8	.16	16	0\n"
		"gpr	r9	.16	18	0\n"
		"gpr	ra	.16	20	0\n"
		"gpr	rb	.16	22	0\n"
		"gpr	rc	.16	24	0\n"
		"gpr	rd	.16	26	0\n"
		"gpr	re	.16	28	0\n"
		"gpr	rf	.16	30	0\n"
	;
	return strdup (p);
}

static int info(RArchSession *as, ut32 q) {
	return 1;
}

const RArchPlugin r_arch_plugin_cosmac = {
	.meta = {
		.author = "pancake",
		.name = "cosmac",
		// COSMAC = COmplementary Symmetry Monolithic Array Computer
		.desc = "RCA COSMAC MicroProcessor 180X family",
		.license = "MIT",
	},
	// .cpus = "1802,1800,1804,1805,cdp1806 ...",
	.arch = "cosmac",
	.endian = R_SYS_ENDIAN_BIG, // ignored by rcore
	.info = info,
	.bits = R_SYS_BITS_PACK2 (8, 16),
	.decode = &decode,
	.regs = &getregs,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_cosmac,
	.version = R2_VERSION
};
#endif
