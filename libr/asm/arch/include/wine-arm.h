// author: esteve <youterm.com>
#ifndef ARM_H
#define ARM_H

#define ARM_SIZEOF_INST 4

#define ARM_COND_EQ 0x00000000	// Z set, equal
#define ARM_COND_NE 0x10000000	// Z clear, no equal
#define ARM_COND_HS 0x20000000	// C set, unsigned higher or same
#define ARM_COND_LO 0x30000000	// C clear, unsgined lower
#define ARM_COND_MI 0x40000000	// N set , negative
#define ARM_COND_PL 0x50000000	// N clear , positive or zero
#define ARM_COND_VS 0x60000000	// V set , overflow
#define ARM_COND_VC 0x70000000	// V clear, no overflow
#define ARM_COND_HI 0x80000000	// C set and Z clear, unsigned higher
#define ARM_COND_LS 0x90000000	// C clear or Z, unsigned lower or same
#define ARM_COND_GE 0xa0000000	// N set and V set , or N clear V clear, >=
#define ARM_COND_LT 0xb0000000	// N clear and V clear , or N clear V set, <
#define ARM_COND_GT 0xc0000000	// >
#define ARM_COND_LE 0xd0000000	// <=
#define ARM_COND_AL 0xe0000000	// Always
#define ARM_COND_NV 0xf0000000	// reserved
#define ARM_COND_MASK  0xf0000000

// registers ( TODO )
#define ARM_R0	0
#define ARM_R1 	1
#define ARM_R2	2
#define ARM_R3	3
#define ARM_R4	4
#define ARM_R5	5
#define ARM_R6	6
#define ARM_R7	7
#define ARM_R8	8
#define ARM_R9	9
#define ARM_R10	10
#define ARM_R11	11
#define ARM_R12	12
#define ARM_R13	13
#define ARM_R14	14
#define ARM_R15	15
#define ARM_PC ARM_R15
#define ARM_LR ARM_R14
#define ARM_SP ARM_R13
#define ARM_FP ARM_R11

// branch instruction
#define ARM_BRANCH_I 0x0a000000
#define ARM_BRANCH_I_MASK 0x0E000000
#define ARM_BRANCH_LINK	0x01000000
#define ARM_BRANCH_NOLINK 0x00000000

// data processing DP instruction
#define ARM_DP_I 0x00
/*
0000 = AND - Rd:= Op1 AND Op2
0010 = SUB - Rd:= Op1 - Op2
0011 = RSB - Rd:= Op2 - Op1
0100 = ADD - Rd:= Op1 + Op2
0101 = ADC - Rd:= Op1 + Op2 + C
0110 = SBC - Rd:= Op1 - Op2 + C
0111 = RSC - Rd:= Op2 - Op1 + C
1000 = TST - set condition codes on Op1 AND Op2
1001 = TEQ - set condition codes on Op1 EOR Op2
1010 = CMP - set condition codes on Op1 - Op2
1011 = CMN - set condition codes on Op1 + Op2
1100 = ORR - Rd:= Op1 OR Op2
1101 = MOV - Rd:= Op2
1110 = BIC - Rd:= Op1 AND NOT Op2
1111 = MVN - Rd:= NOT Op2 */



#define ARM_DP_AND 0x0
#define ARM_DP_EOR (0x01<<21)
#define ARM_DP_SUB (0x02<<21)
#define ARM_DP_RSB (0x03<<21)
#define ARM_DP_ADD (0x04<<21)
#define ARM_DP_ADC (0x05<<21)
#define ARM_DP_SBC (0x06<<21)
#define ARM_DP_RSC (0x07<<21)
#define ARM_DP_TST (0x08<<21)
#define ARM_DP_TEQ (0x09<<21)
#define ARM_DP_CMP (0x0a<<21)
#define ARM_DP_CMN (0x0b<<21)
#define ARM_DP_ORR (0x0c<<21)
#define ARM_DP_MOV (0x0d<<21)
#define ARM_DP_BIC (0x0e<<21)
#define ARM_DP_MVN (0x0f<<21)

// TODO: register shift

#define ARM_DP_IMM 0x2000000
#define ARM_DP_NOIMM 0x000000

#define ARM_DP_SETCOND (1<<20)
#define ARM_DP_NOSETCOND 0


// arm data transfer instruction dtx
#define ARM_DTX_I 0x04000000
#define ARM_DTX_I_MASK 0x0C000000

//is immediate value
#define ARM_DTX_IM 0x00
#define ARM_DTX_NOTIM (0x01<<25)
// pre / post indexing
#define ARM_DTX_PRE (0x01<<24)
#define ARM_DTX_POST 0x00
// up / down ( add /substract )
#define ARM_DTX_ADD (0x01<<23)
#define ARM_DTX_SUB 0x00
// byte word operation
#define ARM_DTX_BYTE (0x01<<22)
#define ARM_DTX_WORD 0x00
// write back
#define ARM_DTX_NOWB 0x00
#define ARM_DTX_WB (0x01<<21)
// load store
#define ARM_DTX_LOAD (0x01<<20)
#define ARM_DTX_STORE 0x00

// mascara registre desti 
#define ARM_DTX_RD_MASK ( 0x0F << 12 )


// arm block data transfer instruction dtm
#define ARM_DTM_I 0x08000000
#define ARM_DTM_I_MASK 0x0E000000

// pre / post indexing
#define ARM_DTM_PRE (0x01<<24)
#define ARM_DTM_POST 0x00

// up / down ( add /substract )
#define ARM_DTM_ADD (0x01<<23)
#define ARM_DTM_SUB 0x00

// write back
#define ARM_DTM_NOWB 0x00
#define ARM_DTM_WB (0x01<<21)

// load store
#define ARM_DTM_LOAD (0x01<<20)
#define ARM_DTM_STORE 0x00

typedef struct _arm_label {	
	char  name[100];
	unsigned int at;
} arm_label;

typedef struct _arm_code_seq {
	unsigned int base;
	unsigned int max_ins;
	unsigned int act_ins;

	int * codeseq;
	arm_label *def_labels;
	unsigned int lastlabel;
} arm_code_seq;

#endif
