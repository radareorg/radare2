/*oddcoder 2016*/
#include <r_asm.h>
#include <r_lib.h>
//PIC18CXXX instruction set
//this algorithm will 100% decompile valid opcodes correctly
//the only one problem is that It may treat certain opcodes
//as if they were valid. which may be problem I cant solve
//one exaple of these opcodes are 013f
//unfortunatly it will it will be handled incorrectly
//and interpreted as MOVLB 0xf although it is not even valid
//but I think it will be fine 
#define NO_ARG 0
#define DAF_T 1
#define F32_T 2
#define BAF_T 3
#define K_T 4
#define N_T 5
#define CALL_T 6
#define NEX_T 7
#define AF_T 8
#define GOTO_T 9
#define SHK_T 10
#define S_T 11
#define LFSR_T 12
static char* fsr[]={"FSR0","FSR1","FSR2","Reserved"};
static struct{
	ut16 opmin;
	ut16 opmax;
	char *name;
	ut8 optype;
	//and some magical hocus pocus ;)
} ops[]={
	{0b1111000000000000,0b1111111111111111,"NOP",NO_ARG},
	{0b1110111100000000,0b1110111111111111,"GOTO",GOTO_T},
	{0b1110111000000000,0b1110111000111111,"LFSR",LFSR_T},
	{0b1110110000000000,0b1110110111111111,"CALL",CALL_T},
	{0b1110011100000000,0b1110011111111111,"BNN",N_T},
	{0b1110011000000000,0b1110011011111111,"BN",N_T},
	{0b1110010100000000,0b1110010111111111,"BNOV",N_T},
	{0b1110010000000000,0b1110010011111111,"BOV",N_T},
	{0b1110001100000000,0b1110001111111111,"BNC",N_T},
	{0b1110001000000000,0b1110001011111111,"BC",N_T},
	{0b1110000100000000,0b1110000111111111,"BNZ",N_T},
	{0b1110000000000000,0b1110000011111111,"BZ",N_T},
	{0b1101100000000000,0b1101111111111111,"RCALL",N_T},
	{0b1101000000000000,0b1110000011111111,"BRA",NEX_T},
	{0b1100000000000000,0b1100111111111111,"MOVFF",F32_T},
	{0b1011000000000000,0b1011111111111111,"BTFSC",BAF_T},
	{0b1010000000000000,0b1010111111111111,"BTFSS",BAF_T},
	{0b1001000000000000,0b1001111111111111,"BCF",BAF_T},
	{0b1000000000000000,0b1000111111111111,"BSF",BAF_T},
	{0b0111000000000000,0b0111111111111111,"BTG",BAF_T},
	{0b0110111000000000,0b0110111111111111,"MOVWF",AF_T},
	{0b0110110000000000,0b0110110111111111,"NEGF",AF_T},
	{0b0110101000000000,0b0110101111111111,"CLRF",AF_T},
	{0b0110100000000000,0b0110100111111111,"SETF",AF_T},
	{0b0110011000000000,0b0110011111111111,"TSTFSZ",AF_T},
	{0b0110010000000000,0b0110010111111111,"CPFSGT",AF_T},
	{0b0110001000000000,0b0110001111111111,"CPFSEQ",AF_T},
	{0b0110000000000000,0b0110000111111111,"CPFSLT",AF_T},
	{0b0101110000000000,0b0101111111111111,"SUBWF",DAF_T},
	{0b0101100000000000,0b0101101111111111,"SUBWFB",DAF_T},
	{0b0101010000000000,0b0101011111111111,"SUBFWB",DAF_T},
	{0b0101000000000000,0b0101001111111111,"MOVF",DAF_T},
	{0b0100110000000000,0b0100111111111111,"DCFSNZ",DAF_T},
	{0b0100100000000000,0b0100101111111111,"INFSNZ",DAF_T},
	{0b0100010000000000,0b0100011111111111,"RLNCF",DAF_T},
	{0b0100000000000000,0b0100001111111111,"RRNCF",DAF_T},
	{0b0011110000000000,0b0011111111111111,"INCFSZ",DAF_T},
	{0b0011100000000000,0b0011101111111111,"SWAPF",DAF_T},
	{0b0011010000000000,0b0011011111111111,"RLCF",DAF_T},
	{0b0011000000000000,0b0011001111111111,"RRCF",DAF_T},
	{0b0010110000000000,0b0010111111111111,"DECFSZ",DAF_T},
	{0b0010100000000000,0b0010101111111111,"INCF",DAF_T},
	{0b0010010000000000,0b0010011111111111,"ADDWF",DAF_T},
	{0b0010000000000000,0b0010001111111111,"ADDWFC",DAF_T},
	{0b0001110000000000,0b0001111111111111,"COMF",DAF_T},
	{0b0001100000000000,0b0001101111111111,"XORWF",DAF_T},
	{0b0001010000000000,0b0001011111111111,"ANDWF",DAF_T},
	{0b0001000000000000,0b0001001111111111,"IORWF",DAF_T},
	{0b0000111100000000,0b0000111111111111,"ADDLW",K_T},
	{0b0000111000000000,0b0000111011111111,"MOVLW",K_T},
	{0b0000110100000000,0b0000110111111111,"MULLW",K_T},
	{0b0000110000000000,0b0000110011111111,"RETLW",K_T},
	{0b0000101100000000,0b0000101111111111,"ANDLW",K_T},
	{0b0000101000000000,0b0000101011111111,"XORLW",K_T},
	{0b0000100100000000,0b0000100111111111,"IORLW",K_T},
	{0b0000100000000000,0b0000100011111111,"SUBLW",K_T},
	{0b0000010000000000,0b0000011111111111,"DECF",DAF_T},
	{0b0000001000000000,0b0000001111111111,"MULWF",AF_T},
	{0b0000000100000000,0b0000000100001111,"MOVLB",SHK_T},
	{0b0000000011111111,0b0000000011111111,"RESET",NO_ARG},
	{0b0000000000010010,0b0000000000010011,"RETURN",S_T},
	{0b0000000000010000,0b0000000000010001,"RETFIE",S_T},
	{0b0000000000001111,0b0000000000001111,"TBLWT+*",NO_ARG},
	{0b0000000000001110,0b0000000000001110,"TBLWT*-",NO_ARG},
	{0b0000000000001101,0b0000000000001101,"TBLWT*+",NO_ARG},
	{0b0000000000001100,0b0000000000001100,"TBLWT*",NO_ARG},
	{0b0000000000001011,0b0000000000001011,"TBLRD+*",NO_ARG},
	{0b0000000000001010,0b0000000000001010,"TBLRD*-",NO_ARG},
	{0b0000000000001001,0b0000000000001001,"TBLRD*+",NO_ARG},
	{0b0000000000001000,0b0000000000001000,"TBLRD*",NO_ARG},
	{0b0000000000000111,0b0000000000000111,"DAW",NO_ARG},
	{0b0000000000000110,0b0000000000000110,"POP",NO_ARG},
	{0b0000000000000101,0b0000000000000101,"PUSH",NO_ARG},
	{0b0000000000000100,0b0000000000000100,"CLRWDT",NO_ARG},
	{0b0000000000000011,0b0000000000000011,"SLEEP",NO_ARG},
	{0b0000000000000000,0b0000000000000000,"NOP",NO_ARG},
	{-1,-1,"invalid",NO_ARG},
	};

static int pic_disassem (RAsm *a, RAsmOp *op,const ut8 *b, int l){
	int i;
	ut16 instr = *(ut16*)b; //instruction
	for(i=0;ops[i].opmin!=-1 &&!(
	    ops[i].opmin == (ops[i].opmin&instr)&& 
	    ops[i].opmax == (ops[i].opmax|instr) );i++ );
	strcpy(op->buf_asm,ops[i].name);
	if(ops[i].opmin ==-1){
		op->size =2;
		return -1;
	}
	char arg[32];
	op->size = 2;
	switch(ops[i].optype){
	case NO_ARG:
		return 2;
	case N_T:
	case K_T:
		sprintf(arg," 0x%x",instr & 0b11111111 );
		break;
	case DAF_T:
		sprintf(arg," 0x%x, %d, %d",
			instr & 0b11111111,(instr>>9)&1,(instr>>8)&1 );
		break;
	case AF_T:
		sprintf(arg," 0x%x, %d",instr & 0b11111111,(instr>>8)&1 );
		break;

	case BAF_T:
		sprintf(arg," 0x%x, %d, %d",
			instr & 0b11111111,(instr>>9)&0b111,(instr>>8)&1);
		break;
	case NEX_T:
		sprintf(arg," 0x%x",instr &0b11111111111 );
		break;
	case CALL_T:if(1){
		if(l<4){
			strcpy(op->buf_asm,"invalid");
			return -1;
		}
		op->size=4;
		ut32 dword_instr = *(ut32*)b;
		if(dword_instr>>28 != 0b1111){
			strcpy(op->buf_asm,"invalid");
			return -1;
		}
		sprintf(arg," 0x%x, %d", dword_instr& 0b11111111|
					(dword_instr>>8 & 0b111111111111111100000000),(dword_instr>>8)&1);
		break;
		}
	case GOTO_T:if(1){
		if(l<4){
			strcpy(op->buf_asm,"invalid");
			return -1;
		}
		op->size=4;
		ut32 dword_instr = *(ut32*)b;
		if(dword_instr>>28 != 0b1111){
			strcpy(op->buf_asm,"invalid");
			return -1;
		}
		sprintf(arg," 0x%x",(dword_instr&0b111111111111)<<12 |
			       (dword_instr>>16)&0b111111111111);
		break;
		}
	case F32_T:if(1){
		if(l<4){
			strcpy(op->buf_asm,"invalid");
			return -1;
		}
		op->size=4;
		ut32 dword_instr = *(ut32*)b;
		if(dword_instr>>28 != 0b1111){
			strcpy(op->buf_asm,"invalid");
			return -1;
		}
		sprintf(arg," 0x%x, 0x%x",dword_instr &0b111111111111,
				 (dword_instr>>16) & 0b111111111111);
		break;
	}
	case SHK_T:
		sprintf(arg," 0x%x",instr & 0b1111 );
		break;
	case S_T:
		sprintf(arg," %d",instr&0b1);
		break;
	case LFSR_T:
		if(1){
		op->size=4;
		ut32 dword_instr= *(ut32*)b;
		if(dword_instr>>28 != 0b1111){
			strcpy(op->buf_asm,"invalid");
			return -1;
		}
		ut8 reg_n = (dword_instr>>4)&0b11;
		sprintf(arg," %s, %d",fsr[reg_n],(dword_instr&0b1111)<<8 | ((dword_instr>>16)&0b11111111));
		break;
		}
	default:
		sprintf(arg,"unknown args");
	};
	strcat(op->buf_asm,arg);
	return op->size;
}
RAsmPlugin r_asm_plugin_pic18c = {
	.disassemble = pic_disassem,
	.name = "pic18c",
	.arch = "pic18c",
	.license = "LGPL3",
	.bits = 16,
	.desc = "pic disassembler"
};
#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
        .type = R_LIB_TYPE_ASM,
        .data = &r_asm_plugin_pic18c
};
#endif
