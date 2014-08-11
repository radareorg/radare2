#include "avr_disasm.c"
#include "format.c"
#include "avr_instructionset.c"
#ifndef ut64
#define ut64 unsigned long long
#endif
#ifndef cut8
#define cut8 const unsigned char
#endif

int avrdis (char *out, ut64 addr, cut8 *buf, int len) {
	formattingOptions opt = { 0 };
	disassembledInstruction dins;
	assembledInstruction ins;
	AVR_Long_Instruction = 0;
	AVR_Long_Address = 0;
	ins.address = addr;
	ins.opcode = (buf[1]<<8) | buf[0] |
		(buf[2]<<16) | (buf[3]<<24);
	if (disassembleInstruction (&dins, ins)) {
		strcpy (out, "invalid");
		return -1;
	}
	if (AVR_Long_Instruction) {
		ins.address = addr;
		ins.opcode = 
			(buf[3]<<8) | (buf[2]);
		/*
			(buf[3]<<24) | (buf[2]<<16) | \
			(buf[1]<<8) | (buf[0]);
		*/
		if (disassembleInstruction (&dins, ins)) {
			strcpy (out, "invalid");
			return -1;
		}
		printDisassembledInstruction (out, dins, opt);
		return 4;
	}
	printDisassembledInstruction (out, dins, opt);
	//printf ("0x%08"PFMT64x" %s\n", addr, out);
	return 2;
}

#if TEST
int main() {
	ut64 addr = 0;
	int ret = 0;
	char *code = "\x8a\xb7\x42\xac\x80\x1e";
	char opcode[65];
	int delta = 0;
	int len;
	len = strlen (code);
	for (;delta<len;){
		ret = avrdis (opcode, addr+delta, code+delta, len-delta);
		if (ret == -1)
			break;
//		printf ("0x%08"PFMT64x"  %s\n", addr+delta, opcode);
		delta += ret;
	}
	return 0;
}
#endif
