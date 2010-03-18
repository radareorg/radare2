#include "format.c"
#include "avr_disasm.c"
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
	ins.address = addr;
	ins.opcode = (buf[1]<<8) | buf[0];
	if (disassembleInstruction (&dins, ins)) {
		fprintf (stderr, "FAIL\n");
		return -1;
	}
	printDisassembledInstruction (out, dins, opt);
	//printf ("0x%08llx %s\n", addr, out);
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
//		printf ("0x%08llx  %s\n", addr+delta, opcode);
		delta += ret;
	}
	return 0;
}
#endif
