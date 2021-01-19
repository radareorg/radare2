#include "avr_disasm.h"
#include "format.h"
#include <string.h>
#include <r_types_base.h>

int avr_decode (char *out, ut64 addr, cut8 *buf, int len) {
	formattingOptions opt = { 0 };
	disassembledInstruction dins;
	assembledInstruction ins;
	avrDisassembleContext context = { 0 };
	if (len < 2) {
		strcpy (out, "truncated");
		return -1;
	}
	ins.address = addr;
	ins.opcode = (buf[0] | buf[1] << 8); // | (buf[2]<<16) | (buf[3]<<24);
	if (disassembleInstruction (&context, &dins, ins)) {
		strcpy (out, "invalid");
		return -1;
	}
	if (context.status > 0) {
		if (len < 4) {
			strcpy (out, "truncated");
			return -1;
		}
		ins.address = addr;
		//ins.opcode = (buf[0] | buf[1]<<8) | (buf[2]<<16) | (buf[3]<<24);
		ins.opcode = (buf[3] << 8) | (buf[2]);
		/*
			(buf[3]<<24) | (buf[2]<<16) | \
			(buf[1]<<8) | (buf[0]);
		*/
		if (disassembleInstruction (&context, &dins, ins)) {
			strcpy (out, "invalid");
			return -1;
		}
		if (printDisassembledInstruction (&context, out, dins, opt) < 0) {
			strcpy (out, "invalid");
			return -1;
		}
		return 4;
	}
	if (printDisassembledInstruction (&context, out, dins, opt) < 0) {
		strcpy (out, "invalid");
		return -1;
	}
	return 2;
}
