#include "avr_disasm.h"
#include "format.h"
#include "r_asm.h"
#include <string.h>

int avr_decode(RAsm *a, char *out, int out_len, ut64 addr, cut8 *buf, int len) {
	formattingOptions opt = {0};
	disassembledInstruction dins;
	assembledInstruction ins;
	avrDisassembleContext context = {0};
	int opsize = 2;

	if (len < 2) {
		strcpy (out, "truncated");
		return -1;
	}
	// be sure that the buffer is always set.
	ins.address = addr;
	ins.opcode = (buf[0] | buf[1] << 8); // | (buf[2]<<16) | (buf[3]<<24);

	out[0] = 0;

	if (disassembleInstruction (&context, &dins, ins)) {
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
			return -1;
		}
		if (printDisassembledInstruction (a, &context, out, out_len, dins, opt) < 0) {
			return -1;
		}
		opsize = 4;
	} else if (printDisassembledInstruction (a, &context, out, out_len, dins, opt) < 0) {
		return -1;
	}
	if (out[0] == '.' || !out[0]) {
		return -1;
	}
	return opsize;
}

int avr_anal(RAnal *a, char *out, int out_size, ut64 addr, cut8 *buf, int len) {
	formattingOptions opt = {0};
	disassembledInstruction dins;
	assembledInstruction ins;
	avrDisassembleContext context = {0};
	int opsize = 2;

	r_str_ncpy (out, "invalid", out_size);
	if (len < 2) {
		return -1;
	}
	// be sure that the buffer is always set.
	ins.address = addr;
	ins.opcode = (buf[0] | buf[1] << 8); // | (buf[2]<<16) | (buf[3]<<24);

	out[0] = 0;

	if (disassembleInstruction (&context, &dins, ins)) {
		return -1;
	}
	if (context.status > 0) {
		if (len < 4) {
			return -2;
		}
		ins.address = addr;
		//ins.opcode = (buf[0] | buf[1]<<8) | (buf[2]<<16) | (buf[3]<<24);
		ins.opcode = (buf[3] << 8) | (buf[2]);
		/*
			(buf[3]<<24) | (buf[2]<<16) | \
			(buf[1]<<8) | (buf[0]);
		*/
		if (disassembleInstruction (&context, &dins, ins)) {
			return -1;
		}
		if (analPrintDisassembledInstruction (a, &context, out, out_size, dins, opt) < 0) {
			return -1;
		}
		opsize = 4;
	} else if (analPrintDisassembledInstruction (a, &context, out, out_size, dins, opt) < 0) {
		return -1;
	}
	if (out[0] == '.' || !out[0]) {
		r_str_ncpy (out, "invalid", out_size);
	}
	return opsize;
}
