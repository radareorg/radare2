#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#define USE_DECODE
#include "decode.h"

extern ut8 *ins_buff;
extern ut32 ins_buff_len;

int debug = 0;

int c55plus_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len)
{
	unsigned int next_ins_pos;
	char *ins_decoded;
	size_t i, ins_decoded_len;

	ins_buff = (ut8 *)buf;
	ins_buff_len = (ut32)len;

	next_ins_pos = 0;

	// decode instruction
	ins_decoded = decode(0, &next_ins_pos);
	if(!ins_decoded) {
		op->inst_len = 0;
		return 0;
	}

	// opcode length
	op->inst_len = next_ins_pos;
	ins_decoded_len = strlen(ins_decoded);
	for(i = 0; i < ins_decoded_len; i++)
		ins_decoded[i] = tolower(ins_decoded[i]);
	
	snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s", ins_decoded);

	free(ins_decoded);
	
	return next_ins_pos;
}
