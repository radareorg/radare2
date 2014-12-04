/* c55plus - LGPL - Copyright 2013 - th0rpe */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#define USE_DECODE
#include "decode.h"

#include "../tms320_p.h"
#include "../tms320_dasm.h"

extern ut8 *ins_buff;
extern ut32 ins_buff_len;
extern st8 *c55plus_decode(ut32 ins_pos, ut32 *next_ins_pos);

int c55x_plus_disassemble(tms320_dasm_t *dasm, const ut8 *buf, int len) {
	unsigned int next_ins_pos;
	char *ins_decoded;
	size_t i, ins_decoded_len;

	ins_buff = (ut8 *)buf;
	ins_buff_len = (ut32)len;

	next_ins_pos = 0;

	// decode instruction
	ins_decoded = c55plus_decode(0, &next_ins_pos);
	dasm->length = next_ins_pos;
	if (!ins_decoded) {
		return 0;
	}

	// opcode length
	dasm->length = next_ins_pos;
	ins_decoded_len = strlen(ins_decoded);
	for (i = 0; i < ins_decoded_len; i++)
		ins_decoded[i] = tolower((unsigned char)ins_decoded[i]);
	snprintf (dasm->syntax, sizeof(dasm->syntax), "%s", ins_decoded);
	free (ins_decoded);
	
	return next_ins_pos;
}
