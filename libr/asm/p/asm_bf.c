/* radare - LGPL - Copyright 2009-2010 pancake <youterm.com> - nibble<.ds@gmail.com> */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>


static int disassemble(struct r_asm_t *a, struct r_asm_op_t *op, ut8 *buf, ut64 len) {
	char *buf_cp, *b;
	int i;

	if ((b = buf_cp = malloc (len+1)) == NULL)
		return 0;
	memcpy (buf_cp, buf, len+1);

	for (i=0; b[0] == b[1] && i<len; b++, i++);
	b[1] = '\0';

	switch(buf[0]) {
	case '[':
		strcpy (op->buf_asm, "[ loop {");
		break;
	case ']':
		strcpy (op->buf_asm, "] }"); // TODO: detect clause and put label name
		break;
	case '>':
		if (i>1) strcpy (op->buf_asm, "> add [ptr]");
		else strcpy (op->buf_asm, "> inc [ptr]");
		break;
	case '<':
		if (i>1) strcpy (op->buf_asm, "< sub [ptr]");
		else strcpy (op->buf_asm, "< dec [ptr]");
		break;
	case '+':
		if (i>1) strcpy (op->buf_asm, "+ add [ptr]");
		else strcpy (op->buf_asm, "+ inc [ptr]");
		break;
	case '-':
		if (i>1) strcpy (op->buf_asm, "- sub [ptr]");
		else strcpy (op->buf_asm, "- dec [ptr]");
		break;
	case ',':
		strcpy (op->buf_asm, ", [ptr] = getch()");
		break;
	case '.':
		strcpy (op->buf_asm, ". print( [ptr] )");
		break;
	case '\x00':
		strcpy (op->buf_asm, "  trap");
		break;
	default:
		strcpy (op->buf_asm, "  nop");
		break;
	}

	if (i>0) sprintf (op->buf_asm, "%s, %d", op->buf_asm, i+1);
	if (i<1) i=1; else i++;

	free (buf_cp);
	return i;
}

RAsmPlugin r_asm_plugin_bf = {
	.name = "bf",
	.arch = "bf",
	.bits = (int[]){ 8, 16, 32, 0 }, // dummy
	.desc = "Brainfuck disassembly plugin",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_bf
};
#endif
