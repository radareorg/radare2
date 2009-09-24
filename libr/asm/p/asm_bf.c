/* radare - GPL3 - Copyright 2009 pancake <youterm.com> - nibble<.ds@gmail.com> */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>


static int disassemble(struct r_asm_t *a, struct r_asm_aop_t *aop, ut8 *buf, ut64 len)
{
	int i;
	char *buf_cp, *b;

	if ((b = buf_cp = alloca(len+1)) == NULL)
		return 0;
	memcpy(buf_cp, buf, len+1);

	for(i=0;b[0] == b[1] && i<len; b=b+1,i++); b[1] = '\0';

	switch(buf[0]) {
	case '[':
		strcpy(aop->buf_asm, "[ loop {");
		break;
	case ']':
		strcpy(aop->buf_asm, "] }"); // TODO: detect clause and put label name
		break;
	case '>':
		if (i>1) strcpy(aop->buf_asm, "> add [ptr]");
		else strcpy(aop->buf_asm, "> inc [ptr]");
		break;
	case '<':
		if (i>1) strcpy(aop->buf_asm, "< sub [ptr]");
		else strcpy(aop->buf_asm, "< dec [ptr]");
		break;
	case '+':
		if (i>1) strcpy(aop->buf_asm, "+ add [ptr]");
		else strcpy(aop->buf_asm, "+ inc [ptr]");
		break;
	case '-':
		if (i>1) strcpy(aop->buf_asm, "- sub [ptr]");
		else strcpy(aop->buf_asm, "- dec [ptr]");
		break;
	case ',':
		strcpy(aop->buf_asm, ", [ptr] = getch()");
		break;
	case '.':
		strcpy(aop->buf_asm, ". print( [ptr] )");
		break;
	case '\x00':
		strcpy(aop->buf_asm, "  trap");
		break;
	default:
		strcpy(aop->buf_asm, "  nop");
		break;
	}

	if (i>0) sprintf(aop->buf_asm, "%s, %d", aop->buf_asm, i+1);
	if (i<1) i=1; else i++;

	aop->disasm_obj = NULL;

	return i;
}

struct r_asm_handle_t r_asm_plugin_bf = {
	.name = "bf",
	.arch = "brainfuck",
	.bits = (int[]){ 8, 0 },
	.desc = "BF disassembly plugin",
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
