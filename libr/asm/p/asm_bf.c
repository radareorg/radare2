/* radare - LGPL - Copyright 2009-2013 - pancake, nibble */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>


static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	char *buf_cp, *b;
	int i;

	if (!(b = buf_cp = malloc (len+1)))
		return 0;
	memcpy (buf_cp, buf, len);
	buf_cp[len] = 0;

	for (i=0; b[0]&&b[1] && b[0] == b[1] && i<len; b++, i++);
	b[1] = '\0';

	switch (*buf) {
	case '[':
		strcpy (op->buf_asm, "while [ptr]");
		break;
	case ']':
		strcpy (op->buf_asm, "loop"); // TODO: detect clause and put label name
		break;
	case '>':
		if (i>1) strcpy (op->buf_asm, "add ptr");
		else strcpy (op->buf_asm, "inc ptr");
		break;
	case '<':
		if (i>1) strcpy (op->buf_asm, "sub ptr");
		else strcpy (op->buf_asm, "dec ptr");
		break;
	case '+':
		if (i>1) strcpy (op->buf_asm, "add [ptr]");
		else strcpy (op->buf_asm, "inc [ptr]");
		break;
	case '-':
		if (i>1) strcpy (op->buf_asm, "sub [ptr]");
		else strcpy (op->buf_asm, "dec [ptr]");
		break;
	case ',':
		strcpy (op->buf_asm, "peek [ptr]");
		break;
	case '.':
		strcpy (op->buf_asm, "poke [ptr]");
		break;
	case 0xff:
	case 0x00:
		strcpy (op->buf_asm, "trap");
		break;
	default:
		strcpy (op->buf_asm, "nop");
		break;
	}

	if (i>0) {
		if (strchr (op->buf_asm, ' '))
		snprintf (op->buf_asm, sizeof (op->buf_asm), "%s, %d", op->buf_asm, i+1);
		else snprintf (op->buf_asm, sizeof (op->buf_asm), "%s %d", op->buf_asm, i+1);
	}
	if (i<1) i=1; else i++;

	free (buf_cp);
	op->inst_len = i;
	return i;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	const char *ref, *arg;
	int n = 0;
	if (buf[0] && buf[1]==' ')
		buf += 2;
	arg = strchr (buf, ',');
	ref = strchr (buf, '[');
	if (!strncmp (buf, "trap", 4)) {
		if (arg) {
			n = atoi (arg+1);
			memset (op->buf, 0xcc, n);
		} else {
			op->buf[0] = 0x90;
			n = 1;
		}
	} else
	if (!strncmp (buf, "nop", 3)) {
		if (arg) {
			n = atoi (arg+1);
			memset (op->buf, 0x90, n);
		} else {
			op->buf[0] = 0x90;
			n = 1;
		}
	} else
	if (!strncmp (buf, "inc", 3)) {
		char ch = ref? '+': '>';
		op->buf[0] = ch;
		n = 1;
	} else
	if (!strncmp (buf, "dec", 3)) {
		char ch = ref? '-': '<';
		op->buf[0] = ch;
		n = 1;
	} else
	if (!strncmp (buf, "sub", 3)) {
		char ch = ref? '-': '<';
		if (arg) {
			n = atoi (arg+1);
			memset (op->buf, ch, n);
		} else {
			op->buf[0] = '<';
			n = 1;
		}
	} else
	if (!strncmp (buf, "add", 3)) {
		char ch = ref? '+': '>';
		if (arg) {
			n = atoi (arg+1);
			memset (op->buf, ch, n);
		} else {
			op->buf[0] = '<';
			n = 1;
		}
	} else
	if (!strncmp (buf, "while", 5)) {
		op->buf[0] = '[';
		n = 1;
	} else
	if (!strncmp (buf, "loop", 4)) {
		op->buf[0] = ']';
		n = 1;
	} else
	if (!strncmp (buf, "peek", 4)) {
		if (arg) {
			n = atoi (arg+1);
			memset (op->buf, ',', n);
		} else {
			op->buf[0] = ',';
			n = 1;
		}
	} else
	if (!strncmp (buf, "poke", 4)) {
		if (arg) {
			n = atoi (arg+1);
			memset (op->buf, '.', n);
		} else {
			op->buf[0] = '.';
			n = 1;
		}
	}
	return n;
}

RAsmPlugin r_asm_plugin_bf = {
	.name = "bf",
	.arch = "bf",
	.license = "LGPL3",
	.bits = (int[]){32,0},
	.desc = "Brainfuck disassembly plugin",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble 
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_bf
};
#endif
