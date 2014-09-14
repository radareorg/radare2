/* radare - LGPL - Copyright 2009-2014 - pancake, nibble */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>


static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	const ut8 *b;
	int rep = 1;

	/* Count repetitions of the current instruction, unless it's a trap. */
	if (*buf != 0x00 && *buf != 0xff)
		for (b = &buf[1]; b < buf+len && *b == *buf; b++)
			rep++;

	switch (*buf) {
	case '[':
		strcpy (op->buf_asm, "while [ptr]");
		break;
	case ']':
		strcpy (op->buf_asm, "loop"); // TODO: detect clause and put label name
		break;
	case '>':
		if (rep>1) strcpy (op->buf_asm, "add ptr");
		else strcpy (op->buf_asm, "inc ptr");
		break;
	case '<':
		if (rep>1) strcpy (op->buf_asm, "sub ptr");
		else strcpy (op->buf_asm, "dec ptr");
		break;
	case '+':
		if (rep>1) strcpy (op->buf_asm, "add [ptr]");
		else strcpy (op->buf_asm, "inc [ptr]");
		break;
	case '-':
		if (rep>1) strcpy (op->buf_asm, "sub [ptr]");
		else strcpy (op->buf_asm, "dec [ptr]");
		break;
	case ',':
		strcpy (op->buf_asm, "in [ptr]");
		break;
	case '.':
		strcpy (op->buf_asm, "out [ptr]");
		break;
	case 0xff:
	case 0x00:
		strcpy (op->buf_asm, "trap");
		break;
	default:
		strcpy (op->buf_asm, "nop");
		break;
	}

	if (rep>1) {
		/* Note: snprintf's source and destination buffers may not
		 * overlap. */
		const char *fmt = strchr (op->buf_asm, ' ')? "%s, %d":"%s %d";
		char buf[sizeof (op->buf_asm)];
		snprintf (buf, sizeof (buf), fmt, op->buf_asm, rep);
		strcpy(op->buf_asm, buf);
	}

	op->size = rep;
	return rep;
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
	if (!strncmp (buf, "in", 4)) {
		if (arg) {
			n = atoi (arg+1);
			memset (op->buf, ',', n);
		} else {
			op->buf[0] = ',';
			n = 1;
		}
	} else
	if (!strncmp (buf, "out", 4)) {
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
	.bits = 16|32,
	.desc = "Brainfuck",
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
