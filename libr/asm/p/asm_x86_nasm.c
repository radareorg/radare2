/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
#if __APPLE__
	char path_r_nasm[] = "/tmp/r_nasm-XXXXXX";
	int fd_r_nasm;
	char asm_buf[R_ASM_BUFSIZE];
#endif
	char cmd[R_ASM_BUFSIZE];
	ut8 *out;
	int len = 0;
	if (a->syntax != R_ASM_SYNTAX_INTEL) {
		eprintf ("asm.x86.nasm does not support non-intel syntax\n");
		return -1;
	}
#if __APPLE__
	fd_r_nasm = mkstemp (path_r_nasm);
	snprintf (asm_buf, sizeof (asm_buf),
			"BITS %i\nORG 0x%"PFMT64x"\n%s\n__", a->bits, a->pc, buf);
	write (fd_r_nasm, asm_buf, sizeof (asm_buf));
	close (fd_r_nasm);
	snprintf (cmd, sizeof (cmd), "nasm %s -o /dev/stdout\n", path_r_nasm);
#elif
	snprintf (cmd, sizeof (cmd),
			"nasm /dev/stdin -o /dev/stdout <<__\n"
			"BITS %i\nORG 0x%"PFMT64x"\n%s\n__", a->bits, a->pc, buf);
#endif
	out = (ut8 *)r_sys_cmd_str (cmd, "", &len);

#if __APPLE__
	unlink (path_r_nasm);
#endif
	if (out && memcmp (out, "/dev/stdin:", len>11?11:len)) {
		memcpy (op->buf, out, len<=R_ASM_BUFSIZE?len:R_ASM_BUFSIZE);
	} else {
		eprintf ("Error running 'nasm'\n");
		len = 0;
	}
	if (out) free (out);
	op->inst_len = len;
	return len;
}

RAsmPlugin r_asm_plugin_x86_nasm = {
	.name = "x86.nasm",
	.desc = "X86 nasm assembler plugin",
	.arch = "x86",
	.bits = (int[]){ 16, 32, 64, 0 },
	.init = NULL,
	.fini = NULL,
	.disassemble = NULL,
	.assemble = &assemble, 
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_nasm
};
#endif
