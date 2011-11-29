/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	char *ipath, *opath;
	int ifd, ofd;
	const char *syntaxstr = "";
	char asm_buf[R_ASM_BUFSIZE];
	int len = 0;

	ifd = r_file_mkstemp ("r_as", &ipath);
	ofd = r_file_mkstemp ("r_as", &opath);

	syntaxstr = ".intel_syntax noprefix\n"; // if intel syntax
	len = snprintf (asm_buf, sizeof (asm_buf),
			"%s.code%i\n" //.org 0x%"PFMT64x"\n"
			".ascii \"BEGINMARK\"\n"
			"%s\n"
			".ascii \"ENDMARK\"\n",
			syntaxstr, a->bits, buf); // a->pc ??
	write (ifd, asm_buf, len);
	//write (1, asm_buf, len);
	close (ifd);

	if (!r_sys_cmdf ("as %s -o %s", ipath, opath)) {
		const ut8 *begin, *end;
		close (ofd);
		ofd = open (opath, O_BINARY|O_RDONLY);
		len = read (ofd, op->buf, R_ASM_BUFSIZE);
		begin = r_mem_mem (op->buf, len, (const ut8*)"BEGINMARK", 9);
		end = r_mem_mem (op->buf, len, (const ut8*)"ENDMARK", 7);
		if (!begin || !end) {
			eprintf ("Cannot find water marks\n");
			len = 0;
		} else {
			len = (int)(size_t)(end-begin-9);
			if (len>0) memcpy (op->buf, begin+9, len);
			else len = 0;
		}
	} else {
		eprintf ("Error running: as %s -o %s", ipath, opath);
		len = 0;
	}

	close (ofd);

	unlink (ipath);
	unlink (opath);
	free (ipath);
	free (opath);

	op->inst_len = len;
	return len;
}

RAsmPlugin r_asm_plugin_x86_as = {
	.name = "x86.as",
	.desc = "X86 assembler plugin using 'as' program",
	.arch = "x86",
	// NOTE: 64bits is not supported on OSX's nasm :(
	.bits = (int[]){ 16, 32, 64, 0 },
	.init = NULL,
	.fini = NULL,
	.disassemble = NULL,
	.assemble = &assemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_as
};
#endif
