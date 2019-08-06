/* radare - LGPL - Copyright 2009-2019 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	char *ipath, *opath;
	int ifd, ofd;
	if (a->syntax != R_ASM_SYNTAX_INTEL) {
		eprintf ("asm.x86.nasm does not support non-intel syntax\n");
		return -1;
	}

	ifd = r_file_mkstemp ("r_nasm", &ipath);
	if (ifd == -1) {
		return -1;
	}

	ofd = r_file_mkstemp ("r_nasm", &opath);
	if (ofd == -1) {
		free (ipath);
		return -1;
	}

	char *asm_buf = r_str_newf ("[BITS %i]\nORG 0x%"PFMT64x"\n%s\n", a->bits, a->pc, buf);
	if (asm_buf) {
		write (ifd, asm_buf, strlen (asm_buf));
		free (asm_buf);
	}

	close (ifd);

	if (!r_sys_cmdf ("nasm %s -o %s", ipath, opath)) {
		ut8 buf[512]; // TODO: remove limits
		op->size = read (ofd, buf, sizeof (buf));
		r_asm_op_set_buf (op, buf, op->size);
	} else {
		eprintf ("Error running 'nasm'\n");
	}

	close (ofd);
	unlink (ipath);
	unlink (opath);
	free (ipath);
	free (opath);

	return op->size;
}

RAsmPlugin r_asm_plugin_x86_nasm = {
	.name = "x86.nasm",
	.desc = "X86 nasm assembler",
	.license = "LGPL3",
	.arch = "x86",
	// NOTE: 64bits is not supported on OSX's nasm :(
	.bits = 16|32|64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.assemble = &assemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_nasm,
	.version = R2_VERSION
};
#endif
