/* radare - LGPL - Copyright 2011-2020 pancake */

#include <r_lib.h>
#include <r_asm.h>

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	char *ipath, *opath;
	const char *syntaxstr = "";
	int len = 0;

	int ifd = r_file_mkstemp ("r_as", &ipath);
	if (ifd == -1) {
		return -1;
	}

	int ofd = r_file_mkstemp ("r_as", &opath);
	if (ofd == -1) {
		free (ipath);
		close (ifd);
		return -1;
	}

	switch (a->syntax) {
	case R_ASM_SYNTAX_INTEL:
		syntaxstr = ".intel_syntax noprefix\n";
		break;
	case R_ASM_SYNTAX_ATT:
		syntaxstr = ".att_syntax\n";
		break;
	}

	char *asm_buf = r_str_newf (
			"%s.code%i\n" //.org 0x%"PFMT64x"\n"
			".ascii \"BEGINMARK\"\n"
			"%s\n"
			".ascii \"ENDMARK\"\n",
			syntaxstr, a->bits, buf); // a->pc ??
	const size_t asm_buf_len = strlen (asm_buf);
	const bool success = write (ifd, asm_buf, asm_buf_len) == asm_buf_len;
	close (ifd);
	free (asm_buf);
	if (!success) {
		return -1;
	}
#if __i386__ || __x86_64__
	const char *x86as = "as";
#else
	const char *x86as = "";
#endif
	char *user_ass = r_sys_getenv ("R2_X86AS");
	if (user_ass) {
		x86as = user_ass;
	}
	if (R_STR_ISEMPTY (x86as)) {
		eprintf ("Please set R2_X86AS env to define an x86 assembler program\n");
		return 1;
	}
	bool res = r_sys_cmdf ("%s %s -o %s", x86as, ipath, opath);
	free (user_ass);
	if (!res) {
		const ut8 *begin, *end;
		close (ofd);
// r_sys_cmdf ("cat %s", opath);
		ofd = r_sandbox_open (opath, O_BINARY | O_RDONLY, 0644);
		if (ofd < 0) {
			free (ipath);
			free (opath);
			return -1;
		}
		ut8 opbuf[512] = {0};
		len = read (ofd, opbuf, sizeof (opbuf));
		begin = r_mem_mem (opbuf, len, (const ut8*)"BEGINMARK", 9);
		end = r_mem_mem (opbuf, len, (const ut8*)"ENDMARK", 7);
		if (!begin || !end) {
			eprintf ("Cannot find water marks\n");
			len = 0;
		} else {
			len = (int)(size_t)(end - begin - 9);
			if (len > 0) {
				r_asm_op_set_buf (op, begin + 9, len);
			} else {
				len = 0;
			}
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

	op->size = len;
	return len;
}

RAsmPlugin r_asm_plugin_x86_as = {
	.name = "x86.as",
	.desc = "Intel X86 GNU Assembler (Use R2_X86AS env)",
	.arch = "x86",
	.license = "LGPL3",
	// NOTE: 64bits is not supported on OSX's nasm :(
	.bits = 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.assemble = &assemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_as,
	.version = R2_VERSION
};
#endif
