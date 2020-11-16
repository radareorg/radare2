/* radare - LGPL - Copyright 2015-2020 pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#define ASSEMBLER "R2_PPC_AS"

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
#if __powerpc__
	char *as = "as";
#else
	char *as = "";
#endif
	char *user_as = r_sys_getenv (ASSEMBLER);
	if (user_as) {
		as = user_as;
	}
	if (R_STR_ISEMPTY (as)) {
		eprintf("Please set "ASSEMBLER" env to define a ppc assembler program\n");
		return 1;
	}

	char *ipath, *opath;

	int ifd = r_file_mkstemp ("r_as", &ipath);
	if (ifd == -1) {
		free (user_as);
		return -1;
	}

	int ofd = r_file_mkstemp ("r_as", &opath);
	if (ofd == -1) {
		free (user_as);
		free (ipath);
		close (ifd);
		return -1;
	}

	char *asm_buf = r_str_newf (".ascii \"   BEGINMARK\"\n" // 4 byte align
			"%s\n"
			".ascii \"ENDMARK\"\n",
			buf);
	if (!asm_buf) {
		free (user_as);
		free (ipath);
		free (opath);
		close (ifd);
		close (ofd);
		return -1;
	}
	const size_t asm_buf_len = strlen (asm_buf);
	const bool success = write (ifd, asm_buf, asm_buf_len) == asm_buf_len;
	close (ifd);
	free (asm_buf);
	if (!success) {
		free (user_as);
		free (ipath);
		free (opath);
		close (ofd);
		return -1;
	}

	int len = 0;
	char *command = r_str_newf ("%s -mregnames -a%d %s %s -o %s", as, a->bits, a->big_endian ? "-be" : "-le", ipath, opath);
	free (user_as);
	if (!command) {
		free (ipath);
		free (opath);
		close (ofd);
		return -1;
	}
	int res = r_sys_cmd (command);
	if (!res) {
		const ut8 *begin, *end;
		close (ofd);
		ofd = r_sandbox_open (opath, O_BINARY|O_RDONLY, 0644);
		if (ofd < 0) {
			free (ipath);
			free (opath);
			free (command);
			return -1;
		}
		ut8 buf[4096];
		len = read (ofd, buf, sizeof (buf));
		begin = r_mem_mem (buf, len, (const ut8*)"BEGINMARK", 9);
		end = r_mem_mem (buf, len, (const ut8*)"ENDMARK", 7);
		if (!begin || !end) {
			eprintf ("Cannot find water marks\n");
			len = 0;
		} else {
			len = (int)(size_t)(end - begin - 9);
			if (len > 0) {
				r_strbuf_setbin (&op->buf, begin + 9, len);
			} else {
				len = 0;
			}
		}
	} else {
		eprintf ("Error running: %s", command);
	}

	close (ofd);

	unlink (ipath);
	unlink (opath);
	free (ipath);
	free (opath);
	free (command);

	return op->size = len;
}

RAsmPlugin r_asm_plugin_ppc_as = {
	.name = "ppc.as",
	.desc = "as PPC Assembler (use "ASSEMBLER" environment)",
	.arch = "ppc",
	.author = "eagleoflqj",
	.license = "LGPL3",
	.bits = 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.assemble = &assemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_ppc_as,
	.version = R2_VERSION
};
#endif
