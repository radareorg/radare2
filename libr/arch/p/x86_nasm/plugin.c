/* radare - LGPL - Copyright 2009-2024 - pancake */

#include <r_asm.h>

static bool encode(RArchSession *a, RAnalOp *op, RArchEncodeMask mask) {
	char *ipath, *opath;
	if (a->config->syntax != R_ARCH_SYNTAX_INTEL) {
		R_LOG_ERROR ("asm.x86.nasm only support intel syntax");
		return false;
	}

	int ifd = r_file_mkstemp ("r_nasm", &ipath);
	if (ifd == -1) {
		return false;
	}

	int ofd = r_file_mkstemp ("r_nasm", &opath);
	if (ofd == -1) {
		free (ipath);
		return false;
	}

	const char *buf = op->mnemonic;
	// Strip size specifiers that NASM doesn't support (xmmword, ymmword, zmmword)
	char *clean_buf = r_str_replace (r_str_replace (r_str_replace (
		strdup (buf), "xmmword ", "", 1), "ymmword ", "", 1), "zmmword ", "", 1);
	char *asm_buf = r_str_newf ("[BITS %i]\nORG 0x%"PFMT64x"\n%s\n",
		a->config->bits, op->addr, clean_buf);
	free (clean_buf);
	if (asm_buf) {
		int slen = strlen (asm_buf);
		int wlen = write (ifd, asm_buf, slen);
		free (asm_buf);
		if (slen != wlen) {
			return false;
		}
	}

	close (ifd);

	if (!r_sys_cmdf ("nasm %s -o %s", ipath, opath)) {
		ut8 buf[512]; // TODO: remove limits
		op->size = read (ofd, buf, sizeof (buf));
		r_anal_op_set_bytes (op, op->addr, buf, op->size);
	} else {
		R_LOG_ERROR ("running 'nasm'");
	}

	close (ofd);
	unlink (ipath);
	unlink (opath);
	free (ipath);
	free (opath);

	return true;
}

const RArchPlugin r_arch_plugin_x86_nasm = {
	.meta = {
		.name = "x86.nasm",
		.desc = "X86 nasm assembler",
		.license = "LGPL-3.0-only",
	},
	.arch = "x86",
	// NOTE: 64bits is not supported on OSX's nasm :(
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.endian = R_SYS_ENDIAN_LITTLE,
	.encode = &encode
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_x86_nasm,
	.version = R2_VERSION
};
#endif
