/* radare - LGPL - Copyright 2015 pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

// USE ARM_AS environment variable
#define ARM32_AS "arm-linux-androideabi-as"
#define ARM64_AS "aarch64-linux-android-as"
// toolchains/arm-linux-androideabi-4.8/prebuilt/darwin-arm_64/bin/
// toolchains/aarch64-linux-android-4.9/prebuilt/darwin-arm_64/bin/

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	const char *bitconfig = "";
	char *ipath, *opath;
	int ifd, ofd;
	char *as = NULL;
	char asm_buf[R_ASM_BUFSIZE];
	int len = 0;

	ifd = r_file_mkstemp ("r_as", &ipath);
	if (ifd == -1)
		return -1;

	ofd = r_file_mkstemp ("r_as", &opath);
	if (ofd == -1) {
		free (ipath);
		return -1;
	}

	as = r_sys_getenv ("ARM_AS");
	if (!as || !*as) {
		free (as);
		if (a->bits == 64) {
			as = strdup (ARM64_AS);
		} else {
			as = strdup (ARM32_AS);
		}
	}
	if (a->bits == 16) {
		bitconfig = ".thumb";
	}

	len = snprintf (asm_buf, sizeof (asm_buf),
			"%s\n" //.org 0x%"PFMT64x"\n"
			".ascii \"BEGINMARK\"\n"
			"%s\n"
			".ascii \"ENDMARK\"\n",
			bitconfig, buf); // a->pc ??
	write (ifd, asm_buf, len);
	close (ifd);

	if (!r_sys_cmdf ("%s %s -o %s", as, ipath, opath)) {
		const ut8 *begin, *end;
		close (ofd);
		ofd = open (opath, O_BINARY|O_RDONLY);
		if (ofd < 0) {
			free (as);
			free (ipath);
			free (opath);
			return -1;
		}
		len = read (ofd, op->buf, R_ASM_BUFSIZE);
		begin = r_mem_mem (op->buf, len, (const ut8*)"BEGINMARK", 9);
		end = r_mem_mem (op->buf, len, (const ut8*)"ENDMARK", 7);
		if (!begin || !end) {
			eprintf ("Cannot find water marks\n");
			len = 0;
		} else {
			len = (int)(size_t)(end-begin-9);
			if (len>0) {
				memcpy (op->buf, begin+9, len);
			} else len = 0;
		}
	} else {
		eprintf ("Error running: %s %s -o %s", as, ipath, opath);
		eprintf ("export PATH=~/NDK/toolchains/arm-linux*/prebuilt/darwin-arm_64/bin\n");
		len = 0;
	}

	close (ofd);

	unlink (ipath);
	unlink (opath);
	free (ipath);
	free (opath);
	free (as);

	op->size = len;
	return len;
}

RAsmPlugin r_asm_plugin_arm_as = {
	.name = "arm.as",
	.desc = "as ARM Assembler (use ARM_AS environment)",
	.arch = "arm",
	.license = "LGPL3",
	.bits = 16|32|64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.init = NULL,
	.fini = NULL,
	.disassemble = NULL,
	.assemble = &assemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm_as,
	.version = R2_VERSION
};
#endif
