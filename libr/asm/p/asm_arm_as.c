/* radare - LGPL - Copyright 2015-2019 pancake */

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
	char *as = NULL;

	int ifd = r_file_mkstemp ("r_as", &ipath);
	if (ifd == -1) {
		return -1;
	}

	int ofd = r_file_mkstemp ("r_as", &opath);
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

	char *asm_buf = r_str_newf ("%s\n" //.org 0x%"PFMT64x"\n"
			".ascii \"BEGINMARK\"\n"
			"%s\n"
			".ascii \"ENDMARK\"\n",
			bitconfig, buf); // a->pc ??
	if (asm_buf) {
		(void)write (ifd, asm_buf, strlen (asm_buf));
		(void)close (ifd);
		free (asm_buf);
	}

	int len = 0;
	if (!r_sys_cmdf ("%s %s -o %s", as, ipath, opath)) {
		const ut8 *begin, *end;
		close (ofd);
		ofd = r_sandbox_open (opath, O_BINARY|O_RDONLY, 0644);
		if (ofd < 0) {
			free (as);
			free (ipath);
			free (opath);
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
		eprintf ("Error running: %s %s -o %s", as, ipath, opath);
		eprintf ("export PATH=~/NDK/toolchains/arm-linux*/prebuilt/darwin-arm_64/bin\n");
	}

	close (ofd);

	unlink (ipath);
	unlink (opath);
	free (ipath);
	free (opath);
	free (as);

	return op->size = len;
}

RAsmPlugin r_asm_plugin_arm_as = {
	.name = "arm.as",
	.desc = "as ARM Assembler (use ARM_AS environment)",
	.arch = "arm",
	.author = "pancake",
	.license = "LGPL3",
	.bits = 16|32|64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.assemble = &assemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm_as,
	.version = R2_VERSION
};
#endif
