/* radare - LGPL - Copyright 2011-2023 - pancake */

#include <r_egg.h>

// compilation environment
struct cEnv_t {
	char *SFLIBPATH;
	char *CC;
	const char *OBJCOPY;
	char *CFLAGS;
	char *LDFLAGS;
	const char *JMP;
	const char *FMT;
	char *SHDR;
	char *TRIPLET;
	const char *TEXT;
};

static char *r_egg_cfile_getCompiler(const char *arch, int bits) {
	const char *compilers[] = { "llvm-gcc", "gcc", "clang", NULL };
	const char *compiler = compilers[0];
	char *compiler_path;
	char *env_cc = r_sys_getenv ("CC");
	int i;

	if (env_cc) {
		return env_cc;
	}

	// Override gcc compilers for arm64 and arm32
	// TODO: I don't seem to be able to make clang work with -target
	if (!strcmp (arch, "arm") && bits == 64) {
		compiler = "aarch64-linux-gnu-gcc";
		compiler_path = r_file_path (compiler);
		if (compiler_path) {
			free (compiler_path);
			return strdup (compiler);
		}
	}

	if (!strcmp (arch, "arm") && bits == 32) {
		compiler = "arm-linux-gnueabihf-gcc";
		compiler_path = r_file_path (compiler);
		if (compiler_path) {
			free (compiler_path);
			return strdup (compiler);
		}
	}

	for (i = 0; (compiler = compilers[i]); i++) {
		compiler_path = r_file_path (compiler);
		if (compiler_path) {
			free (compiler_path);
			return strdup (compiler);
		}
		free (compiler_path);
	}

	R_LOG_ERROR ("Couldn't find a compiler! Please set CC");
	return NULL;
}

static inline bool r_egg_cfile_armOrMips(const char *arch) {
	return (!strcmp (arch, "arm") || !strcmp (arch, "arm64") || !strcmp (arch, "aarch64") || !strcmp (arch, "thumb") || !strcmp (arch, "arm32") || !strcmp (arch, "mips") || !strcmp (arch, "mips32") || !strcmp (arch, "mips64"));
}

static void r_egg_cfile_free_cEnv(struct cEnv_t *cEnv) {
	if (cEnv) {
		free (cEnv->SFLIBPATH);
		free (cEnv->CC);
		free (cEnv->CFLAGS);
		free (cEnv->LDFLAGS);
		free (cEnv->SHDR);
		free (cEnv->TRIPLET);
	}
	free (cEnv);
}

static inline bool r_egg_cfile_check_cEnv(struct cEnv_t *cEnv) {
	return (!cEnv->SFLIBPATH || !cEnv->CC || !cEnv->CFLAGS || !cEnv->LDFLAGS || !cEnv->SHDR || !cEnv->TRIPLET);
}

static inline bool isXNU(const char *os) {
	return (!strcmp (os, "darwin") || !strcmp (os, "macos") || !strcmp (os, "tvos") || !strcmp (os, "watchos") || !strcmp (os, "ios"));
}

static struct cEnv_t *r_egg_cfile_set_cEnv(const char *arch, const char *os, int bits) {
	struct cEnv_t *cEnv = calloc (1, sizeof (struct cEnv_t));
	bool use_clang;
	char *buffer = NULL;
	char *output = NULL;

	if (!cEnv) {
		return NULL;
	}

	if (! (cEnv->CC = r_egg_cfile_getCompiler (arch, bits))) {
		goto fail;
	}

	cEnv->SFLIBPATH = r_sys_getenv ("SFLIBPATH");
	if (!cEnv->SFLIBPATH) {
		output = r_sys_cmd_strf ("r2 -hh | grep INCDIR | awk '{print $2}'");
		if (!output || (output[0] == '\0')) {
			R_LOG_ERROR ("Cannot find SFLIBPATH env var");
			goto fail;
		}

		output[strlen (output) - 1] = '\0'; // strip the ending '\n'
		if (! (cEnv->SFLIBPATH = r_str_newf ("%s/sflib", output))) {
			goto fail;
		}
	}

	cEnv->JMP = r_egg_cfile_armOrMips (arch)? "b": "jmp";

	// TODO: Missing -Os .. caused some rip-relative LEA to be MOVQ on PIE in CLANG.. so sad
	if (isXNU (os)) {
		cEnv->OBJCOPY = "gobjcopy";
		cEnv->FMT = "mach0";
		if (!strcmp (arch, "x86")) {
			if (bits == 32) {
				cEnv->CFLAGS = strdup ("-arch i386 -fPIC -fPIE");
				cEnv->LDFLAGS = strdup ("-arch i386 -fPIC -fPIE -pie");
			} else {
				cEnv->CFLAGS = strdup ("-arch x86_64 -fPIC -fPIE");
				cEnv->LDFLAGS = strdup ("-arch x86_64 -fPIC -fPIE -pie");
			}
		} else {
			cEnv->CFLAGS = strdup ("-shared -c -fPIC -pie -fPIE");
			cEnv->LDFLAGS = strdup ("-shared -c -fPIC -pie -fPIE");
		}
		cEnv->SHDR = r_str_newf ("\n.text\n%s _main\n", cEnv->JMP);
	} else {
		cEnv->OBJCOPY = "objcopy";
		cEnv->FMT = "elf";
		cEnv->SHDR = r_str_newf ("\n.section .text\n.globl  main\n"
					"// .type   main, @function\n%s main\n",
			cEnv->JMP);
		if (!strcmp (arch, "x86")) {
			if (bits == 32) {
				cEnv->CFLAGS = strdup ("-fPIC -fPIE -pie -fpic -m32");
				cEnv->LDFLAGS = strdup ("-fPIC -fPIE -pie -fpic -m32");
			} else {
				cEnv->CFLAGS = strdup ("-fPIC -fPIE -pie -fpic -m64");
				cEnv->LDFLAGS = strdup ("-fPIC -fPIE -pie -fpic -m64");
			}
		} else {
			cEnv->CFLAGS = strdup ("-fPIC -fPIE -pie -fpic -nostartfiles");
			cEnv->LDFLAGS = strdup ("-fPIC -fPIE -pie -fpic -nostartfiles");
		}
	}

	cEnv->TRIPLET = r_str_newf ("%s-%s-%d", os, arch, bits);

	if (!strcmp (os, "windows")) {
		cEnv->TEXT = ".text";
		cEnv->FMT = "pe";
	} else if (isXNU (os)) {
		cEnv->TEXT = "0.__TEXT.__text";
		// cEnv->TEXT = "__text";
	} else {
		cEnv->TEXT = ".text";
	}

	use_clang = false;
	if (!strcmp (cEnv->TRIPLET, "darwin-arm-64")) {
		free (cEnv->CC);
		cEnv->CC = strdup ("xcrun --sdk iphoneos gcc -arch arm64 -miphoneos-version-min=10.0");
		use_clang = true;
		cEnv->TEXT = "0.__TEXT.__text";
	} else if (!strcmp (cEnv->TRIPLET, "darwin-arm-32")) {
		free (cEnv->CC);
		cEnv->CC = strdup ("xcrun --sdk iphoneos gcc -arch armv7 -miphoneos-version-min=10.0");
		use_clang = true;
		cEnv->TEXT = "0.__TEXT.__text";
	}

	buffer = r_str_newf ("%s -fno-stack-protector -nostdinc -include '%s'/'%s'/sflib.h",
		cEnv->CFLAGS, cEnv->SFLIBPATH, cEnv->TRIPLET);
	if (!buffer) {
		goto fail;
	}
	free (cEnv->CFLAGS);
	cEnv->CFLAGS = strdup (buffer);

	if (use_clang) {
		free (buffer);
		buffer = r_str_newf ("%s -fomit-frame-pointer"
				" -fno-zero-initialized-in-bss",
			cEnv->CFLAGS);
		if (!buffer) {
			goto fail;
		}
		free (cEnv->CFLAGS);
		cEnv->CFLAGS = strdup (buffer);
	} else {
		free (buffer);
		buffer = r_str_newf ("%s -z execstack -fomit-frame-pointer"
				" -finline-functions -fno-zero-initialized-in-bss",
			cEnv->CFLAGS);
		if (!buffer) {
			goto fail;
		}
		free (cEnv->CFLAGS);
		cEnv->CFLAGS = strdup (buffer);
	}
	if (!isXNU (os)) {
		/* Every executable must link with libSystem.dylib,
		 * so '-nostdlib' is not needed for XNU/MAC */
		free (buffer);
		buffer = r_str_newf ("%s -nostdlib", cEnv->LDFLAGS);
		if (!buffer) {
			goto fail;
		}
		free (cEnv->LDFLAGS);
		cEnv->LDFLAGS = strdup (buffer);
	}
	if (r_egg_cfile_check_cEnv (cEnv)) {
		R_LOG_ERROR ("invalid cEnv allocation");
		goto fail;
	}

	free (buffer);
	free (output);
	return cEnv;

fail:
	free (buffer);
	free (output);
	r_egg_cfile_free_cEnv (cEnv);
	return NULL;
}

static bool r_egg_cfile_parseCompiled(const char *file) {
	char *fileExt = r_str_newf ("%s.tmp", file);
	char *buffer = r_file_slurp (fileExt, NULL);
	if (!buffer) {
		R_LOG_ERROR ("Could not open '%s'", fileExt);
		goto fail;
	}

	buffer = r_str_replace (buffer, "rdata", "text", false);
	buffer = r_str_replace (buffer, "rodata", "text", false);
	buffer = r_str_replace (buffer, "get_pc_thunk.bx", "__getesp__", true);

	const char *words[] = { ".cstring", "size", "___main", "section", "__alloca", "zero", "cfi" };
	size_t i;
	for (i = 0; i < 7; i++) {
		r_str_stripLine (buffer, words[i]);
	}

	free (fileExt);
	fileExt = r_str_newf ("%s.s", file);
	if (!r_file_dump (fileExt, (const ut8 *)buffer, strlen (buffer), true)) {
		R_LOG_ERROR ("while opening %s.s", file);
		goto fail;
	}

	free (buffer);
	free (fileExt);
	return true;

fail:
	free (buffer);
	free (fileExt);
	return false;
}

R_API char *r_egg_cfile_parser(const char *file, const char *arch, const char *os, int bits) {
	char *output = NULL;
	char *fileExt = NULL; // "file" with extension (.s, .text, ...)
	struct cEnv_t *cEnv = r_egg_cfile_set_cEnv (arch, os, bits);

	if (!cEnv) {
		goto fail;
	}

	r_str_sanitize (cEnv->CC);

	// Compile
	char *cmd = r_str_newf ("%s %s -o '%s.tmp' -S '%s'\n", cEnv->CC, cEnv->CFLAGS, file, file);
	eprintf ("%s\n", cmd);
	int rc = r_sys_cmd (cmd);
	free (cmd);
	if (rc != 0) {
		goto fail;
	}
	if (! (fileExt = r_str_newf ("%s.s", file))) {
		goto fail;
	}

	if (!r_file_dump (fileExt, (const ut8 *)cEnv->SHDR, strlen (cEnv->SHDR), false)) {
		R_LOG_ERROR ("while opening %s.s", file);
		goto fail;
	}

	if (!r_egg_cfile_parseCompiled (file)) {
		goto fail;
	}
	// Assemble
	cmd = r_str_newf ("%s %s -o '%s.o' '%s.s'", cEnv->CC, cEnv->LDFLAGS, file, file);
	eprintf ("%s\n", cmd);
	rc = r_sys_cmd (cmd);
	free (cmd);
	if (rc != 0) {
		goto fail;
	}

	// Link
	printf ("rabin2 -o '%s.text' -O d/S/'%s' '%s.o'\n", file, cEnv->TEXT, file);
	output = r_sys_cmd_strf ("rabin2 -o '%s.text' -O d/S/'%s' '%s'.o", file, cEnv->TEXT, file);
	if (!output) {
		R_LOG_ERROR ("Linkage failed!");
		goto fail;
	}

	free (fileExt);
	if (! (fileExt = r_str_newf ("%s.o", file))) {
		goto fail;
	}

	if (!r_file_exists (fileExt)) {
		R_LOG_ERROR ("Cannot find %s.o", file);
		goto fail;
	}

	free (fileExt);
	if (! (fileExt = r_str_newf ("%s.text", file))) {
		goto fail;
	}
	if (r_file_size (fileExt) == 0) {
		R_LOG_INFO ("FALLBACK: Using objcopy instead of rabin2");
		free (output);
		if (isXNU (os)) {
			output = r_sys_cmd_strf ("'%s' -j 0.__TEXT.__text -O binary '%s.o' '%s.text'",
				cEnv->OBJCOPY, file, file);
		} else {
			output = r_sys_cmd_strf ("'%s' -j .text -O binary '%s.o' '%s.text'",
				cEnv->OBJCOPY, file, file);
		}
		if (!output) {
			R_LOG_ERROR ("objcopy failed!");
			goto fail;
		}
	}

	size_t i;
	const char *extArray[] = { "bin", "tmp", "s", "o" };
	for (i = 0; i < 4; i++) {
		free (fileExt);
		if (! (fileExt = r_str_newf ("%s.%s", file, extArray[i]))) {
			goto fail;
		}
		r_file_rm (fileExt);
	}

	free (fileExt);
	if ((fileExt = r_str_newf ("%s.text", file)) == NULL) {
		goto fail;
	}

	free (output);
	r_egg_cfile_free_cEnv (cEnv);
	return fileExt;

fail:
	free (fileExt);
	free (output);
	r_egg_cfile_free_cEnv (cEnv);
	return NULL;
}
