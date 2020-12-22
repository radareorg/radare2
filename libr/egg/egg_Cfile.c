/* radare - LGPL - Copyright 2011-2018 - pancake */

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

static char* r_egg_Cfile_getCompiler(void) {
	size_t i;
	const char *compilers[] = {"llvm-gcc", "clang", "gcc"};
	char *output = r_sys_getenv ("CC");

	if (output) {
		return output;
	}

	for (i = 0; i < 3; i++) {
		output = r_file_path (compilers[i]);
		if (strcmp (output, compilers[i])) {
			free (output);
			return strdup (compilers[i]);
		}
		free (output);
	}

	eprintf ("Couldn't find a compiler ! Please, set CC.\n");
	return NULL;
}

static inline bool r_egg_Cfile_armOrMips(const char *arch) {
	return (!strcmp (arch, "arm") || !strcmp (arch, "arm64") || !strcmp (arch, "aarch64")
	  	|| !strcmp (arch, "thumb") || !strcmp (arch, "arm32") || !strcmp (arch, "mips")
		|| !strcmp (arch, "mips32") || !strcmp (arch, "mips64"));
}

static void r_egg_Cfile_free_cEnv(struct cEnv_t *cEnv) {
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

static inline bool r_egg_Cfile_check_cEnv(struct cEnv_t *cEnv) {
	return (!cEnv->SFLIBPATH || !cEnv->CC || !cEnv->CFLAGS || !cEnv->LDFLAGS
		|| !cEnv->SHDR || !cEnv->TRIPLET);
}

static inline bool isXNU(const char *os) {
	return (!strcmp (os, "darwin") || !strcmp (os, "macos")
		|| !strcmp (os, "tvos") || !strcmp (os, "watchos") || !strcmp (os, "ios"));
}

static struct cEnv_t* r_egg_Cfile_set_cEnv(const char *arch, const char *os, int bits) {
	struct cEnv_t *cEnv = calloc (1, sizeof (struct cEnv_t));
	bool use_clang;
	char *buffer = NULL;
	char *output = NULL;

	if (!cEnv) {
		return NULL;
	}

	if (!(cEnv->CC = r_egg_Cfile_getCompiler())) {
		goto fail;
	}

	cEnv->SFLIBPATH = r_sys_getenv ("SFLIBPATH");
	if (!cEnv->SFLIBPATH) {
		output = r_sys_cmd_strf ("r2 -hh | grep INCDIR | awk '{print $2}'");
		if (!output || (output[0] == '\0')) {
			eprintf ("Cannot find SFLIBPATH env var.\n"
		  		 "Please define it, or fix r2 installation.\n");
			goto fail;
		}

		output[strlen (output) - 1] = '\0'; // strip the ending '\n'
		if (!(cEnv->SFLIBPATH = r_str_newf ("%s/sflib", output))) {
			goto fail;
		}
	}

	cEnv->JMP = r_egg_Cfile_armOrMips (arch) ? "b" : "jmp";

	// TODO: Missing -Os .. caused some rip-relative LEA to be MOVQ on PIE in CLANG.. so sad
	if (isXNU (os)) {
		cEnv->OBJCOPY = "gobjcopy";
		cEnv->FMT = "mach0";
		if (!strcmp (arch, "x86")) {
			if (bits == 32) {
				cEnv->CFLAGS = strdup ("-arch i386 -fPIC -fPIE");
				cEnv->LDFLAGS = strdup ("-arch i386 -shared -c -fPIC -fPIE -pie");
			} else {
				cEnv->CFLAGS = strdup ("-arch x86_64 -fPIC -fPIE");
				cEnv->LDFLAGS = strdup ("-arch x86_64 -shared -c -fPIC -fPIE -pie");
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
				   "// .type   main, @function\n%s main\n", cEnv->JMP);
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
	} else if (isXNU(os)) {
		//cEnv->TEXT = "0.__TEXT.__text";
		cEnv->TEXT = "0..__text";
	} else {
		cEnv->TEXT = ".text";
	}

	use_clang = false;
	if (!strcmp (cEnv->TRIPLET, "darwin-arm-64")) {
		free (cEnv->CC);
		cEnv->CC = strdup ("xcrun --sdk iphoneos gcc -arch arm64 -miphoneos-version-min=0.0");
		use_clang = true;
		cEnv->TEXT = "0.__TEXT.__text";
	} else if (!strcmp (cEnv->TRIPLET, "darwin-arm-32")) {
		free (cEnv->CC);
		cEnv->CC = strdup ("xcrun --sdk iphoneos gcc -arch armv7 -miphoneos-version-min=0.0");
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
		  		" -fno-zero-initialized-in-bss", cEnv->CFLAGS);
		if (!buffer) {
			goto fail;
		}
		free (cEnv->CFLAGS);
		cEnv->CFLAGS = strdup (buffer);
	} else {
		free (buffer);
		buffer = r_str_newf ("%s -z execstack -fomit-frame-pointer"
				" -finline-functions -fno-zero-initialized-in-bss", cEnv->CFLAGS);
		if (!buffer) {
			goto fail;
		}
		free (cEnv->CFLAGS);
		cEnv->CFLAGS = strdup (buffer);
	}
	free (buffer);
	buffer = r_str_newf ("%s -nostdlib", cEnv->LDFLAGS);
	if (!buffer) {
		goto fail;
	}
	free (cEnv->LDFLAGS);
	cEnv->LDFLAGS = strdup (buffer);

	if (r_egg_Cfile_check_cEnv (cEnv)) {
		eprintf ("Error with cEnv allocation!\n");
		goto fail;
	}

	free (buffer);
	free (output);
	return cEnv;

fail:
	free (buffer);
	free (output);
	r_egg_Cfile_free_cEnv (cEnv);
	return NULL;
}

static bool r_egg_Cfile_parseCompiled(const char *file) {
	char *fileExt = r_str_newf ("%s.tmp", file);
	char *buffer = r_file_slurp (fileExt, NULL);
	if (!buffer) {
		eprintf ("Could not open '%s'.\n", fileExt);
		goto fail;
	}

	buffer = r_str_replace (buffer, "rdata", "text", false);
	buffer = r_str_replace (buffer, "rodata", "text", false);
	buffer = r_str_replace (buffer, "get_pc_thunk.bx", "__getesp__", true);

	const char *words[] = {".cstring", "size", "___main", "section", "__alloca", "zero", "cfi"};
	size_t i;
	for (i = 0; i < 7; i++) {
		r_str_stripLine (buffer, words[i]);
	}

	free (fileExt);
	fileExt = r_str_newf ("%s.s", file);
	if (!r_file_dump (fileExt, (const ut8*) buffer, strlen (buffer), true)) {
		eprintf ("Error while opening %s.s\n", file);
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

R_API char* r_egg_Cfile_parser(const char *file, const char *arch, const char *os, int bits) {
	char *output = NULL;
	char *fileExt = NULL; // "file" with extension (.s, .text, ...)
	struct cEnv_t *cEnv = r_egg_Cfile_set_cEnv (arch, os, bits);

	if (!cEnv) {
		goto fail;
	}

	r_str_sanitize (cEnv->CC);

	// Compile
	char *cmd = r_str_newf ("'%s' %s -o '%s.tmp' -S '%s'\n", cEnv->CC, cEnv->CFLAGS, file, file);
	eprintf ("%s\n", cmd);
	int rc = r_sys_cmd (cmd);
	free (cmd);
	if (rc != 0) {
		goto fail;
	}
	if (!(fileExt = r_str_newf ("%s.s", file))) {
		goto fail;
	}

	if (!r_file_dump (fileExt, (const ut8*) cEnv->SHDR, strlen (cEnv->SHDR), false)) {
		eprintf ("Error while opening %s.s\n", file);
		goto fail;
	}

	if (!r_egg_Cfile_parseCompiled (file)) {
		goto fail;
	}
	// Assemble
	cmd = r_str_newf ("'%s' %s -o '%s.o' '%s.s'", cEnv->CC, cEnv->LDFLAGS, file, file);
	eprintf ("%s\n", cmd);
	rc = r_sys_cmd (cmd);
	free (cmd);
	if (rc != 0) {
		goto fail;
	}

	// Link
	printf ("rabin2 -o '%s.text' -O d/S/'%s' '%s.o'\n", file, cEnv->TEXT, file);
	output = r_sys_cmd_strf ("rabin2 -o '%s.text' -O d/S/'%s' '%s'.o",
		   		file, cEnv->TEXT, file);
	if (!output) {
		eprintf ("Linkage failed!\n");
		goto fail;
	}

	free (fileExt);
	if (!(fileExt = r_str_newf ("%s.o", file))) {
		goto fail;
	}

	if (!r_file_exists (fileExt)) {
		eprintf ("Cannot find %s.o\n", file);
		goto fail;
	}

	free (fileExt);
	if (!(fileExt = r_str_newf ("%s.text", file))) {
		goto fail;
	}
	if (r_file_size (fileExt) == 0) {
		eprintf ("FALLBACK: Using objcopy instead of rabin2");
		free (output);
		output = r_sys_cmd_strf ("'%s' -j .text -O binary '%s.o' '%s.text'",
		  		cEnv->OBJCOPY, file, file);
		if (!output) {
			eprintf ("objcopy failed!\n");
			goto fail;
		}
	}

	size_t i;
	const char *extArray[] = {"bin", "tmp", "s", "o"};
	for (i = 0; i < 4; i++) {
		free (fileExt);
		if (!(fileExt = r_str_newf ("%s.%s", file, extArray[i]))) {
			goto fail;
		}
		r_file_rm (fileExt);
	}

	free (fileExt);
	if ((fileExt = r_str_newf ("%s.text", file)) == NULL) {
		goto fail;
	}

	free (output);
	r_egg_Cfile_free_cEnv (cEnv);
	return fileExt;

fail:
	free (fileExt);
	free (output);
	r_egg_Cfile_free_cEnv (cEnv);
	return NULL;
}
