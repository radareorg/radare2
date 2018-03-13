/* radare - LGPL - Copyright 2011-2017 - pancake */

#include <r_egg.h>
#include <r_bin.h>
#include <r_print.h>
#include <getopt.c>
#include "../blob/version.c"

#include <unistd.h>
#include <sys/types.h>
#include <string.h>


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

static int usage(int v) {
	printf ("Usage: ragg2 [-FOLsrxhvz] [-a arch] [-b bits] [-k os] [-o file] [-I path]\n"
		"             [-i sc] [-e enc] [-B hex] [-c k=v] [-C file] [-p pad] [-q off]\n"
		"             [-q off] [-dDw off:hex] file|f.asm|-\n");
	if (v) printf (
	" -a [arch]       select architecture (x86, mips, arm)\n"
	" -b [bits]       register size (32, 64, ..)\n"
	" -B [hexpairs]   append some hexpair bytes\n"
	" -c [k=v]        set configuration options\n"
	" -C [file]       append contents of file\n"
	" -d [off:dword]  patch dword (4 bytes) at given offset\n"
	" -D [off:qword]  patch qword (8 bytes) at given offset\n"
	" -e [encoder]    use specific encoder. see -L\n"
	" -f [format]     output format (raw, c, pe, elf, mach0, python, javascript)\n"
	" -F              output native format (osx=mach0, linux=elf, ..)\n"
	" -h              show this help\n"
	" -i [shellcode]  include shellcode plugin, uses options. see -L\n"
	" -I [path]       add include path\n"
	" -k [os]         operating system's kernel (linux,bsd,osx,w32)\n"
	" -L              list all plugins (shellcodes and encoders)\n"
	" -n [dword]      append 32bit number (4 bytes)\n"
	" -N [dword]      append 64bit number (8 bytes)\n"
	" -o [file]       output file\n"
	" -O              use default output file (filename without extension or a.out)\n"
	" -p [padding]    add padding after compilation (padding=n10s32)\n"
	"                 ntas : begin nop, trap, 'a', sequence\n"
	"                 NTAS : same as above, but at the end\n"
	" -P [size]       prepend debruijn pattern\n"
	" -q [fragment]   debruijn pattern offset\n"
	" -r              show raw bytes instead of hexpairs\n"
	" -s              show assembler\n"
	" -v              show version\n"
	" -w [off:hex]    patch hexpairs at given offset\n"
	" -x              execute\n"
	" -z              output in C string syntax\n"
	);
	return 1;
}


static void list(REgg *egg) {
	RListIter *iter;
	REggPlugin *p;
	printf ("shellcodes:\n");
	r_list_foreach (egg->plugins, iter, p) {
		if (p->type == R_EGG_PLUGIN_SHELLCODE) {
			printf ("%10s : %s\n", p->name, p->desc);
		}
	}
	printf ("encoders:\n");
	r_list_foreach (egg->plugins, iter, p) {
		if (p->type == R_EGG_PLUGIN_ENCODER) {
			printf ("%10s : %s\n", p->name, p->desc);
		}
	}
}

static int create(const char *format, const char *arch, int bits, const ut8 *code, int codelen) {
	RBin *bin = r_bin_new ();
	RBuffer *b;
	if (!r_bin_use_arch (bin, arch, bits, format)) {
		eprintf ("Cannot set arch\n");
		r_bin_free (bin);
		return 1;
	}
	b = r_bin_create (bin, code, codelen, NULL, 0); //data, datalen);
	if (b) {
		write (1, b->buf, b->length);
		r_buf_free (b);
	} else {
		eprintf ("Cannot create binary for this format '%s'.\n", format);
	}
	r_bin_free (bin);
	return 0;
}

static int openfile(const char *f, int x) {
	int fd = open (f, O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		fd = open (f, O_RDWR);
		if (fd == -1) {
			return -1;
		}
	}
#if __UNIX__
	if (x) fchmod (fd, 0755);
#endif
#if _MSC_VER
	_chsize (fd, 0);
#else
	ftruncate (fd, 0);
#endif
	close (1);
	dup2 (fd, 1);
	return fd;
}
#define ISEXEC (fmt!='r')

static char* getCompiler(void) {
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

static inline bool armOrMips(const char *arch) {
	return (!strcmp (arch, "arm") || !strcmp (arch, "arm64") || !strcmp (arch, "aarch64")
	  	|| !strcmp (arch, "thumb") || !strcmp (arch, "arm32") || !strcmp (arch, "mips")
		|| !strcmp (arch, "mips32") || !strcmp (arch, "mips64"));
}

static void free_cEnv(struct cEnv_t *cEnv) {
	if (cEnv) {
		free (cEnv->SFLIBPATH);
		free (cEnv->CFLAGS);
		free (cEnv->LDFLAGS);
		free (cEnv->SHDR);
		free (cEnv->TRIPLET);
	}
	free (cEnv);
}

static inline bool check_cEnv(struct cEnv_t *cEnv) {
	return (!cEnv->SFLIBPATH || !cEnv->CC || !cEnv->CFLAGS || !cEnv->LDFLAGS
		|| !cEnv->SHDR || !cEnv->TRIPLET);
}

static struct cEnv_t* set_cEnv(const char *arch, const char *os, int bits) {
	struct cEnv_t *cEnv = calloc (1, sizeof (struct cEnv_t));
	bool use_clang;
	char *buffer = NULL;
	char *output = NULL;

	if (!cEnv) {
		return NULL;
	}

	if (!(cEnv->CC = getCompiler())) {
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

	cEnv->JMP = armOrMips (arch) ? "b" : "jmp";

	if (!strcmp (os, "darwin")) {
		cEnv->OBJCOPY = "gobjcopy";
		cEnv->FMT = "mach0";
		if (!strcmp (arch, "x86")) {
			if (bits == 32) {
				cEnv->CFLAGS = strdup ("-arch i386");
				cEnv->LDFLAGS = strdup ("-arch i386 -shared -c");
			} else {
				cEnv->CFLAGS = strdup ("-arch x86_64");
				cEnv->LDFLAGS = strdup ("-arch x86_64 -shared -c");
			}
		} else {
			cEnv->LDFLAGS = strdup ("-shared -c");
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
	} else if (!strcmp (os, "darwin")) {
		cEnv->TEXT = "0.__TEXT.__text";
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

	buffer = r_str_newf ("%s -nostdinc -include '%s'/'%s'/sflib.h",
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

	if (check_cEnv (cEnv)) {
		eprintf ("Error with cEnv allocation!\n");
		goto fail;
	}

	free (buffer);
	free (output);
	return cEnv;

fail:
	free (buffer);
	free (output);
	free_cEnv (cEnv);
	return NULL;
}

// Strips all the lines in str that contain key
static char* r_str_stripLine(char *str, const char *key)
{
	size_t i, klen, slen, off;
	const char *ptr; 
	char *newStr = NULL;

	if (!str || !key) {
		return NULL;
	}
	klen = strlen (key);
	slen = strlen (str);

	for (i = 0; i < slen; ) {
		ptr = (char*) r_mem_mem ((ut8*) str + i, slen - i, (ut8*) "\n", 1);
		if (!ptr) {
			ptr = (char*) r_mem_mem ((ut8*) str + i, slen - i, (ut8*) key, klen);
			if (ptr) {
				free (newStr);
				newStr = malloc (i + 1);
				memcpy (newStr, str, i);
				newStr[i] = '\0';
				free (str);
				str = strdup (newStr);
				break;
			}
			break;
		}
			
		off = (size_t) (ptr - (str + i)) + 1;

		ptr = (char*) r_mem_mem ((ut8*) str + i, off, (ut8*) key, klen);
		if (ptr) {
			free (newStr);
			newStr = malloc (slen - off + 1);
			if (!newStr) {
				free (str);
				str = NULL;
				break;
			}
			memcpy (newStr, str, i);
			memcpy (newStr + i, str + i + off, slen - i - off);
			slen -= off;
			newStr[slen] = '\0';
			free (str);
			str = strdup (newStr);
		} else {
			i += off;
		}
	}
	free (newStr);
	return str;
}

static bool parseCompiled(const char *file) {
	char *fileExt = r_str_newf ("%s.tmp", file);
	char *buffer = r_file_slurp (fileExt, NULL);

	buffer = r_str_replace (buffer, "rdata", "text", false);
	buffer = r_str_replace (buffer, "rodata", "text", false);
	buffer = r_str_replace (buffer, "get_pc_thunk.bx", "__getesp__", true);

	const char *words[] = {".cstring", "size", "___main", "section", "__alloca", "zero", "cfi"};
	size_t i;
	for (i = 0; i < 7; i++) {
		if (!(buffer = r_str_stripLine (buffer, words[i]))) {
			goto fail;
		}
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

static char* parseCFile(const char *file, const char *arch, const char *os, int bits) {
	char *output = NULL;
	char *fileExt = NULL; // "file" with extension (.s, .text, ...)
	struct cEnv_t *cEnv = set_cEnv (arch, os, bits);

	if (!cEnv) {
		goto fail;
	}

	r_str_sanitize (cEnv->CC);

	//printf ("==> Compile\n");
	printf ("'%s' %s -o '%s.tmp' -S -Os '%s'\n", cEnv->CC, cEnv->CFLAGS, file, file);

	output = r_sys_cmd_strf ("('%s' %s -o '%s.tmp' -S -Os '%s') 2>&1",
	  			cEnv->CC, cEnv->CFLAGS, file, file);
	if (output == NULL) {
		eprintf ("Compilation failed!\n");
		goto fail;
	}
	printf ("%s", output);

	if (!(fileExt = r_str_newf ("%s.s", file))) {
		goto fail;
	}

	if (!r_file_dump (fileExt, (const ut8*) cEnv->SHDR, strlen (cEnv->SHDR), false)) {
		eprintf ("Error while opening %s.s\n", file);
		goto fail;
	}

	if (!parseCompiled (file)) {
		goto fail;
	}

	//printf ("==> Assemble\n");
	printf ("'%s' %s -Os -o '%s.o' '%s.s'\n", cEnv->CC, cEnv->LDFLAGS, file, file);

	free (output);
	output = r_sys_cmd_strf ("'%s' %s -Os -o '%s.o' '%s.s'",
		   		cEnv->CC, cEnv->LDFLAGS, file, file);
	if (!output) {
		eprintf ("Assembly failed!\n");
		goto fail;
	}
	printf ("%s", output);

	//printf ("==> Link\n");
	printf ("rabin2 -o '%s.text' -O d/S/'%s' '%s.o'\n", file, cEnv->TEXT, file);

	free (output);
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
		printf ("FALLBACK: Using objcopy instead of rabin2");

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
	free_cEnv (cEnv);
	return fileExt;

fail:
	free (fileExt);
	free (output);
	free_cEnv (cEnv);
	return NULL;
}

int main(int argc, char **argv) {
	const char *file = NULL;
	const char *padding = NULL;
	const char *pattern = NULL;
	char *bytes = NULL;
	const char *contents = NULL;
	const char *arch = R_SYS_ARCH;
	const char *os = R_EGG_OS_NAME;
	char *format = "raw";
	int show_execute = 0;
	int show_hex = 1;
	int show_asm = 0;
	int show_raw = 0;
	int append = 0;
	int show_str = 0;
	ut64 get_offset  = 0;
	char *shellcode = NULL;
	char *encoder = NULL;
	char *sequence = NULL;
	int bits = (R_SYS_BITS & R_SYS_BITS_64) ? 64 : 32;
	int fmt = 0;
	const char *ofile = NULL;
	int ofileauto = 0;
	RBuffer *b;
	int c, i;
	REgg *egg = r_egg_new ();

	while ((c = getopt (argc, argv, "n:N:he:a:b:f:o:sxrk:FOI:Li:c:p:P:B:C:vd:D:w:zq:")) != -1) {
		switch (c) {
		case 'a':
			arch = optarg;
			if (!strcmp (arch, "trace")) {
				show_asm = 1;
				show_hex = 0;
			}
			break;
		case 'e':
			encoder = optarg;
			break;
		case 'b':
			bits = atoi (optarg);
			break;
		case 'B':
			bytes = r_str_append (bytes, optarg);
			break;
		case 'C':
			contents = optarg;
			break;
		case 'w': 
			{
			char *arg = strdup (optarg);
			char *p = strchr (arg, ':');
			if (p) {
				int len, off;
				ut8 *b;
				*p++ = 0;
				off = r_num_math (NULL, arg);
				b = malloc (strlen (optarg) + 1);
				len = r_hex_str2bin (p, b);
				if (len > 0) {
					r_egg_patch (egg, off, (const ut8*)b, len);
				} else {
					eprintf ("Invalid hexstr for -w\n");
				}
				free (b);
			} else {
				eprintf ("Missing colon in -w\n");
			}
			free (arg);
			}
			break;
		case 'n': 
			{
			ut32 n = r_num_math (NULL, optarg);
			append = 1;
			r_egg_patch (egg, -1, (const ut8*)&n, 4);
			}
			break;
		case 'N': 
			{
			ut64 n = r_num_math (NULL, optarg);
			r_egg_patch (egg, -1, (const ut8*)&n, 8);
			append = 1;
			}
			break;
		case 'd':
			{
			ut32 off, n;
			char *p = strchr (optarg, ':');
			if (p) {
				*p = 0;
				off = r_num_math (NULL, optarg);
				n = r_num_math (NULL, p + 1);
				*p = ':';
				// TODO: honor endianness here
				r_egg_patch (egg, off, (const ut8*)&n, 4);
			} else {
				eprintf ("Missing colon in -d\n");
			}
			}
			break;
		case 'D':
			{
			char *p = strchr (optarg, ':');
			if (p) {
				ut64 n, off = r_num_math (NULL, optarg);
				n = r_num_math (NULL, p + 1);
				// TODO: honor endianness here
				r_egg_patch (egg, off, (const ut8*)&n, 8);
			} else {
				eprintf ("Missing colon in -d\n");
			}
			}
			break;
		case 'o':
			ofile = optarg;
			break;
		case 'O':
			ofileauto = 1;
			break;
		case 'I':
			r_egg_lang_include_path (egg, optarg);
			break;
		case 'i':
			 shellcode = optarg;
			 break;
		case 'p':
			padding = optarg;
			break;
		case 'P':
			pattern = optarg;
			break;
		case 'c':
			{
			char *p = strchr (optarg, '=');
			if (p) {
				*p++ = 0;
				r_egg_option_set (egg, optarg, p);
			} else {
				r_egg_option_set (egg, optarg, "true");
			}
			}
			break;
		case 'F':
#if __APPLE__
			format = "mach0";
#elif __WINDOWS__
			format = "pe";
#else
			format = "elf";
#endif
			show_asm = 0;
			break;
		case 'f':
			format = optarg;
			show_asm = 0;
			break;
		case 's':
			show_asm = 1;
			show_hex = 0;
			break;
		case 'k':
			os = optarg;
			break;
		case 'r':
			show_raw = 1;
			break;
		case 'x':
			// execute
			show_execute = 1;
			break;
		case 'L':
			list (egg);
			return 0;
		case 'h':
			return usage (1);
		case 'v':
			return blob_version("ragg2");
		case 'z':
			show_str = 1;
			break;
		case 'q':
			get_offset = 1;
			sequence = strdup (optarg);
			break;
		default:
			free (sequence);
			return 1;
		}
	}

	if (optind == argc && !shellcode && !bytes && !contents && !encoder && !padding && !pattern && !append && !get_offset) {
		return usage (0);
	} else {
		file = argv[optind];
	}

	if (bits == 64) {
		if (!strcmp (format, "mach0")) {
			format = "mach064";
		} else if (!strcmp (format, "elf")) {
			format = "elf64";
		}
	}

	// catch this first
	if (get_offset) {
		if (strncmp (sequence, "0x", 2)) {
			eprintf ("Need hex value with `0x' prefix e.g. 0x41414142\n");
			free (sequence);
			return 1;
		}

		get_offset = r_num_math (0, sequence);
		printf ("Little endian: %d\n", r_debruijn_offset (get_offset, false));
		printf ("Big endian: %d\n", r_debruijn_offset (get_offset, true));
		free (sequence);
		return 0;
	}

	// initialize egg
	r_egg_setup (egg, arch, bits, 0, os);
	if (file) {
		if (!strcmp (file, "-")) {
			char buf[1024];
			for (;;) {
				fgets (buf, sizeof (buf) - 1, stdin);
				if (feof (stdin)) {
					break;
				}
				r_egg_load (egg, buf, 0);
			}
		} else if (strstr (file, ".c")) {
			char *fileSanitized = strdup (file);
			r_str_sanitize (fileSanitized);
			char *textFile = parseCFile (fileSanitized, arch, os, bits);

			if (!textFile) {
				eprintf ("Failure while parsing '%s'\n", fileSanitized);
				goto fail;
			}

			int l;
			char *buf = r_file_slurp (textFile, &l);
			if (buf && l > 0) {
				r_egg_raw (egg, (const ut8*)buf, l);
			} else {
				eprintf ("Error loading '%s'\n", textFile);
			}

			r_file_rm (textFile);
			free (fileSanitized);
			free (textFile);
			free (buf);
		} else {
			if (strstr (file, ".s") || strstr (file, ".asm")) {
				fmt = 'a';
			} else {
				fmt = 0;
			}
			if (!r_egg_include (egg, file, fmt)) {
				eprintf ("Cannot open '%s'\n", file);
				goto fail;
			}
		}
	}

	// compile source code to assembly
	if (!r_egg_compile (egg)) {
		if (!fmt) {
			eprintf ("r_egg_compile: fail\n");
			return 1;
		}
	}

	// add raw file
	if (contents) {
		int l;
		char *buf = r_file_slurp (contents, &l);
		if (buf && l > 0) {
			r_egg_raw (egg, (const ut8*)buf, l);
		} else {
			eprintf ("Error loading '%s'\n", contents);
		}
		free (buf);
	}

	// add shellcode
	if (shellcode) {
		if (!r_egg_shellcode (egg, shellcode)) {
			eprintf ("Unknown shellcode '%s'\n", shellcode);
			return 1;
		}
	}

	// add raw bytes
	if (bytes) {
		ut8 *b = malloc (strlen (bytes) + 1);
		int len = r_hex_str2bin (bytes, b);
		if (len > 0) {
			if (!r_egg_raw (egg, b, len)) {
				eprintf ("Unknown '%s'\n", shellcode);
				return 1;
			}
		} else {
			eprintf ("Invalid hexpair string for -B\n");
		}
		free (b);
		free (bytes);
		bytes = NULL;
	}

	/* set output (create output file if needed) */
	if (ofileauto) {
		int fd;
		if (file) {
			char *o, *q, *p = strdup (file);
			if ( (o = strchr (p, '.')) ) {
				while ( (q = strchr (o + 1, '.')) ) {
					o = q;
				}
				*o = 0;
				fd = openfile (p, ISEXEC);
			} else {
				fd = openfile ("a.out", ISEXEC);
			}
			free (p);
		} else {
			fd = openfile ("a.out", ISEXEC);
		}
		if (fd == -1) {
			eprintf ("cannot open file '%s'\n", optarg);
			goto fail;
		}
	}
	if (ofile) {
		if (openfile (ofile, ISEXEC) == -1) {
			eprintf ("cannot open file '%s'\n", ofile);
			goto fail;
		}
	}

	// assemble to binary
	if (!r_egg_assemble (egg)) {
		eprintf ("r_egg_assemble: invalid assembly\n");
		goto fail;
	}
	if (encoder) {
		if (!r_egg_encode (egg, encoder)) {
			eprintf ("Invalid encoder '%s'\n", encoder);
			return 1;
		}
	}

	// add padding
	if (padding) {
		r_egg_padding (egg, padding); 
	}

	// add pattern
	if (pattern) {
		r_egg_pattern (egg, r_num_math (NULL, pattern));
	}

	// apply patches
	if (!egg->bin) {
		egg->bin = r_buf_new ();
	}
	if (!(b = r_egg_get_bin (egg))) {
		eprintf ("r_egg_get_bin: invalid egg :(\n");
		goto fail;
	}
	r_egg_finalize (egg);

	if (show_asm) {
		printf ("%s\n", r_egg_get_assembly (egg));	
	}

	if (show_raw || show_hex || show_execute) {
		if (show_execute) {
			return r_egg_run (egg);
		}
		b = r_egg_get_bin (egg);
		if (show_raw) {
			write (1, b->buf, b->length);
		} else {
			if (!format) {
				eprintf ("No format specified wtf\n");
				goto fail;
			}
			RPrint *p = r_print_new ();
			switch (*format) {
			case 'c':
				r_print_code (p, 0, b->buf, b->length, 'c');
				break;
			case 'j': // JavaScript
				r_print_code (p, 0, b->buf, b->length, 'j');
				break;
			case 'r':
				if (show_str) {
					printf ("\"");
					for (i = 0; i < b->length; i++) {
						printf ("\\x%02x", b->buf[i]);
					}
					printf ("\"\n");
				} else if (show_hex) {
					for (i = 0; i < b->length; i++) {
						printf ("%02x", b->buf[i]);
					}
					printf ("\n");
				} // else show_raw is_above()
				break;
			case 'p': // PE
				if (strlen(format) >= 2 && format[1] == 'y') { // Python
					r_print_code (p, 0, b->buf, b->length, 'p');
				}
				break;
			case 'e': // ELF
			case 'm': // MACH0
				create (format, arch, bits, b->buf, b->length);
				break;
			default:
				eprintf ("unknown executable format (%s)\n", format);
				goto fail;
			}
		}
	}
	r_egg_free (egg);
	return 0;
fail:
	r_egg_free (egg);
	return 1;
}
