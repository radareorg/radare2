/* radare - LGPL - Copyright 2011-2019 - pancake */

#include <r_egg.h>
#include <r_bin.h>
#include <r_main.h>
#include <r_util/r_print.h>
#include <r_util.h>

static int usage(int v) {
	printf ("Usage: ragg2 [-FOLsrxhvz] [-a arch] [-b bits] [-k os] [-o file] [-I path]\n"
		"             [-i sc] [-e enc] [-B hex] [-c k=v] [-C file] [-p pad] [-q off]\n"
		"             [-S string] [-f fmt] [-nN dword] [-dDw off:hex] file|f.asm|-\n");
	if (v) {
		printf (
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
			" -S [string]     append a string\n"
			" -v              show version\n"
			" -w [off:hex]    patch hexpairs at given offset\n"
			" -x              execute\n"
			" -X [hexpairs]   execute rop chain, using the stack provided\n"
			" -z              output in C string syntax\n");
	}
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
	RBinArchOptions opts;
	RBuffer *b;
	r_bin_arch_options_init (&opts, arch, bits);
	b = r_bin_create (bin, format, code, codelen, NULL, 0, &opts);
	if (b) {
		ut64 blen;
		const ut8 *tmp = r_buf_data (b, &blen);
		if (write (1, tmp, blen) != blen) {
			eprintf ("Failed to write buffer\n");
		}
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
	if (x) {
		fchmod (fd, 0755);
	}
#endif
#if _MSC_VER
	int r = _chsize (fd, 0);
#else
	int r = ftruncate (fd, 0);
#endif
	if (r != 0) {
		eprintf ("Could not resize\n");
	}
	close (1);
	dup2 (fd, 1);
	return fd;
}
#define ISEXEC (fmt!='r')

R_API int r_main_ragg2(int argc, char **argv) {
	const char *file = NULL;
	const char *padding = NULL;
	const char *pattern = NULL;
	const char *str = NULL;
	char *bytes = NULL;
	const char *contents = NULL;
	const char *arch = R_SYS_ARCH;
	const char *os = R_EGG_OS_NAME;
	char *format = "raw";
	bool show_execute = false;
	bool show_execute_rop = false;
	int show_hex = 1;
	int show_asm = 0;
	int show_raw = 0;
	int append = 0;
	int show_str = 0;
	ut64 get_offset  = 0;
	char *shellcode = NULL;
	char *encoder = NULL;
	char *sequence = NULL;
	int bits = (R_SYS_BITS & R_SYS_BITS_64)? 64: 32;
	int fmt = 0;
	const char *ofile = NULL;
	int ofileauto = 0;
	RBuffer *b;
	int c, i;
	REgg *egg = r_egg_new ();

	while ((c = r_getopt (argc, argv, "n:N:he:a:b:f:o:sxXrk:FOI:Li:c:p:P:B:C:vd:D:w:zq:S:")) != -1) {
		switch (c) {
		case 'a':
			arch = r_optarg;
			if (!strcmp (arch, "trace")) {
				show_asm = 1;
				show_hex = 0;
			}
			break;
		case 'e':
			encoder = r_optarg;
			break;
		case 'b':
			bits = atoi (r_optarg);
			break;
		case 'B':
			bytes = r_str_append (bytes, r_optarg);
			break;
		case 'C':
			contents = r_optarg;
			break;
		case 'w':
			{
			char *arg = strdup (r_optarg);
			char *p = strchr (arg, ':');
			if (p) {
				int len, off;
				ut8 *b;
				*p++ = 0;
				off = r_num_math (NULL, arg);
				b = malloc (strlen (r_optarg) + 1);
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
			ut32 n = r_num_math (NULL, r_optarg);
			append = 1;
			r_egg_patch (egg, -1, (const ut8*)&n, 4);
			}
			break;
		case 'N':
			{
			ut64 n = r_num_math (NULL, r_optarg);
			r_egg_patch (egg, -1, (const ut8*)&n, 8);
			append = 1;
			}
			break;
		case 'd':
			{
			ut32 off, n;
			char *p = strchr (r_optarg, ':');
			if (p) {
				*p = 0;
				off = r_num_math (NULL, r_optarg);
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
			char *p = strchr (r_optarg, ':');
			if (p) {
				ut64 n, off = r_num_math (NULL, r_optarg);
				n = r_num_math (NULL, p + 1);
				// TODO: honor endianness here
				r_egg_patch (egg, off, (const ut8*)&n, 8);
			} else {
				eprintf ("Missing colon in -d\n");
			}
			}
			break;
		case 'S':
			str = r_optarg;
			break;
		case 'o':
			ofile = r_optarg;
			break;
		case 'O':
			ofileauto = 1;
			break;
		case 'I':
			r_egg_lang_include_path (egg, r_optarg);
			break;
		case 'i':
			 shellcode = r_optarg;
			 break;
		case 'p':
			padding = r_optarg;
			break;
		case 'P':
			pattern = r_optarg;
			break;
		case 'c':
			{
			char *p = strchr (r_optarg, '=');
			if (p) {
				*p++ = 0;
				r_egg_option_set (egg, r_optarg, p);
			} else {
				r_egg_option_set (egg, r_optarg, "true");
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
			format = r_optarg;
			show_asm = 0;
			break;
		case 's':
			show_asm = 1;
			show_hex = 0;
			break;
		case 'k':
			os = r_optarg;
			break;
		case 'r':
			show_raw = 1;
			break;
		case 'x':
			// execute
			show_execute = true;
			break;
		case 'X':
			// execute rop chain
			show_execute = 1;
			show_execute_rop = 1;
			break;
		case 'L':
			list (egg);
			r_egg_free (egg);
			free (sequence);
			return 0;
		case 'h':
			r_egg_free (egg);
			free (sequence);
			return usage (1);
		case 'v':
			free (sequence);
			r_egg_free (egg);
			return r_main_version_print ("ragg2");
		case 'z':
			show_str = 1;
			break;
		case 'q':
			get_offset = 1;
			sequence = strdup (r_optarg);
			break;
		default:
			free (sequence);
			r_egg_free (egg);
			return 1;
		}
	}

	if (r_optind == argc && !shellcode && !bytes && !contents && !encoder && !padding && !pattern && !append && !get_offset && !str) {
		r_egg_free (egg);
		return usage (0);
	} else {
		file = argv[r_optind];
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
			r_egg_free (egg);
			return 1;
		}

		get_offset = r_num_math (0, sequence);
		printf ("Little endian: %d\n", r_debruijn_offset (get_offset, false));
		printf ("Big endian: %d\n", r_debruijn_offset (get_offset, true));
		free (sequence);
		r_egg_free (egg);
		return 0;
	}

	// initialize egg
	r_egg_setup (egg, arch, bits, 0, os);
	if (file) {
		if (!strcmp (file, "-")) {
			char buf[1024];
			for (;;) {
				if (!fgets (buf, sizeof (buf) - 1, stdin)) {
					break;
				}
				if (feof (stdin)) {
					break;
				}
				r_egg_load (egg, buf, 0);
			}
		} else if (strstr (file, ".c")) {
			char *fileSanitized = strdup (file);
			r_str_sanitize (fileSanitized);
			char *textFile = r_egg_Cfile_parser (fileSanitized, arch, os, bits);

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
			r_egg_free (egg);
			return 1;
		}
	}

	// append the provided string
	if (str) {
		int l = strlen (str);
		if (l > 0) {
			r_egg_raw (egg, (const ut8*)str, l);
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
			r_egg_free (egg);
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
				r_egg_free (egg);
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
			eprintf ("cannot open file '%s'\n", r_optarg);
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
			r_egg_free (egg);
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
			int r;
			if (show_execute_rop) {
				r = r_egg_run_rop (egg);
			} else {
				r = r_egg_run (egg);
			}
			r_egg_free (egg);
			return r;
		}
		b = r_egg_get_bin (egg);
		if (show_raw) {
			ut64 blen;
			const ut8 *tmp = r_buf_data (b, &blen);
			if (write (1, tmp, blen) != blen) {
				eprintf ("Failed to write buffer\n");
				goto fail;
			}
		} else {
			if (!format) {
				eprintf ("No format specified wtf\n");
				goto fail;
			}
			RPrint *p = r_print_new ();
			ut64 tmpsz;
			const ut8 *tmp = r_buf_data (b, &tmpsz);
			switch (*format) {
			case 'c':
				r_print_code (p, 0, tmp, tmpsz, 'c');
				break;
			case 'j': // JavaScript
				r_print_code (p, 0, tmp, tmpsz, 'j');
				break;
			case 'r':
				if (show_str) {
					printf ("\"");
					for (i = 0; i < tmpsz; i++) {
						printf ("\\x%02x", tmp[i]);
					}
					printf ("\"\n");
				} else if (show_hex) {
					r_buf_seek (b, 0, R_BUF_SET);
					for (i = 0; i < tmpsz; i++) {
						printf ("%02x", tmp[i]);
					}
					printf ("\n");
				} // else show_raw is_above()
				break;
			case 'p': // PE
				if (strlen(format) >= 2 && format[1] == 'y') { // Python
					r_print_code (p, 0, tmp, tmpsz, 'p');
				}
				break;
			case 'e': // ELF
			case 'm': // MACH0
				create (format, arch, bits, tmp, tmpsz);
				break;
			default:
				eprintf ("unknown executable format (%s)\n", format);
				goto fail;
			}
			r_print_free (p);
		}
	}
	r_egg_free (egg);
	return 0;
fail:
	r_egg_free (egg);
	return 1;
}
