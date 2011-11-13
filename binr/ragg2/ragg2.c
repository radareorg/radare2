/* radare - LGPL - Copyright 2011 pancake<@nopcode.org> */
#include <r_egg.h>
#include <r_bin.h>
#include <getopt.h>

static int usage () {
	eprintf ("ragg2 [options] [file|-]\n"
	" -a [x86|arm]    select architecture\n"
	" -b [32|64]      register size\n"
	" -k [linux|osx]  operating system's kernel\n"
	" -f [format]     output format (raw, pe, elf, mach0)\n"
	" -F              output native format (osx=mach0, linux=elf, ..)\n"
	" -o [file]       output file\n"
	" -O              use default output file (filename without extension or a.out)\n"
	" -I              add include path\n"
	" -L              list all plugins (shellcodes and encoders)\n"
	" -i [plugin]     include shellcode plugin, uses options\n"
	" -c [k=v]        set configuration options\n"
	" -s              show assembler\n"
	" -r              show raw bytes instead of hexpairs\n"
	" -x              execute\n"
	" -h              show this help\n");
	return 1;
}

static void list (REgg *egg) {
	RListIter *iter;
	REggPlugin *p;
	r_list_foreach (egg->plugins, iter, p) {
		printf ("%10s : sz=%d : %s\n", p->name, p->length, p->desc);
	}
}

static int create (const char *format, const char *arch, int bits, const ut8 *code, int codelen) {
	RBin *bin = r_bin_new ();
	RBuffer *b;
	if (!r_bin_use_arch (bin, arch, bits, format)) {
		eprintf ("Cannot set arch\n");
		return 1;
	}
	b = r_bin_create (bin, code, codelen, NULL, 0); //data, datalen);
	if (b) {
		write (1, b->buf, b->length);
		r_buf_free (b);
	} else eprintf ("Cannot create binary for this format '%s'.\n", format);
	r_bin_free (bin);
	return 0;
}

int openfile (const char *f, int x) {
	int fd = open (f, O_RDWR|O_CREAT, 0644);
	if (fd == -1) return -1;
#if __UNIX__
	if (x) fchmod (fd, 0755);
#endif
	ftruncate (fd, 0);
	close (1);
	dup2 (fd, 1);
	return fd;
}
#define ISEXEC (*format!='r')

int main(int argc, char **argv) {
	const char *file = NULL;
	const char *arch = "x86";
	const char *os = R_EGG_OS_NAME;
	char *format = "raw";
	int show_execute = 0;
	int show_hex = 1;
	int show_asm = 0;
	int show_raw = 0;
	int bits = 32;
	const char *ofile = NULL;
	int ofileauto = 0;
	RBuffer *b;
	int c, i;
	REgg *egg = r_egg_new ();

        while ((c = getopt (argc, argv, "ha:b:f:o:sxrk:FOI:Li:c:")) != -1) {
                switch (c) {
		case 'a':
			arch = optarg;
			if (!strcmp (arch, "trace")) {
				show_asm = 1;
				show_hex = 0;
			}
			break;
		case 'b':
			bits = atoi (optarg);
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
			if (!r_egg_shellcode (egg, optarg)) {
				eprintf ("Unknown shellcode '%s'\n", optarg);
				return 1;
			}
			break;
		case 'c':
			{
			char *p = strchr (optarg, '=');
			if (p) {
				*p=0;
				r_egg_option_set (egg, optarg, p+1);
			} else {
				eprintf ("Missing '='\nExample: ragg2 -c cmd=/bin/ls\n");
				return 1;
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
			return usage ();
		}
	}

	if (optind == argc) {
	//	eprintf ("No filename given\n");
		//return usage ();
	} else file = argv[optind];

	/* create output file if needed */
	if (ofileauto) {
		int fd;
		if (file) {
			char *o, *p = strdup (file);
			if ( (o = strchr (p, '.')) ) {
				*o = 0;
				fd = openfile (p, ISEXEC);
			} else fd = openfile ("a.out", ISEXEC);
			free (p);
		} else fd = openfile ("a.out", ISEXEC);
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

	r_egg_setup (egg, arch, bits, 0, os);
	if (file) {
		if (!strcmp (file, "-")) {
			char buf[1024];
			for (;;) {
				fgets (buf, sizeof (buf)-1, stdin);
				if (feof (stdin)) break;
				r_egg_load (egg, buf, 0);
			}
		} else {
			if (!r_egg_include (egg, file, 0)) {
				eprintf ("Cannot open '%s'\n", file);
				goto fail;
			}
		}
	}
	r_egg_compile (egg);
	//printf ("src (%s)\n", r_egg_get_source (egg));
	if (show_asm)
		printf ("%s\n", r_egg_get_assembly (egg));
	if (show_raw || show_hex || show_execute) {
		if (!r_egg_assemble (egg)) {
			eprintf ("r_egg_assemble: invalid assembly\n");
			goto fail;
		}
		if (!(b = r_egg_get_bin (egg))) {
			eprintf ("r_egg_get_bin: invalid egg :(\n");
			goto fail;
		}

		if (show_raw) {
			write (1, b->buf, b->length);
		} else
		if (show_execute) {
			r_egg_run (egg);
			return 0;
		} else {
			switch (*format) {
			case 'r':
				if (show_hex) {
					for (i=0; i<b->length; i++)
						printf ("%02x", b->buf[i]);
					printf ("\n");
				}
				break;
			case 'p': // PE
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
