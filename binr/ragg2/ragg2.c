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
	" -s              show assembler\n"
	" -x              show hexpairs (enabled by default)\n"
	" -X              execute\n"
	" -h              show this help\n");
	return 1;
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
	const char *arch = "x86";
	const char *os = R_EGG_OS_NAME;
	char *format = "raw";
	int show_execute = 0;
	int show_hex = 1;
	int show_asm = 0;
	int bits = 32;
	const char *ofile = NULL;
	int ofileauto = 0;
	RBuffer *b;
	int c, i;
	REgg *egg = r_egg_new ();

        while ((c = getopt (argc, argv, "ha:b:f:o:sxXk:FOI:")) != -1) {
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
		case 'x':
			show_hex = 1;
			break;
		case 'X':
			// execute
			show_execute = 1;
			break;
		case 'h':
			return usage ();
		}
	}

	if (optind == argc)
		return usage ();

	/* create output file if needed */
	if (ofileauto) {
		int fd;
		char *o, *p = strdup (argv[optind]);
		if ( (o = strchr (p, '.')) ) {
			*o = 0;
			fd = openfile (p, ISEXEC);
		} else {
			fd = openfile ("a.out", ISEXEC);
		}
		free (p);
		if (fd == -1) {
			eprintf ("cannot open file '%s'\n", optarg);
			goto fail;
		}
	}
	if (ofile) {
		if (openfile (ofile, ISEXEC) == -1) {
			eprintf ("cannot open file '%s'\n", optarg);
			goto fail;
		}
	}

	r_egg_setup (egg, arch, bits, 0, os);
	if (!strcmp (argv[optind], "-")) {
		char buf[1024];
		for (;;) {
			fgets (buf, sizeof (buf)-1, stdin);
			if (feof (stdin)) break;
			r_egg_load (egg, buf, 0);
		}
	} else {
		if (!r_egg_include (egg, argv[optind], 0)) {
			eprintf ("Cannot open '%s'\n", argv[optind]);
			goto fail;
		}
	}
	r_egg_compile (egg);
	//printf ("src (%s)\n", r_egg_get_source (egg));
	if (show_asm)
		printf ("%s\n", r_egg_get_assembly (egg));
	if (show_hex || show_execute) {
		if (!r_egg_assemble (egg)) {
			eprintf ("r_egg_assemble: invalid assembly\n");
			goto fail;
		}
		b = r_egg_get_bin (egg);
		if (b == NULL) {
			eprintf ("r_egg_get_bin: invalid egg :(\n");
			goto fail;
		} else {
			if (show_execute) {
				// TODO
				eprintf ("TODO: execute\n");
			}
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
