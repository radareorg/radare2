/* radare - LGPL - Copyright 2011 pancake<@nopcode.org> */
#include <r_egg.h>
#include <r_bin.h>
#include <getopt.h>

static int usage () {
	eprintf ("ragg2 [options] [file|-]\n");
	eprintf (" -a [x86|arm]    select architecture\n");
	eprintf (" -b [32|64]      register size\n");
	eprintf (" -f [format]     output format (raw, pe, elf, mach0)\n");
	eprintf (" -o [file]       output file\n");
	eprintf (" -s              show assembler\n");
	eprintf (" -x              show hexpairs (enabled by default)\n");
	eprintf (" -X              execute\n");
	eprintf (" -h              show this help\n");
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

int main(int argc, char **argv) {
	const char *arch = "x86";
	char *format = "raw";
	int show_execute = 0;
	int show_hex = 1;
	int show_asm = 0;
	int bits = 32;
	int c, i;
	RBuffer *b;
	REgg *egg = r_egg_new ();

        while ((c = getopt (argc, argv, "ha:b:f:o:sxX")) != -1) {
                switch (c) {
		case 'a':
			arch = optarg;
			break;
		case 'b':
			bits = atoi (optarg);
			break;
		case 'o':
			{
				int fd = open (optarg, O_RDWR|O_CREAT, 0644);
				if (fd != -1) {
					if (*format != 'r')
						fchmod (fd, 0755);
					close (1);
					dup2 (fd, 1);
				} else eprintf ("Cannot open '%s'\n", optarg);
			}
			break;
		case 'f':
			format = optarg;
			break;
		case 's':
			show_asm = 1;
			show_hex = 0;
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

	r_egg_setup (egg, arch, bits, 0, NULL);
	if (!strcmp (argv[optind], "-")) {
		char buf[1024];
		for (;;) {
			fgets (buf, sizeof (buf)-1, stdin);
			if (feof (stdin)) break;
			r_egg_load (egg, buf, 0);
		}
	} else r_egg_include (egg, argv[optind], 0);
	r_egg_compile (egg);
	//printf ("src (%s)\n", r_egg_get_source (egg));
	if (show_asm)
		printf ("%s\n", r_egg_get_assembly (egg));
	if (show_hex || show_execute) {
		r_egg_assemble (egg);
		b = r_egg_get_bin (egg);
		if (b == NULL) {
			eprintf ("Cannot assemble egg :(\n");
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
				eprintf ("Unknown format\n");
				r_egg_free (egg);
				return 1;
			}
		}
	}
	r_egg_free (egg);
	return 0;
}
