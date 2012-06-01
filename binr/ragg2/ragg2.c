/* radare - LGPL - Copyright 2011-2012 pancake<@nopcode.org> */
#include <r_egg.h>
#include <r_bin.h>
#include <getopt.c>

static int usage () {
	printf ("ragg2 [options] [file|-]\n"
	" -a [x86|arm]    select architecture\n"
	" -b [32|64]      register size\n"
	" -k [os]         operating system's kernel (linux,bsd,osx,w32)\n"
	" -f [format]     output format (raw, pe, elf, mach0)\n"
	" -F              output native format (osx=mach0, linux=elf, ..)\n"
	" -o [file]       output file\n"
	" -O              use default output file (filename without extension or a.out)\n"
	" -I [path]       add include path\n"
	" -L              list all plugins (shellcodes and encoders)\n"
	" -i [shellcode]  include shellcode plugin, uses options. see -L\n"
	" -e [encoder]    use specific encoder. see -L\n"
	" -B [hexpairs]   append some hexpair bytes\n"
	" -c [k=v]        set configuration options\n"
	" -C [file]       append contents of file\n"
	" -d [off:dword]  patch dword (4 bytes) at given offset\n"
	" -D [off:qword]  patch qword (8 bytes) at given offset\n"
	" -w [off:hex]    patch hexpairs at given offset\n"
	" -p [padding]    add padding after compilation (padding=n10s32)\n"
	"                 ntas : begin nop, trap, 'a', sequence\n"
	"                 NTAS : same as above, but at beginning\n"
	" -s              show assembler\n"
	" -r              show raw bytes instead of hexpairs\n"
	" -x              execute\n"
	" -v              show version\n"
	" -h              show this help\n");
	return 1;
}

static void list (REgg *egg) {
	RListIter *iter;
	REggPlugin *p;
	printf ("shellcodes:\n");
	r_list_foreach (egg->plugins, iter, p) {
		if (p->type == R_EGG_PLUGIN_SHELLCODE)
		printf ("%10s : %s\n", p->name, p->desc);
	}
	printf ("encoders:\n");
	r_list_foreach (egg->plugins, iter, p) {
		if (p->type == R_EGG_PLUGIN_ENCODER)
		printf ("%10s : %s\n", p->name, p->desc);
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
	const char *padding = NULL;
	const char *bytes = NULL;
	const char *contents = NULL;
	const char *arch = R_SYS_ARCH;
	const char *os = R_EGG_OS_NAME;
	char *format = "raw";
	int show_execute = 0;
	int show_hex = 1;
	int show_asm = 0;
	int show_raw = 0;
	char *shellcode = NULL;
	char *encoder = NULL;
	int bits = 32;
	const char *ofile = NULL;
	int ofileauto = 0;
	RBuffer *b;
	int c, i;
	REgg *egg = r_egg_new ();

        while ((c = getopt (argc, argv, "he:a:b:f:o:sxrk:FOI:Li:c:p:B:C:vd:D:w:")) != -1) {
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
			bytes = optarg;
			break;
		case 'C':
			contents = optarg;
			break;
		case 'w':
			{
				char *p = strchr (optarg, ':');
				if (p) {
					int len, off = r_num_math (NULL, optarg);
					ut8 *b = malloc (strlen (optarg)+1);
					len = r_hex_str2bin (p+1, b);
					if (len>0) r_egg_patch (egg, off, (const ut8*)b, len);
					else eprintf ("Invalid hexstr for -w\n");
					free (b);
				} else eprintf ("Missing colon in -w\n");
			}
			break;
		case 'd':
			{
			ut32 off, n;
			char *p = strchr (optarg, ':');
			if (p) {
				off = r_num_get (NULL, optarg);
				n = r_num_get (NULL, p+1);
				// TODO: honor endianness here
				r_egg_patch (egg, off, (const ut8*)&n, 4);
			} else eprintf ("Missing colon in -d\n");
			}
			break;
		case 'D':
			{
			ut64 off, n;
			char *p = strchr (optarg, ':');
			if (p) {
				off = r_num_get (NULL, optarg);
				n = r_num_get (NULL, p+1);
				// TODO: honor endianness here
				r_egg_patch (egg, off, (const ut8*)&n, 8);
			} else eprintf ("Missing colon in -d\n");
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
		case 'c':
			{
			char *p = strchr (optarg, '=');
			if (p) {
				*p=0;
				r_egg_option_set (egg, optarg, p+1);
			} else r_egg_option_set (egg, optarg, "true");
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
		case 'v':
			printf ("ragg2 "R2_VERSION" "R2_INCDIR"/sflib\n");
			return 0;
		}
	}

	if (optind == argc && !shellcode && !bytes && !contents && !encoder && !padding) {
		eprintf ("Missing argument\n");
		return usage ();
	} else file = argv[optind];

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
	if (shellcode) {
		if (!r_egg_shellcode (egg, shellcode)) {
			eprintf ("Unknown shellcode '%s'\n", shellcode);
			return 1;
		}
	}
	if (contents) {
		int l;
		char *buf = r_file_slurp (contents, &l);
		if (buf && l>0) {
			r_egg_raw (egg, (const ut8*)buf, l);
		} else eprintf ("Error loading '%s'\n", contents);
	}
	if (bytes) {
		ut8 *b = malloc (strlen (bytes)+1);
		int len = r_hex_str2bin (bytes, b);
		if (len>0) {
			if (!r_egg_raw (egg, b, len)) {
				eprintf ("Unknown '%s'\n", shellcode);
				return 1;
			}
		} else eprintf ("Invalid hexpair string for -B\n");
		free (b);
	}
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

	//printf ("src (%s)\n", r_egg_get_source (egg));
	if (show_asm)
		printf ("%s\n", r_egg_get_assembly (egg));
	if (show_raw || show_hex || show_execute) {
		if (!r_egg_assemble (egg)) {
			eprintf ("r_egg_assemble: invalid assembly\n");
			goto fail;
		}
		if (encoder)
			if (!r_egg_encode (egg, encoder))
				eprintf ("Invalid encoder '%s'\n", encoder);
		if (padding)
			r_egg_padding (egg, padding);

		if (!(b = r_egg_get_bin (egg))) {
			eprintf ("r_egg_get_bin: invalid egg :(\n");
			goto fail;
		}
		r_egg_finalize (egg); // apply patches
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
				} // else show_raw is_above()
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
