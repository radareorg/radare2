/* radare - LGPL - Copyright 2011-2024 - pancake */

#define R_LOG_ORIGIN "ragg2"

#include <r_egg.h>
#include <r_bin.h>
#include <r_main.h>
#include <r_util/r_print.h>
#include <r_util.h>

typedef struct {
	RLib *l;
	REgg *e;
	RAnal *a;
	// TODO flags
	// bool oneliner;
	// bool coutput;
	// bool json;
	// bool quiet;
} REggState;

typedef struct {
	const char *name;
	const char *desc;
} REggEnv;

static REggEnv env[] = {
	{ "R2_NOPLUGINS", "do not load any plugin" }
};

static void ragg_show_env(bool show_desc);

/* egg callback */
static int __lib_egg_cb(RLibPlugin *pl, void *user, void *data) {
	REggPlugin *hand = (REggPlugin *)data;
	REggState *es = (REggState *)user;
	r_egg_plugin_add (es->e, hand);
	return true;
}

static void __load_plugins(REggState *es) {
	r_lib_add_handler (es->l, R_LIB_TYPE_EGG, "egg plugins", &__lib_egg_cb, NULL, es);

	char *path = r_sys_getenv (R_LIB_ENV);
	if (!R_STR_ISEMPTY (path)) {
		r_lib_opendir (es->l, path);
	}

	// load plugins from the home directory
	char *homeplugindir = r_xdg_datadir ("plugins");
	r_lib_opendir (es->l, homeplugindir);
	free (homeplugindir);

	// load plugins from the system directory
	char *plugindir = r_str_r2_prefix (R2_PLUGINS);
	char *extrasdir = r_str_r2_prefix (R2_EXTRAS);
	char *bindingsdir = r_str_r2_prefix (R2_BINDINGS);
	r_lib_opendir (es->l, plugindir);
	r_lib_opendir (es->l, extrasdir);
	r_lib_opendir (es->l, bindingsdir);
	free (plugindir);
	free (extrasdir);
	free (bindingsdir);

	free (path);
}

static REggState *__es_new(bool load_plugins) {
	REggState *es = R_NEW0 (REggState);
	es->l = r_lib_new (NULL, NULL);
	es->e = r_egg_new ();
	es->a = r_anal_new ();
	r_anal_bind (es->a, &es->e->rasm->analb);
	if (load_plugins) {
		__load_plugins (es);
	}
	return es;
}

static void __es_free(REggState *es) {
	if (es) {
		r_egg_free (es->e);
		r_lib_free (es->l);
		free (es);
	}
}

static int usage(int v) {
	printf ("Usage: ragg2 [-FOLsrxhvz] [-a arch] [-b bits] [-k os] [-o file] [-I path]\n"
		"             [-i sc] [-E enc] [-B hex] [-c k=v] [-C file] [-p pad] [-q off]\n"
		"             [-S string] [-f fmt] [-nN dword] [-dDw off:hex] [-e expr] file|f.asm|-\n");
	if (v) {
		printf (
			" -a [arch]       select architecture (x86, mips, arm)\n"
			" -b [bits]       register size (32, 64, ..)\n"
			" -B [hexpairs]   append some hexpair bytes\n"
			" -c [k=v]        set configuration options\n"
			" -C [file]       append contents of file\n"
			" -d [off:dword]  patch dword (4 bytes) at given offset\n"
			" -D [off:qword]  patch qword (8 bytes) at given offset\n"
			" -e [egg-expr]   take egg program from string instead of file\n"
			" -E [encoder]    use specific encoder. see -L\n"
			" -f [format]     output format (raw, c, pe, elf, mach0, python, javascript)\n"
			" -F              output native format (osx=mach0, linux=elf, ..)\n"
			" -h              show this help\n"
			" -H ([var])      display variable\n"
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
			ragg_show_env (true);
	}
	return 1;
}


static void list(REgg *egg) {
	RListIter *iter;
	REggPlugin *p;
	printf ("shellcodes:\n");
	r_list_foreach (egg->plugins, iter, p) {
		if (p->type == R_EGG_PLUGIN_SHELLCODE) {
			printf ("%10s : %s\n", p->meta.name, p->meta.desc);
		}
	}
	printf ("encoders:\n");
	r_list_foreach (egg->plugins, iter, p) {
		if (p->type == R_EGG_PLUGIN_ENCODER) {
			printf ("%10s : %s\n", p->meta.name, p->meta.desc);
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
			R_LOG_ERROR ("Failed to write buffer");
		}
		r_buf_free (b);
	} else {
		R_LOG_ERROR ("Cannot create binary for this format '%s'", format);
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
#if R2__UNIX__ && !__wasi__
	if (x) {
		fchmod (fd, 0755);
	}
#endif
#if _MSC_VER || R2__WINDOWS__
	int r = _chsize (fd, 0);
#else
	int r = ftruncate (fd, 0);
#endif
	if (r != 0) {
		R_LOG_ERROR ("Could not resize");
	}
	close (1);
#if !__wasi__
	dup2 (fd, 1);
#endif
	return fd;
}
#define ISEXEC (fmt != 'r')

static void ragg_env_print(const char *name) {
	char *value = r_sys_getenv (name);
	printf ("%s\n", R_STR_ISNOTEMPTY (value) ? value : "");
	free (value);
}

static void ragg_show_env(bool show_desc) {
	int id = 0;
	for (id = 0; id < (sizeof (env) / sizeof (env[0])); id++) {
		if (show_desc) {
			printf ("%s\t%s\n", env[id].name, env[id].desc);
		} else {
			printf ("%s=", env[id].name);
			ragg_env_print(env[id].name);
		}
	}
}

R_API int r_main_ragg2(int argc, const char **argv) {
	const char *file = NULL;
	const char *padding = NULL;
	const char *pattern = NULL;
	const char *str = NULL;
	char *bytes = NULL;
	const char *contents = NULL;
	const char *arch = R_SYS_ARCH;
	const char *os = R_EGG_OS_NAME;
	const char *format = "raw";
	bool show_execute = false;
	bool show_execute_rop = false;
	bool show_hex = true;
	bool show_asm = false;
	bool show_raw = false;
	int append = 0;
	int show_str = 0;
	ut64 get_offset  = 0;
	const char *shellcode = NULL;
	const char *encoder = NULL;
	const char *eggprg = NULL;
	char *sequence = NULL;
	int bits = R_SYS_BITS_CHECK (R_SYS_BITS, 64)? 64: 32;
	int fmt = 0;
	const char *ofile = NULL;
	int ofileauto = 0;
	RBuffer *b;
	int c, i, fd = -1;

	if (argc < 2) {
		return usage (1);
	}
	const bool load_plugins = !r_sys_getenv_asbool ("R2_NOPLUGINS");

	REggState *es = __es_new (load_plugins);

	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "a:b:B:c:C:d:D:e:E:f:FhH:i:I:k:Ln:N:o:Op:P:q:rsS:vw:xX:z");
	if (argc == 2 && !strcmp (argv[1], "-H")) {
		ragg_show_env (false);
		__es_free (es);
		free (sequence);
		return 0;
	}
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'a':
			arch = opt.arg;
			if (!strcmp (arch, "trace")) {
				show_asm = true;
				show_hex = false;
			}
			break;
		case 'e':
			eggprg = opt.arg;
			break;
		case 'E':
			encoder = opt.arg;
			break;
		case 'b':
			bits = atoi (opt.arg);
			break;
		case 'B':
			bytes = r_str_append (bytes, opt.arg);
			break;
		case 'C':
			if (R_STR_ISEMPTY (opt.arg)) {
				R_LOG_ERROR ("Cannot open empty contents path");
				free (sequence);
				__es_free (es);
				return 1;
			}
			contents = opt.arg;
			break;
		case 'w':
			{
			char *arg = strdup (opt.arg);
			char *p = strchr (arg, ':');
			if (p) {
				int len, off;
				ut8 *b;
				*p++ = 0;
				off = r_num_math (NULL, arg);
				b = calloc (1, strlen (opt.arg) + 1);
				len = r_hex_str2bin (p, b);
				if (len > 0) {
					r_egg_patch (es->e, off, (const ut8 *)b, len);
				} else {
					R_LOG_ERROR ("Invalid hexstr for -w");
				}
				free (b);
			} else {
				R_LOG_ERROR ("Missing colon in -w");
			}
			free (arg);
			}
			break;
		case 'n':
			{
			ut32 n = r_num_math (NULL, opt.arg);
			append = 1;
			r_egg_patch (es->e, -1, (const ut8 *)&n, 4);
			}
			break;
		case 'N':
			{
			ut64 n = r_num_math (NULL, opt.arg);
			r_egg_patch (es->e, -1, (const ut8 *)&n, 8);
			append = 1;
			}
			break;
		case 'd':
			{
			ut32 off, n;
			char *p = strchr (opt.arg, ':');
			if (p) {
				*p = 0;
				off = r_num_math (NULL, opt.arg);
				n = r_num_math (NULL, p + 1);
				*p = ':';
				ut8 word[4];
				r_write_le32 (word, (ut32)n);
				// TODO: support big endian
				r_egg_patch (es->e, off, word, sizeof (word));
			} else {
				R_LOG_ERROR ("Missing colon in -d");
			}
			}
			break;
		case 'D':
			{
			char *p = strchr (opt.arg, ':');
			if (p) {
				ut64 n, off = r_num_math (NULL, opt.arg);
				n = r_num_math (NULL, p + 1);
				// TODO: honor endianness here
				ut8 word[8];
				r_write_le64 (word, n);
				r_egg_patch (es->e, off, word, sizeof (word));
			} else {
				R_LOG_ERROR ("Missing colon in -d");
			}
			}
			break;
		case 'S':
			str = opt.arg;
			break;
		case 'o':
			ofile = opt.arg;
			break;
		case 'O':
			ofileauto = 1;
			break;
		case 'I':
			if (R_STR_ISEMPTY (opt.arg)) {
				R_LOG_ERROR ("Cannot open empty include path");
				free (sequence);
				__es_free (es);
				return 1;
			}
			r_egg_lang_include_path (es->e, opt.arg);
			break;
		case 'i':
			shellcode = opt.arg;
			break;
		case 'p':
			padding = opt.arg;
			break;
		case 'P':
			pattern = opt.arg;
			break;
		case 'c':
			{
			char *p = strchr (opt.arg, '=');
			if (p) {
				*p++ = 0;
				r_egg_option_set (es->e, opt.arg, p);
			} else {
				r_egg_option_set (es->e, opt.arg, "true");
			}
			}
			break;
		case 'F':
#if __APPLE__
			format = "mach0";
#elif R2__WINDOWS__
			format = "pe";
#else
			format = "elf";
#endif
			show_asm = false;
			break;
		case 'f':
			format = opt.arg;
			show_asm = false;
			break;
		case 's':
			show_asm = true;
			show_hex = false;
			break;
		case 'k':
			os = opt.arg;
			break;
		case 'r':
			show_raw = true;
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
			list (es->e);
			__es_free (es);
			free (sequence);
			return 0;
		case 'h':
			__es_free (es);
			free (sequence);
			return usage (1);
		case 'H':
			ragg_env_print (opt.arg);
			__es_free (es);
			free (sequence);
			return 0;
		case 'v':
			free (sequence);
			__es_free (es);
			return r_main_version_print ("ragg2", 0);
		case 'z':
			show_str = 1;
			break;
		case 'q':
			get_offset = 1;
			sequence = strdup (opt.arg);
			break;
		default:
			free (sequence);
			__es_free (es);
			return 1;
		}
	}

	if (opt.ind == argc && !eggprg && !shellcode && !bytes && !contents && !encoder && !padding && !pattern && !append && !get_offset && !str) {
		free (sequence);
		__es_free (es);
		return usage (0);
	}
	if (opt.ind != argc) {
		file = argv[opt.ind];
	}

	if (bits == 64) {
		if (!strcmp (format, "mach0")) {
			format = "mach064";
		} else if (!strcmp (format, "elf")) {
			format = "elf64";
		} else if (!strcmp (format, "pe")) {
			format = "pe64";
		}
	}

	// catch this first
	if (get_offset) {
		if (strncmp (sequence, "0x", 2)) {
			R_LOG_ERROR ("Need hex value with `0x' prefix e.g. 0x41414142");
			free (sequence);
			__es_free (es);
			return 1;
		}

		get_offset = r_num_math (0, sequence);
		printf ("Little endian: %d\n", r_debruijn_offset (get_offset, false));
		printf ("Big endian: %d\n", r_debruijn_offset (get_offset, true));
		free (sequence);
		__es_free (es);
		return 0;
	}

	// initialize egg
	r_egg_setup (es->e, arch, bits, 0, os);
	if (file) {
		if (R_STR_ISEMPTY (file)) {
			R_LOG_ERROR ("Cannot open empty path");
			goto fail;
		}
		if (!strcmp (file, "-")) {
			char buf[1024];
			for (;;) {
				if (!fgets (buf, sizeof (buf), stdin)) {
					break;
				}
				if (feof (stdin)) {
					break;
				}
				r_egg_load (es->e, buf, 0);
			}
		} else if (strstr (file, ".c")) {
			char *fileSanitized = strdup (file);
			r_str_sanitize (fileSanitized);
			char *textFile = r_egg_cfile_parser (fileSanitized, arch, os, bits);

			if (!textFile) {
				R_LOG_ERROR ("Failure while parsing '%s'", fileSanitized);
				goto fail;
			}

			size_t l;
			char *buf = r_file_slurp (textFile, &l);
			if (buf && l > 0) {
				r_egg_raw (es->e, (const ut8 *)buf, (int)l);
			} else {
				R_LOG_ERROR ("Cannot load '%s'", textFile);
			}

			r_file_rm (textFile);
			free (fileSanitized);
			free (textFile);
			free (buf);
		} else {
			if (strstr (file, ".s") || strstr (file, ".asm")) {
				fmt = 'a';
			} else if (strstr (file, ".bin") || strstr (file, ".raw")) {
				fmt = 'r';
			} else {
				fmt = 0;
			}
			if (!r_egg_include (es->e, file, fmt)) {
				R_LOG_ERROR ("Cannot open '%s'", file);
				goto fail;
			}
		}
	} else {
		if (eggprg && !r_egg_include_str (es->e, eggprg)) {
			R_LOG_ERROR ("Cannot parse egg program");
			goto fail;
		}
	}

	// compile source code to assembly
	if (!r_egg_compile (es->e)) {
		if (!fmt) {
			R_LOG_ERROR ("r_egg_compile failed");
			free (sequence);
			__es_free (es);
			return 1;
		}
	}

	// append the provided string
	if (str) {
		int l = strlen (str);
		if (l > 0) {
			r_egg_raw (es->e, (const ut8 *)str, l);
		}
	}

	// add raw file
	if (contents) {
		size_t l;
		char *buf = r_file_slurp (contents, &l);
		if (buf && l > 0) {
			r_egg_raw (es->e, (const ut8 *)buf, (int)l);
		} else {
			R_LOG_ERROR ("Cannot load '%s'", contents);
		}
		free (buf);
	}

	// add shellcode
	if (shellcode) {
		if (!r_egg_shellcode (es->e, shellcode)) {
			R_LOG_ERROR ("Unknown shellcode '%s'", shellcode);
			goto fail;
		}
	}

	// add raw bytes
	if (bytes) {
		ut8 *b = calloc (1, strlen (bytes) + 1);
		int len = r_hex_str2bin (bytes, b);
		if (len > 0) {
			if (!r_egg_raw (es->e, b, len)) {
				R_LOG_ERROR ("Unknown '%s'", shellcode);
				free (b);
				goto fail;
			}
		} else {
			R_LOG_ERROR ("Invalid hexpair string for -B");
		}
		free (b);
		free (bytes);
		bytes = NULL;
	}


	/* set output (create output file if needed) */
	if (ofileauto) {
		if (file) {
			char *o, *q, *p = strdup (file);
			if ((o = strchr (p, '.'))) {
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
			R_LOG_ERROR ("cannot open file '%s'", opt.arg);
			goto fail;
		}
		close (fd);
	}
	if (ofile) {
		fd = openfile (ofile, ISEXEC);
		if (fd == -1) {
			R_LOG_ERROR ("cannot open file '%s'", ofile);
			goto fail;
		}
	}

	// assemble to binary
	if (!show_asm) {
		if (!r_egg_assemble (es->e)) {
			R_LOG_ERROR ("r_egg_assemble: invalid assembly");
			goto fail;
		}
	}
	if (encoder) {
		if (!r_egg_encode (es->e, encoder)) {
			R_LOG_ERROR ("Invalid encoder '%s'", encoder);
			goto fail;
		}
	}

	// add padding
	if (padding) {
		r_egg_padding (es->e, padding);
	}

	// add pattern
	if (pattern) {
		r_egg_pattern (es->e, r_num_math (NULL, pattern));
	}

	// apply patches
	if (!es->e->bin) {
		es->e->bin = r_buf_new ();
	}
	if (!(b = r_egg_get_bin (es->e))) {
		R_LOG_ERROR ("r_egg_get_bin: invalid egg :(");
		goto fail;
	}
	r_egg_finalize (es->e);

	if (show_asm) {
		printf ("%s\n", r_egg_get_assembly (es->e));
	}

	if (show_raw || show_hex || show_execute) {
		if (show_execute) {
			int r;
			if (show_execute_rop) {
				r = r_egg_run_rop (es->e);
			} else {
				r = r_egg_run (es->e);
			}
			r_egg_free (es->e);
			if (fd != -1) {
				close (fd);
			}
			free (sequence);
			return r;
		}
		b = r_egg_get_bin (es->e);
		if (show_raw) {
			ut64 blen;
			const ut8 *tmp = r_buf_data (b, &blen);
			if (write (1, tmp, blen) != blen) {
				R_LOG_ERROR ("Failed to write buffer");
				goto fail;
			}
		} else {
			if (!format) {
				R_LOG_ERROR ("No format specified wtf");
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
			case 'p': // PE/python
				if (strlen (format) > 2 && format[1] == 'y') { // Python
					r_print_code (p, 0, tmp, tmpsz, 'p');
				} else { // PE
					create (format, arch, bits, tmp, tmpsz);
				}
				break;
			case 'e': // ELF
			case 'm': // MACH0
				create (format, arch, bits, tmp, tmpsz);
				break;
			default:
				R_LOG_ERROR ("unknown executable format (%s)", format);
				goto fail;
			}
			r_print_free (p);
		}
	}
	if (fd != -1) {
		close (fd);
	}
	free (sequence);
	__es_free (es);
	return 0;
fail:
	if (fd != -1) {
		close (fd);
	}
	free (sequence);
	__es_free (es);
	return 1;
}
