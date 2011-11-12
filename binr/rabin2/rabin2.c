/* radare - LGPL - Copyright 2009-2011 nibble<.ds@gmail.com> */

/* TODO:
 * Use -v to show version information.. not -V .. like the rest of tools
 *  --- needs sync with callers and so on..
 * -L [lib]  dlopen library and show addr
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <r_core.h>

#define ACTION_UNK       0x00000
#define ACTION_ENTRIES   0x00001
#define ACTION_IMPORTS   0x00002
#define ACTION_SYMBOLS   0x00004
#define ACTION_SECTIONS  0x00008
#define ACTION_INFO      0x00010
#define ACTION_OPERATION 0x00020
#define ACTION_HELP      0x00040
#define ACTION_STRINGS   0x00080
#define ACTION_FIELDS    0x00100
#define ACTION_LIBS      0x00200
#define ACTION_SRCLINE   0x00400
#define ACTION_MAIN      0x00800
#define ACTION_EXTRACT   0x01000
#define ACTION_RELOCS    0x02000
#define ACTION_LISTARCHS 0x04000
#define ACTION_CREATE    0x08000
#define ACTION_CLASSES   0x10000

static struct r_lib_t *l;
static struct r_bin_t *bin = NULL;
static int rad = R_FALSE;
static int rw = R_FALSE;
static int va = R_FALSE;
static ut64 gbaddr = 0LL;
static char* file = NULL;
static char* output = "out";
static char* create = NULL;
static ut64 at = 0LL;
static char *name = NULL;

static int rabin_show_help() {
	printf ("rabin2 [options] [file]\n"
		" -A              list archs\n"
		" -a [arch_bits]  set arch (x86_32, arm_32, x86_64)\n"
		" -b [addr]       override baddr\n"
		" -c [fmt:C:D]    create [elf,mach0,pe] with Code and Data hexpairs (see -a)\n"
		" -C              list classes\n"
		" -p [patchfile]  patch file (see man rabin2)\n"
		" -e              entrypoint\n"
		" -f [str]        select sub-bin named str\n"
		" -i              imports (symbols imported from libraries)\n"
		" -s              symbols (exports)\n"
		" -S              sections\n"
		" -M              main (show address of main symbol)\n"
		" -z              strings\n"
		" -I              binary info\n"
		" -H              header fields\n"
		" -l              linked libraries\n"
		" -R              relocations\n"
		" -O [str]        write/extract operations (-O help)\n"
		" -o [str]        output file/folder for write operations (out by default)\n"
		" -r              radare output\n"
		" -v              use vaddr in radare output\n"
		" -m [addr]       show source line at addr\n"
		" -L              list supported bin plugins\n"
		" -@ [addr]       show section, symbol or import at addr\n"
		" -n [str]        show section, symbol or import named str\n"
		" -x              extract bins contained in file\n"
		" -V              show version information\n"
		" -h              this help\n");
	return 1;
}

static int rabin_extract(int all) {
	char outfile[512], outpath[512], *path, *ptr;
	int i = 0;

	// XXX: Wrong for w32 (/)
	if (all) {
		for (i=0; i<bin->narch; i++) {
			r_bin_select_idx (bin, i);
			if (bin->curarch.info == NULL) {
				eprintf ("No extract info found.\n");
			} else {
				path = strdup (bin->curarch.file);
				if ((ptr = strrchr (path, '/'))) {
					*ptr = '\0';
					ptr = ptr+1;
				}
				else ptr = bin->curarch.file;
				snprintf (outpath, sizeof (outpath), "%s/%s", output, path);
				if (!r_sys_rmkdir (outpath)) {
					eprintf ("Error creating dir structure\n");
					return R_FALSE;
				}
				snprintf (outfile, sizeof (outfile), "%s/%s.%s_%i",
						outpath, ptr, bin->curarch.info->arch,
						bin->curarch.info->bits);
				if (!r_file_dump (outfile, bin->curarch.buf->buf, bin->curarch.size)) {
					eprintf ("Error extracting %s\n", outfile);
					return R_FALSE;
				} else printf ("%s created (%i)\n", outfile, bin->curarch.size);
			}
		}
	} else { /* XXX: Use 'output' for filename? */
		if (bin->curarch.info == NULL) {
			eprintf ("No extract info found.\n");
		} else {
			if ((ptr = strrchr (bin->curarch.file, '/')))
				ptr = ptr+1;
			else ptr = bin->curarch.file;
			snprintf (outfile, sizeof (outfile), "%s.%s_%i", ptr,
					bin->curarch.info->arch, bin->curarch.info->bits);
			if (!r_file_dump (outfile, bin->curarch.buf->buf, bin->curarch.size)) {
				eprintf ("Error extracting %s\n", outfile);
				return R_FALSE;
			} else printf ("%s created (%i)\n", outfile, bin->curarch.size);
		}
	}
	return R_TRUE;
}

static int rabin_dump_symbols(int len) {
	RList *symbols;
	RListIter *iter;
	RBinSymbol *symbol;
	ut8 *buf;
	char *ret;
	int olen = len;

	if ((symbols = r_bin_get_symbols (bin)) == NULL)
		return R_FALSE;

	r_list_foreach (symbols, iter, symbol) {
		if (symbol->size != 0 && (olen > symbol->size || olen == 0))
			len = symbol->size;
		else if (symbol->size == 0 && olen == 0)
			len = 32;
		else len = olen;

		if (!(buf = malloc (len)) || !(ret = malloc (len*2+1)))
			return R_FALSE;
		r_buf_read_at (bin->curarch.buf, symbol->offset, buf, len);
		r_hex_bin2str (buf, len, ret);
		printf ("%s %s\n", symbol->name, ret);
		free (buf);
		free (ret);
	}

	return R_TRUE;
}

static int rabin_dump_sections(char *scnname) {
	RList *sections;
	RListIter *iter;
	RBinSection *section;
	ut8 *buf;
	char *ret;

	if ((sections = r_bin_get_sections (bin)) == NULL)
		return R_FALSE;

	r_list_foreach (sections, iter, section) {
		if (!strcmp (scnname, section->name)) {
			if (!(buf = malloc (section->size)) ||
					!(ret = malloc (section->size*2+1)))
				return R_FALSE;
			r_buf_read_at (bin->curarch.buf, section->offset, buf, section->size);
			r_hex_bin2str (buf, section->size, ret);
			printf ("%s\n", ret);
			free (buf);
			free (ret);
			break;
		}
	}

	return R_TRUE;
}

static int rabin_do_operation(const char *op) {
	char *arg = NULL, *ptr = NULL, *ptr2 = NULL;

	if (!strcmp (op, "help")) {
		printf ("Operation string:\n"
				"  Dump symbols: d/s/1024\n"
				"  Dump section: d/S/.text\n"
				"  Resize section: r/.data/1024\n");
		return R_FALSE;
	}
	/* Implement alloca with fixed-size buffer? */
	if (!(arg = strdup (op)))
		return R_FALSE;

	if ((ptr = strchr (arg, '/'))) {
		ptr[0] = '\0';
		ptr = ptr + 1;
		if ((ptr2 = strchr (ptr, '/'))) {
			ptr2[0] = '\0';
			ptr2 = ptr2 + 1;
		}
	}

	switch (arg[0]) {
	case 'd':
		if (!ptr)
			goto _rabin_do_operation_error;
		switch (*ptr) {
		case 's':
			if (ptr2) {
				if (!rabin_dump_symbols (r_num_math(NULL, ptr2)))
					return R_FALSE;
			} else if (!rabin_dump_symbols (0))
					return R_FALSE;
			break;
		case 'S':
			if (!ptr2)
				goto _rabin_do_operation_error;
			if (!rabin_dump_sections (ptr2))
				return R_FALSE;
			break;
		default:
			goto _rabin_do_operation_error;
		}
		break;
	case 'r':
		r_bin_wr_scn_resize (bin, ptr, r_num_math (NULL, ptr2));
		r_bin_wr_output (bin, output);
		break;
	default:
	_rabin_do_operation_error:
		eprintf ("Unknown operation. use -O help\n");
		return R_FALSE;
	}

	free (arg);

	return R_TRUE;
}

static int rabin_show_srcline(ut64 at) {
	char *srcline;
	if ((srcline = r_bin_meta_get_source_line (bin, at))) {
		printf ("%s\n", srcline);
		free (srcline);
		return R_TRUE;
	}
	return R_FALSE;
}

/* bin callback */
static int __lib_bin_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	struct r_bin_plugin_t *hand = (struct r_bin_plugin_t *)data;
	//printf(" * Added (dis)assembly plugin\n");
	r_bin_add (bin, hand);
	return R_TRUE;
}

static int __lib_bin_dt(struct r_lib_plugin_t *pl, void *p, void *u) {
	return R_TRUE;
}

/* binxtr callback */
static int __lib_bin_xtr_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	struct r_bin_xtr_plugin_t *hand = (struct r_bin_xtr_plugin_t *)data;
	//printf(" * Added (dis)assembly plugin\n");
	r_bin_xtr_add (bin, hand);
	return R_TRUE;
}

static int __lib_bin_xtr_dt(struct r_lib_plugin_t *pl, void *p, void *u) {
	return R_TRUE;
}

int main(int argc, char **argv) {
	int c, bits = 0;
	int action = ACTION_UNK;
	const char *op = NULL;
	char *arch = NULL, *arch_name = NULL;

	bin = r_bin_new ();
	l = r_lib_new ("radare_plugin");
	r_lib_add_handler (l, R_LIB_TYPE_BIN, "bin plugins",
					   &__lib_bin_cb, &__lib_bin_dt, NULL);
	r_lib_add_handler (l, R_LIB_TYPE_BIN_XTR, "bin xtr plugins",
					   &__lib_bin_xtr_cb, &__lib_bin_xtr_dt, NULL);

	{ /* load plugins everywhere */
		char *homeplugindir = r_str_home (".radare/plugins");
		r_lib_opendir (l, getenv ("LIBR_PLUGINS"));
		r_lib_opendir (l, homeplugindir);
		r_lib_opendir (l, LIBDIR"/radare2/");
	}

	while ((c = getopt (argc, argv, "Af:a:B:b:c:CMm:n:@:VisSzIHelRwO:o:p:rvLhx")) != -1) {
		switch(c) {
		case 'A':
			action |= ACTION_LISTARCHS;
			break;
		case 'a':
			if (optarg) arch = strdup (optarg);
			break;
		case 'c':
			action = ACTION_CREATE;
			create = strdup (optarg);
			break;
		case 'C':
			action |= ACTION_CLASSES;
			break;
		case 'f':
			if (optarg) arch_name = strdup (optarg);
			break;
		case 'B':
			bits = r_num_math (NULL, optarg);
			break;
		case 'm':
			at = r_num_math (NULL, optarg);
			action |= ACTION_SRCLINE;
			break;
		case 'i':
			action |= ACTION_IMPORTS;
			break;
		case 's':
			action |= ACTION_SYMBOLS;
			break;
		case 'S':
			action |= ACTION_SECTIONS;
			break;
		case 'z':
			action |= ACTION_STRINGS;
			break;
		case 'I':
			action |= ACTION_INFO;
			break;
		case 'H':
			action |= ACTION_FIELDS;
			break;
		case 'e':
			action |= ACTION_ENTRIES;
			break;
		case 'M':
			action |= ACTION_MAIN;
			break;
		case 'l':
			action |= ACTION_LIBS;
			break;
		case 'R':
			action |= ACTION_RELOCS;
			break;
		case 'x':
			action |= ACTION_EXTRACT;
			break;
		case 'w':
			rw = R_TRUE;
			break;
		case 'O':
			op = optarg;
			action |= ACTION_OPERATION;
			if (optind==argc)
				return rabin_do_operation (op);
			break;
		case 'o':
			output = optarg;
			break;
		case 'r':
			rad = R_TRUE;
			break;
		case 'v':
			va = R_TRUE;
			break;
		case 'L':
			r_bin_list (bin);
			return 1;
		case 'b':
			gbaddr = r_num_math (NULL, optarg);
			break;
		case '@':
			at = r_num_math (NULL, optarg);
			break;
		case 'n':
			name = optarg;
			break;
		case 'V':
			printf ("rabin2 v"R2_VERSION"\n");
			return 0;
		case 'h':
		default:
			action |= ACTION_HELP;
		}
	}

	file = argv[optind];
	if (action == ACTION_HELP || action == ACTION_UNK || file == NULL)
		return rabin_show_help ();

	if (arch) {
		char *ptr;
		ptr = strchr (arch, '_');
		if (ptr) {
			*ptr = '\0';
			bits = r_num_math (NULL, ptr+1);
		}
	}
	if (action & ACTION_CREATE) {
		// TODO: move in a function outside
		RBuffer *b;
		int datalen, codelen;
		ut8 *data = NULL, *code = NULL;
		char *p2, *p = strchr (create, ':');
		if (!p) {
			eprintf ("Invalid format for -c flag. Use 'format:codehexpair:datahexpair'\n");
			return 1;
		}
		*p++ = 0;
		p2 = strchr (p, ':');
		if (p2) {
			// has data
			*p2++ = 0;
			data = malloc (strlen (p2));
			datalen = r_hex_str2bin (p2, data);
		}
		code = malloc (strlen (p));
		codelen = r_hex_str2bin (p, code);
		if (!arch) arch = "x86";
		if (!bits) bits = 32;

		if (!r_bin_use_arch (bin, arch, bits, create)) {
			eprintf ("Cannot set arch\n");
			return 1;
		}
		b = r_bin_create (bin, code, codelen, data, datalen);
		if (b) {
			if (r_file_dump (file, b->buf, b->length)) {
				eprintf ("dumped %d bytes in '%s'\n", b->length, file);
				r_file_chmod (file, "+x", 0);
			} else eprintf ("error dumping into a.out\n");
			r_buf_free (b);
		} else eprintf ("Cannot create binary for this format '%s'.\n", create);
		r_bin_free (bin);
		return 0;
	}

	if (!r_bin_load (bin, file, R_FALSE) && !r_bin_load (bin, file, R_TRUE)) {
		eprintf ("r_bin: Cannot open '%s'\n", file);
		return 1;
	}

	if (action & ACTION_LISTARCHS || ((arch || bits || arch_name) &&
		!r_bin_select (bin, arch, bits, arch_name))) {
		r_bin_list_archs (bin);
		free (arch);
		free (arch_name);
		r_bin_free (bin);
		return 1;
	}

	RCore core;
	core.bin = bin;
	RCoreBinFilter filter;
	filter.offset = at;
	filter.name = name;

	r_cons_new ();
	if (action&ACTION_SECTIONS)
		r_core_bin_info (&core, R_CORE_BIN_ACC_SECTIONS,
				(rad)?R_CORE_BIN_RADARE:R_CORE_BIN_PRINT, va, &filter);
	if (action&ACTION_ENTRIES)
		r_core_bin_info (&core, R_CORE_BIN_ACC_ENTRIES,
				(rad)?R_CORE_BIN_RADARE:R_CORE_BIN_PRINT, va, NULL);
	if (action&ACTION_MAIN)
		r_core_bin_info (&core, R_CORE_BIN_ACC_MAIN,
				(rad)?R_CORE_BIN_RADARE:R_CORE_BIN_PRINT, va, NULL);
	if (action&ACTION_IMPORTS)
		r_core_bin_info (&core, R_CORE_BIN_ACC_IMPORTS,
				(rad)?R_CORE_BIN_RADARE:R_CORE_BIN_PRINT, va, &filter);
	if (action&ACTION_CLASSES)
		r_core_bin_info (&core, R_CORE_BIN_ACC_CLASSES,
				(rad)?R_CORE_BIN_RADARE:R_CORE_BIN_PRINT, va, NULL);
	if (action&ACTION_SYMBOLS)
		r_core_bin_info (&core, R_CORE_BIN_ACC_SYMBOLS,
				(rad)?R_CORE_BIN_RADARE:R_CORE_BIN_PRINT, va, &filter);
	if (action&ACTION_STRINGS)
		r_core_bin_info (&core, R_CORE_BIN_ACC_STRINGS,
				(rad)?R_CORE_BIN_RADARE:R_CORE_BIN_PRINT, va, NULL);
	if (action&ACTION_INFO)
		r_core_bin_info (&core, R_CORE_BIN_ACC_INFO,
				(rad)?R_CORE_BIN_RADARE:R_CORE_BIN_PRINT, va, NULL);
	if (action&ACTION_FIELDS)
		r_core_bin_info (&core, R_CORE_BIN_ACC_FIELDS,
				(rad)?R_CORE_BIN_RADARE:R_CORE_BIN_PRINT, va, NULL);
	if (action&ACTION_LIBS)
		r_core_bin_info (&core, R_CORE_BIN_ACC_LIBS,
				(rad)?R_CORE_BIN_RADARE:R_CORE_BIN_PRINT, va, NULL);
	if (action&ACTION_RELOCS)
		r_core_bin_info (&core, R_CORE_BIN_ACC_RELOCS,
				(rad)?R_CORE_BIN_RADARE:R_CORE_BIN_PRINT, va, NULL);
	if (action&ACTION_SRCLINE)
		rabin_show_srcline (at);
	if (action&ACTION_EXTRACT)
		rabin_extract ((arch==NULL && arch_name==NULL && bits==0));
	if (op != NULL && action&ACTION_OPERATION)
		rabin_do_operation (op);

	free (arch);
	r_bin_free (bin);
	r_cons_flush ();

	return 0;
}
