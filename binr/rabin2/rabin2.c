/* radare - LGPL - Copyright 2009-2012 - nibble, pancake */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.c>

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
#define ACTION_DWARF     0x20000
#define ACTION_SIZE      0x40000

static struct r_bin_t *bin = NULL;
static char* output = NULL;
static char* create = NULL;
static int rad = R_FALSE;
static ut64 gbaddr = 0LL;
static char* file = NULL;
static char *name = NULL;
static int rw = R_FALSE;
static int va = R_FALSE;
static ut64 at = 0LL;
static RLib *l;

static int rabin_show_help() {
	printf ("rabin2 [options] [file]\n"
		" -A              list archs\n"
		" -a [arch]       set arch (x86, arm, .. or <arch>_<bits>)\n"
		" -b [bits]       set bits (32, 64 ...)\n"
		" -B [addr]       override baddr\n"
		" -c [fmt:C:D]    create [elf,mach0,pe] with Code and Data hexpairs (see -a)\n"
		" -C              list classes\n"
		" -d              show debug/dwarf information\n"
		" -p [patchfile]  patch file (see man rabin2)\n"
		" -e              entrypoint\n"
		" -f [str]        select sub-bin named str\n"
		" -i              imports (symbols imported from libraries)\n"
		" -j              output in json\n"
		" -s              symbols (exports)\n"
		" -S              sections\n"
		" -M              main (show address of main symbol)\n"
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
		" -q              be quite, just show fewer data\n"
		" -x              extract bins contained in file\n"
		" -Z              size of binary\n"
		" -z              strings\n"
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
			if (bin->cur.o->info == NULL) {
				eprintf ("No extract info found.\n");
			} else {
				path = strdup (bin->cur.file);
				if ((ptr = strrchr (path, '/'))) {
					*ptr = '\0';
					ptr++;
				} else ptr = bin->cur.file;
/*
				if (output)
					snprintf (outpath, sizeof (outpath), "%s/%s", output, path);
				else snprintf (outpath, sizeof (outpath), "./%s", path);
*/
				snprintf (outpath, sizeof (outpath), "%s.fat", ptr);
				if (!r_sys_rmkdir (outpath)) {
					eprintf ("Error creating dir structure\n");
					return R_FALSE;
				}
				snprintf (outfile, sizeof (outfile), "%s/%s.%s_%i",
						outpath, ptr, bin->cur.o->info->arch,
						bin->cur.o->info->bits);
				snprintf (outfile, sizeof (outfile), "%s/%s.%s_%i",
						outpath, ptr, bin->cur.o->info->arch,
						bin->cur.o->info->bits);
				if (!r_file_dump (outfile, bin->cur.buf->buf, bin->cur.size)) {
					eprintf ("Error extracting %s\n", outfile);
					return R_FALSE;
				} else printf ("%s created (%i)\n", outfile, bin->cur.size);
			}
		}
	} else { /* XXX: Use 'output' for filename? */
		if (bin->cur.o->info == NULL) {
			eprintf ("No extract info found.\n");
		} else {
			if ((ptr = strrchr (bin->cur.file, '/')))
				ptr++;
			else ptr = bin->cur.file;
			snprintf (outfile, sizeof (outfile), "%s.%s_%i", ptr,
					bin->cur.o->info->arch, bin->cur.o->info->bits);
			if (!r_file_dump (outfile, bin->cur.buf->buf, bin->cur.size)) {
				eprintf ("Error extracting %s\n", outfile);
				return R_FALSE;
			} else printf ("%s created (%i)\n", outfile, bin->cur.size);
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
		r_buf_read_at (bin->cur.buf, symbol->offset, buf, len);
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
			r_buf_read_at (bin->cur.buf, section->offset, buf, section->size);
			if (output) {
				r_file_dump (output, buf, section->size);
			} else {
				r_hex_bin2str (buf, section->size, ret);
				printf ("%s\n", ret);
			}
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
		ptr++;
		if ((ptr2 = strchr (ptr, '/'))) {
			ptr2[0] = '\0';
			ptr2++;
		}
	}

	switch (arg[0]) {
	case 'd':
		if (!ptr)
			goto _rabin_do_operation_error;
		switch (*ptr) {
		case 's':
			if (ptr2) {
				if (!rabin_dump_symbols (r_num_math (NULL, ptr2)))
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
		if (!output) output = "out";
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

static int rabin_show_version () {
	printf ("rabin2 v"R2_VERSION"\n");
	return 0;
}

int main(int argc, char **argv) {
	char *homeplugindir = r_str_home (".radare/plugins");
	char *arch = NULL, *arch_name = NULL;
	int actions_done=0, actions = 0, action = ACTION_UNK;
	RCoreBinFilter filter;
	const char *op = NULL;
	int c, bits = 0;
	ut64 offset;
	RCore core;

	bin = r_bin_new ();
	l = r_lib_new ("radare_plugin");
	r_lib_add_handler (l, R_LIB_TYPE_BIN, "bin plugins",
					   &__lib_bin_cb, &__lib_bin_dt, NULL);
	r_lib_add_handler (l, R_LIB_TYPE_BIN_XTR, "bin xtr plugins",
					   &__lib_bin_xtr_cb, &__lib_bin_xtr_dt, NULL);

	 /* load plugins everywhere */
	r_lib_opendir (l, getenv ("LIBR_PLUGINS"));
	r_lib_opendir (l, homeplugindir);
	r_lib_opendir (l, LIBDIR"/radare2/");

#define set_action(x) actions++; action |=x
	while ((c = getopt (argc, argv, "jqAf:a:B:b:c:CdMm:n:@:VisSIHelRwO:o:p:rvLhxzZ")) != -1) {
		switch (c) {
		case 'q': rad = R_CORE_BIN_SIMPLE; break;
		case 'j': rad = R_CORE_BIN_JSON; break;
		case 'A': set_action(ACTION_LISTARCHS); break;
		case 'a': if (optarg) arch = strdup (optarg); break;
		case 'c':
			if (!optarg) {
				eprintf ("Missing argument for -c");
				return 1;
			}
			set_action (ACTION_CREATE);
			create = strdup (optarg);
			break;
		case 'C': set_action (ACTION_CLASSES); break;
		case 'f': if (optarg) arch_name = strdup (optarg); break;
		case 'b': bits = r_num_math (NULL, optarg); break;
		case 'm':
			at = r_num_math (NULL, optarg);
			set_action (ACTION_SRCLINE);
			break;
		case 'i': set_action (ACTION_IMPORTS); break;
		case 's': set_action(ACTION_SYMBOLS); break;
		case 'S': set_action(ACTION_SECTIONS); break;
		case 'z': set_action(ACTION_STRINGS); break;
		case 'Z': set_action(ACTION_SIZE); break;
		case 'I': set_action(ACTION_INFO); break;
		case 'H': set_action(ACTION_FIELDS); break;
		case 'd': set_action(ACTION_DWARF); break;
		case 'e': set_action(ACTION_ENTRIES); break;
		case 'M': set_action(ACTION_MAIN); break;
		case 'l': set_action(ACTION_LIBS); break;
		case 'R': set_action(ACTION_RELOCS); break;
		case 'x': set_action(ACTION_EXTRACT); break;
		case 'w': rw = R_TRUE; break;
		case 'O':
			op = optarg;
			set_action (ACTION_OPERATION);
			if (optind==argc) {
				eprintf ("Missing filename\n");
				return 1;
			}
			//	return rabin_do_operation (op);
			break;
		case 'o': output = optarg; break;
		case 'r': rad = R_TRUE; break;
		case 'v': va = R_TRUE; break;
		case 'L': r_bin_list (bin); return 1;
		case 'B': gbaddr = r_num_math (NULL, optarg); break;
		case '@': at = r_num_math (NULL, optarg); break;
		case 'n': name = optarg; break;
		case 'V': return rabin_show_version();
		case 'h':
		default:
			action |= ACTION_HELP;
		}
	}

	file = argv[optind];
	if (action & ACTION_HELP || action == ACTION_UNK || file == NULL) {
		if (va) return rabin_show_version ();
		return rabin_show_help ();
	}

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
		} else {
			data = NULL;
			datalen = 0;
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

	// XXX: TODO move this to libr/core/bin.c
	if (action & ACTION_LISTARCHS || ((arch || bits || arch_name) &&
		!r_bin_select (bin, arch, bits, arch_name))) {
		if (rad == R_CORE_BIN_JSON) {
			int i;
			printf ("[");
			for (i = 0; i < bin->narch; i++) {
				if (r_bin_select_idx (bin, i)) {
					RBinInfo *info = bin->cur.o->info;
					printf ("%s{\"arch\":\"%s\",\"bits\":%d,"
						"\"offset\":%"PFMT64d",\"machine\":\"%s\"}",
						i?",":"",info->arch, info->bits,
						bin->cur.offset, info->machine);
				}
			}
			printf ("]");
		} else r_bin_list_archs (bin);
		free (arch);
		free (arch_name);
	}

	if (gbaddr != 0LL)
		bin->cur.o->baddr = gbaddr;

	core.bin = bin;
	filter.offset = at;
	filter.name = name;

	offset = r_bin_get_offset (bin);
	r_cons_new ()->is_interactive = R_FALSE;

#define isradjson rad==R_CORE_BIN_JSON&&actions>1
#define run_action(n,x,y) {\
	if (action&x) {\
		if (isradjson) r_cons_printf ("\"%s\":",n);\
		r_core_bin_info (&core, y, rad, va, &filter, 0);\
		actions_done++;\
		if (isradjson) r_cons_printf (actions==actions_done? "":",");\
	}\
}

	if (isradjson) r_cons_printf ("{");
	run_action ("sections", ACTION_SECTIONS, R_CORE_BIN_ACC_SECTIONS);
	run_action ("entries", ACTION_ENTRIES, R_CORE_BIN_ACC_ENTRIES);
	run_action ("main", ACTION_MAIN, R_CORE_BIN_ACC_MAIN);
	run_action ("imports", ACTION_IMPORTS, R_CORE_BIN_ACC_IMPORTS);
	run_action ("classes", ACTION_CLASSES, R_CORE_BIN_ACC_CLASSES);
	run_action ("symbols", ACTION_SYMBOLS, R_CORE_BIN_ACC_SYMBOLS);
	run_action ("strings", ACTION_STRINGS, R_CORE_BIN_ACC_STRINGS);
	run_action ("info", ACTION_INFO, R_CORE_BIN_ACC_INFO);
	run_action ("fields", ACTION_FIELDS, R_CORE_BIN_ACC_FIELDS);
	run_action ("libs", ACTION_LIBS, R_CORE_BIN_ACC_LIBS);
	run_action ("relocs", ACTION_RELOCS, R_CORE_BIN_ACC_RELOCS);
	run_action ("dwarf", ACTION_DWARF, R_CORE_BIN_ACC_DWARF);
	run_action ("size", ACTION_SIZE, R_CORE_BIN_ACC_SIZE);
	if (action&ACTION_SRCLINE)
		rabin_show_srcline (at);
	if (action&ACTION_EXTRACT)
		rabin_extract ((arch==NULL && arch_name==NULL && bits==0));
	if (op != NULL && action&ACTION_OPERATION)
		rabin_do_operation (op);
	if (isradjson)
		printf ("}");
	free (arch);
	r_bin_free (bin);
	r_cons_flush ();

	return 0;
}
