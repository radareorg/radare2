/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com> */

/* TODO:
 * -L [lib]  dlopen library and show address
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <r_types.h>
#include <r_list.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_flags.h>
#include <r_util.h>

#define ACTION_UNK       0x0000
#define ACTION_ENTRIES   0x0001
#define ACTION_IMPORTS   0x0002
#define ACTION_SYMBOLS   0x0004
#define ACTION_SECTIONS  0x0008
#define ACTION_INFO      0x0010
#define ACTION_OPERATION 0x0020
#define ACTION_HELP      0x0040
#define ACTION_STRINGS   0x0080
#define ACTION_FIELDS    0x0100
#define ACTION_LIBS      0x0200
#define ACTION_SRCLINE   0x0400
#define ACTION_MAIN      0x0800
#define ACTION_EXTRACT   0x1000
#define ACTION_RELOCS    0x2000

static struct r_lib_t *l;
static struct r_bin_t *bin = NULL;
static int rad = R_FALSE;
static int rw = R_FALSE;
static int va = R_FALSE;
static ut64 gbaddr = 0LL;
static char* file = NULL;
static char* output = "a.out";
static ut64 at = 0LL;
static char *name = NULL;

static int rabin_show_help() {
	printf ("rabin2 [options] [file]\n"
		" -b [addr]   Override baddr\n"
		" -e          Entrypoint\n"
		" -M          Main\n"
		" -i          Imports (symbols imported from libraries)\n"
		" -s          Symbols (exports)\n"
		" -S          Sections\n"
		" -z          Strings\n"
		" -I          Binary info\n"
		" -H          Header fields\n"
		" -l          Linked libraries\n"
		" -R          Relocations\n"
		" -O [str]    Write/Extract operations (str=help for help)\n"
		" -o [file]   Output file for write operations (a.out by default)\n"
		" -f [format] Override file format autodetection\n"
		" -r          radare output\n"
		" -v          Use vaddr in radare output\n"
		" -m [addr]   Show source line at addr\n"
		" -L          List supported bin plugins\n"
		" -@ [addr]   Show section, symbol or import at addr\n"
		" -n [str]    Show section, symbol or import named str\n"
		" -x          Extract bins contained in file\n"
		" -V          Show version information\n"
		" -h          This help\n");
	return R_TRUE;
}

static int rabin_show_entrypoints() {
	RList *entries;
	RListIter *iter;
	RBinAddr *entry;
	int i = 0;

	ut64 baddr = gbaddr?gbaddr:r_bin_get_baddr (bin);

	if ((entries = r_bin_get_entries (bin)) == NULL)
		return R_FALSE;

	if (rad) printf ("fs symbols\n");
	else printf ("[Entrypoints]\n");

	r_list_foreach (entries, iter, entry) {
		if (rad) {
			printf ("f entry%i @ 0x%08"PFMT64x"\n", i, va?baddr+entry->rva:entry->offset);
			printf ("s entry%i\n", i);
		} else printf ("address=0x%08"PFMT64x" offset=0x%08"PFMT64x" baddr=0x%08"PFMT64x"\n",
				baddr+entry->rva, entry->offset, baddr);
		i++;
	}

	if (!rad) printf ("\n%i entrypoints\n", i);

	return R_TRUE;
}

static int rabin_show_main() {
	RBinAddr *binmain;
	ut64 baddr = gbaddr?gbaddr:r_bin_get_baddr (bin);

	if ((binmain = r_bin_get_main (bin)) == NULL)
		return R_FALSE;

	if (rad) printf ("fs symbols\n");
	else printf ("[Main]\n");

	if (rad) {
		printf ("f main @ 0x%08"PFMT64x"\n", va?baddr+binmain->rva:binmain->offset);
	} else printf ("address=0x%08"PFMT64x" offset=0x%08"PFMT64x"\n",
			baddr+binmain->rva, binmain->offset);

	return R_TRUE;
}

static int rabin_extract() {
	int n = r_bin_extract (bin);
	if (n != 0) {
		if (!rad) printf ("%i bins extracted\n", n);
		return R_TRUE;
	}
	return R_FALSE;
}

static int rabin_show_libs() {
	RList *libs;
	RListIter *iter;
	char* lib;
	int i = 0;

	if ((libs = r_bin_get_libs (bin)) == NULL)
		return R_FALSE;

	printf ("[Linked libraries]\n");

	r_list_foreach (libs, iter, lib) {
		printf ("%s\n", lib);
		i++;
	}

	if (!rad) printf ("\n%i libraries\n", i);
	
	return R_TRUE;
}

static int rabin_show_relocs() {
	RList *relocs;
	RListIter *iter;
	RBinReloc *reloc;
	int i = 0;

	ut64 baddr = gbaddr?gbaddr:r_bin_get_baddr (bin);

	if ((relocs = r_bin_get_relocs (bin)) == NULL)
		return R_FALSE;

	if (rad) printf ("fs relocs\n");
	else printf ("[Relocations]\n");

	r_list_foreach (relocs, iter, reloc) {
		if (rad) {
			printf ("f reloc.%s @ 0x%08"PFMT64x"\n", reloc->name, va?baddr+reloc->rva:reloc->offset);
		} else printf ("sym=%02i address=0x%08"PFMT64x" offset=0x%08"PFMT64x" type=0x%08x %s\n",
				reloc->sym, baddr+reloc->rva, reloc->offset, reloc->type, reloc->name);
		i++;
	}

	if (!rad) printf ("\n%i relocations\n", i);

	return R_TRUE;
}

static int rabin_show_imports() {
	RList *imports;
	RListIter *iter;
	RBinImport *import;
	ut64 baddr;
	int i = 0;

	baddr = gbaddr?gbaddr:r_bin_get_baddr (bin);

	if ((imports = r_bin_get_imports (bin)) == NULL)
		return R_FALSE;

	if (!at && !rad)
		printf ("[Imports]\n");

	r_list_foreach (imports, iter, import) {
		if (name && strcmp (import->name, name))
			continue;
		if (at) {
			if (baddr+import->rva == at || import->offset == at)
				printf ("%s\n", import->name);
		} else {
			if (rad) {
				r_flag_name_filter (import->name);
				if (import->size) 
					printf ("af+ 0x%08"PFMT64x" %"PFMT64d" fcn.imp.%s\n",
							va?baddr+import->rva:import->offset, import->size, import->name);
				printf ("fs imports\n");
				printf ("f imp.%s @ 0x%08"PFMT64x"\n",
						import->name, va?baddr+import->rva:import->offset);
				printf ("fs functions\n");
				printf ("f fcn.imp.%s @ 0x%08"PFMT64x"\n",
						import->name, va?baddr+import->rva:import->offset);
			} else printf ("address=0x%08"PFMT64x" offset=0x%08"PFMT64x" ordinal=%03"PFMT64d" "
						   "hint=%03"PFMT64d" bind=%s type=%s name=%s\n",
						   baddr+import->rva, import->offset,
						   import->ordinal, import->hint,  import->bind,
						   import->type, import->name);
		}
		i++;
	}

	if (!at && !rad) printf ("\n%i imports\n", i);

	return R_TRUE;
}

static int rabin_show_symbols() {
	RList *symbols;
	RListIter *iter;
	RBinSymbol *symbol;
	ut64 baddr;
	int i = 0;

	baddr = gbaddr?gbaddr:r_bin_get_baddr (bin);

	if ((symbols = r_bin_get_symbols (bin)) == NULL)
		return R_FALSE;

	if (!at) {
		if (rad) printf ("fs symbols\n");
		else printf ("[Symbols]\n");
	}

	r_list_foreach (symbols, iter, symbol) {
		if (name && strcmp (symbol->name, name))
			continue;
		if (at) {
			if ((symbol->size != 0 &&
				((baddr+symbol->rva <= at && baddr+symbol->rva+symbol->size > at) ||
				(symbol->offset <= at && symbol->offset+symbol->size > at))) ||
				baddr+symbol->rva == at || symbol->offset == at)
				printf("%s\n", symbol->name);
		} else {
			if (rad) {
				r_flag_name_filter (symbol->name);
				if (!strncmp (symbol->type,"FUNC", 4)) {
					if (symbol->size) 
						printf ("af+ 0x%08"PFMT64x" %"PFMT64d" fcn.sym.%s\n",
								va?baddr+symbol->rva:symbol->offset, symbol->size, symbol->name);
					printf ("fs functions\n");
					printf ("f fcn.sym.%s %"PFMT64d" 0x%08"PFMT64x"\n",
							symbol->name, symbol->size,
							va?baddr+symbol->rva:symbol->offset);
					printf ("fs symbols\n");
				} else if (!strncmp (symbol->type,"OBJECT", 6))
					printf ("Cd %"PFMT64d" @ 0x%08"PFMT64x"\n",
							symbol->size, va?baddr+symbol->rva:symbol->offset);
				printf ("f sym.%s %"PFMT64d" 0x%08"PFMT64x"\n",
						symbol->name, symbol->size,
						va?baddr+symbol->rva:symbol->offset);
			} else printf ("address=0x%08"PFMT64x" offset=0x%08"PFMT64x" ordinal=%03"PFMT64d" "
						   "forwarder=%s size=%"PFMT64d" bind=%s type=%s name=%s\n",
						   baddr+symbol->rva, symbol->offset,
						   symbol->ordinal, symbol->forwarder,
						   symbol->size, symbol->bind, symbol->type, 
						   symbol->name);
		}
		i++;
	}

	if (!at && !rad) printf ("\n%i symbols\n", i);

	return R_TRUE;
}

static int rabin_show_strings() {
	RList *strings;
	RListIter *iter;
	RBinString *string;
	RBinSection *section;
	int i = 0;
	ut64 baddr = gbaddr?gbaddr:r_bin_get_baddr (bin);

	if ((strings = r_bin_get_strings (bin)) == NULL)
		return R_FALSE;

	if (rad) printf ("fs strings\n");
	else printf ("[strings]\n");

	r_list_foreach (strings, iter, string) {
		section = r_bin_get_section_at (bin, string->offset, 0);
		if (rad) {
			r_flag_name_filter (string->string);
			printf ("f str.%s %"PFMT64d" @ 0x%08"PFMT64x"\n"
				"Cs %"PFMT64d" @ 0x%08"PFMT64x"\n",
				string->string, string->size, va?baddr+string->rva:string->offset,
				string->size, va?baddr+string->rva:string->offset);
		} else printf ("address=0x%08"PFMT64x" offset=0x%08"PFMT64x" ordinal=%03"PFMT64d" "
			"size=%"PFMT64d" section=%s string=%s\n",
			baddr+string->rva, string->offset,
			string->ordinal, string->size,
			section?section->name:"unknown", string->string);
		i++;
	}

	if (!rad) printf ("\n%i strings\n", i);
	
	return R_TRUE;
}

static int rabin_show_sections() {
	RList *sections;
	RListIter *iter;
	RBinSection *section;
	ut64 baddr;
	int i = 0;

	baddr = gbaddr?gbaddr:r_bin_get_baddr (bin);

	if ((sections = r_bin_get_sections (bin)) == NULL)
		return R_FALSE;

	if (!at) {
		if (rad) printf ("fs sections\n");
		else printf ("[Sections]\n");
	}

	r_list_foreach (sections, iter, section) {
		if (name && strcmp (section->name, name))
			continue;
		if (at) {
			if ((section->size != 0 &&
				((baddr+section->rva <= at && baddr+section->rva+section->size > at) ||
				(section->offset <= at && section->offset+section->size > at))) ||
				baddr+section->rva == at || section->offset == at)
				printf ("%s\n", section->name);
		} else {
			if (rad) {
				r_flag_name_filter (section->name);
				printf ("S 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" %s %d\n",
					section->offset, baddr+section->rva,
					section->size, section->vsize, section->name, (int)section->srwx);
				printf ("f section.%s %"PFMT64d" 0x%08"PFMT64x"\n",
					section->name, section->size, va?baddr+section->rva:section->offset);
				printf ("CC [%02i] va=0x%08"PFMT64x" pa=0x%08"PFMT64x" sz=%"PFMT64d" vsz=%"PFMT64d" "
					"rwx=%c%c%c%c %s @ 0x%08"PFMT64x"\n",
					i, baddr+section->rva, section->offset, section->size, section->vsize,
					R_BIN_SCN_SHAREABLE (section->srwx)?'s':'-',
					R_BIN_SCN_READABLE (section->srwx)?'r':'-',
					R_BIN_SCN_WRITABLE (section->srwx)?'w':'-',
					R_BIN_SCN_EXECUTABLE (section->srwx)?'x':'-',
					section->name,va?baddr+section->rva:section->offset);
			} else printf ("idx=%02i address=0x%08"PFMT64x" offset=0x%08"PFMT64x" size=%"PFMT64d" vsize=%"PFMT64d" "
				"privileges=%c%c%c%c name=%s\n",
				i, baddr+section->rva, section->offset, section->size, section->vsize,
				R_BIN_SCN_SHAREABLE (section->srwx)?'s':'-',
				R_BIN_SCN_READABLE (section->srwx)?'r':'-',
				R_BIN_SCN_WRITABLE (section->srwx)?'w':'-',
				R_BIN_SCN_EXECUTABLE (section->srwx)?'x':'-',
				section->name);
		}
		i++;
	}

	if (!at && !rad) printf ("\n%i sections\n", i);

	return R_TRUE;
}

static int rabin_show_info() {
	RBinInfo *info;

	if ((info = r_bin_get_info (bin)) == NULL)
		return R_FALSE;

	if (rad) {
		printf ("e file.type=%s\n"
				"e cfg.bigendian=%s\n"
				"e asm.os=%s\n"
				"e asm.arch=%s\n"
				"e asm.bits=%i\n"
				"e asm.dwarf=%s\n",
				info->rclass, info->big_endian?"true":"false", info->os, info->arch,
				info->bits, R_BIN_DBG_STRIPPED (info->dbg_info)?"false":"true");
	} else printf ("[File info]\n"
				   "File=%s\n"
				   "Type=%s\n"
				   "Class=%s\n"
				   "Arch=%s %i\n"
				   "Machine=%s\n"
				   "OS=%s\n"
				   "Subsystem=%s\n"
				   "Big endian=%s\n"
				   "Stripped=%s\n"
				   "Static=%s\n"
				   "Line_nums=%s\n"
				   "Local_syms=%s\n"
				   "Relocs=%s\n"
				   "RPath=%s\n",
				   info->file, info->type, info->bclass,
				   info->arch, info->bits, info->machine, info->os, 
				   info->subsystem, info->big_endian?"True":"False",
				   R_BIN_DBG_STRIPPED (info->dbg_info)?"True":"False",
				   R_BIN_DBG_STATIC (info->dbg_info)?"True":"False",
				   R_BIN_DBG_LINENUMS (info->dbg_info)?"True":"False",
				   R_BIN_DBG_SYMS (info->dbg_info)?"True":"False",
				   R_BIN_DBG_RELOCS (info->dbg_info)?"True":"False",
				   info->rpath);
	
	return R_TRUE;
}

static int rabin_show_fields() {
	RList *fields;
	RListIter *iter;
	RBinField *field;
	ut64 baddr;
	int i = 0;

	baddr = gbaddr?gbaddr:r_bin_get_baddr (bin);

	if ((fields = r_bin_get_fields (bin)) == NULL)
		return R_FALSE;

	if (rad) printf ("fs header\n");
	else printf ("[Header fields]\n");

	r_list_foreach (fields, iter, field) {
		if (rad) {
			r_flag_name_filter (field->name);
			printf ("f header.%s @ 0x%08"PFMT64x"\n",
					field->name, va?baddr+field->rva:field->offset);
			printf ("[%02i] address=0x%08"PFMT64x" offset=0x%08"PFMT64x" name=%s\n",
					i, baddr+field->rva, field->offset, field->name);
		} else printf ("idx=%02i address=0x%08"PFMT64x" offset=0x%08"PFMT64x" name=%s\n",
					   i, baddr+field->rva, field->offset, field->name);
		i++;
	}

	if (!rad) printf ("\n%i fields\n", i);

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

		if (!(buf = malloc (len)) || !(ret = malloc(len*2+1)))
			return R_FALSE;
		r_buf_read_at (bin->buf, symbol->offset, buf, len);
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
			r_buf_read_at (bin->buf, section->offset, buf, section->size);
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
		if (ptr[0]=='s') {
			if (ptr2) {
				if (!rabin_dump_symbols (r_num_math(NULL, ptr2)))
					return R_FALSE;
			} else 
				if (!rabin_dump_symbols (0))
					return R_FALSE;
		} else if (ptr[0]=='S') {
			if (!ptr2)
				goto _rabin_do_operation_error;
			if (!rabin_dump_sections (ptr2))
				return R_FALSE;
		} else goto _rabin_do_operation_error;
		break;
	case 'r':
		r_bin_wr_scn_resize (bin, ptr, r_num_math (NULL, ptr2));
		r_bin_wr_output (bin, output);
		break;
	default:
	_rabin_do_operation_error:
		printf ("Unknown operation. use -O help\n");
		return R_FALSE;
	}

	free (arg);

	return R_TRUE;
}

static int rabin_show_srcline() {
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

int main(int argc, char **argv)
{
	int c;
	int action = ACTION_UNK;
	const char *format = NULL, *op = NULL;
	const char *plugin_name = NULL;

	bin = r_bin_new ();
	l = r_lib_new ("radare_plugin");
	r_lib_add_handler (l, R_LIB_TYPE_BIN, "bin plugins",
					   &__lib_bin_cb, &__lib_bin_dt, NULL);

	{ /* load plugins everywhere */
		char *homeplugindir = r_str_home (".radare/plugins");
		r_lib_opendir (l, getenv ("LIBR_PLUGINS"));
		r_lib_opendir (l, homeplugindir);
		r_lib_opendir (l, LIBDIR"/radare2/");
	}

	while ((c = getopt (argc, argv, "b:Mm:n:@:VisSzIHelRwO:o:f:rvLhx")) != -1) {
		switch(c) {
		case 'm':
			at = r_num_math (NULL, optarg);
			action |= ACTION_SRCLINE;
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
			break;
		case 'o':
			output = optarg;
			break;
		case 'f':
			format = optarg;
			break;
		case 'r':
			rad = R_TRUE;
			break;
		case 'v':
			va = R_TRUE;
			break;
		case 'L':
			r_bin_list (bin);
			exit(1);
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

	if (format)
		plugin_name = format;

	if (!r_bin_load (bin, file, plugin_name) &&
		!r_bin_load (bin, file, "dummy")) {
		eprintf ("r_bin: Cannot open '%s'\n", file);
		return R_FALSE;
	}

	if (action&ACTION_SECTIONS)
		rabin_show_sections (at);
	if (action&ACTION_ENTRIES)
		rabin_show_entrypoints ();
	if (action&ACTION_MAIN)
		rabin_show_main ();
	if (action&ACTION_IMPORTS)
		rabin_show_imports (at);
	if (action&ACTION_SYMBOLS)
		rabin_show_symbols (at);
	if (action&ACTION_STRINGS)
		rabin_show_strings ();
	if (action&ACTION_INFO)
		rabin_show_info ();
	if (action&ACTION_FIELDS)
		rabin_show_fields();
	if (action&ACTION_LIBS)
		rabin_show_libs();
	if (action&ACTION_RELOCS)
		rabin_show_relocs();
	if (action&ACTION_SRCLINE)
		rabin_show_srcline(at);
	if (action&ACTION_EXTRACT)
		rabin_extract();
	if (op != NULL && action&ACTION_OPERATION)
		rabin_do_operation (op);

	r_bin_free (bin);

	return R_FALSE;
}
