/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

/* TODO:
 * -l        Linked libraries
 * -L [lib]  dlopen library and show address
 * -x        XRefs (-s/-i/-z required)
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <r_types.h>
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

static struct r_lib_t l;
static struct r_bin_t *bin;
static int rad = R_FALSE;
static int rw = R_FALSE;
static int va = R_FALSE;
static char* file;

static int rabin_show_help() {
	printf ("rabin2 [options] [file]\n"
		" -e          Entrypoint\n"
		" -i          Imports (symbols imported from libraries)\n"
		" -s          Symbols (exports)\n"
		" -S          Sections\n"
		" -z          Strings\n"
		" -I          Binary info\n"
		" -H          Header fields\n"
		" -o [str]    Write/Extract operations (str=help for help)\n"
		" -f [format] Override file format autodetection\n"
		" -r          radare output\n"
		" -v          Use vaddr in radare output\n"
		" -w          Open file in rw mode\n"
		" -L          List supported bin plugins\n"
		" -@ [addr]   Show section, symbol or import at addr\n"
		" -V          Show version information\n"
		" -h          This help\n");
	return R_TRUE;
}

static int rabin_show_entrypoints() {
	RFList entries;
	RBinEntry *entry;
	int i = 0;

	ut64 baddr = r_bin_get_baddr (bin);

	if ((entries = r_bin_get_entries (bin)) == NULL)
		return R_FALSE;

	if (rad) {
		printf ("fs symbols\n");
	} else printf ("[Entrypoints]\n");

	r_flist_foreach (entries, entry) {
		if (rad) {
			printf ("f entry%i @ 0x%08llx\n", i, va?baddr+entry->rva:entry->offset);
			printf ("s entry%i\n", i);
		} else printf ("address=0x%08llx offset=0x%08llx baddr=0x%08llx\n",
				baddr+entry->rva, entry->offset, baddr);
		i++;
	}

	if (!rad) printf("\n%i entrypoints\n", i);

	return R_TRUE;
}

static int rabin_show_imports(ut64 at) {
	RFList imports;
	RBinImport *import;
	ut64 baddr;
	int i = 0;

	baddr = r_bin_get_baddr (bin);

	if ((imports = r_bin_get_imports (bin)) == NULL)
		return R_FALSE;

	if (!at) {
		if (rad) printf ("fs imports\n");
		else printf ("[Imports]\n");
	}

	r_flist_foreach (imports, import) {
		if (at) {
			if (baddr+import->rva == at || import->offset == at)
				printf ("%s\n", import->name);
		} else {
			if (rad) {
				r_flag_name_filter (import->name);
				printf ("f imp.%s @ 0x%08llx\n",
						import->name, va?baddr+import->rva:import->offset);
			} else printf ("address=0x%08llx offset=0x%08llx ordinal=%03lli "
						   "hint=%03lli bind=%s type=%s name=%s\n",
						   baddr+import->rva, import->offset,
						   import->ordinal, import->hint,  import->bind,
						   import->type, import->name);
		}
		i++;
	}

	if (!at && !rad) printf ("\n%i imports\n", i);

	return R_TRUE;
}

static int rabin_show_symbols(ut64 at) {
	RFList symbols;
	RBinSymbol *symbol;
	ut64 baddr;
	int i = 0;

	baddr = r_bin_get_baddr (bin);

	if ((symbols = r_bin_get_symbols (bin)) == NULL)
		return R_FALSE;

	if (!at) {
		if (rad) printf ("fs symbols\n");
		else printf ("[Symbols]\n");
	}

	r_flist_foreach (symbols, symbol) {
		if (at) {
			if ((symbol->size != 0 &&
				((baddr+symbol->rva <= at && baddr+symbol->rva+symbol->size > at) ||
				(symbol->offset <= at && symbol->offset+symbol->size > at))) ||
				baddr+symbol->rva == at || symbol->offset == at)
				printf("%s\n", symbol->name);
		} else {
			if (rad) {
				r_flag_name_filter (symbol->name);
				if (symbol->size) {
					if (!strncmp (symbol->type,"FUNC", 4))
						printf ("CF %lli @ 0x%08llx\n",
								symbol->size, va?baddr+symbol->rva:symbol->offset);
					else if (!strncmp (symbol->type,"OBJECT", 6))
							printf ("Cd %lli @ 0x%08llx\n",
									symbol->size, va?baddr+symbol->rva:symbol->offset);
					printf ("f sym.%s %lli @ 0x%08llx\n",
							symbol->name, symbol->size,
							va?baddr+symbol->rva:symbol->offset);
				} else printf ("f sym.%s @ 0x%08llx\n",
							   symbol->name, va?baddr+symbol->rva:symbol->offset);
			} else printf ("address=0x%08llx offset=0x%08llx ordinal=%03lli "
						   "forwarder=%s size=%08lli bind=%s type=%s name=%s\n",
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
	RFList strings;
	RBinString *string;
	ut64 baddr;
	int i = 0;

	baddr = r_bin_get_baddr (bin);

	if ((strings = r_bin_get_strings (bin)) == NULL)
		return R_FALSE;

	if (rad) printf ("fs strings\n");
	else printf ("[strings]\n");

	r_flist_foreach (strings, string) {
		if (rad) {
			r_flag_name_filter (string->string);
			printf ("f str.%s %lli @ 0x%08llx\n"
					"Cs %lli @ 0x%08llx\n",
					string->string, string->size, va?baddr+string->rva:string->offset,
					string->size, va?baddr+string->rva:string->offset);
		} else printf ("address=0x%08llx offset=0x%08llx ordinal=%03lli "
					   "size=%08lli string=%s\n",
					   baddr+string->rva, string->offset,
					   string->ordinal, string->size, string->string);
		i++;
	}

	if (!rad) printf ("\n%i strings\n", i);
	
	return R_TRUE;
}

static int rabin_show_sections(ut64 at) {
	RFList sections;
	RBinSection *section;
	ut64 baddr;
	int i = 0;

	baddr = r_bin_get_baddr (bin);

	if ((sections = r_bin_get_sections (bin)) == NULL)
		return R_FALSE;

	if (!at) {
		if (rad) printf ("fs sections\n");
		else printf ("[Sections]\n");
	}

	r_flist_foreach (sections, section) {
		if (at) {
			if ((section->size != 0 &&
				((baddr+section->rva <= at && baddr+section->rva+section->size > at) ||
				(section->offset <= at && section->offset+section->size > at))) ||
				baddr+section->rva == at || section->offset == at)
				printf ("%s\n", section->name);
		} else {
			if (rad) {
				r_flag_name_filter (section->name);
				printf ("S 0x%08llx 0x%08llx 0x%08llx 0x%08llx %s\n",
						section->offset, baddr+section->rva,
						section->size, section->vsize, section->name);
				printf ("f section.%s %lli 0x%08llx\n",
						section->name, section->size, va?baddr+section->rva:section->offset);
				printf ("CC [%02i] address=0x%08llx offset=0x%08llx size=%08lli vsize=%08lli"
						"privileges=%c%c%c%c name=%s @ 0x%08llx\n",
						i, baddr+section->rva, section->offset, section->size, section->vsize,
						R_BIN_SCN_SHAREABLE (section->characteristics)?'s':'-',
						R_BIN_SCN_READABLE (section->characteristics)?'r':'-',
						R_BIN_SCN_WRITABLE (section->characteristics)?'w':'-',
						R_BIN_SCN_EXECUTABLE (section->characteristics)?'x':'-',
						section->name,va?baddr+section->rva:section->offset);
			} else printf ("idx=%02i address=0x%08llx offset=0x%08llx size=%08lli vsize=%08lli"
						   "privileges=%c%c%c%c name=%s\n",
						   i, baddr+section->rva, section->offset, section->size, section->vsize,
						   R_BIN_SCN_SHAREABLE (section->characteristics)?'s':'-',
						   R_BIN_SCN_READABLE (section->characteristics)?'r':'-',
						   R_BIN_SCN_WRITABLE (section->characteristics)?'w':'-',
						   R_BIN_SCN_EXECUTABLE (section->characteristics)?'x':'-',
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
				"e dbg.dwarf=%s\n",
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
				   "Relocs=%s\n",
				   info->file, info->type, info->bclass,
				   info->arch, info->bits, info->machine, info->os, 
				   info->subsystem, info->big_endian?"True":"False",
				   R_BIN_DBG_STRIPPED (info->dbg_info)?"True":"False",
				   R_BIN_DBG_STATIC (info->dbg_info)?"True":"False",
				   R_BIN_DBG_LINENUMS (info->dbg_info)?"True":"False",
				   R_BIN_DBG_SYMS (info->dbg_info)?"True":"False",
				   R_BIN_DBG_RELOCS (info->dbg_info)?"True":"False");
	
	return R_TRUE;
}

static int rabin_show_fields() {
	RFList fields;
	RBinField *field;
	ut64 baddr;
	int i = 0;

	baddr = r_bin_get_baddr (bin);

	if ((fields = r_bin_get_fields (bin)) == NULL)
		return R_FALSE;

	if (rad) printf ("fs header\n");
	else printf ("[Header fields]\n");

	r_flist_foreach (fields, field) {
		if (rad) {
			r_flag_name_filter (field->name);
			printf ("f header.%s @ 0x%08llx\n",
					field->name, va?baddr+field->rva:field->offset);
			printf ("[%02i] address=0x%08llx offset=0x%08llx name=%s\n",
					i, baddr+field->rva, field->offset, field->name);
		} else printf ("idx=%02i address=0x%08llx offset=0x%08llx name=%s\n",
					   i, baddr+field->rva, field->offset, field->name);
		i++;
	}

	if (!rad) printf ("\n%i fields\n", i);

	return R_TRUE;
}

static int rabin_dump_symbols(int len) {
	RFList symbols;
	RBinSymbol *symbol;
	ut8 *buf;
	char *ret;
	int olen = len;

	if ((symbols = r_bin_get_symbols (bin)) == NULL)
		return R_FALSE;

	r_flist_foreach (symbols, symbol) {
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

static int rabin_dump_sections(char *name) {
	RFList sections;
	RBinSection *section;
	ut8 *buf;
	char *ret;

	if ((sections = r_bin_get_sections (bin)) == NULL)
		return R_FALSE;

	r_flist_foreach (sections, section) {
		if (!strcmp (name, section->name)) {
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
				"  Dump section: d/S/.text\n");
		return R_FALSE;
	}
	arg = alloca (strlen(op)+1);
	strcpy (arg, op);

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
	default:
_rabin_do_operation_error:
		printf ("Unknown operation. use -o help\n");
		return R_FALSE;
	}

	return R_TRUE;
}

/* bin callback */
static int __lib_bin_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	struct r_bin_handle_t *hand = (struct r_bin_handle_t *)data;
	//printf(" * Added (dis)assembly handler\n");
	r_bin_add (bin, hand);
	return R_TRUE;
}

static int __lib_bin_dt(struct r_lib_plugin_t *pl, void *p, void *u) {
	return R_TRUE;
}

int main(int argc, char **argv)
{
	ut64 at = 0LL;
	int c;
	int action = ACTION_UNK;
	const char *format = NULL, *op = NULL;
	const char *plugin_name = NULL;

	bin = r_bin_new ();
	r_lib_init (&l, "radare_plugin");
	r_lib_add_handler (&l, R_LIB_TYPE_BIN, "bin plugins",
					   &__lib_bin_cb, &__lib_bin_dt, NULL);

	{ /* load plugins everywhere */
		char *homeplugindir = r_str_home (".radare/plugins");
		r_lib_opendir (&l, getenv ("LIBR_PLUGINS"));
		r_lib_opendir (&l, homeplugindir);
		r_lib_opendir (&l, LIBDIR"/radare2/");
	}

	while ((c = getopt (argc, argv, "@:VisSzIHewo:f:rvLh")) != -1)
	{
		switch(c) {
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
		case 'w':
			rw = R_TRUE;
			break;
		case 'o':
			op = optarg;
			action |= ACTION_OPERATION;
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
		case '@':
			at = r_num_math (NULL, optarg);
			break;
		case 'V':
			printf ("rabin2 v"VERSION"\n");
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
		ERR ("r_bin: Cannot open '%s'\n", file);
		return R_FALSE;
	}

	if (action&ACTION_SECTIONS)
		rabin_show_sections (at);
	if (action&ACTION_ENTRIES)
		rabin_show_entrypoints ();
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
	if (op != NULL && action&ACTION_OPERATION)
		rabin_do_operation (op);

	r_bin_free (bin);

	return R_FALSE;
}
