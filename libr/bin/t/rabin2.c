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
#define ACTION_ENTRY     0x0001 
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
static struct r_bin_obj_t *binobj;
static int verbose = 0;
static int rad = R_FALSE;
static int rw = R_FALSE;
static char* file;

static int rabin_show_help() {
	printf( "rabin2 [options] [file]\n"
		" -e          Entrypoint\n"
		" -i          Imports (symbols imported from libraries)\n"
		" -s          Symbols (exports)\n"
		" -S          Sections\n"
		" -z          Strings\n"
		" -I          Binary info\n"
		" -H          Header fields\n"
		" -o [str]    Write/Extract operations (str=help for help)\n"
		" -f [format] Override file format autodetection\n"
		" -r          Radare output\n"
		" -w          Open file in rw mode\n"
		" -L          List supported bin plugins\n"
		" -@ [addr]   Show section, symbol or import at addr\n"
		" -V          Show version information\n"
		" -h          This help\n");
	return R_TRUE;
}

static int rabin_show_entrypoint() {
	struct r_bin_entry_t *entry;
	const char *env;
	ut64 baddr = r_bin_get_baddr (bin);
	if ((entry = r_bin_get_entry (bin)) == NULL)
		return R_FALSE;
	if (rad) {
		env = r_sys_getenv ("DEBUG");
		if (env == NULL || (env && strncmp (env, "1", 1)))
			printf ("e io.vaddr=0x%08llx\n", baddr);
		printf ("fs symbols\n");
		printf ("f entry @ 0x%08llx\n", baddr+entry->rva);
		printf ("s entry\n");
	} else {
		printf ("[Entrypoint]\n");
		printf ("address=0x%08llx offset=0x%08llx baddr=0x%08llx\n",
			baddr+entry->rva, entry->offset, baddr);
	}
	free (entry);
	return R_TRUE;
}

static int rabin_show_imports(ut64 at) {
	struct r_bin_import_t *imports;
	ut64 baddr;
	int i;

	baddr = r_bin_get_baddr(bin);

	if ((imports = r_bin_get_imports(bin)) == NULL)
		return R_FALSE;

	if (!at) {
		if (rad) printf("fs imports\n");
		else printf("[Imports]\n");
	}

	 for (i = 0; !imports[i].last; i++) {
		 if (at) {
			 if (baddr+imports[i].rva == at || imports[i].offset == at)
				 printf("%s\n", imports[i].name);
		 } else {
			 if (rad) {
				 r_flag_name_filter(imports[i].name);
				 printf("f imp.%s @ 0x%08llx\n",
						 imports[i].name, baddr+imports[i].rva);
			 } else printf("address=0x%08llx offset=0x%08llx ordinal=%03lli "
					 "hint=%03lli bind=%s type=%s name=%s\n",
					 baddr+imports[i].rva, imports[i].offset,
					 imports[i].ordinal, imports[i].hint,  imports[i].bind,
					 imports[i].type, imports[i].name);
		 }
	 }

	if (!at && !rad) printf("\n%i imports\n", i);

	free(imports);
	return R_TRUE;
}

static int rabin_show_symbols(ut64 at) {
	struct r_bin_symbol_t *symbols;
	ut64 baddr;
	int i;

	baddr = r_bin_get_baddr(bin);

	if ((symbols = r_bin_get_symbols(bin)) == NULL)
		return R_FALSE;

	if (!at) {
		if (rad) printf("fs symbols\n");
		else printf("[Symbols]\n");
	}

	for (i = 0; !symbols[i].last; i++) {
		if (at) {
			if ((symbols[i].size != 0 &&
				((baddr+symbols[i].rva <= at && baddr+symbols[i].rva+symbols[i].size > at) ||
				(symbols[i].offset <= at && symbols[i].offset+symbols[i].size > at))) ||
			 	baddr+symbols[i].rva == at || symbols[i].offset == at)
				printf("%s\n", symbols[i].name);
		} else {
			if (rad) {
				r_flag_name_filter(symbols[i].name);
				if (symbols[i].size) {
					if (!strncmp(symbols[i].type,"FUNC", 4))
						printf("CF %lli @ 0x%08llx\n",
								symbols[i].size, baddr+symbols[i].rva);
					else
						if (!strncmp(symbols[i].type,"OBJECT", 6))
							printf("Cd %lli @ 0x%08llx\n",
									symbols[i].size, baddr+symbols[i].rva);
					printf("f sym.%s %lli @ 0x%08llx\n",
							symbols[i].name, symbols[i].size,
							baddr+symbols[i].rva);
				} else printf("f sym.%s @ 0x%08llx\n",
						symbols[i].name, baddr+symbols[i].rva);
			} else printf("address=0x%08llx offset=0x%08llx ordinal=%03lli "
					"korwarder=%s size=%08lli bind=%s type=%s name=%s\n",
					baddr+symbols[i].rva, symbols[i].offset,
					symbols[i].ordinal, symbols[i].forwarder,
					symbols[i].size, symbols[i].bind, symbols[i].type, 
					symbols[i].name);
		}
	}

	if (!at && !rad) printf("\n%i symbols\n", i);

	free(symbols);

	return R_TRUE;
}

static int rabin_show_strings() {
	struct r_bin_string_t *strings;
	ut64 baddr;
	int i;

	baddr = r_bin_get_baddr(bin);

	if ((strings = r_bin_get_strings(bin)) == NULL)
		return R_FALSE;

	if (rad) printf("fs strings\n");
	else printf("[strings]\n");

	for (i = 0; !strings[i].last; i++) {
		if (rad) {
			r_flag_name_filter(strings[i].string);
			printf( "f str.%s %lli @ 0x%08llx\n"
					"Cs %lli @ 0x%08llx\n",
					strings[i].string, strings[i].size, baddr+strings[i].rva,
					strings[i].size, baddr+strings[i].rva);
		} else printf("address=0x%08llx offset=0x%08llx ordinal=%03lli "
				"size=%08lli string=%s\n",
				baddr+strings[i].rva, strings[i].offset,
				strings[i].ordinal, strings[i].size, strings[i].string);
	}

	if (!rad) printf("\n%i strings\n", i);
	free(strings);

	return R_TRUE;
}

static int rabin_show_sections(ut64 at) {
	struct r_bin_section_t *sections;
	ut64 baddr;
	int i;

	baddr = r_bin_get_baddr(bin);

	if ((sections = r_bin_get_sections(bin)) == NULL)
		return R_FALSE;
	
	if (!at) {
		if (rad) printf("fs sections\n");
		else printf("[Sections]\n");
	}

	for (i = 0; !sections[i].last; i++) {
		if (at) {
			if ((sections[i].size != 0 &&
				((baddr+sections[i].rva <= at && baddr+sections[i].rva+sections[i].size > at) ||
				(sections[i].offset <= at && sections[i].offset+sections[i].size > at))) ||
			 	baddr+sections[i].rva == at || sections[i].offset == at)
				printf("%s\n", sections[i].name);
		} else {
			if (rad) {
				r_flag_name_filter(sections[i].name);
				printf("f section.%s @ 0x%08llx\n",
						sections[i].name, baddr+sections[i].rva);
				printf("f section.%s_end @ 0x%08llx\n",
						sections[i].name, baddr+sections[i].rva+sections[i].size);
				printf("[%02i] address=0x%08llx offset=0x%08llx size=%08lli "
						"privileges=%c%c%c%c name=%s\n",
						i, baddr+sections[i].rva, sections[i].offset, sections[i].size,
						R_BIN_SCN_SHAREABLE(sections[i].characteristics)?'s':'-',
						R_BIN_SCN_READABLE(sections[i].characteristics)?'r':'-',
						R_BIN_SCN_WRITABLE(sections[i].characteristics)?'w':'-',
						R_BIN_SCN_EXECUTABLE(sections[i].characteristics)?'x':'-',
						sections[i].name);
			} else printf("idx=%02i address=0x%08llx offset=0x%08llx size=%08lli "
					"privileges=%c%c%c%c name=%s\n",
					i, baddr+sections[i].rva, sections[i].offset, sections[i].size,
					R_BIN_SCN_SHAREABLE(sections[i].characteristics)?'s':'-',
					R_BIN_SCN_READABLE(sections[i].characteristics)?'r':'-',
					R_BIN_SCN_WRITABLE(sections[i].characteristics)?'w':'-',
					R_BIN_SCN_EXECUTABLE(sections[i].characteristics)?'x':'-',
					sections[i].name);
		}
	}

	if (!at && !rad) printf("\n%i sections\n", i);
	free(sections);
	return R_TRUE;
}

static int rabin_show_info() {
	struct r_bin_info_t *info;

	if ((info = r_bin_get_info(bin)) == NULL)
		return R_FALSE;

	if (rad) {
		printf("e file.type=%s\n"
			"e cfg.bigendian=%s\n"
			"e asm.os=%s\n"
			"e asm.arch=%s\n"
			"e dbg.dwarf=%s\n",
			info->rclass, info->big_endian?"True":"False", info->os, info->arch,
			R_BIN_DBG_STRIPPED(info->dbg_info)?"False":"True");
	} else printf("[File info]\n"
			"Type=%s\n"
			"Class=%s\n"
			"Arch=%s\n"
			"Machine=%s\n"
			"OS=%s\n"
			"Subsystem=%s\n"
			"Big endian=%s\n"
			"Stripped=%s\n"
			"Static=%s\n"
			"Line_nums=%s\n"
			"Local_syms=%s\n"
			"Relocs=%s\n",
			info->type, info->class, info->arch, info->machine, info->os, 
			info->subsystem, info->big_endian?"True":"False",
			R_BIN_DBG_STRIPPED(info->dbg_info)?"True":"False",
			R_BIN_DBG_STATIC(info->dbg_info)?"True":"False",
			R_BIN_DBG_LINENUMS(info->dbg_info)?"True":"False",
			R_BIN_DBG_SYMS(info->dbg_info)?"True":"False",
			R_BIN_DBG_RELOCS(info->dbg_info)?"True":"False");
	free(info);
	return R_TRUE;
}

static int rabin_show_fields() {
	struct r_bin_field_t *fields;
	ut64 baddr;
	int i;

	baddr = r_bin_get_baddr(bin);

	if ((fields = r_bin_get_fields(bin)) == NULL)
		return R_FALSE;
	
	if (rad) printf("fs header\n");
	else printf("[Header fields]\n");

	for (i = 0; !fields[i].last; i++) {
		if (rad) {
			r_flag_name_filter(fields[i].name);
			printf("f header.%s @ 0x%08llx\n",
					fields[i].name, baddr+fields[i].rva);
			printf("[%02i] address=0x%08llx offset=0x%08llx name=%s\n",
					i, baddr+fields[i].rva, fields[i].offset, fields[i].name);
		} else printf("idx=%02i address=0x%08llx offset=0x%08llx name=%s\n",
				i, baddr+fields[i].rva, fields[i].offset, fields[i].name);
	}

	if (!rad) printf("\n%i fields\n", i);
	free(fields);
	return R_TRUE;
}

static int rabin_dump_symbols(int len) {
	struct r_bin_symbol_t *symbols;
	ut8 *buf;
	char *ret;
	int olen = len, i;

	if ((symbols = r_bin_get_symbols(bin)) == NULL)
		return R_FALSE;

	for (i = 0; !symbols[i].last; i++) {
		if (symbols[i].size != 0 && (olen > symbols[i].size || olen == 0))
			len = symbols[i].size;
		else if (symbols[i].size == 0 && olen == 0)
			len = 32;
		else len = olen;

		if (!(buf = malloc(len)) ||
			!(ret = malloc(len*2+1)))
		return R_FALSE;
		r_buf_read_at(bin->buf, symbols[i].offset, buf, len);
		r_hex_bin2str(buf, len, ret);
		printf("%s %s\n", symbols[i].name, ret);
		free(buf);
		free(ret);
	}

	free(symbols);
	return R_TRUE;
}

static int rabin_dump_sections(char *name) {
	struct r_bin_section_t *sections;
	ut8 *buf;
	char *ret;
	int i;

	if ((sections = r_bin_get_sections(bin)) == NULL)
		return R_FALSE;

	for (i = 0; !sections[i].last; i++)
		if (!strcmp(name, sections[i].name)) {
			if (!(buf = malloc(sections[i].size)) ||
				!(ret = malloc(sections[i].size*2+1)))
				return R_FALSE;
			r_buf_read_at(bin->buf, sections[i].offset, buf, sections[i].size);
			r_hex_bin2str(buf, sections[i].size, ret);
			printf("%s\n", ret);
			free(buf);
			free(ret);
			break;
		}

	free(sections);
	return R_TRUE;
}

static int rabin_do_operation(const char *op) {
	char *arg = NULL, *ptr = NULL, *ptr2 = NULL;

	if (!strcmp(op, "help")) {
		printf( "Operation string:\n"
			"  Dump symbols: d/s/1024\n"
			"  Dump section: d/S/.text\n");
		return R_FALSE;
	}
	arg = alloca(strlen(op)+1);
	strcpy(arg, op);

	if ((ptr = strchr(arg, '/'))) {
		ptr[0] = '\0';
		ptr = ptr + 1;
		if ((ptr2 = strchr(ptr, '/'))) {
			ptr2[0] = '\0';
			ptr2 = ptr2 + 1;
		}
	}

	switch(arg[0]) {
	case 'd':
		if (!ptr)
			goto _rabin_do_operation_error;
		if (ptr[0]=='s') {
			if (ptr2) {
				if (!rabin_dump_symbols(r_num_math(NULL, ptr2)))
					return R_FALSE;
			} else 
				if (!rabin_dump_symbols(0))
					return R_FALSE;
		} else if (ptr[0]=='S') {
			if (!ptr2)
				goto _rabin_do_operation_error;
			if (!rabin_dump_sections(ptr2))
				return R_FALSE;
		} else goto _rabin_do_operation_error;
		break;
	default:
	_rabin_do_operation_error:
		printf("Unknown operation. use -o help\n");
		return R_FALSE;
	}

	return R_TRUE;
}

/* bin callback */
static int __lib_bin_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	struct r_bin_handle_t *hand = (struct r_bin_handle_t *)data;
	//printf(" * Added (dis)assembly handler\n");
	r_bin_add(bin, hand);
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

	bin = r_bin_new();
	r_lib_init(&l, "radare_plugin");
	r_lib_add_handler(&l, R_LIB_TYPE_BIN, "bin plugins",
		&__lib_bin_cb, &__lib_bin_dt, NULL);

	{ /* load plugins everywhere */
		char *homeplugindir = r_str_home(".radare/plugins");
		r_lib_opendir(&l, getenv("LIBR_PLUGINS"));
		r_lib_opendir(&l, homeplugindir);
		r_lib_opendir(&l, LIBDIR"/radare2/");
	}

	while ((c = getopt(argc, argv, "@:VisSzIHewo:f:rvLh")) != -1)
	{
		switch( c ) {
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
			action |= ACTION_ENTRY;
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
			verbose++;
			break;
		case 'L':
			r_bin_list(bin);
			exit(1);
		case '@':
			at = r_num_math(NULL, optarg);
			break;
		case 'V':
			printf("rabin2 v"VERSION"\n");
			return 0;
		case 'h':
		default:
			action |= ACTION_HELP;
		}
	}

	file = argv[optind];
	if (action == ACTION_HELP || action == ACTION_UNK || file == NULL)
		return rabin_show_help();

	if (format)
		plugin_name = format;

	if (!(binobj = r_bin_load(bin, file, plugin_name)) &&
		!(binobj = r_bin_load(bin, file, "dummy"))) {
		ERR("r_bin: Cannot open '%s'\n", file);
		return R_FALSE;
	}

	if (action&ACTION_ENTRY)
		rabin_show_entrypoint();
	if (action&ACTION_IMPORTS)
		rabin_show_imports(at);
	if (action&ACTION_SYMBOLS)
		rabin_show_symbols(at);
	if (action&ACTION_SECTIONS)
		rabin_show_sections(at);
	if (action&ACTION_STRINGS)
		rabin_show_strings();
	if (action&ACTION_INFO)
		rabin_show_info();
	if (action&ACTION_FIELDS)
		rabin_show_fields();
	if (op != NULL && action&ACTION_OPERATION)
		rabin_do_operation(op);

	r_bin_free_obj(binobj);
	r_bin_free(bin);
	return R_FALSE;
}
