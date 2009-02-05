/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

/* TODO:
 * -l        Linked libraries
 * -L [lib]  dlopen library and show address
 * -z        Strings
 * -x        XRefs (-s/-i/-z required)
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <r_types.h>
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

static int verbose = 0;
static int rad = 0;

static int rabin_show_help()
{
	printf( "rabin2 [options] [file]\n"
			" -e        Entrypoint\n"
			" -i        Imports (symbols imported from libraries)\n"
			" -s        Symbols (exports)\n"
			" -S        Sections\n"
			" -I        Binary info\n"
			" -o [str]  Operation action (str=help for help)\n"
			" -r        Radare output\n"
			" -h        This help\n" );

	return 1;
}

static int rabin_show_entrypoint(const char *file)
{
	r_bin_obj bin;
	r_bin_entry *entry;
	u64 baddr;
	char *env;

	if (r_bin_init(&bin, file, 0) == -1) {
		fprintf(stderr, "Cannot open file\n");
		return 1;
	}

	baddr = r_bin_get_baddr(&bin);
	entry = r_bin_get_entry(&bin);

	if (rad) {
		env = getenv("DEBUG");
		if (env == NULL || (env && strncmp(env, "1", 1)))
			printf("e io.vaddr=0x%08llx\n", baddr);
		printf("fs symbols\n");
		printf("f entry @ 0x%08llx\n", baddr+entry->rva);
		printf("s entry\n");
	} else {
		printf("[Entrypoint]\n");
		printf("address=0x%08llx offset=0x%08llx baddr=0x%08llx\n",
				baddr+entry->rva, entry->offset, baddr);
	}

	r_bin_close(&bin);
	free(entry);

	return 0;
}

static int rabin_show_imports(const char *file)
{
	int ctr = 0;
	r_bin_obj bin;
	u64 baddr;
	char name[R_BIN_SIZEOF_NAMES];
	r_bin_import *imports, *importsp;

	if (r_bin_init(&bin, file, 0) == -1) {
		fprintf(stderr, "Cannot open file\n");
		return 1;
	}

	baddr = r_bin_get_baddr(&bin);

	imports = r_bin_get_imports(&bin);

	if (rad)
		printf("fs imports\n");
	else printf("[Imports]\n");

	importsp = imports;
	while (!importsp->last) {
		if (rad) {
			r_flag_name_filter(importsp->name);
			printf("f imp.%s @ 0x%08llx\n",
					importsp->name, baddr+importsp->rva);
		} else printf("address=0x%08llx offset=0x%08llx ordinal=%03i "
				"hint=%03i bind=%s type=%s name=%s\n",
				baddr+importsp->rva, importsp->offset,
				importsp->ordinal, importsp->hint,  importsp->bind,
				importsp->type, importsp->name);
		importsp++; ctr++;
	}

	if (!rad) printf("\n%i imports\n", ctr);

	r_bin_close(&bin);
	free(imports);

	return 0;
}

static int rabin_show_symbols(const char *file)
{
	int ctr = 0;
	r_bin_obj bin;
	u64 baddr;
	r_bin_symbol *symbols, *symbolsp;

	if (r_bin_init(&bin, file, 0) == -1) {
		fprintf(stderr, "Cannot open file\n");
		return 1;
	}

	baddr = r_bin_get_baddr(&bin);

	symbols = r_bin_get_symbols(&bin);

	if (rad) printf("fs symbols\n");
	else printf("[Symbols]\n");

	symbolsp = symbols;
	while (!symbolsp->last) {
		if (rad) {
			r_flag_name_filter(symbolsp->name);
			if (symbolsp->size) {
				if (!strncmp(symbolsp->type,"FUNC", 4))
					printf("CF %li @ 0x%08llx\n",
							symbolsp->size, baddr+symbolsp->rva);
				else
				if (!strncmp(symbolsp->type,"OBJECT", 6))
					printf("Cd %li @ 0x%08llx\n",
							symbolsp->size, baddr+symbolsp->rva);
				printf("b %li && ", symbolsp->size);
			}
			printf("f sym.%s @ 0x%08llx\n",
					symbolsp->name, baddr+symbolsp->rva);
		} else printf("address=0x%08llx offset=0x%08llx ordinal=%03i "
				"forwarder=%s size=%08i bind=%s type=%s name=%s\n",
				baddr+symbolsp->rva, symbolsp->offset,
				symbolsp->ordinal, symbolsp->forwarder,
				symbolsp->size, symbolsp->bind, symbolsp->type, 
				symbolsp->name);
		symbolsp++; ctr++;
	}

	if (!rad) printf("\n%i symbols\n", ctr);

	r_bin_close(&bin);
	free(symbols);

	return 0;
}

static int rabin_show_sections(const char *file)
{
	int ctr = 0;
	r_bin_obj bin;
	u64 baddr;
	r_bin_section *sections, *sectionsp;

	if (r_bin_init(&bin, file, 0) == -1) {
		fprintf(stderr, "Cannot open file\n");
		return 1;
	}

	baddr = r_bin_get_baddr(&bin);

	sections = r_bin_get_sections(&bin);
	
	if (rad) printf("fs sections\n");
	else printf("[Sections]\n");

	sectionsp = sections;
	while (!sectionsp->last) {
		if (rad) {
			r_flag_name_filter(sectionsp->name);
			printf("f section.%s @ 0x%08llx\n",
					sectionsp->name, baddr+sectionsp->rva);
			printf("f section.%s_end @ 0x%08llx\n",
					sectionsp->name, baddr+sectionsp->rva+sectionsp->size);
			printf("[%02i] address=0x%08llx offset=0x%08llx size=%08li "
					"privileges=%c%c%c%c name=%s\n",
					ctr, baddr+sectionsp->rva, sectionsp->offset, sectionsp->size,
					R_BIN_SCN_SHAREABLE(sectionsp->characteristics)?'s':'-',
					R_BIN_SCN_READABLE(sectionsp->characteristics)?'r':'-',
					R_BIN_SCN_WRITABLE(sectionsp->characteristics)?'w':'-',
					R_BIN_SCN_EXECUTABLE(sectionsp->characteristics)?'x':'-',
					sectionsp->name);
		} else printf("idx=%02i address=0x%08llx offset=0x%08llx size=%08li "
				"privileges=%c%c%c%c name=%s\n",
				ctr, baddr+sectionsp->rva, sectionsp->offset, sectionsp->size,
				R_BIN_SCN_SHAREABLE(sectionsp->characteristics)?'s':'-',
				R_BIN_SCN_READABLE(sectionsp->characteristics)?'r':'-',
				R_BIN_SCN_WRITABLE(sectionsp->characteristics)?'w':'-',
				R_BIN_SCN_EXECUTABLE(sectionsp->characteristics)?'x':'-',
				sectionsp->name);
		sectionsp++; ctr++;
	}

	if (!rad) printf("\n%i sections\n", ctr);

	r_bin_close(&bin);
	free(sections);

	return 0;

}

static int rabin_show_info(const char *file)
{
	r_bin_obj bin;
	r_bin_info *info;

	if (r_bin_init(&bin, file, 0) == -1) {
		fprintf(stderr, "Cannot open file\n");
		return 1;
	}

	info = r_bin_get_info(&bin);

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

	r_bin_close(&bin);
	free(info);

	return 0;
}

static int rabin_do_operation(const char *file, const char *op)
{
	r_bin_obj bin;
	char *arg, *ptr, *ptr2;

	if (!strcmp(op, "help")) {
		printf("Operation string:\n"
				"  Resize section: r/.data/1024 (ONLY ELF32)\n");
		return 1;
	}
	arg = alloca(strlen(op)+1);
	strcpy(arg, op);

	ptr = strchr(op, '/');
	if (!ptr) {
		printf("Unknown action. use -o help\n");
		return 1;
	}

	if (r_bin_init(&bin, file, 1) == -1) {
		fprintf(stderr, "cannot open file\n");
		return 1;
	}

	ptr = ptr+1;
	switch(arg[0]) {
	case 'r':
		ptr2 = strchr(ptr, '/');
		ptr2[0]='\0';

		if (r_bin_resize_section(&bin, ptr, r_num_math(NULL,ptr2+1)) == 0) {
			fprintf(stderr, "Delta = 0\n");
			return 1;
		}
	}

	r_bin_close(&bin);

	return 0;
}

int main(int argc, char **argv)
{
	int c;
	int action = ACTION_UNK;
	const char *file = NULL;
	const char *op = NULL;

	while ((c = getopt(argc, argv, "isSIeo:rvh")) != -1)
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
		case 'I':
			action |= ACTION_INFO;
			break;
		case 'e':
			action |= ACTION_ENTRY;
			break;
		case 'o':
			op = optarg;
			action |= ACTION_OPERATION;
			break;
		case 'r':
			rad = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'h':
		default:
			return rabin_show_help();
		}
	}
	
	file = argv[optind];

	if (action == ACTION_UNK)
		return rabin_show_help();
	else if (file == NULL)
		return rabin_show_help();

	if (action&ACTION_ENTRY)
		rabin_show_entrypoint(file);
	if (action&ACTION_IMPORTS)
		rabin_show_imports(file);
	if (action&ACTION_SYMBOLS)
		rabin_show_symbols(file);
	if (action&ACTION_SECTIONS)
		rabin_show_sections(file);
	if (action&ACTION_INFO)
		rabin_show_info(file);
	if (op != NULL && action&ACTION_OPERATION)
		rabin_do_operation(file, op);

	return 0;
}
