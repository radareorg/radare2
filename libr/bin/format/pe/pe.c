/* radare - LGPL - Copyright 2008-2014 nibble, pancake */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include "pe.h"

ut64 PE_(r_bin_pe_get_main_offset)(struct PE_(r_bin_pe_obj_t) *bin) {
	struct r_bin_pe_addr_t *entry = PE_(r_bin_pe_get_entrypoint) (bin);
	ut64 addr = 0;
	ut8 buf[512];

	// option2: /x 8bff558bec83ec20
	if (r_buf_read_at (bin->b, entry->offset, buf, sizeof (buf)) == -1) {
		eprintf ("Error: Cannot read entry at 0x%08"PFMT64x"\n", entry->offset);
	} else {
		if (buf[367] == 0xe8) {
			int delta = (buf[368] | buf[369]<<8 | buf[370]<<16 | buf[371]<<24);
			addr = entry->rva + 367 + 5 + delta;
		}
	}
	free (entry);
	return addr;
}

static PE_DWord PE_(r_bin_pe_rva_to_offset)(struct PE_(r_bin_pe_obj_t)* bin, PE_DWord rva) {
	PE_DWord section_base;
	int i, section_size;

	for (i = 0; i < bin->nt_headers->file_header.NumberOfSections; i++) {
		section_base = bin->section_header[i].VirtualAddress;
		section_size = bin->section_header[i].Misc.VirtualSize;
		if (rva >= section_base && rva < section_base + section_size)
			return bin->section_header[i].PointerToRawData + (rva - section_base);
	}
	return 0;
}

#if 0
static PE_DWord PE_(r_bin_pe_offset_to_rva)(struct PE_(r_bin_pe_obj_t)* bin, PE_DWord offset)
{
	PE_DWord section_base;
	int i, section_size;

	for (i = 0; i < bin->nt_headers->file_header.NumberOfSections; i++) {
		section_base = bin->section_header[i].PointerToRawData;
		section_size = bin->section_header[i].SizeOfRawData;
		if (offset >= section_base && offset < section_base + section_size)
			return bin->section_header[i].VirtualAddress + (offset - section_base);
	}
	return 0;
}
#endif

static int PE_(r_bin_pe_get_import_dirs_count)(struct PE_(r_bin_pe_obj_t) *bin) {
	PE_(image_data_directory) *data_dir_import = &bin->nt_headers->optional_header.DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_IMPORT];

	return (int)(data_dir_import->Size / sizeof(PE_(image_import_directory)) - 1);
}

static int PE_(r_bin_pe_get_delay_import_dirs_count)(struct PE_(r_bin_pe_obj_t) *bin) {
	PE_(image_data_directory) *data_dir_delay_import = \
		&bin->nt_headers->optional_header.DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

	return (int)(data_dir_delay_import->Size / sizeof(PE_(image_delay_import_directory)) - 1);
}

static int PE_(r_bin_pe_parse_imports)(struct PE_(r_bin_pe_obj_t)* bin, struct r_bin_pe_import_t** importp, int* nimp, char* dll_name, PE_DWord OriginalFirstThunk, PE_DWord FirstThunk) {
	char import_name[PE_NAME_LENGTH + 1], name[PE_NAME_LENGTH + 1];
	PE_Word import_hint, import_ordinal = 0;
	PE_DWord import_table = 0, off = 0;
	int i = 0;

	if ((off = PE_(r_bin_pe_rva_to_offset)(bin, OriginalFirstThunk)) == 0 &&
		(off = PE_(r_bin_pe_rva_to_offset)(bin, FirstThunk)) == 0)
		return 0;

	do {
		if (r_buf_read_at (bin->b, off + i * sizeof (PE_DWord),
				(ut8*)&import_table, sizeof (PE_DWord)) == -1) {
			eprintf("Error: read (import table)\n");
			return 0;
		}
		if (import_table) {
			if (import_table & ILT_MASK1) {
				import_ordinal = import_table & ILT_MASK2;
				import_hint = 0;
				snprintf(import_name, PE_NAME_LENGTH, "%s_Ordinal_%i", dll_name, import_ordinal);
			} else {
				import_ordinal ++;
				ut64 off = PE_(r_bin_pe_rva_to_offset)(bin, import_table);
				if (r_buf_read_at (bin->b, off, (ut8*)&import_hint, sizeof (PE_Word)) == -1) {
					eprintf ("Error: read import hint at 0x%08"PFMT64x"\n", off);
					return 0;
				}
				if (r_buf_read_at (bin->b, PE_(r_bin_pe_rva_to_offset)(bin, import_table) + sizeof(PE_Word),
							(ut8*)name, PE_NAME_LENGTH) == -1) {
					eprintf ("Error: read (import name)\n");
					return 0;
				}
				snprintf (import_name, PE_NAME_LENGTH, "%s_%s", dll_name, name);
			}
			if (!(*importp = realloc (*importp, (*nimp+1) * sizeof(struct r_bin_pe_import_t)))) {
				perror ("realloc (import)");
				return R_FALSE;
			}
			memcpy((*importp)[*nimp].name, import_name, PE_NAME_LENGTH);
			(*importp)[*nimp].name[PE_NAME_LENGTH] = '\0';
			(*importp)[*nimp].rva = FirstThunk + i * sizeof (PE_DWord);
			(*importp)[*nimp].offset = PE_(r_bin_pe_rva_to_offset)(bin, FirstThunk) + i * sizeof(PE_DWord);
			(*importp)[*nimp].hint = import_hint;
			(*importp)[*nimp].ordinal = import_ordinal;
			(*importp)[*nimp].last = 0;
			(*nimp)++; i++;
		}
	} while (import_table);
	return i;
}

static int PE_(r_bin_pe_init_hdr)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!(bin->dos_header = malloc(sizeof(PE_(image_dos_header))))) {
		perror ("malloc (dos header)");
		return R_FALSE;
	}
	if (r_buf_read_at (bin->b, 0, (ut8*)bin->dos_header, sizeof(PE_(image_dos_header))) == -1) {
		eprintf("Error: read (dos header)\n");
		return R_FALSE;
	}
	if (bin->dos_header->e_lfanew > bin->size) {
		eprintf("Invalid e_lfanew field\n");
		return R_FALSE;
	}
	if (!(bin->nt_headers = malloc(sizeof(PE_(image_nt_headers))))) {
		perror("malloc (nt header)");
		return R_FALSE;
	}
	if (r_buf_read_at (bin->b, bin->dos_header->e_lfanew,
				(ut8*)bin->nt_headers, sizeof(PE_(image_nt_headers))) == -1) {
		eprintf ("Error: read (dos header)\n");
		return R_FALSE;
	}
	if (strncmp ((char*)&bin->dos_header->e_magic, "MZ", 2) ||
		strncmp ((char*)&bin->nt_headers->Signature, "PE", 2))
		return R_FALSE;
	return R_TRUE;
}

typedef struct {
	ut64 shortname;
	ut32 value;
	ut16 secnum;
	ut16 symtype;
	ut8 symclass;
	ut8 numaux;
} SymbolRecord;

static struct r_bin_pe_export_t* parse_symbol_table(struct PE_(r_bin_pe_obj_t)* bin, struct r_bin_pe_export_t *exports, int sz) {
	ut64 baddr = (ut64)bin->nt_headers->optional_header.ImageBase;
	ut64 off = bin->nt_headers->file_header.PointerToSymbolTable;
	ut64 num = bin->nt_headers->file_header.NumberOfSymbols;
	const int srsz = 18; // symbol record size
	struct r_bin_pe_section_t* sections;
	struct r_bin_pe_export_t* exp;
	int bufsz = num * srsz;
	int I, i, shsz = bufsz;
	SymbolRecord *sr;
	ut64 text_off = 0LL;
	ut64 text_rva = 0LL;
	ut64 text = 0LL;
	int textn = 0;
	int exports_sz;
	int symctr = 0;
	char *buf = malloc (bufsz);

	if (!buf)
		return 0;
	exports_sz = sizeof (struct r_bin_pe_export_t)*num;
	if (exports) {
		int osz = sz;
		exports[sz].last = 0;
		sz += exports_sz;
		exports = realloc (exports, sz);
		if (!exports)
			return 0;
		exp =  (struct r_bin_pe_export_t*) (((const ut8*)exports) + osz);
	} else {
		sz = exports_sz;
		exports = malloc (sz);
		exp = exports;
	}

	sections = PE_(r_bin_pe_get_sections)(bin);
	for (i = 0; i < bin->nt_headers->file_header.NumberOfSections; i++) {
		if (!strcmp (sections[i].name, ".text")) {
			text_rva = sections[i].rva; // + baddr;
			text_off = sections[i].offset;
			textn = i +1;
		}
	}
#undef D
#define D if (0)
	text = text_rva; // text_off // TODO: io.va
	symctr = 0;
	if (r_buf_read_at (bin->b, off, buf, bufsz)) {
		for (I=0; I<shsz; I += srsz) {
			sr = (SymbolRecord *) (buf+I);
			//eprintf ("SECNUM %d\n", sr->secnum);
			if (sr->secnum == textn) {
				if (sr->symtype == 32) {
					char shortname[9];
					memcpy (shortname, &sr->shortname, 8);
					shortname[8] = 0;
					if (*shortname) {
						D printf ("0x%08"PFMT64x"  %s\n", text + sr->value, shortname);
						strncpy (exp[symctr].name, shortname, PE_NAME_LENGTH-1);
					} else {
						char *longname, name[128];
						ut32 *idx = (ut32 *) (buf+I+4)	;
						if (r_buf_read_at (bin->b, off+ *idx+shsz, name, 128)) {
							longname = name;
							D printf ("0x%08"PFMT64x"  %s\n", text + sr->value, longname);
							strncpy (exp[symctr].name, longname, PE_NAME_LENGTH-1);
						} else {
							D printf ("0x%08"PFMT64x"  unk_%d\n", text + sr->value, I/srsz);
							sprintf (exp[symctr].name, "unk_%d", symctr);
						}
					}
					exp[symctr].name[PE_NAME_LENGTH] = 0;
					exp[symctr].rva = text_rva+sr->value;
					exp[symctr].offset = text_off+sr->value;
					exp[symctr].ordinal = symctr;
					exp[symctr].forwarder[0] = 0;
					exp[symctr].last = 0;
					symctr ++;
				}
			}
		} // for
	} // if read ok
	exp[symctr].last = 1;
	free (buf);
	return exports;
}

static int PE_(r_bin_pe_init_sections)(struct PE_(r_bin_pe_obj_t)* bin) {
	int sections_size = sizeof (PE_(image_section_header)) *
		bin->nt_headers->file_header.NumberOfSections;
	if (sections_size > bin->size) {
		eprintf ("Invalid NumberOfSections value\n");
		return R_FALSE;
	}
	if (!(bin->section_header = malloc (sections_size))) {
		perror ("malloc (section header)");
		return R_FALSE;
	}
	if (r_buf_read_at (bin->b, bin->dos_header->e_lfanew + 4 + sizeof (PE_(image_file_header)) +
				bin->nt_headers->file_header.SizeOfOptionalHeader,
				(ut8*)bin->section_header, sections_size) == -1) {
		eprintf ("Error: read (import directory)\n");
		return R_FALSE;
	}
#if 0
Each symbol table entry includes a name, storage class, type, value and section number. Short names (8 characters or fewer) are stored directly in the symbol table; longer names are stored as an offset into the string table at the end of the COFF object.

================================================================
COFF SYMBOL TABLE RECORDS (18 BYTES)
================================================================
record
offset

struct symrec {
	union {
		char string[8]; // short name
		struct {
			ut32 seros;
			ut32 stridx;
		} stridx;
	} name;
	ut32 value;
	ut16 secnum;
	ut16 symtype;
	ut8 symclass;
	ut8 numaux;
}
       -------------------------------------------------------
   0  |                  8-char symbol name                   |
      |          or 32-bit zeroes followed by 32-bit          |
      |                 index into string table               |
       -------------------------------------------------------
   8  |                     symbol value                      |
       -------------------------------------------------------
  0Ch |       section number      |         symbol type       |
       -------------------------------------------------------
  10h |  sym class  |   num aux   |
       ---------------------------
  12h

#endif
	return R_TRUE;
}

static int PE_(r_bin_pe_init_imports)(struct PE_(r_bin_pe_obj_t) *bin) {
	PE_(image_data_directory) *data_dir_import = \
		&bin->nt_headers->optional_header.DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_IMPORT];
	PE_(image_data_directory) *data_dir_delay_import = \
		&bin->nt_headers->optional_header.DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	PE_DWord import_dir_offset = PE_(r_bin_pe_rva_to_offset)(bin, data_dir_import->VirtualAddress);
	PE_DWord delay_import_dir_offset = PE_(r_bin_pe_rva_to_offset)(bin, data_dir_delay_import->VirtualAddress);
	int import_dir_size = data_dir_import->Size;
	int delay_import_dir_size = data_dir_delay_import->Size;

	if (import_dir_offset == 0 && delay_import_dir_offset == 0)
		return R_FALSE;
	if (import_dir_offset != 0) {
		if (import_dir_size>0xffff) {
			eprintf ("Warning: Invalid import directory size: 0x%x\n", import_dir_size);
			import_dir_size = 0xffff;
		}
		if (!(bin->import_directory = malloc(import_dir_size))) {
			perror("malloc (import directory)");
			return R_FALSE;
		}
		if (r_buf_read_at (bin->b, import_dir_offset, (ut8*)bin->import_directory, import_dir_size) == -1) {
			eprintf("Error: read (import directory)\n");
			return R_FALSE;
		}
	}
	if (delay_import_dir_offset != 0) {
		if (!(bin->delay_import_directory = malloc(delay_import_dir_size))) {
			perror("malloc (delay import directory)");
			return R_FALSE;
		}
		if (r_buf_read_at (bin->b, delay_import_dir_offset,
				(ut8*)bin->delay_import_directory, delay_import_dir_size) == -1) {
			eprintf ("Error: read (delay import directory)\n");
			return R_FALSE;
		}
	}
	return R_TRUE;
}

static int PE_(r_bin_pe_init_exports)(struct PE_(r_bin_pe_obj_t) *bin) {
	PE_(image_data_directory) *data_dir_export = \
		&bin->nt_headers->optional_header.DataDirectory \
		[PE_IMAGE_DIRECTORY_ENTRY_EXPORT];
	PE_DWord export_dir_offset = PE_(r_bin_pe_rva_to_offset)
		(bin, data_dir_export->VirtualAddress);
#if 0
	// STAB PARSER
	int i;
	{
	ut8 *stab = NULL;
	int stab_sz = 0;
	ut8 *stabst = NULL;
	int n, stabst_sz = 0;

	struct r_bin_pe_section_t* sections = PE_(r_bin_pe_get_sections)(bin);
	for (i = 0; i < bin->nt_headers->file_header.NumberOfSections; i++) {
		if (!strcmp (sections[i].name, ".stab")) {
			stab = malloc ( ( stab_sz = sections[i].size ) );
			r_buf_read_at (bin->b, sections[i].offset, stab, stab_sz);
		}
		if (!strcmp (sections[i].name, ".stabst")) {
			stabst_sz = sections[i].size;
			eprintf ("Stab String Table found\n");
			stabst = malloc (sections[i].size);
			r_buf_read_at (bin->b, sections[i].offset, stabst, stabst_sz);
		}
	}
	if (stab && stabst) {
		__attribute__ ((packed))
		struct stab_item {
#if R_BIN_PE64
			ut64 n_strx; /* index into string table of name */
#else
			ut32 n_strx; /* index into string table of name */
#endif
			ut8 n_type;         /* type of symbol */
			ut8 n_other;        /* misc info (usually empty) */
			ut16 n_desc;        /* description field */
#if R_BIN_PE64
			ut64 n_value;    /* value of symbol (bfd_vma) */
#else
			ut32 n_value;    /* value of symbol (bfd_vma) */
#endif
		};
eprintf ("SIZE IS %d\n", sizeof (struct stab_item));
		ut8 *p = stab;
		struct stab_item *si = p;
#if 0
	struct internal_nlist {
		ut32 n_strx; /* index into string table of name */
		ut8 n_type;         /* type of symbol */
		ut8 n_other;        /* misc info (usually empty) */
		ut16 n_desc;        /* description field */
		ut32 n_value;    /* value of symbol (bfd_vma) */
	};
#endif
n = 0;
i = 0;
#define getstring(x) (x<stabst_sz)?stabst+x:"???"
		while (i<stab_sz) {
	//		printf ("%d vs %d\n", i, stab_sz);
			if (si->n_strx>0) {
switch (si->n_type) {
	case 0x80: // LSYM
		if (si->n_desc>0 && si->n_value) {
			eprintf ("MAIN SYMBOL %d %d %d %s\n",
				si->n_strx,
				si->n_desc,
				si->n_value,
				getstring (si->n_strx+si->n_desc));
		}
		break;
}
if (si->n_type == 0x64) {
printf ("SYMBOL 0x%x = %d (%s)\n", (ut32)si->n_value, (int)si->n_strx,
				getstring (si->n_strx)
);
}
#if 1
				printf ("%d stridx = 0x%x\n", n, si->n_strx);
				printf ("%d string = %s\n", n, getstring (si->n_strx));
				printf ("%d desc   = %d (%s)\n", n, si->n_desc, getstring (si->n_desc));
				printf ("%d type   = 0x%x\n", n, si->n_type);
				printf ("%d value  = 0x%llx\n", n, (ut64)si->n_value);
#endif
			}
			//i += 12; //sizeof (struct stab_item);
			i += sizeof (struct stab_item);
			si = stab + i;
			n++;
		}

		// TODO  : iterate over all stab elements
	} else {
		// you failed //
	}
	free (stab);
	free (stabst);
	free (sections);
	}
#endif

	if (export_dir_offset == 0) {
		// This export-dir-offset should only appear in DLL files
		//eprintf ("Warning: Cannot find the offset of the export directory\n");
		return R_FALSE;
	}
	//sdb_setn (DB, "hdr.exports_directory", export_dir_offset);
//eprintf ("Pexports offset at 0x%"PFMT64x"\n", export_dir_offset);
	if (!(bin->export_directory = malloc(sizeof(PE_(image_export_directory))))) {
		perror ("malloc (export directory)");
		return R_FALSE;
	}
	if (r_buf_read_at (bin->b, export_dir_offset, (ut8*)bin->export_directory,
			sizeof (PE_(image_export_directory))) == -1) {
		eprintf ("Error: read (export directory)\n");
		return R_FALSE;
	}
	return R_TRUE;
}

static int PE_(r_bin_pe_init)(struct PE_(r_bin_pe_obj_t)* bin) {
	bin->dos_header = NULL;
	bin->nt_headers = NULL;
	bin->section_header = NULL;
	bin->export_directory = NULL;
	bin->import_directory = NULL;
	bin->delay_import_directory = NULL;
	bin->endian = 0; /* TODO: get endian */
	if (!PE_(r_bin_pe_init_hdr)(bin)) {
		eprintf ("Warning: File is not PE\n");
		return R_FALSE;
	}
	if (!PE_(r_bin_pe_init_sections)(bin)) {
		eprintf ("Warning: Cannot initialize sections\n");
		return R_FALSE;
	}
	PE_(r_bin_pe_init_imports)(bin);
	PE_(r_bin_pe_init_exports)(bin);
	bin->relocs = NULL;
	return R_TRUE;
}

char* PE_(r_bin_pe_get_arch)(struct PE_(r_bin_pe_obj_t)* bin) {
	char *arch;
	switch (bin->nt_headers->file_header.Machine) {
	case PE_IMAGE_FILE_MACHINE_ALPHA:
	case PE_IMAGE_FILE_MACHINE_ALPHA64:
		arch = strdup("alpha");
		break;
	case PE_IMAGE_FILE_MACHINE_ARM:
	case PE_IMAGE_FILE_MACHINE_THUMB:
		arch = strdup("arm");
		break;
	case PE_IMAGE_FILE_MACHINE_M68K:
		arch = strdup("m68k");
		break;
	case PE_IMAGE_FILE_MACHINE_MIPS16:
	case PE_IMAGE_FILE_MACHINE_MIPSFPU:
	case PE_IMAGE_FILE_MACHINE_MIPSFPU16:
	case PE_IMAGE_FILE_MACHINE_WCEMIPSV2:
		arch = strdup("mips");
		break;
	case PE_IMAGE_FILE_MACHINE_POWERPC:
	case PE_IMAGE_FILE_MACHINE_POWERPCFP:
		arch = strdup("ppc");
		break;
	case PE_IMAGE_FILE_MACHINE_EBC:
		arch = strdup("ebc");
		break;
	default:
		arch = strdup("x86");
	}
	return arch;
}

struct r_bin_pe_addr_t* PE_(r_bin_pe_get_entrypoint)(struct PE_(r_bin_pe_obj_t)* bin) {
	struct r_bin_pe_addr_t *entry = NULL;
	if ((entry = malloc(sizeof(struct r_bin_pe_addr_t))) == NULL) {
		perror("malloc (entrypoint)");
		return NULL;
	}
	entry->rva = bin->nt_headers->optional_header.AddressOfEntryPoint;
	if (entry->rva == 0) // in PE if EP = 0 then EP = baddr
		entry->rva = bin->nt_headers->optional_header.ImageBase;
	entry->offset = PE_(r_bin_pe_rva_to_offset)(bin, entry->rva);
	return entry;
}

struct r_bin_pe_export_t* PE_(r_bin_pe_get_exports)(struct PE_(r_bin_pe_obj_t)* bin) {
	struct r_bin_pe_export_t *exports = NULL;
	PE_Word function_ordinal;
	PE_VWord functions_offset, names_offset, ordinals_offset, function_rva, name_rva, name_offset;
	char function_name[PE_NAME_LENGTH + 1], forwarder_name[PE_NAME_LENGTH + 1];
	char dll_name[PE_NAME_LENGTH + 1], export_name[PE_NAME_LENGTH + 1];
	PE_(image_data_directory) *data_dir_export = \
		&bin->nt_headers->optional_header.DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_EXPORT];
	PE_VWord export_dir_rva = data_dir_export->VirtualAddress;
	int i, export_dir_size = data_dir_export->Size;
	int exports_sz = 0;

	if (bin->export_directory) {
		exports_sz = (bin->export_directory->NumberOfNames + 1) * sizeof(struct r_bin_pe_export_t);
		if (!(exports = malloc (exports_sz)))
			return NULL;
		if (r_buf_read_at (bin->b, PE_(r_bin_pe_rva_to_offset)(bin, bin->export_directory->Name),
				(ut8*)dll_name, PE_NAME_LENGTH) == -1) {
			eprintf ("Error: read (dll name)\n");
			return NULL;
		}
		functions_offset = PE_(r_bin_pe_rva_to_offset)(bin, bin->export_directory->AddressOfFunctions);
		names_offset = PE_(r_bin_pe_rva_to_offset)(bin, bin->export_directory->AddressOfNames);
		ordinals_offset = PE_(r_bin_pe_rva_to_offset)(bin, bin->export_directory->AddressOfOrdinals);
		for (i = 0; i < bin->export_directory->NumberOfNames; i++) {
			if (r_buf_read_at (bin->b, names_offset + i * sizeof (PE_VWord), (ut8*)&name_rva,
					sizeof (PE_VWord)) == -1) {
				eprintf ("Error: read (name rva)\n");
				return NULL;
			}
			if (r_buf_read_at (bin->b, ordinals_offset + i * sizeof(PE_Word), (ut8*)&function_ordinal,
					sizeof (PE_Word)) == -1) {
				eprintf ("Error: read (function ordinal)\n");
				return NULL;
			}
			if (r_buf_read_at (bin->b, functions_offset + function_ordinal * sizeof(PE_VWord),
					(ut8*)&function_rva, sizeof(PE_VWord)) == -1) {
				eprintf ("Error: read (function rva)\n");
				return NULL;
			}
			name_offset = PE_(r_bin_pe_rva_to_offset)(bin, name_rva);
			if (name_offset) {
				if (r_buf_read_at(bin->b, name_offset, (ut8*)function_name, PE_NAME_LENGTH) == -1) {
					eprintf("Error: read (function name)\n");
					return NULL;
				}
			} else {
				snprintf (function_name, PE_NAME_LENGTH, "Ordinal_%i", function_ordinal);
			}
			snprintf(export_name, PE_NAME_LENGTH, "%s_%s", dll_name, function_name);
			if (function_rva >= export_dir_rva && function_rva < (export_dir_rva + export_dir_size)) {
				if (r_buf_read_at (bin->b, PE_(r_bin_pe_rva_to_offset)(bin, function_rva),
						(ut8*)forwarder_name, PE_NAME_LENGTH) == -1) {
					eprintf ("Error: read (magic)\n");
					return NULL;
				}
			} else {
				snprintf (forwarder_name, PE_NAME_LENGTH, "NONE");
			}
			exports[i].rva = function_rva;
			exports[i].offset = PE_(r_bin_pe_rva_to_offset)(bin, function_rva);
			exports[i].ordinal = function_ordinal;
			memcpy (exports[i].forwarder, forwarder_name, PE_NAME_LENGTH);
			exports[i].forwarder[PE_NAME_LENGTH] = '\0';
			memcpy (exports[i].name, export_name, PE_NAME_LENGTH);
			exports[i].name[PE_NAME_LENGTH] = '\0';
			exports[i].last = 0;
		}
		exports[i].last = 1;
	}
	return parse_symbol_table (bin, exports, exports_sz);
}

int PE_(r_bin_pe_get_file_alignment)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->optional_header.FileAlignment;
}

ut64 PE_(r_bin_pe_get_image_base)(struct PE_(r_bin_pe_obj_t)* bin) {
	return (ut64)bin->nt_headers->optional_header.ImageBase;
}

struct r_bin_pe_import_t* PE_(r_bin_pe_get_imports)(struct PE_(r_bin_pe_obj_t) *bin) {
	struct r_bin_pe_import_t *imps, *imports = NULL;
	char dll_name[PE_NAME_LENGTH + 1];
	int import_dirs_count = PE_(r_bin_pe_get_import_dirs_count)(bin);
	int delay_import_dirs_count = PE_(r_bin_pe_get_delay_import_dirs_count)(bin);
	int i, nimp = 0;

	if (bin->import_directory)
	for (i = 0; i < import_dirs_count; i++) {
		if (r_buf_read_at(bin->b, PE_(r_bin_pe_rva_to_offset)(bin, bin->import_directory[i].Name),
					(ut8*)dll_name, PE_NAME_LENGTH) == -1) {
			eprintf("Error: read (magic)\n");
			return NULL;
		}
		if (!PE_(r_bin_pe_parse_imports)(bin, &imports, &nimp, dll_name,
					bin->import_directory[i].Characteristics, bin->import_directory[i].FirstThunk))
			break;
	}
	if (bin->delay_import_directory)
	for (i = 0; i < delay_import_dirs_count; i++) {
		if (r_buf_read_at(bin->b, PE_(r_bin_pe_rva_to_offset)(bin, bin->delay_import_directory[i].Name),
					(ut8*)dll_name, PE_NAME_LENGTH) == -1) {
			eprintf ("Error: read (magic)\n");
			return NULL;
		}
		if (!PE_(r_bin_pe_parse_imports)(bin, &imports, &nimp, dll_name,
					bin->delay_import_directory[i].DelayImportNameTable, bin->delay_import_directory[i].DelayImportAddressTable))
			break;
	}
	if (nimp) {
		imps = realloc (imports, (nimp+1) * sizeof(struct r_bin_pe_import_t));
		if (!imps) {
			perror ("realloc (import)");
			return NULL;
		}
		imports = imps;
		imports[nimp].last = 1;
	}
	return imports;
}

struct r_bin_pe_lib_t* PE_(r_bin_pe_get_libs)(struct PE_(r_bin_pe_obj_t) *bin) {
	struct r_bin_pe_lib_t *libs = NULL;
	int import_dirs_count = PE_(r_bin_pe_get_import_dirs_count)(bin);
	int delay_import_dirs_count = PE_(r_bin_pe_get_delay_import_dirs_count)(bin);
	int mallocsz, i, j = 0;

	/* NOTE: import_dirs and delay_import_dirs can be -1 */
	mallocsz = (import_dirs_count + delay_import_dirs_count + 3) * sizeof (struct r_bin_pe_lib_t);
	libs = malloc (mallocsz);
	if (!libs) {
		perror ("malloc (libs)");
		return NULL;
	}
	if (bin->import_directory) {
		for (i = j = 0; i < import_dirs_count; i++, j++) {
			if (r_buf_read_at(bin->b, PE_(r_bin_pe_rva_to_offset)(bin, bin->import_directory[i].Name),
					(ut8*)libs[j].name, PE_STRING_LENGTH) == -1) {
				eprintf("Error: read (libs - import dirs)\n");
				return NULL;
			}
			if (PE_(r_bin_pe_rva_to_offset)(bin, bin->import_directory[i].Characteristics) == 0 &&
				PE_(r_bin_pe_rva_to_offset)(bin, bin->import_directory[i].FirstThunk) == 0)
				break;
		}
		for (i = 0; i < delay_import_dirs_count; i++, j++) {
			if (!bin->delay_import_directory)
				break;
			if (r_buf_read_at (bin->b, PE_(r_bin_pe_rva_to_offset)(bin, bin->delay_import_directory[i].Name),
					(ut8*)libs[j].name, PE_STRING_LENGTH) == -1) {
				eprintf("Error: read (libs - delay import dirs)\n");
				return NULL;
			}
			if (PE_(r_bin_pe_rva_to_offset)(bin, bin->delay_import_directory[i].DelayImportNameTable) == 0 &&
				PE_(r_bin_pe_rva_to_offset)(bin, bin->delay_import_directory[i].DelayImportAddressTable) == 0)
				break;
		}
	}
	for (i = 0; i < j; i++) {
		libs[i].name[PE_STRING_LENGTH-1] = '\0';
		libs[i].last = 0;
	}
	libs[i].last = 1;
	return libs;
}

int PE_(r_bin_pe_get_image_size)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->optional_header.SizeOfImage;
}

// TODO: make it const! like in elf
char* PE_(r_bin_pe_get_machine)(struct PE_(r_bin_pe_obj_t)* bin) {
	char *machine;

	switch (bin->nt_headers->file_header.Machine) {
	case PE_IMAGE_FILE_MACHINE_ALPHA:
		machine = strdup("Alpha");
		break;
	case PE_IMAGE_FILE_MACHINE_ALPHA64:
		machine = strdup("Alpha 64");
		break;
	case PE_IMAGE_FILE_MACHINE_AM33:
		machine = strdup("AM33");
		break;
	case PE_IMAGE_FILE_MACHINE_AMD64:
		machine = strdup("AMD 64");
		break;
	case PE_IMAGE_FILE_MACHINE_ARM:
		machine = strdup("ARM");
		break;
	case PE_IMAGE_FILE_MACHINE_CEE:
		machine = strdup("CEE");
		break;
	case PE_IMAGE_FILE_MACHINE_CEF:
		machine = strdup("CEF");
		break;
	case PE_IMAGE_FILE_MACHINE_EBC:
		machine = strdup("EBC");
		break;
	case PE_IMAGE_FILE_MACHINE_I386:
		machine = strdup("i386");
		break;
	case PE_IMAGE_FILE_MACHINE_IA64:
		machine = strdup("ia64");
		break;
	case PE_IMAGE_FILE_MACHINE_M32R:
		machine = strdup("M32R");
		break;
	case PE_IMAGE_FILE_MACHINE_M68K:
		machine = strdup("M68K");
		break;
	case PE_IMAGE_FILE_MACHINE_MIPS16:
		machine = strdup("Mips 16");
		break;
	case PE_IMAGE_FILE_MACHINE_MIPSFPU:
		machine = strdup("Mips FPU");
		break;
	case PE_IMAGE_FILE_MACHINE_MIPSFPU16:
		machine = strdup("Mips FPU 16");
		break;
	case PE_IMAGE_FILE_MACHINE_POWERPC:
		machine = strdup("PowerPC");
		break;
	case PE_IMAGE_FILE_MACHINE_POWERPCFP:
		machine = strdup("PowerPC FP");
		break;
	case PE_IMAGE_FILE_MACHINE_R10000:
		machine = strdup("R10000");
		break;
	case PE_IMAGE_FILE_MACHINE_R3000:
		machine = strdup("R3000");
		break;
	case PE_IMAGE_FILE_MACHINE_R4000:
		machine = strdup("R4000");
		break;
	case PE_IMAGE_FILE_MACHINE_SH3:
		machine = strdup("SH3");
		break;
	case PE_IMAGE_FILE_MACHINE_SH3DSP:
		machine = strdup("SH3DSP");
		break;
	case PE_IMAGE_FILE_MACHINE_SH3E:
		machine = strdup("SH3E");
		break;
	case PE_IMAGE_FILE_MACHINE_SH4:
		machine = strdup("SH4");
		break;
	case PE_IMAGE_FILE_MACHINE_SH5:
		machine = strdup("SH5");
		break;
	case PE_IMAGE_FILE_MACHINE_THUMB:
		machine = strdup("Thumb");
		break;
	case PE_IMAGE_FILE_MACHINE_TRICORE:
		machine = strdup("Tricore");
		break;
	case PE_IMAGE_FILE_MACHINE_WCEMIPSV2:
		machine = strdup("WCE Mips V2");
		break;
	default:
		machine = strdup("unknown");
	}
	return machine;
}

// TODO: make it const! like in elf
char* PE_(r_bin_pe_get_os)(struct PE_(r_bin_pe_obj_t)* bin) {
	char *os;

	switch (bin->nt_headers->optional_header.Subsystem) {
	case PE_IMAGE_SUBSYSTEM_NATIVE:
		os = strdup("native");
		break;
	case PE_IMAGE_SUBSYSTEM_WINDOWS_GUI:
	case PE_IMAGE_SUBSYSTEM_WINDOWS_CUI:
	case PE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		os = strdup ("windows");
		break;
	case PE_IMAGE_SUBSYSTEM_POSIX_CUI:
		os = strdup ("posix");
		break;
	case PE_IMAGE_SUBSYSTEM_EFI_APPLICATION:
	case PE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
	case PE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
	case PE_IMAGE_SUBSYSTEM_EFI_ROM:
		os = strdup ("efi");
		break;
	case PE_IMAGE_SUBSYSTEM_XBOX:
		os = strdup ("xbox");
		break;
	default:
		// XXX: this is unknown
		os = strdup ("windows");
	}
	return os;
}

// TODO: make it const
char* PE_(r_bin_pe_get_class)(struct PE_(r_bin_pe_obj_t)* bin) {
	char *class;

	switch (bin->nt_headers->optional_header.Magic) {
	case PE_IMAGE_FILE_TYPE_PE32:
		class = strdup("PE32");
		break;
	case PE_IMAGE_FILE_TYPE_PE32PLUS:
		class = strdup("PE32+");
		break;
	default:
		class = strdup("Unknown");
	}
	return class;
}

int PE_(r_bin_pe_get_bits)(struct PE_(r_bin_pe_obj_t)* bin) {
	int bits;

	switch (bin->nt_headers->optional_header.Magic) {
	case PE_IMAGE_FILE_TYPE_PE32:
		bits = 32;
		break;
	case PE_IMAGE_FILE_TYPE_PE32PLUS:
		bits = 64;
		break;
	default:
		bits = -1;
	}
	return bits;
}

int PE_(r_bin_pe_get_section_alignment)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->optional_header.SectionAlignment;
}

struct r_bin_pe_section_t* PE_(r_bin_pe_get_sections)(struct PE_(r_bin_pe_obj_t)* bin) {
	struct r_bin_pe_section_t *sections = NULL;
	PE_(image_section_header) *shdr = bin->section_header;
	int i, sections_count = bin->nt_headers->file_header.NumberOfSections;

	if ((sections = malloc ((sections_count + 1) * sizeof (struct r_bin_pe_section_t))) == NULL) {
		perror ("malloc (sections)");
		return NULL;
	}
	for (i = 0; i < sections_count; i++) {
		memcpy (sections[i].name, shdr[i].Name, PE_IMAGE_SIZEOF_SHORT_NAME);
		sections[i].name[PE_IMAGE_SIZEOF_SHORT_NAME-1] = '\0';
		sections[i].rva = shdr[i].VirtualAddress;
		sections[i].size = shdr[i].SizeOfRawData;
		sections[i].vsize = shdr[i].Misc.VirtualSize;
		sections[i].offset = shdr[i].PointerToRawData;
		sections[i].flags = shdr[i].Characteristics;
		sections[i].last = 0;
	}
	sections[i].last = 1;
	return sections;
}

char* PE_(r_bin_pe_get_subsystem)(struct PE_(r_bin_pe_obj_t)* bin) {
	char *subsystem;

	switch (bin->nt_headers->optional_header.Subsystem) {
	case PE_IMAGE_SUBSYSTEM_NATIVE:
		subsystem = strdup("Native");
		break;
	case PE_IMAGE_SUBSYSTEM_WINDOWS_GUI:
		subsystem = strdup("Windows GUI");
		break;
	case PE_IMAGE_SUBSYSTEM_WINDOWS_CUI:
		subsystem = strdup("Windows CUI");
		break;
	case PE_IMAGE_SUBSYSTEM_POSIX_CUI:
		subsystem = strdup("POSIX CUI");
		break;
	case PE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		subsystem = strdup("Windows CE GUI");
		break;
	case PE_IMAGE_SUBSYSTEM_EFI_APPLICATION:
		subsystem = strdup("EFI Application");
		break;
	case PE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		subsystem = strdup("EFI Boot Service Driver");
		break;
	case PE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		subsystem = strdup("EFI Runtime Driver");
		break;
	case PE_IMAGE_SUBSYSTEM_EFI_ROM:
		subsystem = strdup("EFI ROM");
		break;
	case PE_IMAGE_SUBSYSTEM_XBOX:
		subsystem = strdup("XBOX");
		break;
	default:
		subsystem = strdup("Unknown");
	}
	return subsystem;
}

int PE_(r_bin_pe_is_dll)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->file_header.Characteristics & PE_IMAGE_FILE_DLL;
}

int PE_(r_bin_pe_is_pie)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->optional_header.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
#if 0
	BOOL aslr = inh->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
//TODO : implement dep?
	BOOL dep = inh->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
#endif
}

int PE_(r_bin_pe_is_big_endian)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->file_header.Characteristics & PE_IMAGE_FILE_BYTES_REVERSED_HI;
}

int PE_(r_bin_pe_is_stripped_relocs)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->file_header.Characteristics & PE_IMAGE_FILE_RELOCS_STRIPPED;
}

int PE_(r_bin_pe_is_stripped_line_nums)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->file_header.Characteristics & PE_IMAGE_FILE_LINE_NUMS_STRIPPED;
}

int PE_(r_bin_pe_is_stripped_local_syms)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->file_header.Characteristics & PE_IMAGE_FILE_LOCAL_SYMS_STRIPPED;
}

int PE_(r_bin_pe_is_stripped_debug)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->file_header.Characteristics & PE_IMAGE_FILE_DEBUG_STRIPPED;
}

void* PE_(r_bin_pe_free)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin) return NULL;
	free (bin->dos_header);
	free (bin->nt_headers);
	free (bin->section_header);
	free (bin->export_directory);
	free (bin->import_directory);
	free (bin->delay_import_directory);
	r_buf_free (bin->b);
	bin->b = NULL;
	free (bin);
	return NULL;
}

struct PE_(r_bin_pe_obj_t)* PE_(r_bin_pe_new)(const char* file) {
	ut8 *buf;
	struct PE_(r_bin_pe_obj_t) *bin = R_NEW0 (struct PE_(r_bin_pe_obj_t));
	if (!bin) return NULL;
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp(file, &bin->size)))
		return PE_(r_bin_pe_free)(bin);
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf, bin->size)) {
		free (buf);
		return PE_(r_bin_pe_free)(bin);
	}
	free (buf);
	if (!PE_(r_bin_pe_init)(bin))
		return PE_(r_bin_pe_free)(bin);
	return bin;
}

struct PE_(r_bin_pe_obj_t)* PE_(r_bin_pe_new_buf)(struct r_buf_t *buf) {
	struct PE_(r_bin_pe_obj_t) *bin = R_NEW0 (struct PE_(r_bin_pe_obj_t));
	if (!bin) return NULL;
	bin->b = r_buf_new ();
	bin->size = buf->length;
	if (!r_buf_set_bytes (bin->b, buf->buf, bin->size)){
		return PE_(r_bin_pe_free)(bin);
	}
	if (!PE_(r_bin_pe_init)(bin))
		return PE_(r_bin_pe_free)(bin);
	return bin;
}
