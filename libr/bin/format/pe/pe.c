/* radare - LGPL - Copyright 2008-2014 nibble, pancake, inisider */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include "pe.h"

struct SCV_NB10_HEADER;
typedef struct {
	ut8 signature[4];
	ut32 offset;
	ut32 timestamp;
	ut32 age;
	ut8 *file_name;
	void (*free)(struct SCV_NB10_HEADER *cv_nb10_header);
} SCV_NB10_HEADER;

typedef struct {
	ut32 data1;
	ut16 data2;
	ut16 data3;
	ut8 data4[8];
} SGUID;

struct SCV_RSDS_HEADER;
typedef struct {
	ut8 signature[4];
	SGUID guid;
	ut32 age;
	ut8 *file_name;

	void (*free)(struct SCV_RSDS_HEADER *rsds_hdr);
} SCV_RSDS_HEADER;

struct r_bin_pe_addr_t *PE_(r_bin_pe_get_main_vaddr)(struct PE_(r_bin_pe_obj_t) *bin) {
	struct r_bin_pe_addr_t *entry;
	ut8 b[512];

	if (!bin || !bin->b)
		return 0LL;

	entry = PE_(r_bin_pe_get_entrypoint) (bin);

	// option2: /x 8bff558bec83ec20
	b[367] = 0;
	if (r_buf_read_at (bin->b, entry->paddr, b, sizeof (b)) < 0) {
		eprintf ("Error: Cannot read entry at 0x%08"PFMT64x"\n",
			entry->paddr);
		free (entry);
		return NULL;
	}

	/* Decode the jmp instruction, this gets the address of the 'main'
	 * function for PE produced by a compiler whose name someone forgot to
	 * write down. */ 
	if (b[367] == 0xe8) {
		const ut32 jmp_dst = b[368] | (b[369]<<8) | (b[370]<<16) | (b[371]<<24);
		entry->paddr += 367 + 5 + jmp_dst;
		entry->vaddr += 367 + 5 + jmp_dst;
	}

	return entry;
}

#define RBinPEObj struct PE_(r_bin_pe_obj_t)
static PE_DWord PE_(r_bin_pe_vaddr_to_paddr)(RBinPEObj* bin, PE_DWord vaddr) {
	PE_DWord section_base;
	int i, section_size;

	for (i = 0; i < bin->nt_headers->file_header.NumberOfSections; i++) {
		section_base = bin->section_header[i].VirtualAddress;
		section_size = bin->section_header[i].Misc.VirtualSize;
		if (vaddr >= section_base && vaddr < section_base + section_size)
			return bin->section_header[i].PointerToRawData \
				+ (vaddr - section_base);
	}
	return vaddr;
}

#if 0
static PE_DWord PE_(r_bin_pe_paddr_to_vaddr)(struct PE_(r_bin_pe_obj_t)* bin, PE_DWord paddr)
{
	PE_DWord section_base;
	int i, section_size;

	for (i = 0; i < bin->nt_headers->file_header.NumberOfSections; i++) {
		section_base = bin->section_header[i].PointerToRawData;
		section_size = bin->section_header[i].SizeOfRawData;
		if (paddr >= section_base && paddr < section_base + section_size)
			return bin->section_header[i].VirtualAddress + (paddr - section_base);
	}
	return 0;
}

static int PE_(r_bin_pe_get_import_dirs_count)(struct PE_(r_bin_pe_obj_t) *bin) {
	if (!bin || !bin->nt_headers)
		return 0;
	PE_(image_data_directory) *data_dir_import = \
		&bin->nt_headers->optional_header.DataDirectory[\
			PE_IMAGE_DIRECTORY_ENTRY_IMPORT];
	return (int)(data_dir_import->Size / sizeof(PE_(image_import_directory)) - 1);
}

static int PE_(r_bin_pe_get_delay_import_dirs_count)(struct PE_(r_bin_pe_obj_t) *bin) {
	PE_(image_data_directory) *data_dir_delay_import;
	if (!bin || !bin->nt_headers)
		return 0;
	data_dir_delay_import = \
		&bin->nt_headers->optional_header.DataDirectory[\
		PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	return (int)(data_dir_delay_import->Size / \
		sizeof(PE_(image_delay_import_directory)) - 1);
}
#endif

static char *resolveModuleOrdinal (Sdb *sdb, const char *module, int ordinal) {
#if 0
	char res[128], *foo;
	Sdb *db = sdb_ns_path (sdb, "bin/pe", 0);
	if (!db) return NULL;
	db = sdb_ns (db, module, 0);
	if (!db) return NULL;
#endif
	Sdb *db = sdb;
	char *foo = sdb_get (db, sdb_fmt (0, "%d", ordinal), 0);
	if (foo && *foo) {
		return foo;
	} else free (foo); // should never happen
	return NULL;
}

static int PE_(r_bin_pe_parse_imports)(struct PE_(r_bin_pe_obj_t)* bin, struct r_bin_pe_import_t** importp, int* nimp, char* dll_name, PE_DWord OriginalFirstThunk, PE_DWord FirstThunk) {
	char import_name[PE_NAME_LENGTH + 1], name[PE_NAME_LENGTH + 1];
	PE_Word import_hint, import_ordinal = 0;
	PE_DWord import_table = 0, off = 0;
	int i = 0;
	Sdb *db = NULL;
	char *sdb_module = NULL;
	char *symname;
	char *filename;
	char *symdllname;
	if ((off = PE_(r_bin_pe_vaddr_to_paddr)(bin, OriginalFirstThunk)) == 0 &&
		(off = PE_(r_bin_pe_vaddr_to_paddr)(bin, FirstThunk)) == 0)
		return 0;

	do {
		if (import_ordinal >= UT16_MAX) {
			break;
		}
		if (r_buf_read_at (bin->b, off + i * sizeof (PE_DWord),
				(ut8*)&import_table, sizeof (PE_DWord)) == -1) {
			eprintf("Error: read (import table)\n");
			return 0;
		}
		if (import_table) {
			if (import_table & ILT_MASK1) {
				import_ordinal = import_table & ILT_MASK2;
				import_hint = 0;
				snprintf (import_name, PE_NAME_LENGTH, "qq%s_Ordinal_%i", dll_name, import_ordinal);
				//
				symdllname=strdup(dll_name);
				// rip ".dll"
				symdllname[strlen(symdllname)-4]=0;
				if (!sdb_module || strcmp (symdllname, sdb_module)) {
							sdb_free (db);
							db = NULL;
							free (sdb_module);
							sdb_module = strdup (symdllname);
							filename = sdb_fmt (1, "%s.sdb", symdllname);
							if (r_file_exists (filename)) {
								db = sdb_new (NULL, filename, 0);
							} else {
#if __WINDOWS__
								filename = sdb_fmt (1, "share/radare2/"R2_VERSION"/format/dll/%s.sdb", symdllname);
#else
								filename = sdb_fmt (1, R2_PREFIX"/share/radare2/" R2_VERSION"/format/dll/%s.sdb", symdllname);
#endif
								if (r_file_exists (filename)) {
									db = sdb_new (NULL, filename, 0);
								}
							}
						}
						if (db) {
							// ordinal-1 because we enumerate starting at 0
							symname = resolveModuleOrdinal (db, symdllname, import_ordinal-1);
							if (symname) {
								snprintf (import_name, 
									PE_NAME_LENGTH,
									"%s_%s", dll_name, symname);
							}
						}
			} else {
				import_ordinal ++;
				ut64 off = PE_(r_bin_pe_vaddr_to_paddr)(bin, import_table);
				if (r_buf_read_at (bin->b, off, (ut8*)&import_hint, sizeof (PE_Word)) == -1) {
					eprintf ("Error: read import hint at 0x%08"PFMT64x"\n", off);
					return 0;
				}
				name[0] = 0;
				if (r_buf_read_at (bin->b, PE_(r_bin_pe_vaddr_to_paddr)(bin, import_table) + sizeof(PE_Word),
							(ut8*)name, PE_NAME_LENGTH) == -1) {
					eprintf ("Error: read (import name)\n");
					return 0;
				}
				if (!*name)
					break;
				snprintf (import_name, PE_NAME_LENGTH, "%s_%s", dll_name, name);
			}
			if (!(*importp = realloc (*importp, (*nimp+1) * sizeof(struct r_bin_pe_import_t)))) {
				r_sys_perror ("realloc (import)");
				return R_FALSE;
			}
			memcpy((*importp)[*nimp].name, import_name, PE_NAME_LENGTH);
			(*importp)[*nimp].name[PE_NAME_LENGTH] = '\0';
			(*importp)[*nimp].vaddr = FirstThunk + i * sizeof (PE_DWord);
			(*importp)[*nimp].paddr = PE_(r_bin_pe_vaddr_to_paddr)(bin, FirstThunk) + i * sizeof(PE_DWord);
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
		r_sys_perror ("malloc (dos header)");
		return R_FALSE;
	}
	if (r_buf_read_at (bin->b, 0, (ut8*)bin->dos_header, sizeof(PE_(image_dos_header))) == -1) {
		eprintf("Error: read (dos header)\n");
		return R_FALSE;
	}
	sdb_num_set (bin->kv, "pe_dos_header.offset", 0, 0);
	sdb_set (bin->kv, "pe_dos_header.format", "[2]zwwwwwwwwwwwww[4]www[10]wx"
			" e_magic e_cblp e_cp e_crlc e_cparhdr e_minalloc e_maxalloc"
			" e_ss e_sp e_csum e_ip e_cs e_lfarlc e_ovno e_res e_oemid"
			" e_oeminfo e_res2 e_lfanew", 0);
	if (bin->dos_header->e_lfanew > bin->size) {
		eprintf("Invalid e_lfanew field\n");
		return R_FALSE;
	}
	if (!(bin->nt_headers = malloc (sizeof (PE_(image_nt_headers))))) {
		r_sys_perror("malloc (nt header)");
		return R_FALSE;
	}
	bin->nt_header_offset = bin->dos_header->e_lfanew;
	if (r_buf_read_at (bin->b, bin->dos_header->e_lfanew,
			(ut8*)bin->nt_headers, sizeof (PE_(image_nt_headers))) == -1) {
		eprintf ("Error: read (dos header)\n");
		return R_FALSE;
	}
	sdb_set (bin->kv, "pe_magic.cparse", "enum pe_magic { IMAGE_NT_OPTIONAL_HDR32_MAGIC=0x10b, IMAGE_NT_OPTIONAL_HDR64_MAGIC=0x20b, IMAGE_ROM_OPTIONAL_HDR_MAGIC=0x107 };", 0);
	sdb_set (bin->kv, "pe_subsystem.cparse", "enum pe_subsystem { IMAGE_SUBSYSTEM_UNKNOWN=0, IMAGE_SUBSYSTEM_NATIVE=1, IMAGE_SUBSYSTEM_WINDOWS_GUI=2, "
					  " IMAGE_SUBSYSTEM_WINDOWS_CUI=3, IMAGE_SUBSYSTEM_OS2_CUI=5, IMAGE_SUBSYSTEM_POSIX_CUI=7, IMAGE_SUBSYSTEM_WINDOWS_CE_GUI=9, "
					  " IMAGE_SUBSYSTEM_EFI_APPLICATION=10, IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER=11, IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER=12, "
					  " IMAGE_SUBSYSTEM_EFI_ROM=13, IMAGE_SUBSYSTEM_XBOX=14, IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION=16 };", 0);
	sdb_set (bin->kv, "pe_dllcharacteristics.cparse", "enum pe_dllcharacteristics { IMAGE_LIBRARY_PROCESS_INIT=0x0001, IMAGE_LIBRARY_PROCESS_TERM=0x0002, "
					  " IMAGE_LIBRARY_THREAD_INIT=0x0004, IMAGE_LIBRARY_THREAD_TERM=0x0008, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA=0x0020, "
					  " IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE=0x0040, IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY=0x0080, "
					  " IMAGE_DLLCHARACTERISTICS_NX_COMPAT=0x0100, IMAGE_DLLCHARACTERISTICS_NO_ISOLATION=0x0200,IMAGE_DLLCHARACTERISTICS_NO_SEH=0x0400, "
					  " IMAGE_DLLCHARACTERISTICS_NO_BIND=0x0800, IMAGE_DLLCHARACTERISTICS_APPCONTAINER=0x1000, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER=0x2000, "
					  " IMAGE_DLLCHARACTERISTICS_GUARD_CF=0x4000, IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE=0x8000};", 0);
	#if R_BIN_PE64
	sdb_num_set (bin->kv, "pe_nt_image_headers64.offset", bin->dos_header->e_lfanew, 0);
	sdb_set (bin->kv, "pe_nt_image_headers64.format", "[4]z?? signature (pe_image_file_header)fileHeader (pe_image_optional_header64)optionalHeader", 0);
	sdb_set (bin->kv, "pe_image_optional_header64.format", "[2]Ebbxxxxxqxxwwwwwwxxxx[2]E[2]Bqqqqxx[16]?"
					  " (pe_magic)magic majorLinkerVersion minorLinkerVersion sizeOfCode sizeOfInitializedData"
					  " sizeOfUninitializedData addressOfEntryPoint baseOfCode imageBase"
					  " sectionAlignment fileAlignment majorOperatingSystemVersion minorOperatingSystemVersion"
					  " majorImageVersion minorImageVersion majorSubsystemVersion minorSubsystemVersion"
					  " win32VersionValue sizeOfImage sizeOfHeaders checkSum (pe_subsystem)subsystem (pe_dllcharacteristics)dllCharacteristics"
					  " sizeOfStackReserve sizeOfStackCommit sizeOfHeapReserve sizeOfHeapCommit loaderFlags"
					  " numberOfRvaAndSizes (pe_image_data_directory)dataDirectory", 0);
	#else
	sdb_num_set (bin->kv, "pe_nt_image_headers32.offset", bin->dos_header->e_lfanew, 0);
	sdb_set (bin->kv, "pe_nt_image_headers32.format", "[4]z?? signature (pe_image_file_header)fileHeader (pe_image_optional_header32)optionalHeader", 0);
	sdb_set (bin->kv, "pe_image_optional_header32.format", "[2]Ebbxxxxxxxxxwwwwwwxxxx[2]E[2]Bxxxxxx[16]?"
					  " (pe_magic)magic majorLinkerVersion minorLinkerVersion sizeOfCode sizeOfInitializedData"
					  " sizeOfUninitializedData addressOfEntryPoint baseOfCode baseOfData imageBase"
					  " sectionAlignment fileAlignment majorOperatingSystemVersion minorOperatingSystemVersion"
					  " majorImageVersion minorImageVersion majorSubsystemVersion minorSubsystemVersion"
					  " win32VersionValue sizeOfImage sizeOfHeaders checkSum (pe_subsystem)subsystem (pe_dllcharacteristics)dllCharacteristics"
					  " sizeOfStackReserve sizeOfStackCommit sizeOfHeapReserve sizeOfHeapCommit loaderFlags numberOfRvaAndSizes"
					  " (pe_image_data_directory)dataDirectory", 0);
	#endif
	sdb_set (bin->kv, "pe_machine.cparse", "enum pe_machine { IMAGE_FILE_MACHINE_I386=0x014c, IMAGE_FILE_MACHINE_IA64=0x0200, IMAGE_FILE_MACHINE_AMD64=0x8664 };", 0);
	sdb_set (bin->kv, "pe_characteristics.cparse", "enum pe_characteristics { "
					  " IMAGE_FILE_RELOCS_STRIPPED=0x0001, IMAGE_FILE_EXECUTABLE_IMAGE=0x0002, IMAGE_FILE_LINE_NUMS_STRIPPED=0x0004, "
					  " IMAGE_FILE_LOCAL_SYMS_STRIPPED=0x0008, IMAGE_FILE_AGGRESIVE_WS_TRIM=0x0010, IMAGE_FILE_LARGE_ADDRESS_AWARE=0x0020, "
					  " IMAGE_FILE_BYTES_REVERSED_LO=0x0080, IMAGE_FILE_32BIT_MACHINE=0x0100, IMAGE_FILE_DEBUG_STRIPPED=0x0200, "
					  " IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP=0x0400, IMAGE_FILE_NET_RUN_FROM_SWAP=0x0800, IMAGE_FILE_SYSTEM=0x1000, "
					  " IMAGE_FILE_DLL=0x2000, IMAGE_FILE_UP_SYSTEM_ONLY=0x4000, IMAGE_FILE_BYTES_REVERSED_HI=0x8000 };", 0);
	sdb_set (bin->kv, "pe_image_file_header.format", "[2]Ewtxxw[2]B"
					  " (pe_machine)machine numberOfSections timeDateStamp pointerToSymbolTable"
					  " numberOfSymbols sizeOfOptionalHeader (pe_characteristics)characteristics", 0);
	sdb_set (bin->kv, "pe_image_data_directory.format", "xx virtualAddress size",0);
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
	//ut64 baddr = (ut64)bin->nt_headers->optional_header.ImageBase;
	ut64 off, num = 0;
	const int srsz = 18; // symbol record size
	struct r_bin_pe_section_t* sections;
	struct r_bin_pe_export_t* exp;
	int bufsz, I, i, shsz;
	SymbolRecord *sr;
	ut64 text_off = 0LL;
	ut64 text_vaddr = 0LL;
	ut64 text = 0LL;
	int textn = 0;
	int exports_sz;
	int symctr = 0;
	char *buf;

	if (!bin || !bin->nt_headers)
		return NULL;
	off = bin->nt_headers->file_header.PointerToSymbolTable;
	num = bin->nt_headers->file_header.NumberOfSymbols;
	shsz = bufsz = num * srsz;
	if (bufsz<1 || bufsz>bin->size)
		return NULL;
	buf = calloc (num, srsz);
	if (!buf)
		return NULL;
	exports_sz = sizeof (struct r_bin_pe_export_t)*num;
	if (exports) {
		int osz = sz;
		sz += exports_sz;
		exports = realloc (exports, sz);
		if (!exports) {
			free (buf);
			return NULL;
		}
		exp =  (struct r_bin_pe_export_t*) (((const ut8*)exports) + osz);
	} else {
		sz = exports_sz;
		exports = malloc (sz);
		exp = exports;
	}

	sections = PE_(r_bin_pe_get_sections)(bin);
	for (i = 0; i < bin->nt_headers->file_header.NumberOfSections; i++) {
		if (!strcmp ((char*)sections[i].name, ".text")) {
			text_vaddr = sections[i].vaddr; // + baddr;
			text_off = sections[i].paddr;
			textn = i +1;
		}
	}
#undef D
#define D if (0)
	text = text_vaddr; // text_off // TODO: io.va
	symctr = 0;
	if (r_buf_read_at (bin->b, off, (ut8*)buf, bufsz)) {
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
						strncpy ((char*)exp[symctr].name, shortname, PE_NAME_LENGTH-1);
					} else {
						char *longname, name[128];
						ut32 *idx = (ut32 *) (buf+I+4)	;
						if (r_buf_read_at (bin->b, off+ *idx+shsz, (ut8*)name, 128)) {
							longname = name;
							D printf ("0x%08"PFMT64x"  %s\n", text + sr->value, longname);
							strncpy ((char*)exp[symctr].name, longname, PE_NAME_LENGTH-1);
						} else {
							D printf ("0x%08"PFMT64x"  unk_%d\n", text + sr->value, I/srsz);
							sprintf ((char*)exp[symctr].name, "unk_%d", symctr);
						}
					}
					exp[symctr].name[PE_NAME_LENGTH] = 0;
					exp[symctr].vaddr = bin->nt_headers->optional_header.ImageBase + text_vaddr+sr->value;
					exp[symctr].paddr = text_off+sr->value;
					exp[symctr].ordinal = symctr;
					exp[symctr].forwarder[0] = 0;
					exp[symctr].last = 0;
					symctr ++;
				}
			}
		} // for
	} // if read ok
	exp[symctr].last = 1;
	free (sections);
	free (buf);
	return exports;
}

static int PE_(r_bin_pe_init_sections)(struct PE_(r_bin_pe_obj_t)* bin) {
	int num_of_sections = bin->nt_headers->file_header.NumberOfSections;
	int sections_size;
	if (num_of_sections<1) {
		//eprintf("Warning: Invalid number of sections\n");
		return R_TRUE;
	}
	sections_size = sizeof (PE_(image_section_header)) * num_of_sections;

	if (sections_size > bin->size) {
		eprintf ("Invalid NumberOfSections value\n");
		return R_FALSE;
	}
	if (!(bin->section_header = malloc (sections_size))) {
		r_sys_perror ("malloc (section header)");
		return R_FALSE;
	}
	if (r_buf_read_at (bin->b, bin->dos_header->e_lfanew + 4 + sizeof (PE_(image_file_header)) +
				bin->nt_headers->file_header.SizeOfOptionalHeader,
				(ut8*)bin->section_header, sections_size) == -1) {
		eprintf ("Error: read (sections)\n");
		return R_FALSE;
	}
#if 0
Each symbol table entry includes a name, storage class, type, value and section number. Short names (8 characters or fewer) are stored directly in the symbol table; longer names are stored as an paddr into the string table at the end of the COFF object.

================================================================
COFF SYMBOL TABLE RECORDS (18 BYTES)
================================================================
record
paddr

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
		&bin->nt_headers->optional_header.DataDirectory[ \
		PE_IMAGE_DIRECTORY_ENTRY_IMPORT];
	PE_(image_data_directory) *data_dir_delay_import = \
		&bin->nt_headers->optional_header.DataDirectory[\
		PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	PE_DWord import_dir_paddr = PE_(r_bin_pe_vaddr_to_paddr)(bin,
		data_dir_import->VirtualAddress);
	PE_DWord import_dir_offset = PE_(r_bin_pe_vaddr_to_paddr)(bin,
		data_dir_import->VirtualAddress);
	PE_DWord delay_import_dir_offset = data_dir_delay_import?
		PE_(r_bin_pe_vaddr_to_paddr)(bin, data_dir_delay_import->VirtualAddress): 0;
	PE_(image_import_directory) *import_dir = NULL;
	PE_(image_import_directory) *new_import_dir = NULL;
	PE_(image_import_directory) *curr_import_dir = NULL;
	PE_(image_delay_import_directory) *delay_import_dir = NULL;
	PE_(image_delay_import_directory) *curr_delay_import_dir = NULL;
	int dir_size = sizeof (PE_(image_import_directory));
	int delay_import_size = sizeof (PE_(image_delay_import_directory));
	int indx = 0;
	int count = 0;
	int import_dir_size = data_dir_import->Size;
	int delay_import_dir_size = data_dir_delay_import->Size;
	/// HACK to modify import size because of begin 0.. this may report wrong info con corkami tests
	if (import_dir_size == 0) {
		// asume 1 entry for each
		import_dir_size = data_dir_import->Size = 0xffff;
	}
	if (delay_import_dir_size == 0) {
		// asume 1 entry for each
		delay_import_dir_size = data_dir_delay_import->Size = 0xffff;
	}
	int maxidsz = R_MIN (bin->size, import_dir_offset+import_dir_size);
	maxidsz -= import_dir_offset;
	if (maxidsz<0) maxidsz = 0;
	//int maxcount = maxidsz/ sizeof (struct r_bin_pe_import_t);

	free (bin->import_directory);
	bin->import_directory = NULL;
	if (import_dir_paddr != 0) {
		if (import_dir_size<1 || import_dir_size>maxidsz) {
			eprintf ("Warning: Invalid import directory size: 0x%x\n",
				import_dir_size);
			import_dir_size = maxidsz;
		}
		bin->import_directory_offset = import_dir_offset;
		count = 0;
		do {
			indx++;
			if ( ((2+indx)*dir_size) > import_dir_size) {
				break; //goto fail;
			}
			new_import_dir = (PE_(image_import_directory) *)realloc (
				import_dir, ((1+indx) * dir_size));
			if (!new_import_dir) {
				r_sys_perror ("malloc (import directory)");
				free (import_dir);
				import_dir = NULL;
				break; //
				//			goto fail;
			}
			import_dir = new_import_dir;
			new_import_dir = NULL;
			curr_import_dir = import_dir + (indx - 1);
			if (r_buf_read_at (bin->b, import_dir_offset + (indx - 1) * dir_size,
					(ut8*)(curr_import_dir), dir_size) == -1) {
				eprintf ("Error: read (import directory)\n");
				free (import_dir);
				import_dir = NULL;
				break; //return R_FALSE;
			}
			count ++;
		} while (curr_import_dir->FirstThunk != 0 || curr_import_dir->Name != 0 ||
				curr_import_dir->TimeDateStamp != 0 || curr_import_dir->Characteristics != 0 ||
				curr_import_dir->ForwarderChain != 0);

		bin->import_directory = import_dir;
		bin->import_directory_size = import_dir_size;
	}

	indx = 0;
	if ((delay_import_dir_offset != 0) && (delay_import_dir_offset < bin->b->length)) {
		bin->delay_import_directory_offset = delay_import_dir_offset;
		do {
			indx++;

			delay_import_dir = (PE_(image_delay_import_directory) *)realloc (
				delay_import_dir, (indx * delay_import_size)+1);
			if (delay_import_dir == 0) {
				r_sys_perror ("malloc (delay import directory)");
				free (delay_import_dir);
				return R_FALSE;
			}

			curr_delay_import_dir = delay_import_dir + (indx - 1);

			if (r_buf_read_at (bin->b, delay_import_dir_offset + (indx - 1) * delay_import_size,
					(ut8*)(curr_delay_import_dir), dir_size) == -1) {
				eprintf("Error: read (delay import directory)\n");
				goto fail;
			}
		} while (curr_delay_import_dir->Name != 0);

		bin->delay_import_directory = delay_import_dir;
	}

	return R_TRUE;
fail:
	free (import_dir);
	free (delay_import_dir);
	return R_FALSE;
}

static int PE_(r_bin_pe_init_exports)(struct PE_(r_bin_pe_obj_t) *bin) {
	PE_(image_data_directory) *data_dir_export = \
		&bin->nt_headers->optional_header.DataDirectory \
		[PE_IMAGE_DIRECTORY_ENTRY_EXPORT];
	PE_DWord export_dir_paddr = PE_(r_bin_pe_vaddr_to_paddr)
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
			r_buf_read_at (bin->b, sections[i].paddr, stab, stab_sz);
		}
		if (!strcmp (sections[i].name, ".stabst")) {
			stabst_sz = sections[i].size;
			eprintf ("Stab String Table found\n");
			stabst = malloc (sections[i].size);
			r_buf_read_at (bin->b, sections[i].paddr, stabst, stabst_sz);
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

	if (export_dir_paddr == 0) {
		// This export-dir-paddr should only appear in DLL files
		//eprintf ("Warning: Cannot find the paddr of the export directory\n");
		return R_FALSE;
	}
	//sdb_setn (DB, "hdr.exports_directory", export_dir_paddr);
//eprintf ("Pexports paddr at 0x%"PFMT64x"\n", export_dir_paddr);
	if (!(bin->export_directory = malloc (sizeof(PE_(image_export_directory))))) {
		r_sys_perror ("malloc (export directory)");
		return R_FALSE;
	}
	if (r_buf_read_at (bin->b, export_dir_paddr, (ut8*)bin->export_directory,
			sizeof (PE_(image_export_directory))) == -1) {
		eprintf ("Error: read (export directory)\n");
		free (bin->export_directory);
		bin->export_directory = NULL;
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
	if (!bin || !bin->nt_headers)
		return strdup ("x86");
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
	if (!bin || !bin->nt_headers)
		return NULL;
	if ((entry = malloc(sizeof(struct r_bin_pe_addr_t))) == NULL) {
		r_sys_perror("malloc (entrypoint)");
		return NULL;
	}
	entry->vaddr  = bin->nt_headers->optional_header.AddressOfEntryPoint;
	entry->paddr  = PE_(r_bin_pe_vaddr_to_paddr)(bin, entry->vaddr);
	entry->vaddr += bin->nt_headers->optional_header.ImageBase;
	return entry;
}

struct r_bin_pe_export_t* PE_(r_bin_pe_get_exports)(struct PE_(r_bin_pe_obj_t)* bin) {
	struct r_bin_pe_export_t *exp, *exports = NULL;
	PE_Word function_ordinal;
	PE_VWord functions_paddr, names_paddr, ordinals_paddr, function_vaddr, name_vaddr, name_paddr;
	char function_name[PE_NAME_LENGTH + 1], forwarder_name[PE_NAME_LENGTH + 1];
	char dll_name[PE_NAME_LENGTH + 1], export_name[PE_NAME_LENGTH + 1];
	PE_(image_data_directory) *data_dir_export;
	PE_VWord export_dir_vaddr ;
	int i, export_dir_size;
	int exports_sz = 0;

	if (!bin || !bin->nt_headers)
		return NULL;
	data_dir_export = \
		&bin->nt_headers->optional_header.\
		DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_EXPORT];
	export_dir_vaddr = data_dir_export->VirtualAddress;
	export_dir_size = data_dir_export->Size;

	if (bin->export_directory && bin->export_directory->NumberOfNames<0xfff) {
		exports_sz = (bin->export_directory->NumberOfNames + 1) \
			* sizeof (struct r_bin_pe_export_t);
		if (!(exports = malloc (exports_sz)))
			return NULL;
		if (r_buf_read_at (bin->b, PE_(r_bin_pe_vaddr_to_paddr)(
				bin, bin->export_directory->Name),
				(ut8*)dll_name, PE_NAME_LENGTH) == -1) {
			eprintf ("Error: read (dll name)\n");
			free (exports);
			return NULL;
		}
		functions_paddr = PE_(r_bin_pe_vaddr_to_paddr)(bin,
			bin->export_directory->AddressOfFunctions);
		names_paddr = PE_(r_bin_pe_vaddr_to_paddr)(bin,
			bin->export_directory->AddressOfNames);
		ordinals_paddr = PE_(r_bin_pe_vaddr_to_paddr)(bin,
			bin->export_directory->AddressOfOrdinals);
		for (i = 0; i < bin->export_directory->NumberOfNames; i++) {
			if (r_buf_read_at (bin->b, names_paddr + i *
					sizeof (PE_VWord), (ut8*)&name_vaddr,
					sizeof (PE_VWord)) == -1) {
				eprintf ("Error: read (name vaddr)\n");
				free (exports);
				return NULL;
			}
			if (r_buf_read_at (bin->b, ordinals_paddr + i *
					sizeof(PE_Word), (ut8*)&function_ordinal,
					sizeof (PE_Word)) == -1) {
				eprintf ("Error: read (function ordinal)\n");
				free (exports);
				return NULL;
			}
			if (-1 == r_buf_read_at (bin->b, functions_paddr +
					function_ordinal * sizeof(PE_VWord),
					(ut8*)&function_vaddr, sizeof(PE_VWord))) {
				eprintf ("Error: read (function vaddr)\n");
				free (exports);
				return NULL;
			}
			name_paddr = PE_(r_bin_pe_vaddr_to_paddr)(bin, name_vaddr);
			if (name_paddr) {
				if (-1 == r_buf_read_at(bin->b, name_paddr,
					(ut8*)function_name, PE_NAME_LENGTH)) {
					eprintf("Error: read (function name)\n");
					free (exports);
					return NULL;
				}
			} else {
				snprintf (function_name, PE_NAME_LENGTH, "Ordinal_%i", function_ordinal);
			}
			snprintf (export_name, PE_NAME_LENGTH, "%s_%s", dll_name, function_name);
			if (function_vaddr >= export_dir_vaddr && function_vaddr < (export_dir_vaddr + export_dir_size)) {
				if (r_buf_read_at (bin->b, PE_(r_bin_pe_vaddr_to_paddr)(bin, function_vaddr),
						(ut8*)forwarder_name, PE_NAME_LENGTH) == -1) {
					eprintf ("Error: read (magic)\n");
					free (exports);
					return NULL;
				}
			} else {
				snprintf (forwarder_name, PE_NAME_LENGTH, "NONE");
			}
			exports[i].vaddr = function_vaddr;
			exports[i].paddr = PE_(r_bin_pe_vaddr_to_paddr)(bin, function_vaddr);
			exports[i].ordinal = function_ordinal;
			memcpy (exports[i].forwarder, forwarder_name, PE_NAME_LENGTH);
			exports[i].forwarder[PE_NAME_LENGTH] = '\0';
			memcpy (exports[i].name, export_name, PE_NAME_LENGTH);
			exports[i].name[PE_NAME_LENGTH] = '\0';
			exports[i].last = 0;
		}
		exports[i].last = 1;
	}

	exp = parse_symbol_table (bin, exports, exports_sz - 1);
	if (exp) exports = exp;
	//else eprintf ("Warning: bad symbol table\n");

	return exports;
}

int PE_(r_bin_pe_get_file_alignment)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->optional_header.FileAlignment;
}

ut64 PE_(r_bin_pe_get_image_base)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers)
		return 0LL;
	return (ut64)bin->nt_headers->optional_header.ImageBase;
}

static void free_rsdr_hdr(SCV_RSDS_HEADER *rsds_hdr) {
	R_FREE(rsds_hdr->file_name);
}

static void init_rsdr_hdr(SCV_RSDS_HEADER *rsds_hdr) {
	memset (rsds_hdr, 0, sizeof (SCV_RSDS_HEADER));
	rsds_hdr->free = (void (*)(struct SCV_RSDS_HEADER *)) free_rsdr_hdr;
}

static void free_cv_nb10_header(SCV_NB10_HEADER *cv_nb10_header) {
	R_FREE(cv_nb10_header->file_name);
}

static void init_cv_nb10_header(SCV_NB10_HEADER *cv_nb10_header) {
	memset (cv_nb10_header, 0, sizeof (SCV_NB10_HEADER));
	cv_nb10_header->free = (void (*)(struct SCV_NB10_HEADER *)) free_cv_nb10_header;
}

static void get_rsds(ut8 *dbg_data, SCV_RSDS_HEADER *res) {
	const int rsds_sz = 4 + sizeof (SGUID) + 4;
	memcpy (res, dbg_data, rsds_sz);
	res->file_name = (ut8 *)strdup ((const char *)dbg_data + rsds_sz);
}

static void get_nb10(ut8 *dbg_data, SCV_NB10_HEADER *res) {
	const int nb10sz = 16;
	memcpy(res, dbg_data, nb10sz);
	res->file_name = (ut8 *)strdup ((const char *)dbg_data + nb10sz);
}

static int get_debug_info(PE_(image_debug_directory_entry) *dbg_dir_entry, ut8 *dbg_data, SDebugInfo *res) {
#define SIZEOF_FILE_NAME 255
	int i = 0;

	switch (dbg_dir_entry->Type) {
	case IMAGE_DEBUG_TYPE_CODEVIEW:
		if (strncmp((char *)dbg_data, "RSDS", 4) == 0) {
			SCV_RSDS_HEADER rsds_hdr;
			init_rsdr_hdr (&rsds_hdr);
			get_rsds (dbg_data, &rsds_hdr);
			snprintf ((st8 *) res->guidstr, GUIDSTR_LEN,
				"%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x%x",
				rsds_hdr.guid.data1,
				rsds_hdr.guid.data2,
				rsds_hdr.guid.data3,
				rsds_hdr.guid.data4[0],
				rsds_hdr.guid.data4[1],
				rsds_hdr.guid.data4[2],
				rsds_hdr.guid.data4[3],
				rsds_hdr.guid.data4[4],
				rsds_hdr.guid.data4[5],
				rsds_hdr.guid.data4[6],
				rsds_hdr.guid.data4[7],
				rsds_hdr.age);
			strncpy (res->file_name, (const char*)
				rsds_hdr.file_name, sizeof (res->file_name));
			res->file_name[sizeof (res->file_name)-1] = 0;
			rsds_hdr.free ((struct SCV_RSDS_HEADER *)&rsds_hdr);
		} else if (strncmp((const char *)dbg_data, "NB10", 4) == 0) {
			SCV_NB10_HEADER nb10_hdr;
			init_cv_nb10_header (&nb10_hdr);
			get_nb10 (dbg_data, &nb10_hdr);
			snprintf ((st8 *) res->guidstr, sizeof (res->guidstr),
				"%x%x", nb10_hdr.timestamp, nb10_hdr.age);
			strncpy (res->file_name, (const char *)
				nb10_hdr.file_name, sizeof(res->file_name)-1);
			res->file_name[sizeof (res->file_name)-1] = 0;
			nb10_hdr.free ((struct SCV_NB10_HEADER *)&nb10_hdr);
		} else {
			eprintf ("CodeView section not NB10 or RSDS\n");
			return 0;
		}
		break;
	default:
		//eprintf("get_debug_info(): not supported type\n");
		return 0;
	}

	while (i < 33) {
		res->guidstr[i] = toupper (res->guidstr[i]);
		i++;
	}

	return 1;
}

int PE_(r_bin_pe_get_debug_data)(struct PE_(r_bin_pe_obj_t) *bin, SDebugInfo *res) {
	PE_(image_debug_directory_entry) *img_dbg_dir_entry = NULL;
	PE_(image_data_directory) *dbg_dir;
	PE_DWord dbg_dir_offset;
	ut8 *dbg_data = 0;
	int result = 0;
	if (!bin) return 0;
	dbg_dir = &bin->nt_headers->optional_header.DataDirectory[6/*IMAGE_DIRECTORY_ENTRY_DEBUG*/];
	dbg_dir_offset = PE_(r_bin_pe_vaddr_to_paddr)(bin, dbg_dir->VirtualAddress);
	if ((int)dbg_dir_offset<0 || dbg_dir_offset>= bin->size)
		return R_FALSE;
	img_dbg_dir_entry = (PE_(image_debug_directory_entry)*)(bin->b->buf + dbg_dir_offset);
	if (img_dbg_dir_entry) {
		dbg_data = (ut8 *) malloc(img_dbg_dir_entry->SizeOfData);
		r_buf_read_at(bin->b, img_dbg_dir_entry->PointerToRawData, dbg_data, img_dbg_dir_entry->SizeOfData);
		result = get_debug_info(img_dbg_dir_entry, dbg_data, res);
		R_FREE(dbg_data);
	}
	return result;
}

struct r_bin_pe_import_t* PE_(r_bin_pe_get_imports)(struct PE_(r_bin_pe_obj_t) *bin) {
	struct r_bin_pe_import_t *imps, *imports = NULL;
	char dll_name[PE_NAME_LENGTH + 1];
	int nimp = 0;
	PE_DWord dll_name_offset = 0;
	PE_DWord import_func_name_offset;
	PE_(image_import_directory) *curr_import_dir = NULL;
	PE_(image_delay_import_directory) *curr_delay_import_dir = 0;

	if (bin->import_directory_offset < bin->size && bin->import_directory_offset > 0) {
		curr_import_dir = (PE_(image_import_directory)*)(bin->b->buf + bin->import_directory_offset);
		dll_name_offset = curr_import_dir->Name;
		void *last = curr_import_dir + bin->import_directory_size;
		while (curr_import_dir->FirstThunk != 0 || curr_import_dir->Name != 0 ||
				curr_import_dir->TimeDateStamp != 0 || curr_import_dir->Characteristics != 0 ||
				curr_import_dir->ForwarderChain != 0) {
			dll_name_offset = curr_import_dir->Name;
			if (r_buf_read_at (bin->b, PE_(r_bin_pe_vaddr_to_paddr)(bin, dll_name_offset),
					(ut8*)dll_name, PE_NAME_LENGTH) == -1) {
				eprintf ("Error: read (magic)\n");
				return NULL;
			}
			if (!PE_(r_bin_pe_parse_imports)(bin, &imports, &nimp, dll_name,
					curr_import_dir->Characteristics,
					curr_import_dir->FirstThunk))
				break;
			curr_import_dir++;
			if ((void*)curr_import_dir>= last) { 
				break;
			}
		}
	}

	if (bin->delay_import_directory_offset < bin->size && bin->delay_import_directory_offset > 0) {
		curr_delay_import_dir = (PE_(image_delay_import_directory)*) (
			bin->b->buf + bin->delay_import_directory_offset);

		if (curr_delay_import_dir->Attributes == 0) {
			dll_name_offset = PE_(r_bin_pe_vaddr_to_paddr)(bin,
				curr_delay_import_dir->Name - PE_(r_bin_pe_get_image_base)(bin));
			import_func_name_offset = curr_delay_import_dir->DelayImportNameTable -
				PE_(r_bin_pe_get_image_base)(bin);
		} else {
			dll_name_offset = PE_(r_bin_pe_vaddr_to_paddr)(bin, curr_delay_import_dir->Name);
			import_func_name_offset = curr_delay_import_dir->DelayImportNameTable;
		}

		while ((curr_delay_import_dir->Name != 0) && (curr_delay_import_dir->DelayImportAddressTable !=0)) {
			if (r_buf_read_at(bin->b, dll_name_offset, (ut8*)dll_name, PE_NAME_LENGTH) == -1) {
				eprintf ("Error: read (magic)\n");
				return NULL;
			}
			if (!PE_(r_bin_pe_parse_imports)(bin, &imports, &nimp, dll_name,
					import_func_name_offset,
					curr_delay_import_dir->DelayImportAddressTable))
				break;
			curr_delay_import_dir++;
		}
	}

	if (nimp) {
		imps = realloc (imports, (nimp+1) * sizeof(struct r_bin_pe_import_t));
		if (!imps) {
			r_sys_perror ("realloc (import)");
			return NULL;
		}
		imports = imps;
		imports[nimp].last = 1;
	}
	return imports;
}

struct r_bin_pe_lib_t* PE_(r_bin_pe_get_libs)(struct PE_(r_bin_pe_obj_t) *bin) {
	if (!bin) return NULL;
	struct r_bin_pe_lib_t *libs = NULL;
	PE_(image_import_directory) *curr_import_dir = NULL;
	PE_(image_delay_import_directory) *curr_delay_import_dir = NULL;
	PE_DWord name_off = 0;
	int index = 0;
	int len = 0;
	int max_libs = 20;
	libs = calloc (max_libs, sizeof(struct r_bin_pe_lib_t));
	if (!libs) {
		r_sys_perror ("malloc (libs)");
		return NULL;
	}

	RStrHT *lib_map = r_strht_new();
	if (bin->import_directory_offset < bin->size && bin->import_directory_offset > 0) {
		// normal imports
		curr_import_dir = (PE_(image_import_directory)*)(
			bin->b->buf + bin->import_directory_offset);
		while (curr_import_dir->FirstThunk != 0 || curr_import_dir->Name != 0 ||
				curr_import_dir->TimeDateStamp != 0 || curr_import_dir->Characteristics != 0 ||
				curr_import_dir->ForwarderChain != 0) {
			name_off = PE_(r_bin_pe_vaddr_to_paddr)(bin, curr_import_dir->Name);
			len = r_buf_read_at (bin->b, name_off, (ut8*)libs[index].name, PE_STRING_LENGTH);
			if (len < 0) {
				eprintf ("Error: read (libs - import dirs)\n");
				break;
			}
			libs[index].name[len] = '\0';
			r_str_case (libs[index].name, 0);
			if (r_strht_get (lib_map, libs[index].name) == NULL) {
				r_strht_set (lib_map, libs[index].name, "a");
				libs[index++].last = 0;
				if (index >= max_libs) {
					libs = realloc (libs, (max_libs * 2) * sizeof (struct r_bin_pe_lib_t));
					if (!libs) {
						r_sys_perror ("realloc (libs)");
						r_strht_free (lib_map);
						return NULL;
					}
					max_libs *= 2;
				}
			}
			curr_import_dir++;
		}
	}

	if (bin->delay_import_directory_offset < bin->size && bin->delay_import_directory_offset > 0) {
		curr_delay_import_dir = (PE_(image_delay_import_directory)*)(
			bin->b->buf + bin->delay_import_directory_offset);
		while (curr_delay_import_dir->Name != 0 && curr_delay_import_dir->DelayImportNameTable != 0) {
			name_off = PE_(r_bin_pe_vaddr_to_paddr)(bin, curr_delay_import_dir->Name);
			len = r_buf_read_at (bin->b, name_off, (ut8*)libs[index].name, PE_STRING_LENGTH);
			if (len < 0) {
				eprintf ("Error: read (libs - delay import dirs)\n");
				break;
			}
			libs[index].name[len] = '\0';
			r_str_case (libs[index].name, 0);
			if (r_strht_get (lib_map, libs[index].name) == NULL) {
				r_strht_set (lib_map, libs[index].name, "a");
				libs[index++].last = 0;
				if (index >= max_libs) {
					libs = realloc (libs, (max_libs * 2) * sizeof (struct r_bin_pe_lib_t));
					if (!libs) {
						r_strht_free (lib_map);
						r_sys_perror ("realloc (libs)");
						return NULL;
					}
					max_libs *= 2;
				}
			}
			curr_delay_import_dir++;
		}
	}
	r_strht_free (lib_map);
	libs[index].last = 1;
	return libs;
}

int PE_(r_bin_pe_get_image_size)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->optional_header.SizeOfImage;
}

// TODO: make it const! like in elf
char* PE_(r_bin_pe_get_machine)(struct PE_(r_bin_pe_obj_t)* bin) {
	char *machine = NULL;

	if (bin && bin->nt_headers)
	switch (bin->nt_headers->file_header.Machine) {
	case PE_IMAGE_FILE_MACHINE_ALPHA: machine = "Alpha"; break;
	case PE_IMAGE_FILE_MACHINE_ALPHA64: machine = "Alpha 64"; break;
	case PE_IMAGE_FILE_MACHINE_AM33: machine = "AM33"; break;
	case PE_IMAGE_FILE_MACHINE_AMD64: machine = "AMD 64"; break;
	case PE_IMAGE_FILE_MACHINE_ARM: machine = "ARM"; break;
	case PE_IMAGE_FILE_MACHINE_CEE: machine = "CEE"; break;
	case PE_IMAGE_FILE_MACHINE_CEF: machine = "CEF"; break;
	case PE_IMAGE_FILE_MACHINE_EBC: machine = "EBC"; break;
	case PE_IMAGE_FILE_MACHINE_I386: machine = "i386"; break;
	case PE_IMAGE_FILE_MACHINE_IA64: machine = "ia64"; break;
	case PE_IMAGE_FILE_MACHINE_M32R: machine = "M32R"; break;
	case PE_IMAGE_FILE_MACHINE_M68K: machine = "M68K"; break;
	case PE_IMAGE_FILE_MACHINE_MIPS16: machine = "Mips 16"; break;
	case PE_IMAGE_FILE_MACHINE_MIPSFPU: machine = "Mips FPU"; break;
	case PE_IMAGE_FILE_MACHINE_MIPSFPU16: machine = "Mips FPU 16"; break;
	case PE_IMAGE_FILE_MACHINE_POWERPC: machine = "PowerPC"; break;
	case PE_IMAGE_FILE_MACHINE_POWERPCFP: machine = "PowerPC FP"; break;
	case PE_IMAGE_FILE_MACHINE_R10000: machine = "R10000"; break;
	case PE_IMAGE_FILE_MACHINE_R3000: machine = "R3000"; break;
	case PE_IMAGE_FILE_MACHINE_R4000: machine = "R4000"; break;
	case PE_IMAGE_FILE_MACHINE_SH3: machine = "SH3"; break;
	case PE_IMAGE_FILE_MACHINE_SH3DSP: machine = "SH3DSP"; break;
	case PE_IMAGE_FILE_MACHINE_SH3E: machine = "SH3E"; break;
	case PE_IMAGE_FILE_MACHINE_SH4: machine = "SH4"; break;
	case PE_IMAGE_FILE_MACHINE_SH5: machine = "SH5"; break;
	case PE_IMAGE_FILE_MACHINE_THUMB: machine = "Thumb"; break;
	case PE_IMAGE_FILE_MACHINE_TRICORE: machine = "Tricore"; break;
	case PE_IMAGE_FILE_MACHINE_WCEMIPSV2: machine = "WCE Mips V2"; break;
	default: machine = "unknown";
	}
	return machine? strdup (machine): NULL;
}

// TODO: make it const! like in elf
char* PE_(r_bin_pe_get_os)(struct PE_(r_bin_pe_obj_t)* bin) {
	char *os;
	if (!bin || !bin->nt_headers)
		return NULL;
	switch (bin->nt_headers->optional_header.Subsystem) {
	case PE_IMAGE_SUBSYSTEM_NATIVE:
		os = strdup ("native");
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
	if (bin && bin->nt_headers)
	switch (bin->nt_headers->optional_header.Magic) {
	case PE_IMAGE_FILE_TYPE_PE32: return strdup("PE32");
	case PE_IMAGE_FILE_TYPE_PE32PLUS: return strdup("PE32+");
	default: return strdup("Unknown");
	}
	return NULL;
}

int PE_(r_bin_pe_get_bits)(struct PE_(r_bin_pe_obj_t)* bin) {
	int bits = 32;
	if (bin && bin->nt_headers)
	switch (bin->nt_headers->optional_header.Magic) {
	case PE_IMAGE_FILE_TYPE_PE32: bits = 32; break;
	case PE_IMAGE_FILE_TYPE_PE32PLUS: bits = 64; break;
	default: bits = -1;
	}
	return bits;
}

int PE_(r_bin_pe_get_section_alignment)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers)
		return 0;
	return bin->nt_headers->optional_header.SectionAlignment;
}

struct r_bin_pe_section_t* PE_(r_bin_pe_get_sections)(struct PE_(r_bin_pe_obj_t)* bin) {
	struct r_bin_pe_section_t *sections = NULL;
	PE_(image_section_header) *shdr;
	int i, sections_count;

	if (!bin || !bin->nt_headers)
		return NULL;
	shdr = bin->section_header;
	sections_count = bin->nt_headers->file_header.NumberOfSections;
	if (sections_count == 0xffff)
		sections_count = 16; // hackaround for 65k sections file
	sections = calloc (sections_count + 1, sizeof (struct r_bin_pe_section_t));
	if (!sections) {
		r_sys_perror ("malloc (sections)");
		return NULL;
	}
	for (i = 0; i < sections_count; i++) {
		memcpy (sections[i].name, shdr[i].Name, \
			PE_IMAGE_SIZEOF_SHORT_NAME);
		sections[i].name[PE_IMAGE_SIZEOF_SHORT_NAME-1] = '\0';
		sections[i].vaddr = shdr[i].VirtualAddress;
		sections[i].size = shdr[i].SizeOfRawData;
		sections[i].vsize = shdr[i].Misc.VirtualSize;
		sections[i].paddr = shdr[i].PointerToRawData;
		sections[i].flags = shdr[i].Characteristics;
		sections[i].last = 0;
	}
	sections[i].last = 1;
	return sections;
}

char* PE_(r_bin_pe_get_subsystem)(struct PE_(r_bin_pe_obj_t)* bin) {
	char *subsystem = NULL;
	if (bin && bin->nt_headers)
	switch (bin->nt_headers->optional_header.Subsystem) {
	case PE_IMAGE_SUBSYSTEM_NATIVE:
		subsystem = "Native"; break;
	case PE_IMAGE_SUBSYSTEM_WINDOWS_GUI:
		subsystem = "Windows GUI"; break;
	case PE_IMAGE_SUBSYSTEM_WINDOWS_CUI:
		subsystem = "Windows CUI"; break;
	case PE_IMAGE_SUBSYSTEM_POSIX_CUI:
		subsystem = "POSIX CUI"; break;
	case PE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		subsystem = "Windows CE GUI"; break;
	case PE_IMAGE_SUBSYSTEM_EFI_APPLICATION:
		subsystem = "EFI Application"; break;
	case PE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		subsystem = "EFI Boot Service Driver"; break;
	case PE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		subsystem = "EFI Runtime Driver"; break;
	case PE_IMAGE_SUBSYSTEM_EFI_ROM:
		subsystem = "EFI ROM"; break;
	case PE_IMAGE_SUBSYSTEM_XBOX:
		subsystem = "XBOX"; break;
	default: subsystem = "Unknown";
	}
	return subsystem? strdup (subsystem): NULL;
}

#define HASCHR(x) bin->nt_headers->file_header.Characteristics & x

int PE_(r_bin_pe_is_dll)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers)
		return R_FALSE;
	return HASCHR (PE_IMAGE_FILE_DLL);
}

int PE_(r_bin_pe_is_pie)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers)
		return R_FALSE;
	return HASCHR (IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE);
#if 0
	BOOL aslr = inh->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
//TODO : implement dep?
	BOOL dep = inh->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
#endif
}

int PE_(r_bin_pe_is_big_endian)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers)
		return R_FALSE;
	return HASCHR (PE_IMAGE_FILE_BYTES_REVERSED_HI);
}

int PE_(r_bin_pe_is_stripped_relocs)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers)
		return R_FALSE;
	return HASCHR (PE_IMAGE_FILE_RELOCS_STRIPPED);
}

int PE_(r_bin_pe_is_stripped_line_nums)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers)
		return R_FALSE;
	return HASCHR (PE_IMAGE_FILE_LINE_NUMS_STRIPPED);
}

int PE_(r_bin_pe_is_stripped_local_syms)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers)
		return R_FALSE;
	return HASCHR (PE_IMAGE_FILE_LOCAL_SYMS_STRIPPED);
}

int PE_(r_bin_pe_is_stripped_debug)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers)
		return R_FALSE;
	return HASCHR (PE_IMAGE_FILE_DEBUG_STRIPPED);
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
	bin->kv = sdb_new0 ();
	bin->b = r_buf_new ();
	bin->size = buf->length;
	if (!r_buf_set_bytes (bin->b, buf->buf, bin->size)){
		return PE_(r_bin_pe_free)(bin);
	}
	if (!PE_(r_bin_pe_init)(bin))
		return PE_(r_bin_pe_free)(bin);
	return bin;
}
