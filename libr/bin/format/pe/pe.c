/* radare - LGPL - Copyright 2008-2016 nibble, pancake, inisider */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include "pe.h"
#include <sys/time.h>
#include <time.h>

#define PE_IMAGE_FILE_MACHINE_RPI2 452

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

static inline int is_thumb (struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->optional_header.AddressOfEntryPoint & 1;
}

static inline int is_arm (struct PE_(r_bin_pe_obj_t)* bin) {
	switch (bin->nt_headers->file_header.Machine) {
	case PE_IMAGE_FILE_MACHINE_RPI2: // 462
	case PE_IMAGE_FILE_MACHINE_ARM:
	case PE_IMAGE_FILE_MACHINE_THUMB:
		return 1;
	}
	return 0;
}

struct r_bin_pe_addr_t *PE_(r_bin_pe_get_main_vaddr)(struct PE_(r_bin_pe_obj_t) *bin) {
	struct r_bin_pe_addr_t *entry;
	ut8 b[512];

	if (!bin || !bin->b) {
		return 0LL;
	}
	entry = PE_(r_bin_pe_get_entrypoint) (bin);
	// option2: /x 8bff558bec83ec20
	b[367] = 0;
	if (r_buf_read_at (bin->b, entry->paddr, b, sizeof (b)) < 0) {
		eprintf ("Warning: Cannot read entry at 0x%08"PFMT64x"\n", entry->paddr);
		free (entry);
		return NULL;
	}

	/* Decode the jmp instruction, this gets the address of the 'main'
	 * function for PE produced by a compiler whose name someone forgot to
	 * write down. */
	if (b[367] == 0xe8) {
		const ut32 jmp_dst = b[368] | (b[369] << 8) | (b[370] << 16) | (b[371] << 24);
		entry->paddr += 367 + 5 + jmp_dst;
		entry->vaddr += 367 + 5 + jmp_dst;
		return entry;
	}
	free (entry);
	return NULL;
}

#define RBinPEObj struct PE_(r_bin_pe_obj_t)
static PE_DWord bin_pe_rva_to_paddr(RBinPEObj* bin, PE_DWord rva) {
	PE_DWord section_base;
	int i, section_size;

	for (i = 0; i < bin->num_sections; i++) {
		section_base = bin->section_header[i].VirtualAddress;
		section_size = bin->section_header[i].Misc.VirtualSize;
		if (rva >= section_base && rva < section_base + section_size) {
			return bin->section_header[i].PointerToRawData  + (rva - section_base);
		}
	}
	return rva;
}

static PE_DWord bin_pe_rva_to_va(RBinPEObj* bin, PE_DWord rva) {
	return bin->nt_headers->optional_header.ImageBase + rva;
}

static PE_DWord bin_pe_va_to_rva(RBinPEObj* bin, PE_DWord va) {
	if (va < bin->nt_headers->optional_header.ImageBase) {
		return va;
	}
	return va - bin->nt_headers->optional_header.ImageBase;
}

static char *resolveModuleOrdinal(Sdb *sdb, const char *module, int ordinal) {
	Sdb *db = sdb;
	char *foo = sdb_get (db, sdb_fmt (0, "%d", ordinal), 0);
	if (foo && *foo) {
	   	return foo;
	} else {
	   	free (foo); // should never happen
	}
	return NULL;
}

static int bin_pe_parse_imports(struct PE_(r_bin_pe_obj_t)* bin,
				struct r_bin_pe_import_t** importp, int* nimp,
				const char* dll_name,
				PE_DWord OriginalFirstThunk,
				PE_DWord FirstThunk) {
	char import_name[PE_NAME_LENGTH + 1];
	char name[PE_NAME_LENGTH + 1];
	PE_Word import_hint, import_ordinal = 0;
	PE_DWord import_table = 0, off = 0;
	int i = 0, len;
	Sdb *db = NULL;
	char *sdb_module = NULL;
	char *symname;
	char *filename;
	char *symdllname = NULL;

	if (!dll_name || *dll_name == '0') {
		return 0;
	}

	if (!(off = bin_pe_rva_to_paddr (bin, OriginalFirstThunk)) &&
		!(off = bin_pe_rva_to_paddr (bin, FirstThunk))) {
		return 0;
	}
	do {
		if (import_ordinal >= UT16_MAX) {
			break;
		}
		if (off + i * sizeof(PE_DWord) > bin->size) {
			break;
		}
		len = r_buf_read_at (bin->b, off + i * sizeof (PE_DWord), (ut8*)&import_table, sizeof (PE_DWord));
		if (len != sizeof (PE_DWord)) {
			eprintf("Warning: read (import table)\n");
			goto error;
		}
		else if (import_table) {
			if (import_table & ILT_MASK1) {
				import_ordinal = import_table & ILT_MASK2;
				import_hint = 0;
				snprintf (import_name, PE_NAME_LENGTH, "%s_Ordinal_%i", dll_name, import_ordinal);
				free (symdllname);
				strncpy (name, dll_name, sizeof (name)-1);
				name[sizeof(name) - 1] = 0;
				symdllname = strdup (name);

				// remove the trailling ".dll"
				size_t len = strlen (symdllname);
				r_str_case (symdllname, 0);
				len = len < 4 ? 0 : len - 4;
				symdllname[len] = 0;

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
					symname = resolveModuleOrdinal (db, symdllname, import_ordinal);
					if (symname) {
						snprintf (import_name, PE_NAME_LENGTH, "%s_%s", dll_name, symname);
					}	
				} else {
					eprintf ("Cannot find %s\n", filename);

				}
			} else {
				import_ordinal++;
				const ut64 off = bin_pe_rva_to_paddr(bin, import_table);
				if (off > bin->size || (off + sizeof (PE_Word)) > bin->size) {
					eprintf ("Warning: off > bin->size\n");
					goto error;
				}
				len = r_buf_read_at (bin->b, off, (ut8*)&import_hint, sizeof (PE_Word));
				if (len != sizeof (PE_Word)) {
					eprintf ("Warning: read import hint at 0x%08"PFMT64x"\n", off);
					goto error;
				}
				name[0] = '\0';
				len = r_buf_read_at (bin->b, off + sizeof(PE_Word), (ut8*)name, PE_NAME_LENGTH);
				if (len < 1) {
					eprintf ("Warning: read (import name)\n");
					goto error;
				} else if (!*name) {
					break;
				}
				name[PE_NAME_LENGTH] = '\0';
				snprintf (import_name, PE_NAME_LENGTH, "%s_%s", dll_name, name);
			}
			if (!(*importp = realloc (*importp, (*nimp + 1) * sizeof(struct r_bin_pe_import_t)))) {
				r_sys_perror ("realloc (import)");
				goto error;
			}
			memcpy((*importp)[*nimp].name, import_name, PE_NAME_LENGTH);
			(*importp)[*nimp].name[PE_NAME_LENGTH] = '\0';
			(*importp)[*nimp].vaddr = bin_pe_rva_to_va (bin, FirstThunk + i * sizeof (PE_DWord));
			(*importp)[*nimp].paddr = bin_pe_rva_to_paddr (bin, FirstThunk) + i * sizeof(PE_DWord);
			(*importp)[*nimp].hint = import_hint;
			(*importp)[*nimp].ordinal = import_ordinal;
			(*importp)[*nimp].last = 0;
			(*nimp)++;
			i++;
		}
	} while (import_table);

	free (symdllname);
	free (sdb_module);
	return i;

error:
	free (symdllname);
	free (sdb_module);
	return false;
}

static int bin_pe_init_hdr(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!(bin->dos_header = malloc(sizeof(PE_(image_dos_header))))) {
		r_sys_perror ("malloc (dos header)");
		return false;
	}
	if (r_buf_read_at (bin->b, 0, (ut8*)bin->dos_header, sizeof(PE_(image_dos_header))) == -1) {
		eprintf("Warning: read (dos header)\n");
		return false;
	}
	sdb_num_set (bin->kv, "pe_dos_header.offset", 0, 0);
	sdb_set (bin->kv, "pe_dos_header.format", "[2]zwwwwwwwwwwwww[4]www[10]wx"
			" e_magic e_cblp e_cp e_crlc e_cparhdr e_minalloc e_maxalloc"
			" e_ss e_sp e_csum e_ip e_cs e_lfarlc e_ovno e_res e_oemid"
			" e_oeminfo e_res2 e_lfanew", 0);
	if (bin->dos_header->e_lfanew > (unsigned int)bin->size) {
		eprintf("Invalid e_lfanew field\n");
		return false;
	}
	if (!(bin->nt_headers = malloc (sizeof (PE_(image_nt_headers))))) {
		r_sys_perror("malloc (nt header)");
		return false;
	}
	bin->nt_header_offset = bin->dos_header->e_lfanew;
	if (r_buf_read_at (bin->b, bin->dos_header->e_lfanew, (ut8*)bin->nt_headers, sizeof (PE_(image_nt_headers))) < -1) {
		eprintf ("Warning: read (dos header)\n");
		return false;
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

	// adding compile time to the SDB
	 {
		struct my_timezone {
			int tz_minuteswest;     /* minutes west of Greenwich */
			int tz_dsttime;         /* type of DST correction */
		} tz;
		struct timeval tv;
		int gmtoff;
		char *timestr;
		time_t ts = (time_t)bin->nt_headers->file_header.TimeDateStamp;
		sdb_num_set (bin->kv, "image_file_header.TimeDateStamp", bin->nt_headers->file_header.TimeDateStamp, 0);
		gettimeofday (&tv, (void*)&tz);
		gmtoff = (int)(tz.tz_minuteswest*60); // in seconds
		ts += gmtoff;
		timestr = r_str_chop (strdup (ctime (&ts)));
		// gmt offset for pe date is t->tm_gmtoff
		sdb_set_owned (bin->kv,
			"image_file_header.TimeDateStamp_string",
			      timestr, 0);
	 }
	bin->optional_header = &bin->nt_headers->optional_header;
	bin->data_directory = (PE_(image_data_directory *))&bin->optional_header->DataDirectory;

	if (strncmp ((char*)&bin->dos_header->e_magic, "MZ", 2) ||
		strncmp ((char*)&bin->nt_headers->Signature, "PE", 2)) {
			return false;
	}
	return true;
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
	ut64 sym_tbl_off, num = 0;
	const int srsz = 18; // symbol record size
	struct r_bin_pe_section_t* sections;
	struct r_bin_pe_export_t* exp;
	int bufsz, i, shsz;
	SymbolRecord *sr;
	ut64 text_off = 0LL;
	ut64 text_rva = 0LL;
	int textn = 0;
	int exports_sz;
	int symctr = 0;
	char *buf;

	if (!bin || !bin->nt_headers) {
		return NULL;
	}

	sym_tbl_off  = bin->nt_headers->file_header.PointerToSymbolTable;
	num  = bin->nt_headers->file_header.NumberOfSymbols;
	shsz = bufsz = num * srsz;
	if (bufsz < 1 || bufsz > bin->size) {
		return NULL;
	}
	buf = calloc (num, srsz);
	if (!buf) {
		return NULL;
	}
	exports_sz = sizeof(struct r_bin_pe_export_t) * num;
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

	sections = PE_(r_bin_pe_get_sections) (bin);
	for (i = 0; i < bin->num_sections; i++) {
	    	//XXX search by section with +x permission since the section can be left blank
		if (!strcmp ((char*)sections[i].name, ".text")) {
			text_rva = sections[i].vaddr;
			text_off = sections[i].paddr;
			textn = i + 1;
		}
	}
	free (sections);
	symctr = 0;
	if (r_buf_read_at (bin->b, sym_tbl_off, (ut8*)buf, bufsz)) {
		for (i = 0; i < shsz; i += srsz) {
			sr = (SymbolRecord *) (buf + i);
			//eprintf ("SECNUM %d\n", sr->secnum);
			if (sr->secnum == textn) {
				if (sr->symtype == 32) {
					char shortname[9];
					memcpy (shortname, &sr->shortname, 8);
					shortname[8] = 0;
					if (*shortname) {
						strncpy ((char*)exp[symctr].name, shortname, PE_NAME_LENGTH-1);
					} else {
						char *longname, name[128];
						ut32 *idx = (ut32 *) (buf + i + 4);
						if (r_buf_read_at (bin->b, sym_tbl_off + *idx+shsz, (ut8*)name, 128)) {// == 128) {
							longname = name;
							name[sizeof(name)-1] = 0;
							strncpy ((char*)exp[symctr].name, longname, PE_NAME_LENGTH-1);
						} else {
							sprintf ((char*)exp[symctr].name, "unk_%d", symctr);
						}
					}
					exp[symctr].name[PE_NAME_LENGTH] = 0;
					exp[symctr].vaddr   = bin_pe_rva_to_va (bin, text_rva + sr->value);
					exp[symctr].paddr   = text_off+sr->value;
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

static int bin_pe_init_sections(struct PE_(r_bin_pe_obj_t)* bin) {
	bin->num_sections = bin->nt_headers->file_header.NumberOfSections;
	int sections_size;
	if (bin->num_sections < 1) {
		return true;
	}
	sections_size = sizeof (PE_(image_section_header)) * bin->num_sections;
	if (sections_size > bin->size) {
		eprintf ("Invalid NumberOfSections value\n");
		return false;
	}
	if (!(bin->section_header = malloc (sections_size))) {
		r_sys_perror ("malloc (section header)");
		return false;
	}
	if (r_buf_read_at (bin->b, bin->dos_header->e_lfanew + 4 + sizeof (PE_(image_file_header)) +
				bin->nt_headers->file_header.SizeOfOptionalHeader,
				(ut8*)bin->section_header, sections_size) == -1) {
		eprintf ("Warning: read (sections)\n");
		return false;
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
	return true;
}

int PE_(bin_pe_get_claimed_checksum)(struct PE_(r_bin_pe_obj_t) *bin) {
	if (!bin || !bin->optional_header) {
		return 0;
	}
	return bin->optional_header->CheckSum;
}

int PE_(bin_pe_get_actual_checksum)(struct PE_(r_bin_pe_obj_t) *bin) {
	int i, j, checksum_offset = 0;
	ut8 *buf = NULL;
	ut64 computed_cs = 0;
	int remaining_bytes;
	int shift;
	ut32 cur;
	if (!bin || !bin->nt_header_offset) {
		return 0;
	}
	buf = bin->b->buf;
	checksum_offset = bin->nt_header_offset + 4 + sizeof(PE_(image_file_header)) + 0x40;
	for (i = 0; i < bin->size / 4; i++) {
		cur = (buf[i * 4] << 0)  |
			  (buf[i * 4 + 1] << 8)  |
			  (buf[i * 4 + 2] << 16) |
			  (buf[i * 4 + 3] << 24);

		// skip the checksum bytes
		if (i * 4 == checksum_offset) {
			continue;
		}

		computed_cs = (computed_cs & 0xFFFFFFFF) + cur + (computed_cs >> 32);
		if (computed_cs >> 32) {
			computed_cs = (computed_cs & 0xFFFFFFFF) + (computed_cs >> 32);
		}
	}

	// add resultant bytes to checksum
	remaining_bytes = bin->size % 4;
	i = i * 4;
	if (remaining_bytes != 0) {
		cur = buf[i];
		shift = 8;
		for (j = 1; j < remaining_bytes; j++, shift += 8) {
			cur |= buf[i + j] << shift;
		}
		computed_cs = (computed_cs & 0xFFFFFFFF) + cur + (computed_cs >> 32);
		if (computed_cs >> 32) {
			computed_cs = (computed_cs & 0xFFFFFFFF) + (computed_cs >> 32);
		}
	}

	// 32bits -> 16bits
	computed_cs = (computed_cs & 0xFFFF) + (computed_cs >> 16);
	computed_cs = (computed_cs)          + (computed_cs >> 16);
	computed_cs = (computed_cs & 0xFFFF);

	// add filesize
	computed_cs += bin->size;
	return computed_cs;
}

static int bin_pe_init_imports(struct PE_(r_bin_pe_obj_t) *bin) {
	PE_(image_data_directory) *data_dir_import = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_IMPORT];
	PE_(image_data_directory) *data_dir_delay_import = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

	PE_DWord import_dir_paddr  = bin_pe_rva_to_paddr (bin, data_dir_import->VirtualAddress);
	PE_DWord import_dir_offset = bin_pe_rva_to_paddr (bin, data_dir_import->VirtualAddress);
	PE_DWord delay_import_dir_offset = data_dir_delay_import
					   ? bin_pe_rva_to_paddr (bin, data_dir_delay_import->VirtualAddress)
					   : 0;

	PE_(image_import_directory) *import_dir      = NULL;
	PE_(image_import_directory) *new_import_dir  = NULL;
	PE_(image_import_directory) *curr_import_dir = NULL;

	PE_(image_delay_import_directory) *delay_import_dir      = NULL;
	PE_(image_delay_import_directory) *curr_delay_import_dir = NULL;

	int dir_size = sizeof(PE_(image_import_directory));
	int delay_import_size = sizeof(PE_(image_delay_import_directory));
	int indx = 0;
	int rr, count = 0;
	int import_dir_size = data_dir_import->Size;
	int delay_import_dir_size = data_dir_delay_import->Size;
	/// HACK to modify import size because of begin 0.. this may report wrong info con corkami tests
	if (!import_dir_size) {
		// asume 1 entry for each
		import_dir_size = data_dir_import->Size = 0xffff;
	}
	if (!delay_import_dir_size) {
		// asume 1 entry for each
		delay_import_dir_size = data_dir_delay_import->Size = 0xffff;
	}
	int maxidsz = R_MIN ((PE_DWord)bin->size, import_dir_offset + import_dir_size);
	maxidsz    -= import_dir_offset;
	if (maxidsz < 0) maxidsz = 0;
	//int maxcount = maxidsz/ sizeof (struct r_bin_pe_import_t);

	free (bin->import_directory);
	bin->import_directory = NULL;
	if (import_dir_paddr != 0) {
		if (import_dir_size < 1 || import_dir_size > maxidsz) {
			eprintf ("Warning: Invalid import directory size: 0x%x is now 0x%x\n", import_dir_size, maxidsz);
			import_dir_size = maxidsz;
		}
		bin->import_directory_offset = import_dir_offset;
		count = 0;
		do {
			indx++;
			if (((2+indx)*dir_size) > import_dir_size) {
				break; //goto fail;
			}
			new_import_dir = (PE_(image_import_directory) *)realloc (import_dir, ((1 + indx) * dir_size));
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
			if (r_buf_read_at (bin->b, import_dir_offset + (indx - 1) * dir_size, (ut8*)(curr_import_dir), dir_size) < 1) {
				eprintf ("Warning: read (import directory)\n");
				free (import_dir);
				import_dir = NULL;
				break; //return false;
			}
			count ++;
		} while (curr_import_dir->FirstThunk != 0 || curr_import_dir->Name != 0 ||
				curr_import_dir->TimeDateStamp != 0 || curr_import_dir->Characteristics != 0 ||
				curr_import_dir->ForwarderChain != 0);

		bin->import_directory = import_dir;
		bin->import_directory_size = import_dir_size;
	}

	indx = 0;
	if (bin->b->length > 0) {
		if ((delay_import_dir_offset != 0) && (delay_import_dir_offset < (ut32)bin->b->length)) {
			ut64 off;
			bin->delay_import_directory_offset = delay_import_dir_offset;
			do {
				indx++;
				off = indx * delay_import_size;
				if (off >= bin->b->length) {
					eprintf ("Warning: Cannot find end of import symbols\n");
					break;
				}
				delay_import_dir = (PE_(image_delay_import_directory) *)realloc (
				  delay_import_dir, (indx * delay_import_size) + 1);
				if (delay_import_dir == 0) {
					r_sys_perror ("malloc (delay import directory)");
					free (delay_import_dir);
					return false;
				}

				curr_delay_import_dir = delay_import_dir + (indx - 1);
				rr = r_buf_read_at (bin->b, delay_import_dir_offset + (indx - 1) * delay_import_size,
				  (ut8*)(curr_delay_import_dir), dir_size);
				if (rr != dir_size) {
					eprintf("Warning: read (delay import directory)\n");
					goto fail;
				}
			} while (curr_delay_import_dir->Name != 0);
			bin->delay_import_directory = delay_import_dir;
		}
	}

	return true;
fail:
	free (import_dir);
	import_dir = NULL;
	bin->import_directory = import_dir;
	free (delay_import_dir);
	return false;
}

static int bin_pe_init_exports(struct PE_(r_bin_pe_obj_t) *bin) {
	PE_(image_data_directory) *data_dir_export = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_EXPORT];
	PE_DWord export_dir_paddr = bin_pe_rva_to_paddr (bin, data_dir_export->VirtualAddress);
	if (!export_dir_paddr) {
		// This export-dir-paddr should only appear in DLL files
		//eprintf ("Warning: Cannot find the paddr of the export directory\n");
		return false;
	}
	//sdb_setn (DB, "hdr.exports_directory", export_dir_paddr);
//eprintf ("Pexports paddr at 0x%"PFMT64x"\n", export_dir_paddr);
	if (!(bin->export_directory = malloc (sizeof(PE_(image_export_directory))))) {
		r_sys_perror ("malloc (export directory)");
		return false;
	}
	if (r_buf_read_at (bin->b, export_dir_paddr, (ut8*)bin->export_directory, sizeof (PE_(image_export_directory))) == -1) {
		eprintf ("Warning: read (export directory)\n");
		free (bin->export_directory);
		bin->export_directory = NULL;
		return false;
	}
	return true;
}

static int bin_pe_init_resource(struct PE_(r_bin_pe_obj_t)* bin) {
	PE_(image_data_directory) *resource_dir = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_RESOURCE];
	PE_DWord resource_dir_paddr = bin_pe_rva_to_paddr (bin, resource_dir->VirtualAddress);
	if (!resource_dir_paddr) {
		return false;
	}
	if (!(bin->resource_directory = malloc (sizeof(*bin->resource_directory)))) {
		r_sys_perror ("malloc (resource directory)");
		return false;
	}
	if (r_buf_read_at (bin->b, resource_dir_paddr, (ut8*)bin->resource_directory,
			sizeof (*bin->resource_directory)) != sizeof (*bin->resource_directory)) {
		eprintf ("Warning: read (resource directory)\n");
		free (bin->resource_directory);
		bin->resource_directory = NULL;
		return false;
	}
	bin->resource_directory_offset = resource_dir_paddr;
	return true;
}

static void bin_pe_store_tls_callbacks(struct PE_(r_bin_pe_obj_t) *bin, PE_DWord callbacks) {
	PE_DWord paddr;
	int count = 0;
	PE_DWord addressOfTLSCallback = 1;
	char *key;

	while (addressOfTLSCallback != 0) {
		if (r_buf_read_at (bin->b, callbacks, (ut8*)&addressOfTLSCallback, sizeof(addressOfTLSCallback)) != sizeof (addressOfTLSCallback)) {
			eprintf("Warning: read (tls_callback)\n");
			return;
		}
		if (!addressOfTLSCallback) {
			break;
		}
		if (bin->optional_header->SizeOfImage) {
			int rva_callback = bin_pe_va_to_rva (bin, (PE_DWord) addressOfTLSCallback);
			if (rva_callback > bin->optional_header->SizeOfImage) break;
		}
		key = sdb_fmt (0, "pe.tls_callback%d_vaddr", count);
		sdb_num_set (bin->kv, key, addressOfTLSCallback, 0);
		key = sdb_fmt (0, "pe.tls_callback%d_paddr", count);
		paddr = bin_pe_rva_to_paddr (bin, bin_pe_va_to_rva(bin, (PE_DWord) addressOfTLSCallback));
		sdb_num_set (bin->kv, key, paddr, 0);
		count++;
		callbacks += sizeof (addressOfTLSCallback);
	}
}

static int bin_pe_init_tls(struct PE_(r_bin_pe_obj_t) *bin) {
	PE_(image_tls_directory) *image_tls_directory;
	PE_(image_data_directory) *data_dir_tls = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_TLS];
	PE_DWord tls_paddr = bin_pe_rva_to_paddr (bin, data_dir_tls->VirtualAddress);

	image_tls_directory = R_NEW0 (PE_(image_tls_directory));
	if (r_buf_read_at (bin->b, tls_paddr, (ut8*)image_tls_directory, sizeof (PE_(image_tls_directory))) != sizeof (PE_(image_tls_directory))) {
		eprintf ("Warning: read (image_tls_directory)\n");
		free(image_tls_directory);
		return 0;
	}
	bin->tls_directory = image_tls_directory;
	if (!image_tls_directory->AddressOfCallBacks) {
		return 0;
	}
	PE_DWord callbacks_paddr = bin_pe_rva_to_paddr (bin, bin_pe_va_to_rva(bin, (PE_DWord) image_tls_directory->AddressOfCallBacks));
	bin_pe_store_tls_callbacks (bin, callbacks_paddr);
	return 0;
}

static void free_Var(Var *var) {
	if (var) {
		free(var->szKey);
		free(var->Value);
		free(var);
	}
}

static void free_VarFileInfo(VarFileInfo *varFileInfo) {
	if (varFileInfo) {
		free(varFileInfo->szKey);
		if (varFileInfo->Children) {
			ut32 children = 0;
			for (;children < varFileInfo->numOfChildren; children++) {
				free_Var(varFileInfo->Children[children]);
			}
			free(varFileInfo->Children);
		}
		free(varFileInfo);
	}
}

static void free_String(String *string) {
	if (string) {
		free(string->szKey);
		free(string->Value);
		free(string);
	}
}

static void free_StringTable(StringTable *stringTable) {
	if (stringTable) {
		free(stringTable->szKey);
		if (stringTable->Children) {
			ut32 childrenST = 0;
			for (;childrenST < stringTable->numOfChildren; childrenST++) {
				free_String(stringTable->Children[childrenST]);
			}
			free(stringTable->Children);
		}
		free(stringTable);
	}
}

static void free_StringFileInfo(StringFileInfo *stringFileInfo) {
	if (stringFileInfo) {
		free(stringFileInfo->szKey);
		if (stringFileInfo->Children) {
			ut32 childrenSFI = 0;
			for (;childrenSFI < stringFileInfo->numOfChildren; childrenSFI++) {
				free_StringTable(stringFileInfo->Children[childrenSFI]);
			}
			free(stringFileInfo->Children);
		}
		free(stringFileInfo);
	}
}

#define align32(x) x = ((x & 0x3) == 0)? x: (x & ~0x3) + 0x4;

static void free_VS_VERSIONINFO(PE_VS_VERSIONINFO *vs_VersionInfo) {
	if (vs_VersionInfo) {
		free(vs_VersionInfo->szKey);
		free(vs_VersionInfo->Value);
		free_VarFileInfo(vs_VersionInfo->varFileInfo);
		free_StringFileInfo(vs_VersionInfo->stringFileInfo);
		free(vs_VersionInfo);
	}
}

void PE_(free_VS_VERSIONINFO)(PE_VS_VERSIONINFO *vs_VersionInfo) {
	free_VS_VERSIONINFO(vs_VersionInfo);
}

static Var *Pe_r_bin_pe_parse_var(struct PE_(r_bin_pe_obj_t)* bin, PE_DWord *curAddr) {
	Var *var = calloc (1, sizeof(*var));
	if (!var) {
		eprintf ("Warning: calloc (Var)\n");
		return NULL;
	}
	if (r_buf_read_at(bin->b, *curAddr, (ut8*)&var->wLength, sizeof(var->wLength)) != sizeof(var->wLength)) {
		eprintf ("Warning: read (Var wLength)\n");
		free_Var(var);
		return NULL;
	}
	*curAddr += sizeof(var->wLength);
	if (r_buf_read_at(bin->b, *curAddr, (ut8*)&var->wValueLength, sizeof(var->wValueLength)) != sizeof(var->wValueLength)) {
		eprintf ("Warning: read (Var wValueLength)\n");
		free_Var(var);
		return NULL;
	}
	*curAddr += sizeof(var->wValueLength);
	if (r_buf_read_at(bin->b, *curAddr, (ut8*)&var->wType, sizeof(var->wType)) != sizeof(var->wType)) {
		eprintf ("Warning: read (Var wType)\n");
		free_Var(var);
		return NULL;
	}
	*curAddr += sizeof(var->wType);
	if (var->wType != 0 && var->wType != 1) {
		eprintf ("Warning: check (Var wType)\n");
		free_Var(var);
		return NULL;
	}
	var->szKey = (ut16 *) malloc (TRANSLATION_UTF_16_LEN); //L"Translation"
	if (!var->szKey) {
		eprintf ("Warning: malloc (Var szKey)\n");
		free_Var(var);
		return NULL;
	}
	if (r_buf_read_at(bin->b, *curAddr, (ut8*)var->szKey, TRANSLATION_UTF_16_LEN) != TRANSLATION_UTF_16_LEN) {
		eprintf ("Warning: read (Var szKey)\n");
		free_Var(var);
		return NULL;
	}
	*curAddr += TRANSLATION_UTF_16_LEN;
	if (memcmp(var->szKey, TRANSLATION_UTF_16, TRANSLATION_UTF_16_LEN)) {
		eprintf ("Warning: check (Var szKey)\n");
		free_Var(var);
		return NULL;
	}
	align32(*curAddr);
	var->numOfValues = var->wValueLength / 4;
	if (!var->numOfValues) {
		eprintf ("Warning: check (Var numOfValues)\n");
		free_Var(var);
		return NULL;
	}
	var->Value = (ut32 *) malloc (var->wValueLength);
	if (!var->Value) {
		eprintf ("Warning: malloc (Var Value)\n");
		free_Var(var);
		return NULL;
	}
	if (r_buf_read_at(bin->b, *curAddr, (ut8*)var->Value, var->wValueLength) != var->wValueLength) {
		eprintf ("Warning: read (Var Value)\n");
		free_Var(var);
		return NULL;
	}
	*curAddr += var->wValueLength;
	return var;
}

static VarFileInfo *Pe_r_bin_pe_parse_var_file_info(struct PE_(r_bin_pe_obj_t)* bin, PE_DWord *curAddr) {
	VarFileInfo *varFileInfo = calloc (1, sizeof(*varFileInfo));
	if (!varFileInfo) {
		eprintf ("Warning: calloc (VarFileInfo)\n");
		return NULL;
	}
	PE_DWord startAddr = *curAddr;
	if (r_buf_read_at(bin->b, *curAddr, (ut8*)&varFileInfo->wLength, sizeof(varFileInfo->wLength)) != sizeof(varFileInfo->wLength)) {
		eprintf ("Warning: read (VarFileInfo wLength)\n");
		free_VarFileInfo(varFileInfo);
		return NULL;
	}
	*curAddr += sizeof(varFileInfo->wLength);

	if (r_buf_read_at(bin->b, *curAddr, (ut8*)&varFileInfo->wValueLength, sizeof(varFileInfo->wValueLength)) != sizeof(varFileInfo->wValueLength)) {
		eprintf ("Warning: read (VarFileInfo wValueLength)\n");
		free_VarFileInfo(varFileInfo);
		return NULL;
	}
	*curAddr += sizeof(varFileInfo->wValueLength);

	if (varFileInfo->wValueLength != 0) {
		eprintf ("Warning: check (VarFileInfo wValueLength)\n");
		free_VarFileInfo(varFileInfo);
		return NULL;
	}

	if (r_buf_read_at(bin->b, *curAddr, (ut8*)&varFileInfo->wType, sizeof(varFileInfo->wType)) != sizeof(varFileInfo->wType)) {
		eprintf ("Warning: read (VarFileInfo wType)\n");
		free_VarFileInfo(varFileInfo);
		return NULL;
	}
	*curAddr += sizeof(varFileInfo->wType);
	if (varFileInfo->wType && varFileInfo->wType != 1) {
		eprintf ("Warning: check (VarFileInfo wType)\n");
		free_VarFileInfo(varFileInfo);
		return NULL;
	}

	varFileInfo->szKey = (ut16 *) malloc (VARFILEINFO_UTF_16_LEN); //L"VarFileInfo"
	if (!varFileInfo->szKey) {
		eprintf ("Warning: malloc (VarFileInfo szKey)\n");
		free_VarFileInfo(varFileInfo);
		return NULL;
	}

	if (r_buf_read_at(bin->b, *curAddr, (ut8*)varFileInfo->szKey, VARFILEINFO_UTF_16_LEN) != VARFILEINFO_UTF_16_LEN) {
		eprintf ("Warning: read (VarFileInfo szKey)\n");
		free_VarFileInfo(varFileInfo);
		return NULL;
	}
	*curAddr += VARFILEINFO_UTF_16_LEN;

	if (memcmp(varFileInfo->szKey, VARFILEINFO_UTF_16, VARFILEINFO_UTF_16_LEN)) {
		eprintf ("Warning: check (VarFileInfo szKey)\n");
		free_VarFileInfo(varFileInfo);
		return NULL;
	}
	align32(*curAddr);
	while (startAddr + varFileInfo->wLength > *curAddr) {
		Var **tmp = (Var **) realloc(varFileInfo->Children, (varFileInfo->numOfChildren + 1) * sizeof(*varFileInfo->Children));
		if (!tmp) {
			eprintf ("Warning: realloc (VarFileInfo Children)\n");
			free_VarFileInfo(varFileInfo);
			return NULL;
		}
		varFileInfo->Children = tmp;
		if (!(varFileInfo->Children[varFileInfo->numOfChildren] = Pe_r_bin_pe_parse_var(bin, curAddr))) {
			eprintf ("Warning: bad parsing Var\n");
			free_VarFileInfo(varFileInfo);
			return NULL;
		}
		varFileInfo->numOfChildren++;
		align32(*curAddr);
	}
	return varFileInfo;
}

static String *Pe_r_bin_pe_parse_string(struct PE_(r_bin_pe_obj_t)* bin, PE_DWord *curAddr) {
	String *string = calloc (1, sizeof(*string));
	PE_DWord begAddr = *curAddr;
	int len_value = 0;
	int i = 0;
	if (!string) {
		eprintf ("Warning: calloc (String)\n");
		return NULL;
	}
	if (begAddr > bin->size || begAddr + sizeof(string->wLength) > bin->size) {
		return NULL;
	}
	if (r_buf_read_at(bin->b, *curAddr, (ut8*)&string->wLength, sizeof(string->wLength)) != sizeof(string->wLength)) {
		eprintf ("Warning: read (String wLength)\n");
		goto out_error;
	}
	*curAddr += sizeof(string->wLength);
	if (*curAddr > bin->size || *curAddr + sizeof(string->wValueLength) > bin->size) {
		goto out_error;
	}
	if (r_buf_read_at(bin->b, *curAddr, (ut8*)&string->wValueLength, sizeof(string->wValueLength)) != sizeof(string->wValueLength)) {
		eprintf ("Warning: read (String wValueLength)\n");
		goto out_error;
	}
	*curAddr += sizeof(string->wValueLength);

	if (*curAddr > bin->size || *curAddr + sizeof(string->wType) > bin->size) {
		goto out_error;
	}
	if (r_buf_read_at(bin->b, *curAddr, (ut8*)&string->wType, sizeof(string->wType)) != sizeof(string->wType)) {
		eprintf ("Warning: read (String wType)\n");
		goto out_error;
	}
	*curAddr += sizeof(string->wType);
	if (string->wType != 0 && string->wType != 1) {
		eprintf ("Warning: check (String wType)\n");
		goto out_error;
	}

	for (i = 0; *curAddr < begAddr + string->wLength; ++i, *curAddr += sizeof (ut16)) {
		ut16 utf16_char;
		if (*curAddr > bin->size || *curAddr + sizeof (ut16) > bin->size) {
			goto out_error;
		}
		if (r_buf_read_at(bin->b, *curAddr, (ut8*)&utf16_char, sizeof (ut16)) != sizeof (ut16)) {
			eprintf ("Warning: check (String szKey)\n");
			goto out_error;
		}
		string->szKey = (ut16*)realloc (string->szKey, (i + 1) * sizeof (ut16));
		string->szKey[i] = utf16_char;
		string->wKeyLen += sizeof (ut16);
		if (!utf16_char) {
			*curAddr += sizeof (ut16);
			break;
		}
	}
	align32(*curAddr);
	len_value = R_MIN (string->wValueLength * 2, string->wLength - (*curAddr - begAddr));
	string->wValueLength = len_value;
	if (len_value < 0) {
		len_value = 0;
	}
	string->Value = (ut16 *) calloc (len_value + 1, 1);
	if (!string->Value) {
		eprintf ("Warning: malloc (String Value)\n");
		goto out_error;
	}
	if (*curAddr > bin->size || *curAddr + len_value > bin->size) {
		goto out_error;
	}
	if (r_buf_read_at(bin->b, *curAddr, (ut8*)string->Value, len_value) != len_value) {
		eprintf ("Warning: read (String Value)\n");
		goto out_error;
	}
	*curAddr += len_value;
	return string;
out_error:
	free_String (string);
	return NULL;
}

static StringTable *Pe_r_bin_pe_parse_string_table(struct PE_(r_bin_pe_obj_t)* bin, PE_DWord *curAddr) {
	StringTable *stringTable = calloc (1, sizeof(*stringTable));
	if (!stringTable) {
		eprintf ("Warning: calloc (stringTable)\n");
		return NULL;
	}

	PE_DWord startAddr = *curAddr;
	if (r_buf_read_at(bin->b, *curAddr, (ut8*)&stringTable->wLength, sizeof(stringTable->wLength)) != sizeof(stringTable->wLength)) {
		eprintf ("Warning: read (StringTable wLength)\n");
		free_StringTable(stringTable);
		return NULL;
	}
	*curAddr += sizeof(stringTable->wLength);

	if (r_buf_read_at(bin->b, *curAddr, (ut8*)&stringTable->wValueLength, sizeof(stringTable->wValueLength)) != sizeof(stringTable->wValueLength)) {
		eprintf ("Warning: read (StringTable wValueLength)\n");
		free_StringTable(stringTable);
		return NULL;
	}
	*curAddr += sizeof(stringTable->wValueLength);

	if (stringTable->wValueLength) {
		eprintf ("Warning: check (StringTable wValueLength)\n");
		free_StringTable(stringTable);
		return NULL;
	}

	if (r_buf_read_at(bin->b, *curAddr, (ut8*)&stringTable->wType, sizeof(stringTable->wType)) != sizeof(stringTable->wType)) {
		eprintf ("Warning: read (StringTable wType)\n");
		free_StringTable(stringTable);
		return NULL;
	}
	*curAddr += sizeof(stringTable->wType);
	if (stringTable->wType && stringTable->wType != 1) {
		eprintf ("Warning: check (StringTable wType)\n");
		free_StringTable(stringTable);
		return NULL;
	}
	stringTable->szKey = (ut16 *) malloc (EIGHT_HEX_DIG_UTF_16_LEN); //EIGHT_HEX_DIG_UTF_16_LEN
	if (!stringTable->szKey) {
		eprintf ("Warning: malloc (stringTable szKey)\n");
		free_StringTable(stringTable);
		return NULL;
	}

	if (r_buf_read_at(bin->b, *curAddr, (ut8*)stringTable->szKey, EIGHT_HEX_DIG_UTF_16_LEN) != EIGHT_HEX_DIG_UTF_16_LEN) {
		eprintf ("Warning: read (StringTable szKey)\n");
		free_StringTable(stringTable);
		return NULL;
	}
	*curAddr += EIGHT_HEX_DIG_UTF_16_LEN;
	align32(*curAddr);
	while (startAddr + stringTable->wLength > *curAddr) {
		String **tmp = (String **) realloc(stringTable->Children, (stringTable->numOfChildren + 1) * sizeof(*stringTable->Children));
		if (!tmp) {
			eprintf ("Warning: realloc (StringTable Children)\n");
			free_StringTable(stringTable);
			return NULL;
		}
		stringTable->Children = tmp;
		if (!(stringTable->Children[stringTable->numOfChildren] = Pe_r_bin_pe_parse_string(bin, curAddr))) {
			eprintf ("Warning: bad parsing String\n");
			free_StringTable(stringTable);
			return NULL;
		}
		stringTable->numOfChildren++;
		align32(*curAddr);
	}

	if (!stringTable->numOfChildren) {
		eprintf ("Warning: check (StringTable numOfChildren)\n");
		free_StringTable(stringTable);
		return NULL;
	}

	return stringTable;
}

static StringFileInfo *Pe_r_bin_pe_parse_string_file_info(struct PE_(r_bin_pe_obj_t)* bin, PE_DWord *curAddr) {
	StringFileInfo *stringFileInfo = calloc (1, sizeof(*stringFileInfo));
	if (!stringFileInfo) {
		eprintf ("Warning: calloc (StringFileInfo)\n");
		return NULL;
	}

	PE_DWord startAddr = *curAddr;

	if (r_buf_read_at(bin->b, *curAddr, (ut8*)&stringFileInfo->wLength, sizeof(stringFileInfo->wLength)) != sizeof(stringFileInfo->wLength)) {
		eprintf ("Warning: read (StringFileInfo wLength)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}
	*curAddr += sizeof(stringFileInfo->wLength);

	if (r_buf_read_at(bin->b, *curAddr, (ut8*)&stringFileInfo->wValueLength, sizeof(stringFileInfo->wValueLength)) != sizeof(stringFileInfo->wValueLength)) {
		eprintf ("Warning: read (StringFileInfo wValueLength)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}
	*curAddr += sizeof(stringFileInfo->wValueLength);

	if (stringFileInfo->wValueLength) {
		eprintf ("Warning: check (StringFileInfo wValueLength)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}

	if (r_buf_read_at(bin->b, *curAddr, (ut8*)&stringFileInfo->wType, sizeof(stringFileInfo->wType)) != sizeof(stringFileInfo->wType)) {
		eprintf ("Warning: read (StringFileInfo wType)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}
	*curAddr += sizeof(stringFileInfo->wType);

	if (stringFileInfo->wType && stringFileInfo->wType != 1) {
		eprintf ("Warning: check (StringFileInfo wType)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}

	stringFileInfo->szKey = (ut16 *) malloc (STRINGFILEINFO_UTF_16_LEN); //L"StringFileInfo"
	if (!stringFileInfo->szKey) {
		eprintf ("Warning: malloc (StringFileInfo szKey)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}

	if (r_buf_read_at(bin->b, *curAddr, (ut8*)stringFileInfo->szKey, STRINGFILEINFO_UTF_16_LEN) != STRINGFILEINFO_UTF_16_LEN) {
		eprintf ("Warning: read (StringFileInfo szKey)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}
	*curAddr += STRINGFILEINFO_UTF_16_LEN;

	if (memcmp(stringFileInfo->szKey, STRINGFILEINFO_UTF_16, STRINGFILEINFO_UTF_16_LEN) != 0) {
		eprintf ("Warning: check (StringFileInfo szKey)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}

	align32(*curAddr);

	while (startAddr + stringFileInfo->wLength > *curAddr) {
		StringTable **tmp = (StringTable **) realloc(stringFileInfo->Children, (stringFileInfo->numOfChildren + 1) * sizeof(*stringFileInfo->Children));
		if (!tmp) {
			eprintf ("Warning: realloc (StringFileInfo Children)\n");
			free_StringFileInfo(stringFileInfo);
			return NULL;
		}
		stringFileInfo->Children = tmp;
		if (!(stringFileInfo->Children[stringFileInfo->numOfChildren] = Pe_r_bin_pe_parse_string_table(bin, curAddr))) {
			eprintf ("Warning: bad parsing StringTable\n");
			free_StringFileInfo(stringFileInfo);
			return NULL;
		}
		stringFileInfo->numOfChildren++;
		align32(*curAddr);
	}

	if (!stringFileInfo->numOfChildren) {
		eprintf ("Warning: check (StringFileInfo numOfChildren)\n");
		free_StringFileInfo(stringFileInfo);
		return NULL;
	}

	return stringFileInfo;
}

#define EXIT_ON_OVERFLOW(S) \
	if (curAddr > bin->size || curAddr + (S) > bin->size) \
		goto out_error;
static PE_VS_VERSIONINFO *Pe_r_bin_pe_parse_version_info(struct PE_(r_bin_pe_obj_t)* bin, PE_DWord version_info_paddr) {
	ut32 sz;
	PE_VS_VERSIONINFO *vs_VersionInfo = calloc (1, sizeof(PE_VS_VERSIONINFO));
	if (!vs_VersionInfo) {
		return NULL;
	}
	PE_DWord startAddr = version_info_paddr;
	PE_DWord curAddr = version_info_paddr;
	//align32(curAddr); // XXX: do we really need this? Because in msdn
	//wLength is The length, in bytes, of the VS_VERSIONINFO structure.
	//This length does not include any padding that aligns any subsequent
	//version resource data on a 32-bit boundary.
	//Mb we are in subsequent version resource data and not aligned.
	sz = sizeof(ut16);
	EXIT_ON_OVERFLOW(sz);
	if (r_buf_read_at(bin->b, curAddr, (ut8*)&vs_VersionInfo->wLength, sz) != sz) {
		eprintf ("Warning: read (VS_VERSIONINFO wLength)\n");
		goto out_error;
	}
	curAddr += sz;
	EXIT_ON_OVERFLOW(sz);
	if (r_buf_read_at(bin->b, curAddr, (ut8*)&vs_VersionInfo->wValueLength, sz) != sz) {
		eprintf ("Warning: read (VS_VERSIONINFO wValueLength)\n");
		goto out_error;
	}
	curAddr += sz;
	EXIT_ON_OVERFLOW(sz);
	if (r_buf_read_at(bin->b, curAddr, (ut8*)&vs_VersionInfo->wType, sz) != sz) {
		eprintf ("Warning: read (VS_VERSIONINFO wType)\n");
		goto out_error;
	}
	curAddr += sz;
	if (vs_VersionInfo->wType && vs_VersionInfo->wType != 1) {
		eprintf ("Warning: check (VS_VERSIONINFO wType)\n");
		goto out_error;
	}

	vs_VersionInfo->szKey = (ut16 *) malloc (VS_VERSION_INFO_UTF_16_LEN); //L"VS_VERSION_INFO"
	if (!vs_VersionInfo->szKey) {
		eprintf ("Warning: malloc (VS_VERSIONINFO szKey)\n");
		goto out_error;
	}
	sz = VS_VERSION_INFO_UTF_16_LEN;
	EXIT_ON_OVERFLOW(sz);
	if (r_buf_read_at (bin->b, curAddr, (ut8*)vs_VersionInfo->szKey, sz) != sz) {
		eprintf ("Warning: read (VS_VERSIONINFO szKey)\n");
		goto out_error;
	}
	curAddr += sz;
	if (memcmp (vs_VersionInfo->szKey, VS_VERSION_INFO_UTF_16, sz)) {
		goto out_error;
	}
	align32 (curAddr);
	if (vs_VersionInfo->wValueLength) {
		if (vs_VersionInfo->wValueLength != sizeof (*vs_VersionInfo->Value)) {
			eprintf ("Warning: check (VS_VERSIONINFO wValueLength != sizeof PE_VS_FIXEDFILEINFO)\n");
			goto out_error;
		}

		vs_VersionInfo->Value = (PE_VS_FIXEDFILEINFO *) malloc (sizeof(*vs_VersionInfo->Value));
		if (!vs_VersionInfo->Value) {
			eprintf ("Warning: malloc (VS_VERSIONINFO Value)\n");
			goto out_error;
		}
		sz = sizeof(PE_VS_FIXEDFILEINFO);
		EXIT_ON_OVERFLOW(sz);
		if (r_buf_read_at (bin->b, curAddr, (ut8*)vs_VersionInfo->Value, sz) != sz) {
			eprintf ("Warning: read (VS_VERSIONINFO Value)\n");
			goto out_error;
		}

		if (vs_VersionInfo->Value->dwSignature != 0xFEEF04BD) {
			eprintf ("Warning: check (PE_VS_FIXEDFILEINFO signature) 0x%08x\n", vs_VersionInfo->Value->dwSignature);
			goto out_error;
		}
		curAddr += sz;
		align32(curAddr);
	}

	if (startAddr + vs_VersionInfo->wLength > curAddr) {
		char t = '\0';
		if (curAddr + 3 * sizeof(ut16) > bin->size || curAddr + 3 + sizeof(ut64) + 1 > bin->size) {
			goto out_error;
		}
		if (r_buf_read_at(bin->b, curAddr + 3 * sizeof(ut16), (ut8*)&t, 1) != 1) {
			eprintf ("Warning: read (VS_VERSIONINFO Children V or S)\n");
			goto out_error;
		}
		if (!(t == 'S' || t == 'V')) {
			eprintf ("Warning: bad type (VS_VERSIONINFO Children)\n");
			goto out_error;
		}
		if (t == 'S') {
			if (!(vs_VersionInfo->stringFileInfo = Pe_r_bin_pe_parse_string_file_info(bin, &curAddr))) {
				eprintf ("Warning: bad parsing (VS_VERSIONINFO StringFileInfo)\n");
				goto out_error;
			}
		}
		if (t == 'V') {
			if (!(vs_VersionInfo->varFileInfo = Pe_r_bin_pe_parse_var_file_info(bin, &curAddr))) {
				eprintf ("Warning: bad parsing (VS_VERSIONINFO VarFileInfo)\n");
				goto out_error;
			}
		}

		align32(curAddr);

		if (startAddr + vs_VersionInfo->wLength > curAddr) {
			if (t == 'V') {
				if (!(vs_VersionInfo->stringFileInfo = Pe_r_bin_pe_parse_string_file_info(bin, &curAddr))) {
					eprintf ("Warning: bad parsing (VS_VERSIONINFO StringFileInfo)\n");
					goto out_error;
				}
			} else if (t == 'S') {
				if (!(vs_VersionInfo->varFileInfo = Pe_r_bin_pe_parse_var_file_info(bin, &curAddr))) {
					eprintf ("Warning: bad parsing (VS_VERSIONINFO VarFileInfo)\n");
					goto out_error;
				}
			}
			if (startAddr + vs_VersionInfo->wLength > curAddr) {
				eprintf ("Warning: bad parsing (VS_VERSIONINFO wLength left)\n");
				goto out_error;
			}
		}
	}
	return vs_VersionInfo;
out_error:
	free_VS_VERSIONINFO(vs_VersionInfo);
	return NULL;

}

static Sdb *Pe_r_bin_store_var(Var *var) {
	unsigned int i = 0;
	char key[20];
	Sdb *sdb = NULL;
	if (var) {
		sdb = sdb_new0();
		if (sdb) {
			for (; i < var->numOfValues; i++) {
				snprintf(key, 20, "%d", i);
				sdb_num_set(sdb, key, var->Value[i], 0);
			}
		}
	}
	return sdb;
}

static Sdb *Pe_r_bin_store_var_file_info(VarFileInfo *varFileInfo) {
	char key[20];
	unsigned int i = 0;
	if (!varFileInfo) {
		return NULL;
	}
	Sdb *sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}
	for (; i < varFileInfo->numOfChildren; i++) {
		snprintf(key, 20, "var%d", i);
		sdb_ns_set (sdb, key, Pe_r_bin_store_var(varFileInfo->Children[i]));
	}
	return sdb;
}

static Sdb *Pe_r_bin_store_string(String *string) {
	Sdb *sdb = NULL; 
	char *encodedVal = NULL, *encodedKey = NULL;
	if (!string) {
		return NULL;
	}
	sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}
	encodedKey = sdb_encode((unsigned char *) string->szKey, string->wKeyLen);
	if (!encodedKey) {
		sdb_free(sdb);
		return NULL;
	}
	encodedVal = sdb_encode((unsigned char *) string->Value, string->wValueLength);
	if (!encodedVal) {
		free(encodedKey);
		sdb_free(sdb);
		return NULL;
	}
	sdb_set(sdb, "key", encodedKey, 0);
	sdb_set(sdb, "value", encodedVal, 0);
	return sdb;
}

static Sdb *Pe_r_bin_store_string_table(StringTable *stringTable) {
	char key[20];
	char *encodedKey = NULL;
	int i = 0;
	Sdb *sdb = NULL; 
	if (!stringTable) {
		return NULL;
	}
	sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}
	encodedKey = sdb_encode((unsigned char *) stringTable->szKey, EIGHT_HEX_DIG_UTF_16_LEN);
	if (!encodedKey) {
		sdb_free(sdb);
		return NULL;
	}
	sdb_set(sdb, "key", encodedKey, 0);
	for (; i < stringTable->numOfChildren; i++) {
		snprintf(key, 20, "string%d", i);
		sdb_ns_set (sdb, key, Pe_r_bin_store_string(stringTable->Children[i]));
	}
	return sdb;
}

static Sdb *Pe_r_bin_store_string_file_info(StringFileInfo *stringFileInfo) {
	char key[30];
	int i = 0;
	Sdb *sdb = NULL;
	if (!stringFileInfo) {
		return NULL;
	}
	sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}
	for (; i < stringFileInfo->numOfChildren; i++) {
		snprintf(key, 30, "stringtable%d", i);
		sdb_ns_set (sdb, key, Pe_r_bin_store_string_table(stringFileInfo->Children[i]));
	}
	return sdb;
}

static Sdb *Pe_r_bin_store_fixed_file_info(PE_VS_FIXEDFILEINFO *vs_fixedFileInfo) {
	Sdb *sdb = NULL; 
	if (!vs_fixedFileInfo) {
		return NULL;
	}
	sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}
	sdb_num_set(sdb, "Signature", vs_fixedFileInfo->dwSignature, 0);
	sdb_num_set(sdb, "StrucVersion", vs_fixedFileInfo->dwStrucVersion, 0);
	sdb_num_set(sdb, "FileVersionMS", vs_fixedFileInfo->dwFileVersionMS, 0);
	sdb_num_set(sdb, "FileVersionLS", vs_fixedFileInfo->dwFileVersionLS, 0);
	sdb_num_set(sdb, "ProductVersionMS", vs_fixedFileInfo->dwProductVersionMS, 0);
	sdb_num_set(sdb, "ProductVersionLS", vs_fixedFileInfo->dwProductVersionLS, 0);
	sdb_num_set(sdb, "FileFlagsMask", vs_fixedFileInfo->dwFileFlagsMask, 0);
	sdb_num_set(sdb, "FileFlags", vs_fixedFileInfo->dwFileFlags, 0);
	sdb_num_set(sdb, "FileOS", vs_fixedFileInfo->dwFileOS, 0);
	sdb_num_set(sdb, "FileType", vs_fixedFileInfo->dwFileType, 0);
	sdb_num_set(sdb, "FileSubtype", vs_fixedFileInfo->dwFileSubtype, 0);
	sdb_num_set(sdb, "FileDateMS", vs_fixedFileInfo->dwFileDateMS, 0);
	sdb_num_set(sdb, "FileDateLS", vs_fixedFileInfo->dwFileDateLS, 0);
	return sdb;
}

static Sdb *Pe_r_bin_store_resource_version_info(PE_VS_VERSIONINFO *vs_VersionInfo) {
	Sdb *sdb = NULL; 
	if (!vs_VersionInfo) {
		return NULL;
	}
	sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}
	if (vs_VersionInfo->Value) {
		sdb_ns_set (sdb, "fixed_file_info", Pe_r_bin_store_fixed_file_info(vs_VersionInfo->Value));
	}
	if (vs_VersionInfo->varFileInfo) {
		sdb_ns_set (sdb, "var_file_info", Pe_r_bin_store_var_file_info(vs_VersionInfo->varFileInfo));
	}
	if (vs_VersionInfo->stringFileInfo) {
		sdb_ns_set (sdb, "string_file_info", Pe_r_bin_store_string_file_info(vs_VersionInfo->stringFileInfo));
	}
	return sdb;
}

void PE_(r_bin_store_all_resource_version_info)(struct PE_(r_bin_pe_obj_t)* bin) {
	char key[30];
	ut64 off = 0;
	int counter = 0;
	Sdb *sdb = NULL;
	if (!bin || !bin->resource_directory) {
		return;
	}
	sdb = sdb_new0();
	if (!sdb) {
		return; 
	}
	// XXX: assume there is only 3 layers in the tree
	ut32 totalRes = bin->resource_directory->NumberOfNamedEntries + bin->resource_directory->NumberOfIdEntries;
	ut32 curRes = bin->resource_directory->NumberOfNamedEntries;
	for (; curRes < totalRes; curRes++) {
		Pe_image_resource_directory_entry typeEntry;
		off = bin->resource_directory_offset + sizeof (*bin->resource_directory) + curRes * sizeof (typeEntry);
		if (off > bin->size || off + sizeof(Pe_image_resource_directory_entry) > bin->size) {
			goto out_error;
		}
		if (r_buf_read_at (bin->b, off, (ut8*)&typeEntry, sizeof(Pe_image_resource_directory_entry)) < 1) {
			eprintf ("Warning: read (resource type directory entry)\n");
			goto out_error;
		}
		if (!typeEntry.u1.s.NameIsString && typeEntry.u1.Id == PE_RESOURCE_ENTRY_VERSION) {
			Pe_image_resource_directory identDir;
			off = bin->resource_directory_offset + typeEntry.u2.s.OffsetToDirectory;
			if (off > bin->size || off + sizeof(Pe_image_resource_directory) > bin->size) {
				goto out_error;
			}
			if (r_buf_read_at (bin->b, off, (ut8*)&identDir, sizeof(Pe_image_resource_directory)) < 1) {
				eprintf ("Warning: read (resource identifier directory)\n");
				goto out_error;
			}
			ut32 totalIdent = identDir.NumberOfNamedEntries + identDir.NumberOfIdEntries;
			ut32 curIdent = 0;
			for (; curIdent < totalIdent; curIdent++) {
				Pe_image_resource_directory_entry identEntry;
				off = bin->resource_directory_offset + typeEntry.u2.s.OffsetToDirectory +
					sizeof(identDir) + curIdent * sizeof(identEntry);
				if (off > bin->size || off + sizeof(Pe_image_resource_directory_entry) > bin->size) {
					goto out_error;
				}
				if (r_buf_read_at (bin->b, off, (ut8*)&identEntry, sizeof(Pe_image_resource_directory_entry)) < 1) {
					eprintf ("Warning: read (resource identifier entry)\n");
					goto out_error;
				}
				if (!identEntry.u2.s.DataIsDirectory) {
					continue;
				}
				Pe_image_resource_directory langDir;
				off = bin->resource_directory_offset + identEntry.u2.s.OffsetToDirectory;
				if (off > bin->size || off + sizeof (Pe_image_resource_directory) > bin->size) {
					goto out_error;
				}	
				if (r_buf_read_at (bin->b, off, (ut8*)&langDir, sizeof(Pe_image_resource_directory)) < 1) {
					eprintf ("Warning: read (resource language directory)\n");
					goto out_error;
				}
				ut32 totalLang = langDir.NumberOfNamedEntries + langDir.NumberOfIdEntries;
				ut32 curLang = 0;
				for (; curLang < totalLang; curLang++) {
					Pe_image_resource_directory_entry langEntry;
					off = bin->resource_directory_offset + identEntry.u2.s.OffsetToDirectory + sizeof(langDir) + curLang * sizeof(langEntry);
					if (off > bin->size || off + sizeof(Pe_image_resource_directory_entry) > bin->size) {
						goto out_error;
					}
					if (r_buf_read_at (bin->b, off, (ut8*)&langEntry, sizeof(Pe_image_resource_directory_entry)) < 1) {
						eprintf ("Warning: read (resource language entry)\n");
						goto out_error;
					}
					if (langEntry.u2.s.DataIsDirectory) {
						continue;
					}
					Pe_image_resource_data_entry data;
					off = bin->resource_directory_offset + langEntry.u2.OffsetToData;
					if (off > bin->size || off + sizeof (Pe_image_resource_data_entry) > bin->size) {
						goto out_error;
					}
					if (r_buf_read_at (bin->b, off, (ut8*)&data, sizeof (data)) != sizeof (data)) {
						eprintf ("Warning: read (resource data entry)\n");
						goto out_error;
					}
					PE_DWord data_paddr = bin_pe_rva_to_paddr(bin, data.OffsetToData);
					if (!data_paddr) {
						eprintf ("Warning: bad RVA in resource data entry\n");
						goto out_error;
					}
					PE_DWord cur_paddr = data_paddr;
					if ((cur_paddr & 0x3) != 0) {
						// XXX: mb align address and read structure?
						eprintf ("Warning: not aligned version info address\n");
						continue;
					}
					while(cur_paddr < data_paddr + data.Size && cur_paddr < bin->size) {
						PE_VS_VERSIONINFO *vs_VersionInfo = Pe_r_bin_pe_parse_version_info(bin, cur_paddr);
						if (vs_VersionInfo) {
							snprintf(key, 30, "VS_VERSIONINFO%d", counter++);
							sdb_ns_set (sdb, key, Pe_r_bin_store_resource_version_info(vs_VersionInfo));
						} else {
							break;
						}
						cur_paddr += vs_VersionInfo->wLength;
						free_VS_VERSIONINFO(vs_VersionInfo);
						align32(cur_paddr);
					}
				}
			}
		}
	}
	sdb_ns_set (bin->kv, "vs_version_info", sdb);
out_error:
	sdb_free (sdb);
	return;
}

static int bin_pe_init(struct PE_(r_bin_pe_obj_t)* bin) {
	bin->dos_header = NULL;
	bin->nt_headers = NULL;
	bin->section_header = NULL;
	bin->export_directory = NULL;
	bin->import_directory = NULL;
	bin->resource_directory = NULL;
	bin->delay_import_directory = NULL;
	bin->optional_header = NULL;
	bin->data_directory = NULL;
	bin->endian = 0; /* TODO: get endian */
	if (!bin_pe_init_hdr(bin)) {
		eprintf ("Warning: File is not PE\n");
		return false;
	}
	if (!bin_pe_init_sections(bin)) {
		eprintf ("Warning: Cannot initialize sections\n");
		return false;
	}
	bin_pe_init_imports(bin);
	bin_pe_init_exports(bin);
	bin_pe_init_resource(bin);
	bin_pe_init_tls(bin);

	PE_(r_bin_store_all_resource_version_info)(bin);
	bin->relocs = NULL;
	return true;
}

char* PE_(r_bin_pe_get_arch)(struct PE_(r_bin_pe_obj_t)* bin) {
	char *arch;
	if (!bin || !bin->nt_headers) {
		return strdup ("x86");
	}
	switch (bin->nt_headers->file_header.Machine) {
	case PE_IMAGE_FILE_MACHINE_ALPHA:
	case PE_IMAGE_FILE_MACHINE_ALPHA64:
		arch = strdup("alpha");
		break;
	case PE_IMAGE_FILE_MACHINE_RPI2: // 462
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
	static bool debug = false;
	PE_DWord pe_entry;
	int i;
	ut64 base_addr = PE_(r_bin_pe_get_image_base) (bin);
	if (!bin || !bin->optional_header) {
		return NULL;
	}
	if (!(entry = malloc (sizeof (struct r_bin_pe_addr_t)))) {
		r_sys_perror("malloc (entrypoint)");
		return NULL;
	}
	pe_entry      = bin->optional_header->AddressOfEntryPoint;
	entry->vaddr  = bin_pe_rva_to_va (bin, pe_entry);
	entry->paddr  = bin_pe_rva_to_paddr (bin, pe_entry);

	if (entry->paddr >= bin->size) {
	 	struct r_bin_pe_section_t *sections =  PE_(r_bin_pe_get_sections) (bin);
		ut64 paddr = 0;
		if (!debug) {
			eprintf ("Warning: Invalid entrypoint ... "
					"trying to fix it but i do not promise nothing\n");
		}
		for (i = 0; i < bin->num_sections; i++) {
			if (sections[i].flags & PE_IMAGE_SCN_MEM_EXECUTE) {
				entry->paddr = sections[i].paddr;
				entry->vaddr = sections[i].vaddr + base_addr;
				paddr = 1;
				break;
			}

		}
		if (!paddr) {
			ut64 min_off = -1;
			for (i = 0; i < bin->num_sections; i++) {
				//get the lowest section's paddr
				if (sections[i].paddr < min_off) {
					entry->paddr = sections[i].paddr;
					entry->vaddr = sections[i].vaddr + base_addr;
					min_off = sections[i].paddr;
				}
			}
			if (min_off == -1) {
				//no section just a hack to try to fix entrypoint
				//maybe doesn't work always
				entry->paddr = pe_entry & ((bin->optional_header->SectionAlignment << 1) - 1);
				entry->vaddr = entry->paddr + base_addr;
			}
		}
		free (sections);

	}
	if (!entry->paddr) {
		if (!debug) {
			eprintf ("Warning: NULL entrypoint\n");
		}
	 	struct r_bin_pe_section_t *sections =  PE_(r_bin_pe_get_sections) (bin);
		for (i = 0; i < bin->num_sections; i++) {
			//If there is a section with x without w perm is a good candidate to be the entrypoint
			if (sections[i].flags & PE_IMAGE_SCN_MEM_EXECUTE && !(sections[i].flags & PE_IMAGE_SCN_MEM_WRITE)) {
				entry->paddr = sections[i].paddr;
				entry->vaddr = sections[i].vaddr + base_addr;
				break;
			}

		}
		free (sections);
	}

	if (is_arm (bin) && entry->vaddr & 1) {
		entry->vaddr--;
		if (entry->paddr & 1) {
			entry->paddr--;
		}
	}
	if (!debug) {
		debug = true;
	}
	return entry;
}

struct r_bin_pe_export_t* PE_(r_bin_pe_get_exports)(struct PE_(r_bin_pe_obj_t)* bin) {
	struct r_bin_pe_export_t *exp, *exports = NULL;
	PE_Word function_ordinal;
	PE_VWord functions_paddr, names_paddr, ordinals_paddr, function_rva, name_vaddr, name_paddr;
	char function_name[PE_NAME_LENGTH + 1], forwarder_name[PE_NAME_LENGTH + 1];
	char dll_name[PE_NAME_LENGTH + 1], export_name[256];
	PE_(image_data_directory) *data_dir_export;
	PE_VWord export_dir_rva ;
	int n,i, export_dir_size;
	st64 exports_sz = 0;

	if (!bin || !bin->data_directory) {
	    return NULL;
	}

	data_dir_export = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_EXPORT];
	export_dir_rva  = data_dir_export->VirtualAddress;
	export_dir_size = data_dir_export->Size;
	if (bin->export_directory) {
		if (bin->export_directory->NumberOfFunctions + 1 <
		    bin->export_directory->NumberOfFunctions) {
			// avoid integer overflow
			return NULL;
		}
		exports_sz = (bin->export_directory->NumberOfFunctions + 1) * sizeof (struct r_bin_pe_export_t);
		if (exports_sz < 0) {
			return NULL;
		}
		if (!(exports = malloc (exports_sz))) {
			return NULL;
		}
		if (r_buf_read_at (bin->b, bin_pe_rva_to_paddr (bin, bin->export_directory->Name), (ut8*)dll_name, PE_NAME_LENGTH) < 1) {
			eprintf ("Warning: read (dll name)\n");
			free (exports);
			return NULL;
		}
		functions_paddr = bin_pe_rva_to_paddr (bin, bin->export_directory->AddressOfFunctions);
		names_paddr     = bin_pe_rva_to_paddr (bin, bin->export_directory->AddressOfNames);
		ordinals_paddr  = bin_pe_rva_to_paddr (bin, bin->export_directory->AddressOfOrdinals);
		for (i = 0; i < bin->export_directory->NumberOfFunctions; i++) {
			// get vaddr from AddressOfFunctions array
			int ret = r_buf_read_at (bin->b, functions_paddr + i * sizeof(PE_VWord), (ut8*)&function_rva, sizeof(PE_VWord));
			if (ret < 1) {
				break;
			}
			// have exports by name?
			if (bin->export_directory->NumberOfNames != 0) {
				// search for value of i into AddressOfOrdinals
				name_vaddr = 0;
				for (n = 0; n < bin->export_directory->NumberOfNames; n++) {
					ret = r_buf_read_at (bin->b, ordinals_paddr + n * sizeof(PE_Word), (ut8*)&function_ordinal, sizeof (PE_Word));
					if (ret < 1) {
						break;
					}
					// if exist this index into AddressOfOrdinals
					if (i == function_ordinal) {
						// get the VA of export name  from AddressOfNames
						r_buf_read_at (bin->b, names_paddr + n * sizeof (PE_VWord), (ut8*)&name_vaddr, sizeof (PE_VWord));
						break;
					}
				}
				// have an address into name_vaddr?
				if (name_vaddr) {
					// get the name of the Export
					name_paddr = bin_pe_rva_to_paddr (bin, name_vaddr);
					if (r_buf_read_at (bin->b, name_paddr, (ut8*)function_name, PE_NAME_LENGTH) < 1) {
						eprintf("Warning: read (function name)\n");
						free (exports);
						return NULL;
					}
				} else { // No name export, get the ordinal
					snprintf (function_name, PE_NAME_LENGTH, "Ordinal_%i", i+1);
				}
			}
			else { // if dont export by name exist, get the ordinal taking in mind the Base value.
				function_ordinal = i + bin->export_directory->Base;
				snprintf (function_name, PE_NAME_LENGTH, "Ordinal_%i", function_ordinal);
			}
			// check if VA are into export directory, this mean a forwarder export
			if (function_rva >= export_dir_rva && function_rva < (export_dir_rva + export_dir_size)) {
				// if forwarder, the VA point to Forwarded name
				if (r_buf_read_at (bin->b, bin_pe_rva_to_paddr (bin, function_rva), (ut8*)forwarder_name, PE_NAME_LENGTH) < 1) {
					eprintf ("Warning: read (magic)\n");
					free (exports);
					return NULL;
				}
			} else { // no forwarder export
				snprintf (forwarder_name, PE_NAME_LENGTH, "NONE");
			}
			dll_name[PE_NAME_LENGTH] = '\0';
			function_name[PE_NAME_LENGTH] = '\0';
			snprintf (export_name, sizeof (export_name) - 1, "%s_%s", dll_name, function_name);
			exports[i].vaddr = bin_pe_rva_to_va (bin, function_rva);
			exports[i].paddr = bin_pe_rva_to_paddr (bin, function_rva);
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
	if (exp) {
		exports = exp;
	}
	return exports;
}

int PE_(r_bin_pe_get_file_alignment)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->optional_header.FileAlignment;
}

ut64 PE_(r_bin_pe_get_image_base)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers) {
		return 0LL; 
	}	
	return (ut64)bin->nt_headers->optional_header.ImageBase;
}

static void free_rsdr_hdr(SCV_RSDS_HEADER *rsds_hdr) {
	R_FREE (rsds_hdr->file_name);
}

static void init_rsdr_hdr(SCV_RSDS_HEADER *rsds_hdr) {
	memset (rsds_hdr, 0, sizeof (SCV_RSDS_HEADER));
	rsds_hdr->free = (void (*)(struct SCV_RSDS_HEADER *)) free_rsdr_hdr;
}

static void free_cv_nb10_header(SCV_NB10_HEADER *cv_nb10_header) {
	R_FREE (cv_nb10_header->file_name);
}

static void init_cv_nb10_header(SCV_NB10_HEADER *cv_nb10_header) {
	memset (cv_nb10_header, 0, sizeof (SCV_NB10_HEADER));
	cv_nb10_header->free = (void (*)(struct SCV_NB10_HEADER *)) free_cv_nb10_header;
}

static bool get_rsds(ut8 *dbg_data, int dbg_data_len, SCV_RSDS_HEADER *res) {
	const int rsds_sz = 4 + sizeof (SGUID) + 4;
	if (dbg_data_len < rsds_sz) {
		return false;
	}
	memcpy (res, dbg_data, rsds_sz);
	res->file_name = (ut8 *)strdup ((const char *)dbg_data + rsds_sz);
	return true;
}

static void get_nb10(ut8 *dbg_data, SCV_NB10_HEADER *res) {
	const int nb10sz = 16;
	memcpy(res, dbg_data, nb10sz);
	res->file_name = (ut8 *)strdup ((const char *)dbg_data + nb10sz);
}

static int get_debug_info(PE_(image_debug_directory_entry) *dbg_dir_entry, ut8 *dbg_data, int dbg_data_len, SDebugInfo *res) {
#define SIZEOF_FILE_NAME 255
	int i = 0;
	if (!dbg_data) {
		return 0;
	}
	switch (dbg_dir_entry->Type) {
	case IMAGE_DEBUG_TYPE_CODEVIEW:
		if (!strncmp ((char *)dbg_data, "RSDS", 4)) {
			SCV_RSDS_HEADER rsds_hdr;
			init_rsdr_hdr (&rsds_hdr);
			if (!get_rsds (dbg_data, dbg_data_len, &rsds_hdr)) {
				eprintf ("Warning: Cannot read PE debug info\n");
				return 0;
			}
			snprintf (res->guidstr, GUIDSTR_LEN,
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
			snprintf (res->guidstr, sizeof (res->guidstr),
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
		res->guidstr[i] = toupper ((int)res->guidstr[i]);
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
	if (!bin) {
		return 0;
	}
	dbg_dir = &bin->nt_headers->optional_header.DataDirectory[6/*IMAGE_DIRECTORY_ENTRY_DEBUG*/];
	dbg_dir_offset = bin_pe_rva_to_paddr (bin, dbg_dir->VirtualAddress);
	if ((int)dbg_dir_offset < 0 || dbg_dir_offset >= bin->size) {
		return false;
	}
	if (dbg_dir_offset >= bin->b->length) {
		return false;
	}
	img_dbg_dir_entry = (PE_(image_debug_directory_entry)*)(bin->b->buf + dbg_dir_offset);
	if ((bin->b->length - dbg_dir_offset) < sizeof (PE_(image_debug_directory_entry))) {
		return false;
	}
	if (img_dbg_dir_entry) {
		ut32 dbg_data_poff = R_MIN (img_dbg_dir_entry->PointerToRawData, bin->b->length);
		int dbg_data_len = R_MIN (img_dbg_dir_entry->SizeOfData, bin->b->length - dbg_data_poff);
		if (dbg_data_len < 1)  {
			return false;
		}
		dbg_data = (ut8 *) calloc (1, dbg_data_len + 1);
		if (dbg_data) {
			r_buf_read_at (bin->b, dbg_data_poff, dbg_data, dbg_data_len);
			result = get_debug_info (img_dbg_dir_entry, dbg_data, dbg_data_len, res);
			R_FREE (dbg_data);
		}
	}
	return result;
}

struct r_bin_pe_import_t* PE_(r_bin_pe_get_imports)(struct PE_(r_bin_pe_obj_t) *bin) {
	struct r_bin_pe_import_t *imps, *imports = NULL;
	char dll_name[PE_NAME_LENGTH + 1];
	int nimp = 0;
	ut64 off; //used to cache value
	PE_DWord dll_name_offset = 0;
	PE_DWord paddr = 0;
	PE_DWord import_func_name_offset;
	PE_(image_import_directory) *curr_import_dir = NULL;
	PE_(image_delay_import_directory) *curr_delay_import_dir = 0;

	if (!bin) {
		return NULL;
	}
	if (bin->import_directory_offset >= bin->size) {
		return NULL;
	}
	if (bin->import_directory_offset + 32 >= bin->size) {
		return NULL;
	}

	off = bin->import_directory_offset;
	if (off < bin->size && off > 0) {
		void *last;
		if (off + sizeof(PE_(image_import_directory)) > bin->size) {
			return NULL;
		}
		curr_import_dir = (PE_(image_import_directory)*)(bin->b->buf + bin->import_directory_offset);
		dll_name_offset = curr_import_dir->Name;

		if (bin->import_directory_size < 1) {
			return NULL;
		}
		if (off + bin->import_directory_size > bin->size) {
			//why chopping instead of returning and cleaning?
			eprintf ("Warning: read (import directory too big)\n");
			bin->import_directory_size = bin->size - bin->import_directory_offset;
		}
		last = (char *)curr_import_dir + bin->import_directory_size;
		while ((void*)(curr_import_dir + 1) <= last && (
				curr_import_dir->FirstThunk != 0 || curr_import_dir->Name != 0 ||
				curr_import_dir->TimeDateStamp != 0 || curr_import_dir->Characteristics != 0 ||
				curr_import_dir->ForwarderChain != 0)) {
			int rr;
			dll_name_offset = curr_import_dir->Name;
			paddr = bin_pe_rva_to_paddr (bin, dll_name_offset);
			if (paddr > bin->size) {
				return NULL;
			}
			if (paddr + PE_NAME_LENGTH > bin->size) {
				rr = r_buf_read_at (bin->b, paddr, (ut8*)dll_name, bin->size - paddr);
				if (rr != bin->size - paddr) {
					eprintf ("Warning: read (magic)\n");
					return NULL;
				}
				dll_name[bin->size - paddr] = '\0';
			}
			else {
				rr = r_buf_read_at (bin->b, paddr, (ut8*)dll_name, PE_NAME_LENGTH);
				if (rr != PE_NAME_LENGTH) {
					eprintf ("Warning: read (magic)\n");
					return NULL;
				}
				dll_name[PE_NAME_LENGTH] = '\0';
			}
			if (!bin_pe_parse_imports (bin, &imports, &nimp, dll_name,
					curr_import_dir->Characteristics,
					curr_import_dir->FirstThunk)) {
				break;
			}
			curr_import_dir++;
		}
	}
	off = bin->delay_import_directory_offset;
	if (off < bin->size && off > 0) {
		if (off + sizeof(PE_(image_delay_import_directory)) > bin->size) {
			return NULL;
		}
		curr_delay_import_dir = (PE_(image_delay_import_directory)*) (bin->b->buf + off);
		if (!curr_delay_import_dir->Attributes) {
			dll_name_offset = bin_pe_rva_to_paddr(bin,
				curr_delay_import_dir->Name - PE_(r_bin_pe_get_image_base)(bin));
			import_func_name_offset = curr_delay_import_dir->DelayImportNameTable -
				PE_(r_bin_pe_get_image_base)(bin);
		} else {
			dll_name_offset = bin_pe_rva_to_paddr(bin, curr_delay_import_dir->Name);
			import_func_name_offset = curr_delay_import_dir->DelayImportNameTable;
		}
		while ((curr_delay_import_dir->Name != 0) && (curr_delay_import_dir->DelayImportAddressTable !=0)) {
			if (dll_name_offset > bin->size || dll_name_offset + PE_NAME_LENGTH > bin->size) {
				return NULL;
			}
			int rr = r_buf_read_at (bin->b, dll_name_offset, (ut8*)dll_name, PE_NAME_LENGTH);
			if (rr < 5) {
				eprintf ("Warning: read (magic)\n");
				return NULL;
			}

			dll_name[PE_NAME_LENGTH] = '\0';
			if (!bin_pe_parse_imports (bin, &imports, &nimp, dll_name, import_func_name_offset,
				  		  curr_delay_import_dir->DelayImportAddressTable)) {
				break;
			}
			if ((char *)(curr_delay_import_dir + 2) > (char *)(bin->b->buf + bin->size)) {
				eprintf ("Warning: malformed pe\n");
				return NULL;
			}
			curr_delay_import_dir++;
		}
	}

	if (nimp) {
		imps = realloc (imports, (nimp + 1) * sizeof(struct r_bin_pe_import_t));
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
	RStrHT *lib_map = NULL;
	ut64 off; //cache value
	int index = 0;
	int len = 0;
	int max_libs = 20;
	libs = calloc (max_libs+1, sizeof(struct r_bin_pe_lib_t));
	if (!libs) {
		r_sys_perror ("malloc (libs)");
		return NULL;
	}

	if (bin->import_directory_offset + bin->import_directory_size > bin->size) {
		eprintf ("import directory offset bigger than file\n");
		goto out_error;
	}
	lib_map = r_strht_new();
	off = bin->import_directory_offset;
	if (off < bin->size && off > 0) {
		void *last = NULL;
		// normal imports
		if (off + sizeof (PE_(image_import_directory)) > bin->size)
			goto out_error;
		curr_import_dir = (PE_(image_import_directory)*)(bin->b->buf + off);
		last = (char *)curr_import_dir + bin->import_directory_size;
		while ((void*)(curr_import_dir+1) <= last && (
				curr_import_dir->FirstThunk || curr_import_dir->Name ||
				curr_import_dir->TimeDateStamp || curr_import_dir->Characteristics ||
				curr_import_dir->ForwarderChain)) {
			name_off = bin_pe_rva_to_paddr (bin, curr_import_dir->Name);
			len = r_buf_read_at (bin->b, name_off, (ut8*)libs[index].name, PE_STRING_LENGTH);
			if (!libs[index].name[0]) { // minimum string length
				goto next;
			}
			if (len < 2 || libs[index].name[0] == 0) { // minimum string length
				eprintf ("Warning: read (libs - import dirs) %d\n", len);
				break;
			}
			libs[index].name[len-1] = '\0';
			r_str_case (libs[index].name, 0);
			if (!r_strht_get (lib_map, libs[index].name)) {
				r_strht_set (lib_map, libs[index].name, "a");
				libs[index++].last = 0;
				if (index >= max_libs) {
					libs = realloc (libs, (max_libs * 2) * sizeof (struct r_bin_pe_lib_t));
					if (!libs) {
						r_sys_perror ("realloc (libs)");
						goto out_error;
					}
					max_libs *= 2;
				}
			}
next:
			curr_import_dir++;
		}
	}
	off = bin->delay_import_directory_offset;
	if (off < bin->size && off > 0) {
		if (off + sizeof(PE_(image_delay_import_directory)) > bin->size) {
			goto out_error;
		}
		curr_delay_import_dir = (PE_(image_delay_import_directory)*)(bin->b->buf + off);
		while (curr_delay_import_dir->Name != 0 && curr_delay_import_dir->DelayImportNameTable != 0) {
			name_off = bin_pe_rva_to_paddr(bin, curr_delay_import_dir->Name);
			if (name_off > bin->size || name_off + PE_STRING_LENGTH > bin->size) {
				goto out_error;
			}
			len = r_buf_read_at (bin->b, name_off, (ut8*)libs[index].name, PE_STRING_LENGTH);
			if (len != PE_STRING_LENGTH) {
				eprintf ("Warning: read (libs - delay import dirs)\n");
				break;
			}
			libs[index].name[len-1] = '\0';
			r_str_case (libs[index].name, 0);
			if (!r_strht_get (lib_map, libs[index].name)) {
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
			if ((const ut8*)(curr_delay_import_dir+1) >= (const ut8*)(bin->b->buf+bin->size)) {
				break;
			}
		}
	}
	r_strht_free (lib_map);
	libs[index].last = 1;
	return libs;
out_error:
	r_strht_free (lib_map);
	free (libs);
	return NULL;
}

int PE_(r_bin_pe_get_image_size)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->optional_header.SizeOfImage;
}

// TODO: make it const! like in elf
char* PE_(r_bin_pe_get_machine)(struct PE_(r_bin_pe_obj_t)* bin) {
	char *machine = NULL;

	if (bin && bin->nt_headers) {
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
	}
	return machine? strdup (machine): NULL;
}

// TODO: make it const! like in elf
char* PE_(r_bin_pe_get_os)(struct PE_(r_bin_pe_obj_t)* bin) {
	char *os;
	if (!bin || !bin->nt_headers) {
		return NULL;
	}
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
	if (bin && bin->nt_headers) {
		switch (bin->nt_headers->optional_header.Magic) {
		case PE_IMAGE_FILE_TYPE_PE32: return strdup("PE32");
		case PE_IMAGE_FILE_TYPE_PE32PLUS: return strdup("PE32+");
		default: return strdup("Unknown");
		}
	}
	return NULL;
}

int PE_(r_bin_pe_get_bits)(struct PE_(r_bin_pe_obj_t)* bin) {
	int bits = 32;
	if (bin && bin->nt_headers) {
		if (is_arm (bin)) {
			if (is_thumb (bin)) {
				bits = 16;
			}
		} else {
			switch (bin->nt_headers->optional_header.Magic) {
			case PE_IMAGE_FILE_TYPE_PE32: bits = 32; break;
			case PE_IMAGE_FILE_TYPE_PE32PLUS: bits = 64; break;
			default: bits = -1;
			}
		}
	}
	return bits;
}

int PE_(r_bin_pe_get_section_alignment)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers) {
		return 0;
	}
	return bin->nt_headers->optional_header.SectionAlignment;
}

//This function try to detect anomalies within section
//we check if there is a section mapped at entrypoint, otherwise add it up
void PE_(r_bin_pe_check_sections)(struct PE_(r_bin_pe_obj_t)* bin, struct r_bin_pe_section_t **sects) {
	int i = 0;
	struct r_bin_pe_section_t *sections = *sects;
	ut64 addr_beg, addr_end, new_section_size, new_perm, base_addr;
	struct r_bin_pe_addr_t *entry =  PE_(r_bin_pe_get_entrypoint) (bin);

	if (!entry) {
		return;
	}
	new_section_size = bin->size;
	new_section_size -= entry->paddr > bin->size? 0 : entry->paddr;
	new_perm = (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_WRITE | PE_IMAGE_SCN_MEM_EXECUTE);
	base_addr = PE_(r_bin_pe_get_image_base) (bin);

	for (i = 0; !sections[i].last; i++) {
	        //strcmp against .text doesn't work in somes cases
		if (strstr ((const char*)sections[i].name, "text")) {
			bool fix = false;
			int j;
			//check paddr boundaries
			addr_beg = sections[i].paddr;
			addr_end = addr_beg + sections[i].size;
			if (entry->paddr < addr_beg || entry->paddr > addr_end) {
				fix = true;
			}
			//check vaddr boundaries
			addr_beg = sections[i].vaddr + base_addr;
			addr_end = addr_beg + sections[i].vsize;
			if (entry->vaddr < addr_beg || entry->vaddr > addr_end) {
				fix = true;
			}
			//look for other segment with x that is already mapped and hold entrypoint
			for (j = 0; !sections[j].last; j++) {
				if (sections[j].flags & PE_IMAGE_SCN_MEM_EXECUTE) {
					addr_beg = sections[j].paddr;
					addr_end = addr_beg + sections[j].size;
					if (addr_beg <= entry->paddr && entry->paddr < addr_end) {
						if (!sections[j].vsize) {
							sections[j].vsize = sections[j].size;
						}
						addr_beg = sections[j].vaddr + base_addr;
						addr_end = addr_beg + sections[j].vsize;
						if (addr_beg <= entry->vaddr || entry->vaddr < addr_end) {
							fix = false;
							break;
						}
					}
				}

			}
			//if either vaddr or paddr fail we should update this section
			if (fix) {
				strcpy ((char *)sections[i].name, "blob");
				sections[i].paddr = entry->paddr;
				sections[i].vaddr = entry->vaddr - base_addr;
				sections[i].size = sections[i].vsize  = new_section_size;
				sections[i].flags = new_perm;
			}
			goto out_function;
		}
	}
	//if we arrive til here means there is no text section find one that is holding the code
	for (i = 0; !sections[i].last; i++) {
		if (sections[i].size > bin->size) {
			continue;
		}
		addr_beg = sections[i].paddr;
		addr_end = addr_beg + sections[i].size;
		if (addr_beg <= entry->paddr && entry->paddr < addr_end) {
			if (!sections[i].vsize) {
				sections[i].vsize = sections[i].size;
			}
			addr_beg = sections[i].vaddr + base_addr;
			addr_end = addr_beg + sections[i].vsize;
			if (entry->vaddr < addr_beg || entry->vaddr > addr_end) {
				sections[i].vaddr = entry->vaddr - base_addr;
			}
			goto out_function;
		}
	}
	//we need to create another section in order to load the entrypoint
	sections = realloc (sections, (bin->num_sections + 2) * sizeof(struct r_bin_pe_section_t));
	i = bin->num_sections;
	sections[i].last = 0;
	strcpy ((char *)sections[i].name, "blob");
	sections[i].paddr = entry->paddr;
	sections[i].vaddr = entry->vaddr - PE_(r_bin_pe_get_image_base) (bin);
	sections[i].size = sections[i].vsize = new_section_size;
	sections[i].flags = new_perm;
	sections[i+1].last = 1;
	*sects = sections;
out_function:
	free (entry);
	return;

}

struct r_bin_pe_section_t* PE_(r_bin_pe_get_sections)(struct PE_(r_bin_pe_obj_t)* bin) {
	struct r_bin_pe_section_t *sections = NULL;
	PE_(image_section_header) *shdr;
	int i, j, section_count = 0;

	if (!bin || !bin->nt_headers) {
		return NULL;
	}
	shdr = bin->section_header;
	for (i = 0; i < bin->num_sections; i++) {
		//just allocate the needed
		if (shdr[i].SizeOfRawData || shdr[i].Misc.VirtualSize) section_count++;
	}
	sections = calloc (section_count + 1, sizeof(struct r_bin_pe_section_t));
	if (!sections) {
		r_sys_perror ("malloc (sections)");
		return NULL;
	}
	for (i = 0, j = 0; i < bin->num_sections; i++) {
		//if sz = 0 r_io_section_add will not add it so just skeep
		if (!shdr[i].SizeOfRawData && !shdr[i].Misc.VirtualSize) {
			continue;
		}
		if (shdr[i].Name[0] == '\0') {
			char *new_name = r_str_newf ("sect_%d", j);
			strncpy ((char *)sections[j].name, new_name, R_ARRAY_SIZE(sections[j].name) - 1);
			free (new_name);
		} else {
			memcpy (sections[j].name, shdr[i].Name, PE_IMAGE_SIZEOF_SHORT_NAME);
			sections[j].name[PE_IMAGE_SIZEOF_SHORT_NAME-1] = '\0';
		}
		sections[j].vaddr = shdr[i].VirtualAddress;
		sections[j].size  = shdr[i].SizeOfRawData;
		sections[j].vsize = shdr[i].Misc.VirtualSize;
		if (bin->optional_header) {
			sections[j].vsize +=
				(bin->optional_header->SectionAlignment -
				(sections[j].vsize &
				 (bin->optional_header->SectionAlignment - 1)));
		}
		sections[j].paddr = shdr[i].PointerToRawData;
		sections[j].flags = shdr[i].Characteristics;
		sections[j].last = 0;
		j++;
	}
	sections[j].last = 1;
	bin->num_sections = section_count;
	return sections;
}

char* PE_(r_bin_pe_get_subsystem)(struct PE_(r_bin_pe_obj_t)* bin) {
	char *subsystem = NULL;
	if (bin && bin->nt_headers) {
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
	}
	return subsystem? strdup (subsystem): NULL;
}

#define HASCHR(x) bin->nt_headers->file_header.Characteristics & x

int PE_(r_bin_pe_is_dll)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers) {
		return false;
	}
	return HASCHR (PE_IMAGE_FILE_DLL);
}

int PE_(r_bin_pe_is_pie)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers) {
		return false;
	}
	return HASCHR (IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE);
#if 0
	BOOL aslr = inh->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
//TODO : implement dep?
	BOOL dep = inh->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
#endif
}

int PE_(r_bin_pe_is_big_endian)(struct PE_(r_bin_pe_obj_t)* bin) {
	ut16 arch; 
	if (!bin || !bin->nt_headers) {
		return false;
	}
	arch = bin->nt_headers->file_header.Machine;
	if (arch == PE_IMAGE_FILE_MACHINE_I386 || 
		arch == PE_IMAGE_FILE_MACHINE_AMD64) {
		return false;
	}
	return HASCHR (PE_IMAGE_FILE_BYTES_REVERSED_HI);
}

int PE_(r_bin_pe_is_stripped_relocs)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers) {
		return false;
	}
	return HASCHR (PE_IMAGE_FILE_RELOCS_STRIPPED);
}

int PE_(r_bin_pe_is_stripped_line_nums)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers) {
		return false;
	}
	return HASCHR (PE_IMAGE_FILE_LINE_NUMS_STRIPPED);
}

int PE_(r_bin_pe_is_stripped_local_syms)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers) {
		return false;
	}
	return HASCHR (PE_IMAGE_FILE_LOCAL_SYMS_STRIPPED);
}

int PE_(r_bin_pe_is_stripped_debug)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->nt_headers) {
		return false;
	}
	return HASCHR (PE_IMAGE_FILE_DEBUG_STRIPPED);
}

void* PE_(r_bin_pe_free)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin) {
		return NULL;
	}
	free (bin->dos_header);
	free (bin->nt_headers);
	free (bin->section_header);
	free (bin->export_directory);
	free (bin->import_directory);
	free (bin->resource_directory);
	free (bin->delay_import_directory);
	r_buf_free (bin->b);
	bin->b = NULL;
	free (bin);
	return NULL;
}

struct PE_(r_bin_pe_obj_t)* PE_(r_bin_pe_new)(const char* file) {
	ut8 *buf;
	struct PE_(r_bin_pe_obj_t) *bin = R_NEW0 (struct PE_(r_bin_pe_obj_t));
	if (!bin) {
		return NULL;
	}
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp(file, &bin->size))) {
		return PE_(r_bin_pe_free)(bin);
	}
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf, bin->size)) {
		free (buf);
		return PE_(r_bin_pe_free)(bin);
	}
	free (buf);
	if (!bin_pe_init(bin)) {
		return PE_(r_bin_pe_free)(bin);
	}
	return bin;
}

struct PE_(r_bin_pe_obj_t)* PE_(r_bin_pe_new_buf)(struct r_buf_t *buf) {
	struct PE_(r_bin_pe_obj_t) *bin = R_NEW0 (struct PE_(r_bin_pe_obj_t));
	if (!bin) {
		return NULL;
	}
	bin->kv = sdb_new0 ();
	bin->b = r_buf_new ();
	bin->size = buf->length;
	if (!r_buf_set_bytes (bin->b, buf->buf, bin->size)){
		return PE_(r_bin_pe_free)(bin);
	}
	if (!bin_pe_init(bin))
		return PE_(r_bin_pe_free)(bin);
	return bin;
}
