/* radare - LGPL - Copyright 2008-2017 nibble, pancake, inisider */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include "pe.h"
#include <time.h>

#define PE_IMAGE_FILE_MACHINE_RPI2 452
#define MAX_METADATA_STRING_LENGTH 256
#define bprintf if(bin->verbose) eprintf
#define COFF_SYMBOL_SIZE 18

struct SCV_NB10_HEADER;
typedef struct {
	ut8 signature[4];
	ut32 offset;
	ut32 timestamp;
	ut32 age;
	ut8* file_name;
	void (* free)(struct SCV_NB10_HEADER* cv_nb10_header);
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
	ut8* file_name;
	void (* free)(struct SCV_RSDS_HEADER* rsds_hdr);
} SCV_RSDS_HEADER;

static inline int is_thumb(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->optional_header.AddressOfEntryPoint & 1;
}

static inline int is_arm(struct PE_(r_bin_pe_obj_t)* bin) {
	switch (bin->nt_headers->file_header.Machine) {
	case PE_IMAGE_FILE_MACHINE_RPI2: // 462
	case PE_IMAGE_FILE_MACHINE_ARM:
	case PE_IMAGE_FILE_MACHINE_THUMB:
		return 1;
	}
	return 0;
}

struct r_bin_pe_addr_t *PE_(check_msvcseh) (struct PE_(r_bin_pe_obj_t) *bin) {
	struct r_bin_pe_addr_t* entry;
	ut8 b[512];
	int n = 0;
	if (!bin || !bin->b) {
		return 0LL;
	}
	entry = PE_(r_bin_pe_get_entrypoint) (bin);
	ZERO_FILL (b);
	if (r_buf_read_at (bin->b, entry->paddr, b, sizeof (b)) < 0) {
		bprintf ("Warning: Cannot read entry at 0x%08"PFMT64x "\n", entry->paddr);
		free (entry);
		return NULL;
	}
	// MSVC SEH
	// E8 13 09 00 00  call    0x44C388
	// E9 05 00 00 00  jmp     0x44BA7F
	if (b[0] == 0xe8 && b[5] == 0xe9) {
		const st32 jmp_dst = r_read_ble32 (b + 6, bin->big_endian);
		entry->paddr += (5 + 5 + jmp_dst);
		entry->vaddr += (5 + 5 + jmp_dst);
		if (r_buf_read_at (bin->b, entry->paddr, b, sizeof (b)) > 0) {
			// case1:
			// from des address of jmp search for 68 xx xx xx xx e8 and test xx xx xx xx = imagebase
			// 68 00 00 40 00  push    0x400000
			// E8 3E F9 FF FF  call    0x44B4FF
			ut32 imageBase = bin->nt_headers->optional_header.ImageBase;
			for (n = 0; n < sizeof (b) - 6; n++) {
				const ut32 tmp_imgbase = r_read_ble32 (b + n + 1, bin->big_endian);
				if (b[n] == 0x68 && tmp_imgbase == imageBase && b[n + 5] == 0xe8) {
					const st32 call_dst = r_read_ble32 (b + n + 6, bin->big_endian);
					entry->paddr += (n + 5 + 5 + call_dst);
					entry->vaddr += (n + 5 + 5 + call_dst);
					return entry;
				}
			}
			//case2:
			// from des address of jmp search for 50 FF xx FF xx E8
			//50			 push    eax
			//FF 37			 push    dword ptr[edi]
			//FF 36          push    dword ptr[esi]
			//E8 6F FC FF FF call    _main
			for (n = 0; n < sizeof (b) - 6; n++) {
				if (b[n] == 0x50 && b[n+1] == 0xff && b[n + 3] == 0xff && b[n + 5] == 0xe8) {
					const st32 call_dst = r_read_ble32 (b + n + 6, bin->big_endian);
					entry->paddr += (n + 5 + 5 + call_dst);
					entry->vaddr += (n + 5 + 5 + call_dst);
					return entry;
				}
			}
			//case3:
			//50                                         push    eax
			//FF 35 0C E2 40 00                          push    xxxxxxxx
			//FF 35 08 E2 40 00                          push    xxxxxxxx
			//E8 2B FD FF FF                             call    _main
			for (n = 0; n < sizeof (b) - 20; n++) {
				if (b[n] == 0x50 && b[n + 1] == 0xff && b[n + 7] == 0xff && b[n + 13] == 0xe8) {
					const st32 call_dst = r_read_ble32 (b + n + 14, bin->big_endian);
					entry->paddr += (n + 5 + 13 + call_dst);
					entry->vaddr += (n + 5 + 13 + call_dst);
					return entry;
				}
			}

		}
	}
	// MSVC AMD64
	// 48 83 EC 28       sub     rsp, 0x28
	// E8 xx xx xx xx    call    xxxxxxxx
	// 48 83 C4 28       add     rsp, 0x28
	// E9 xx xx xx xx    jmp     xxxxxxxx
	if (b[4] == 0xe8 && b[13] == 0xe9) {
		//const st32 jmp_dst = b[14] | (b[15] << 8) | (b[16] << 16) | (b[17] << 24);
		const st32 jmp_dst = r_read_ble32 (b + 14, bin->big_endian);
		entry->paddr += (5 + 13 + jmp_dst);
		entry->vaddr += (5 + 13 + jmp_dst);
		if (r_buf_read_at (bin->b, entry->paddr, b, sizeof (b)) > 0) {
			// from des address of jmp, search for 4C ... 48 ... 8B ... E8
			// 4C 8B C0                    mov     r8, rax
			// 48 8B 17                    mov     rdx, qword [rdi]
			// 8B 0B                       mov     ecx, dword [rbx]
			// E8 xx xx xx xx              call    main
			for (n = 0; n < sizeof (b) - 13; n++) {
				if (b[n] == 0x4c && b[n + 3] == 0x48 && b[n + 6] == 0x8b && b[n + 8] == 0xe8) {
					const st32 call_dst = r_read_ble32 (b + n + 9, bin->big_endian);
					entry->paddr += (n + 5 + 8 + call_dst);
					entry->vaddr += (n + 5 + 8 + call_dst);
					return entry;
				}
			}
		}
	}
	//Microsoft Visual-C
	// 50                  push eax
	// FF 75 9C            push dword [ebp - local_64h]
	// 56                  push    esi
	// 56                  push    esi
	// FF 15 CC C0  44 00  call dword [sym.imp.KERNEL32.dll_GetModuleHandleA]
	// 50                  push    eax
	// E8 DB DA 00 00      call    main
	// 89 45 A0            mov dword [ebp - local_60h], eax
	// 50                  push    eax
	// E8 2D 00 00  00     call 0x4015a6
	if (b[188] == 0x50 && b[201] == 0xe8) {
		const st32 call_dst = r_read_ble32 (b + 202, bin->big_endian);
		entry->paddr += (201 + 5 + call_dst);
		entry->vaddr += (201 + 5 + call_dst);
		return entry;
	}

	if (b[292] == 0x50 && b[303] == 0xe8) {
		const st32 call_dst = r_read_ble32 (b + 304, bin->big_endian);
		entry->paddr += (303 + 5 + call_dst);
		entry->vaddr += (303 + 5 + call_dst);
		return entry;
	}

	free (entry);
	return NULL;
}

struct r_bin_pe_addr_t *PE_(check_mingw) (struct PE_(r_bin_pe_obj_t) *bin) {
	struct r_bin_pe_addr_t* entry;
	int sw = 0;
	ut8 b[1024];
	int n = 0;
	if (!bin || !bin->b) {
		return 0LL;
	}
	entry = PE_(r_bin_pe_get_entrypoint) (bin);
	ZERO_FILL (b);
	if (r_buf_read_at (bin->b, entry->paddr, b, sizeof (b)) < 0) {
		bprintf ("Warning: Cannot read entry at 0x%08"PFMT64x "\n", entry->paddr);
		free (entry);
		return NULL;
	}
	// mingw
	//55                                         push    ebp
	//89 E5                                      mov     ebp, esp
	//83 EC 08                                   sub     esp, 8
	//C7 04 24 01 00 00 00                       mov     dword ptr[esp], 1
	//FF 15 C8 63 41 00                          call    ds : __imp____set_app_type
	//E8 B8 FE FF FF                             call    ___mingw_CRTStartup
	if (b[0] == 0x55 && b[1] == 0x89 && b[3] == 0x83 && b[6] == 0xc7 && b[13] == 0xff && b[19] == 0xe8) {
		const st32 jmp_dst = (st32) r_read_le32 (&b[20]);
		entry->paddr += (5 + 19 + jmp_dst);
		entry->vaddr += (5 + 19 + jmp_dst);
		sw = 1;
	}
	//83 EC 1C                                   sub     esp, 1Ch
	//C7 04 24 01 00 00 00                       mov[esp + 1Ch + var_1C], 1
	//FF 15 F8 60 40 00                          call    ds : __imp____set_app_type
	//E8 6B FD FF FF                             call    ___mingw_CRTStartup
	if (b[0] == 0x83 && b[3] == 0xc7 && b[10] == 0xff && b[16] == 0xe8) {
		const st32 jmp_dst = (st32) r_read_le32 (&b[17]);
		entry->paddr += (5 + 16 + jmp_dst);
		entry->vaddr += (5 + 16 + jmp_dst);
		sw = 1;
	}
	//83 EC 0C                                            sub     esp, 0Ch
	//C7 05 F4 0A 81 00 00 00 00 00                       mov     ds : _mingw_app_type, 0
	//ED E8 3E AD 24 00                                      call    ___security_init_cookie
	//F2 83 C4 0C                                            add     esp, 0Ch
	//F5 E9 86 FC FF FF                                      jmp     ___tmainCRTStartup
	if (b[0] == 0x83 && b[3] == 0xc7 && b[13] == 0xe8 && b[18] == 0x83 && b[21] == 0xe9) {
		const st32 jmp_dst = (st32) r_read_le32 (&b[22]);
		entry->paddr += (5 + 21 + jmp_dst);
		entry->vaddr += (5 + 21 + jmp_dst);
		sw = 1;
	}
	if (sw) {
		if (r_buf_read_at (bin->b, entry->paddr, b, sizeof (b)) > 0) {
			// case1:
			// from des address of call search for a1 xx xx xx xx 89 xx xx e8 xx xx xx xx
			//A1 04 50 44 00                             mov     eax, ds:dword_445004
			//89 04 24                                   mov[esp + 28h + lpTopLevelExceptionFilter], eax
			//E8 A3 01 00 00                             call    sub_4013EE
			// ut32 imageBase = bin->nt_headers->optional_header.ImageBase;
			for (n = 0; n < sizeof (b) - 12; n++) {
				if (b[n] == 0xa1 && b[n + 5] == 0x89 && b[n + 8] == 0xe8) {
					const st32 call_dst = (st32) r_read_le32 (&b[n + 9]);
					entry->paddr += (n + 5 + 8 + call_dst);
					entry->vaddr += (n + 5 + 8 + call_dst);
					return entry;
				}
			}
		}
	}
	free (entry);
	return NULL;
}

struct r_bin_pe_addr_t *PE_(check_unknow) (struct PE_(r_bin_pe_obj_t) *bin) {
	struct r_bin_pe_addr_t *entry;
	if (!bin || !bin->b) {
		return 0LL;
	}
	ut8 *b = calloc (1, 512);
	if (!b) {
		return NULL;
	}
	entry = PE_ (r_bin_pe_get_entrypoint) (bin);
	// option2: /x 8bff558bec83ec20
	if (r_buf_read_at (bin->b, entry->paddr, b, 512) < 1) {
		bprintf ("Warning: Cannot read entry at 0x%08"PFMT64x"\n", entry->paddr);
		free (entry);
		free (b);
		return NULL;
	}
	/* Decode the jmp instruction, this gets the address of the 'main'
	   function for PE produced by a compiler whose name someone forgot to
	   write down. */
	// this is dirty only a single byte check, can return false positives
	if (b[367] == 0xe8) {
		const st32 jmp_dst = (st32) r_read_le32 (&b[368]);
		entry->paddr += 367 + 5 + jmp_dst;
		entry->vaddr += 367 + 5 + jmp_dst;
		free (b);
		return entry;
	}
	int i;
	for (i = 0; i < 512 - 16 ; i++) {
		// 5. ff 15 .. .. .. .. 50 e8 [main]
		if (!memcmp (b + i, "\xff\x15", 2)) {
			if (b[i+6] == 0x50) {
				if (b[i+7] == 0xe8) {
					const st32 call_dst = (st32) r_read_le32 (&b[i + 8]);
					entry->paddr = entry->vaddr - entry->paddr;
					entry->vaddr += (i + 7 + 5 + (long)call_dst);
					entry->paddr += entry->vaddr;
					free (b);
					return entry;
				}
			}
		}
	}
	free (entry);
	free (b);
	return NULL;
}

struct r_bin_pe_addr_t *PE_(r_bin_pe_get_main_vaddr)(struct PE_(r_bin_pe_obj_t) *bin) {
	struct r_bin_pe_addr_t *winmain = PE_(check_msvcseh) (bin);
	if (!winmain) {
		winmain = PE_(check_mingw) (bin);
		if (!winmain) {
			winmain = PE_(check_unknow) (bin);
		}
	}
	return winmain;
}

#define RBinPEObj struct PE_(r_bin_pe_obj_t)
static PE_DWord bin_pe_rva_to_paddr(RBinPEObj* bin, PE_DWord rva) {
	PE_DWord section_base;
	int i, section_size;
	for (i = 0; i < bin->num_sections; i++) {
		section_base = bin->section_header[i].VirtualAddress;
		section_size = bin->section_header[i].Misc.VirtualSize;
		if (rva >= section_base && rva < section_base + section_size) {
			return bin->section_header[i].PointerToRawData + (rva - section_base);
		}
	}
	return rva;
}

ut64 PE_(r_bin_pe_get_image_base)(struct PE_(r_bin_pe_obj_t)* bin) {
	ut64 imageBase = 0;
	if (!bin || !bin->nt_headers) {
		return 0LL;
	}
	imageBase = bin->nt_headers->optional_header.ImageBase;
	if (!imageBase) {
		//this should only happens with messed up binaries
		//XXX this value should be user defined by bin.baddr
		//but from here we can not access config API
		imageBase = 0x10000;
	}
	return imageBase;
}

static PE_DWord bin_pe_rva_to_va(RBinPEObj* bin, PE_DWord rva) {
	return PE_(r_bin_pe_get_image_base) (bin) + rva;
}

static PE_DWord bin_pe_va_to_rva(RBinPEObj* bin, PE_DWord va) {
	ut64 imageBase = PE_(r_bin_pe_get_image_base) (bin);
	if (va < imageBase) {
		return va;
	}
	return va - imageBase;
}

static char* resolveModuleOrdinal(Sdb* sdb, const char* module, int ordinal) {
	Sdb* db = sdb;
	char* foo = sdb_get (db, sdb_fmt (0, "%d", ordinal), 0);
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
	Sdb* db = NULL;
	char* sdb_module = NULL;
	char* symname;
	char* filename;
	char* symdllname = NULL;

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
		len = r_buf_read_at (bin->b, off + i * sizeof (PE_DWord), (ut8*) &import_table, sizeof (PE_DWord));
		if (len != sizeof (PE_DWord)) {
			bprintf ("Warning: read (import table)\n");
			goto error;
		} else if (import_table) {
			if (import_table & ILT_MASK1) {
				import_ordinal = import_table & ILT_MASK2;
				import_hint = 0;
				snprintf (import_name, PE_NAME_LENGTH, "%s_Ordinal_%i", dll_name, import_ordinal);
				free (symdllname);
				strncpy (name, dll_name, sizeof (name) - 1);
				name[sizeof(name) - 1] = 0;
				symdllname = strdup (name);

				// remove the trailling ".dll"
				size_t len = strlen (symdllname);
				r_str_case (symdllname, 0);
				len = len < 4? 0: len - 4;
				symdllname[len] = 0;

				if (!sdb_module || strcmp (symdllname, sdb_module)) {
					sdb_free (db);
					if (db) {
						sdb_free (db);
					}
					db = NULL;
					free (sdb_module);
					sdb_module = strdup (symdllname);
					filename = sdb_fmt (1, "%s.sdb", symdllname);
					if (r_file_exists (filename)) {
						db = sdb_new (NULL, filename, 0);
					} else {
#if __WINDOWS__
						char invoke_dir[MAX_PATH];
						if (r_sys_get_src_dir_w32 (invoke_dir)) {
							filename = sdb_fmt (1, "%s\\share\\radare2\\"R2_VERSION "\\format\\dll\\%s.sdb", invoke_dir, symdllname);
						} else {
							filename = sdb_fmt (1, "share/radare2/"R2_VERSION "/format/dll/%s.sdb", symdllname);
						}
#else
						const char *dirPrefix = r_sys_prefix (NULL);
						filename = sdb_fmt (1, "%s/share/radare2/" R2_VERSION "/format/dll/%s.sdb", dirPrefix, symdllname);
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
						R_FREE (symname);
					}
				} else {
					bprintf ("Cannot find %s\n", filename);

				}
			} else {
				import_ordinal++;
				const ut64 off = bin_pe_rva_to_paddr (bin, import_table);
				if (off > bin->size || (off + sizeof (PE_Word)) > bin->size) {
					bprintf ("Warning: off > bin->size\n");
					goto error;
				}
				len = r_buf_read_at (bin->b, off, (ut8*) &import_hint, sizeof (PE_Word));
				if (len != sizeof (PE_Word)) {
					bprintf ("Warning: read import hint at 0x%08"PFMT64x "\n", off);
					goto error;
				}
				name[0] = '\0';
				len = r_buf_read_at (bin->b, off + sizeof(PE_Word), (ut8*) name, PE_NAME_LENGTH);
				if (len < 1) {
					bprintf ("Warning: read (import name)\n");
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
			memcpy ((*importp)[*nimp].name, import_name, PE_NAME_LENGTH);
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

	if (db) {
		sdb_free (db);
		db = NULL;
	}
	free (symdllname);
	free (sdb_module);
	return i;

error:
	if (db) {
		sdb_free (db);
		db = NULL;
	}
	free (symdllname);
	free (sdb_module);
	return false;
}

static char *_time_stamp_to_str(ut32 timeStamp) {
#ifdef _MSC_VER
	time_t rawtime;
	struct tm *tminfo;
	rawtime = (time_t)timeStamp;
	tminfo = localtime (&rawtime);
	//tminfo = gmtime (&rawtime);
	return r_str_trim (strdup (asctime (tminfo)));
#else
	struct my_timezone {
		int tz_minuteswest;     /* minutes west of Greenwich */
		int tz_dsttime;         /* type of DST correction */
	} tz;
	struct timeval tv;
	int gmtoff;
	time_t ts = (time_t) timeStamp;
	gettimeofday (&tv, (void*) &tz);
	gmtoff = (int) (tz.tz_minuteswest * 60); // in seconds
	ts += (time_t)gmtoff;
	return r_str_trim (strdup (ctime (&ts)));
#endif
}

static int bin_pe_init_hdr(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!(bin->dos_header = malloc (sizeof(PE_(image_dos_header))))) {
		r_sys_perror ("malloc (dos header)");
		return false;
	}
	if (r_buf_read_at (bin->b, 0, (ut8*) bin->dos_header, sizeof(PE_(image_dos_header))) == -1) {
		bprintf ("Warning: read (dos header)\n");
		return false;
	}
	sdb_num_set (bin->kv, "pe_dos_header.offset", 0, 0);
	sdb_set (bin->kv, "pe_dos_header.format", "[2]zwwwwwwwwwwwww[4]www[10]wx"
		" e_magic e_cblp e_cp e_crlc e_cparhdr e_minalloc e_maxalloc"
		" e_ss e_sp e_csum e_ip e_cs e_lfarlc e_ovno e_res e_oemid"
		" e_oeminfo e_res2 e_lfanew", 0);
	if (bin->dos_header->e_lfanew > (unsigned int) bin->size) {
		bprintf ("Invalid e_lfanew field\n");
		return false;
	}
	if (!(bin->nt_headers = malloc (sizeof (PE_(image_nt_headers))))) {
		r_sys_perror ("malloc (nt header)");
		return false;
	}
	bin->nt_header_offset = bin->dos_header->e_lfanew;
	if (r_buf_read_at (bin->b, bin->dos_header->e_lfanew, (ut8*) bin->nt_headers, sizeof (PE_(image_nt_headers))) < -1) {
		bprintf ("Warning: read (dos header)\n");
		return false;
	}
	sdb_set (bin->kv, "pe_magic.cparse",     "enum pe_magic { IMAGE_NT_OPTIONAL_HDR32_MAGIC=0x10b, IMAGE_NT_OPTIONAL_HDR64_MAGIC=0x20b, IMAGE_ROM_OPTIONAL_HDR_MAGIC=0x107 };", 0);
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
	sdb_set (bin->kv, "pe_nt_image_headers64.format",      "[4]z?? signature (pe_image_file_header)fileHeader (pe_image_optional_header64)optionalHeader", 0);
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
	sdb_set (bin->kv, "pe_nt_image_headers32.format",      "[4]z?? signature (pe_image_file_header)fileHeader (pe_image_optional_header32)optionalHeader", 0);
	sdb_set (bin->kv, "pe_image_optional_header32.format", "[2]Ebbxxxxxxxxxwwwwwwxxxx[2]E[2]Bxxxxxx[16]?"
		" (pe_magic)magic majorLinkerVersion minorLinkerVersion sizeOfCode sizeOfInitializedData"
		" sizeOfUninitializedData addressOfEntryPoint baseOfCode baseOfData imageBase"
		" sectionAlignment fileAlignment majorOperatingSystemVersion minorOperatingSystemVersion"
		" majorImageVersion minorImageVersion majorSubsystemVersion minorSubsystemVersion"
		" win32VersionValue sizeOfImage sizeOfHeaders checkSum (pe_subsystem)subsystem (pe_dllcharacteristics)dllCharacteristics"
		" sizeOfStackReserve sizeOfStackCommit sizeOfHeapReserve sizeOfHeapCommit loaderFlags numberOfRvaAndSizes"
		" (pe_image_data_directory)dataDirectory", 0);
#endif
	sdb_set (bin->kv, "pe_machine.cparse",         "enum pe_machine { IMAGE_FILE_MACHINE_I386=0x014c, IMAGE_FILE_MACHINE_IA64=0x0200, IMAGE_FILE_MACHINE_AMD64=0x8664 };", 0);
	sdb_set (bin->kv, "pe_characteristics.cparse", "enum pe_characteristics { "
		" IMAGE_FILE_RELOCS_STRIPPED=0x0001, IMAGE_FILE_EXECUTABLE_IMAGE=0x0002, IMAGE_FILE_LINE_NUMS_STRIPPED=0x0004, "
		" IMAGE_FILE_LOCAL_SYMS_STRIPPED=0x0008, IMAGE_FILE_AGGRESIVE_WS_TRIM=0x0010, IMAGE_FILE_LARGE_ADDRESS_AWARE=0x0020, "
		" IMAGE_FILE_BYTES_REVERSED_LO=0x0080, IMAGE_FILE_32BIT_MACHINE=0x0100, IMAGE_FILE_DEBUG_STRIPPED=0x0200, "
		" IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP=0x0400, IMAGE_FILE_NET_RUN_FROM_SWAP=0x0800, IMAGE_FILE_SYSTEM=0x1000, "
		" IMAGE_FILE_DLL=0x2000, IMAGE_FILE_UP_SYSTEM_ONLY=0x4000, IMAGE_FILE_BYTES_REVERSED_HI=0x8000 };", 0);
	sdb_set (bin->kv, "pe_image_file_header.format",    "[2]Ewtxxw[2]B"
		" (pe_machine)machine numberOfSections timeDateStamp pointerToSymbolTable"
		" numberOfSymbols sizeOfOptionalHeader (pe_characteristics)characteristics", 0);
	sdb_set (bin->kv, "pe_image_data_directory.format", "xx virtualAddress size",0);

	// adding compile time to the SDB
	{
		sdb_num_set (bin->kv, "image_file_header.TimeDateStamp", bin->nt_headers->file_header.TimeDateStamp, 0);
		char *timestr = _time_stamp_to_str (bin->nt_headers->file_header.TimeDateStamp);
		sdb_set_owned (bin->kv, "image_file_header.TimeDateStamp_string", timestr, 0);
	}
	bin->optional_header = &bin->nt_headers->optional_header;
	bin->data_directory = (PE_(image_data_directory*)) & bin->optional_header->DataDirectory;

	if (strncmp ((char*) &bin->dos_header->e_magic, "MZ", 2) ||
	(strncmp ((char*) &bin->nt_headers->Signature, "PE", 2) &&
	/* Check also for Phar Lap TNT DOS extender PL executable */
	strncmp ((char*) &bin->nt_headers->Signature, "PL", 2))) {
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

static struct r_bin_pe_export_t* parse_symbol_table(struct PE_(r_bin_pe_obj_t)* bin, struct r_bin_pe_export_t* exports, int sz) {
	ut64 sym_tbl_off, num = 0;
	const int srsz = COFF_SYMBOL_SIZE; // symbol record size
	struct r_bin_pe_section_t* sections;
	struct r_bin_pe_export_t* exp;
	int bufsz, i, shsz;
	SymbolRecord* sr;
	ut64 text_off = 0LL;
	ut64 text_rva = 0LL;
	int textn = 0;
	int exports_sz;
	int symctr = 0;
	char* buf;

	if (!bin || !bin->nt_headers) {
		return NULL;
	}

	sym_tbl_off = bin->nt_headers->file_header.PointerToSymbolTable;
	num = bin->nt_headers->file_header.NumberOfSymbols;
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
		exp = (struct r_bin_pe_export_t*) (((const ut8*) exports) + osz);
	} else {
		sz = exports_sz;
		exports = malloc (sz);
		exp = exports;
	}

	sections = PE_(r_bin_pe_get_sections) (bin);
	for (i = 0; i < bin->num_sections; i++) {
		//XXX search by section with +x permission since the section can be left blank
		if (!strcmp ((char*) sections[i].name, ".text")) {
			text_rva = sections[i].vaddr;
			text_off = sections[i].paddr;
			textn = i + 1;
		}
	}
	free (sections);
	symctr = 0;
	if (r_buf_read_at (bin->b, sym_tbl_off, (ut8*) buf, bufsz)) {
		for (i = 0; i < shsz; i += srsz) {
			sr = (SymbolRecord*) (buf + i);
			//bprintf ("SECNUM %d\n", sr->secnum);
			if (sr->secnum == textn) {
				if (sr->symtype == 32) {
					char shortname[9];
					memcpy (shortname, &sr->shortname, 8);
					shortname[8] = 0;
					if (*shortname) {
						strncpy ((char*) exp[symctr].name, shortname, PE_NAME_LENGTH - 1);
					} else {
						char* longname, name[128];
						ut32* idx = (ut32*) (buf + i + 4);
						if (r_buf_read_at (bin->b, sym_tbl_off + *idx + shsz, (ut8*) name, 128)) { // == 128) {
							longname = name;
							name[sizeof(name) - 1] = 0;
							strncpy ((char*) exp[symctr].name, longname, PE_NAME_LENGTH - 1);
						} else {
							sprintf ((char*) exp[symctr].name, "unk_%d", symctr);
						}
					}
					exp[symctr].name[PE_NAME_LENGTH] = 0;
					exp[symctr].vaddr = bin_pe_rva_to_va (bin, text_rva + sr->value);
					exp[symctr].paddr = text_off + sr->value;
					exp[symctr].ordinal = symctr;
					exp[symctr].forwarder[0] = 0;
					exp[symctr].last = 0;
					symctr++;
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
		sections_size = bin->size;
		bin->num_sections = bin->size / sizeof (PE_(image_section_header));
		// massage this to make corkami happy
		//bprintf ("Invalid NumberOfSections value\n");
		//goto out_error;
	}
	if (!(bin->section_header = malloc (sections_size))) {
		r_sys_perror ("malloc (section header)");
		goto out_error;
	}
	bin->section_header_offset = bin->dos_header->e_lfanew + 4 + sizeof (PE_(image_file_header)) +
		bin->nt_headers->file_header.SizeOfOptionalHeader;
	if (r_buf_read_at (bin->b, bin->section_header_offset,
		(ut8*) bin->section_header, sections_size) == -1) {
		bprintf ("Warning: read (sections)\n");
		R_FREE (bin->section_header);
		goto out_error;
	}
#if 0
	Each symbol table entry includes a name, storage class, type, value and section number.Short names (8 characters or fewer) are stored directly in the symbol table;
	longer names are stored as an paddr into the string table at the end of the COFF object.

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
	------------------------------------------------------ -
	0 | 8 - char symbol name |
	| or 32 - bit zeroes followed by 32 - bit |
	| index into string table |
	------------------------------------------------------ -
	8 | symbol value |
	------------------------------------------------------ -
	0Ch | section number | symbol type |
	------------------------------------------------------ -
	10h | sym class | num aux |
	-------------------------- -
	12h

#endif
	return true;
out_error:
	bin->num_sections = 0;
	return false;
}

int PE_(bin_pe_get_claimed_checksum)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin || !bin->optional_header) {
		return 0;
	}
	return bin->optional_header->CheckSum;
}

int PE_(bin_pe_get_actual_checksum)(struct PE_(r_bin_pe_obj_t)* bin) {
	int i, j, checksum_offset = 0;
	ut8* buf = NULL;
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
		cur = r_read_le32 (&buf[i * 4]);

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
	computed_cs = (computed_cs) + (computed_cs >> 16);
	computed_cs = (computed_cs & 0xFFFF);

	// add filesize
	computed_cs += bin->size;
	return computed_cs;
}

static void computeOverlayOffset(ut64 offset, ut64 size, ut64 file_size, ut64* largest_offset, ut64* largest_size) {
	if (offset + size <= file_size && offset + size > (*largest_offset + *largest_size)) {
		*largest_offset = offset;
		*largest_size = size;
	}
}

/* Inspired from https://github.com/erocarrera/pefile/blob/master/pefile.py#L5425 */
int PE_(bin_pe_get_overlay)(struct PE_(r_bin_pe_obj_t)* bin, ut64* size) {
	ut64 largest_offset = 0;
	ut64 largest_size = 0;
	*size = 0;
	int i;

	if (!bin) {
		return 0;
	}

	if (bin->optional_header) {
		computeOverlayOffset (
				bin->nt_header_offset+4+sizeof(bin->nt_headers->file_header),
				bin->nt_headers->file_header.SizeOfOptionalHeader,
				bin->size,
				&largest_offset,
				&largest_size);
	}

	struct r_bin_pe_section_t *sects = NULL;
	sects = PE_(r_bin_pe_get_sections) (bin);
	for (i = 0; !sects[i].last; i++) {
		computeOverlayOffset(
				sects[i].paddr,
				sects[i].size,
				bin->size,
				&largest_offset,
				&largest_size
				);
	}

	if (bin->optional_header) {
		for (i = 0; i < PE_IMAGE_DIRECTORY_ENTRIES; i++) {
			if (i == PE_IMAGE_DIRECTORY_ENTRY_SECURITY) {
				continue;
			}

			computeOverlayOffset (
				bin_pe_rva_to_paddr (bin, bin->data_directory[i].VirtualAddress),
				bin->data_directory[i].Size,
				bin->size,
				&largest_offset,
				&largest_size);
		}

	}

	if ((ut64) bin->size > largest_offset + largest_size) {
		*size = bin->size - largest_offset - largest_size;
		free (sects);
		return largest_offset + largest_size;
	}
	free (sects);
	return 0;
}

static int bin_pe_read_metadata_string(char* to, char* from) {
	int covered = 0;
	while (covered < MAX_METADATA_STRING_LENGTH) {
		to[covered] = from[covered];
		if (from[covered] == '\0') {
			covered += 1;
			break;
		}
		covered++;
	}
	while (covered % 4 != 0) { covered++; }
	return covered;
}

static int bin_pe_init_metadata_hdr(struct PE_(r_bin_pe_obj_t)* bin) {
	PE_DWord metadata_directory = bin->clr_hdr? bin_pe_rva_to_paddr (bin, bin->clr_hdr->MetaDataDirectoryAddress): 0;
	PE_(image_metadata_header) * metadata = R_NEW0 (PE_(image_metadata_header));
	int rr;
	if (!metadata) {
		return 0;
	}
	if (!metadata_directory) {
		free (metadata);
		return 0;
	}


	rr = r_buf_fread_at (bin->b, metadata_directory,
		(ut8*) metadata, bin->big_endian? "1I2S": "1i2s", 1);
	if (rr < 1) {
		goto fail;
	}

	rr = r_buf_fread_at (bin->b, metadata_directory + 8,
		(ut8*) (&metadata->Reserved), bin->big_endian? "1I": "1i", 1);
	if (rr < 1) {
		goto fail;
	}

	rr = r_buf_fread_at (bin->b, metadata_directory + 12,
		(ut8*) (&metadata->VersionStringLength), bin->big_endian? "1I": "1i", 1);
	if (rr < 1) {
		goto fail;
	}

	eprintf ("Metadata Signature: 0x%"PFMT64x" 0x%"PFMT64x" %d\n",
		(ut64)metadata_directory, (ut64)metadata->Signature, (int)metadata->VersionStringLength);

	// read the version string
	int len = metadata->VersionStringLength; // XXX: dont trust this length
	if (len > 0) {
		metadata->VersionString = calloc (1, len + 1);
		if (!metadata->VersionString) {
			goto fail;
		}

		rr = r_buf_read_at (bin->b, metadata_directory + 16, (ut8*)(metadata->VersionString),  len);
		if (rr != len) {
			eprintf ("Warning: read (metadata header) - cannot parse version string\n");
			free (metadata->VersionString);
			free (metadata);
			return 0;
		}
		eprintf (".NET Version: %s\n", metadata->VersionString);
	}

	// read the header after the string
	rr = r_buf_fread_at (bin->b, metadata_directory + 16 + metadata->VersionStringLength,
		(ut8*) (&metadata->Flags), bin->big_endian? "2S": "2s", 1);

	if (rr < 1) {
		goto fail;
	}

	eprintf ("Number of Metadata Streams: %d\n", metadata->NumberOfStreams);
	bin->metadata_header = metadata;


	// read metadata streams
	int start_of_stream = metadata_directory + 20 + metadata->VersionStringLength;
	PE_(image_metadata_stream) * stream;
	PE_(image_metadata_stream) **streams = calloc (sizeof (PE_(image_metadata_stream)*), metadata->NumberOfStreams);
	if (!streams) {
		goto fail;
	}
	int count = 0;

	while (count < metadata->NumberOfStreams) {
		stream = R_NEW0 (PE_(image_metadata_stream));
		if (!stream) {
			free (streams);
			goto fail;
		}

		if (r_buf_fread_at (bin->b, start_of_stream, (ut8*) stream, bin->big_endian? "2I": "2i", 1) < 1) {
			free (stream);
			free (streams);
			goto fail;
		}
		eprintf ("DirectoryAddress: %x Size: %x\n", stream->Offset, stream->Size);
		char* stream_name = calloc (1, MAX_METADATA_STRING_LENGTH + 1);

		if (!stream_name) {
			free (stream);
			free (streams);
			goto fail;
		}

		if (r_buf_size (bin->b) < (start_of_stream + 8 + MAX_METADATA_STRING_LENGTH)) {
			free (stream_name);
			free (stream);
			free (streams);
			goto fail;
		}
		int c = bin_pe_read_metadata_string (stream_name,
			(char *)(bin->b->buf + start_of_stream + 8));
		if (c == 0) {
			free (stream_name);
			free (stream);
			free (streams);
			goto fail;
		}
		eprintf ("Stream name: %s %d\n", stream_name, c);
		stream->Name = stream_name;
		streams[count] = stream;
		start_of_stream += 8 + c;
		count += 1;
	}
	bin->streams = streams;
	return 1;
fail:
	eprintf ("Warning: read (metadata header)\n");
	free (metadata);
	return 0;
}

static int bin_pe_init_overlay(struct PE_(r_bin_pe_obj_t)* bin) {
	ut64 pe_overlay_size;
	ut64 pe_overlay_offset = PE_(bin_pe_get_overlay) (bin, &pe_overlay_size);
	if (pe_overlay_offset) {
		sdb_num_set (bin->kv, "pe_overlay.offset", pe_overlay_offset, 0);
		sdb_num_set (bin->kv, "pe_overlay.size", pe_overlay_size, 0);
	}
	return 0;
}

static int bin_pe_init_clr_hdr(struct PE_(r_bin_pe_obj_t)* bin) {
	PE_(image_data_directory) * clr_dir = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
	PE_DWord image_clr_hdr_paddr = bin_pe_rva_to_paddr (bin, clr_dir->VirtualAddress);
	// int clr_dir_size = clr_dir? clr_dir->Size: 0;
	PE_(image_clr_header) * clr_hdr = R_NEW0 (PE_(image_clr_header));
	int rr, len = sizeof (PE_(image_clr_header));

	if (!clr_hdr) {
		return 0;
	}
	rr = r_buf_read_at (bin->b, image_clr_hdr_paddr, (ut8*) (clr_hdr), len);

//	printf("%x\n", clr_hdr->HeaderSize);

	if (clr_hdr->HeaderSize != 0x48) {
		// probably not a .NET binary
		// 64bit?
		free (clr_hdr);
		return 0;
	}
	if (rr != len) {
		free (clr_hdr);
		return 0;
	}

	bin->clr_hdr = clr_hdr;
	return 1;
}

static int bin_pe_init_imports(struct PE_(r_bin_pe_obj_t)* bin) {
	PE_(image_data_directory) * data_dir_import = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_IMPORT];
	PE_(image_data_directory) * data_dir_delay_import = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

	PE_DWord import_dir_paddr = bin_pe_rva_to_paddr (bin, data_dir_import->VirtualAddress);
	PE_DWord import_dir_offset = bin_pe_rva_to_paddr (bin, data_dir_import->VirtualAddress);
	PE_DWord delay_import_dir_offset = data_dir_delay_import
	? bin_pe_rva_to_paddr (bin, data_dir_delay_import->VirtualAddress)
					: 0;

	PE_(image_import_directory) * import_dir = NULL;
	PE_(image_import_directory) * new_import_dir = NULL;
	PE_(image_import_directory) * curr_import_dir = NULL;

	PE_(image_delay_import_directory) * delay_import_dir = NULL;
	PE_(image_delay_import_directory) * curr_delay_import_dir = NULL;

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
	int maxidsz = R_MIN ((PE_DWord) bin->size, import_dir_offset + import_dir_size);
	maxidsz -= import_dir_offset;
	if (maxidsz < 0) {
		maxidsz = 0;
	}
	//int maxcount = maxidsz/ sizeof (struct r_bin_pe_import_t);

	free (bin->import_directory);
	bin->import_directory = NULL;
	if (import_dir_paddr != 0) {
		if (import_dir_size < 1 || import_dir_size > maxidsz) {
			bprintf ("Warning: Invalid import directory size: 0x%x is now 0x%x\n", import_dir_size, maxidsz);
			import_dir_size = maxidsz;
		}
		bin->import_directory_offset = import_dir_offset;
		count = 0;
		do {
			indx++;
			if (((2 + indx) * dir_size) > import_dir_size) {
				break; //goto fail;
			}
			new_import_dir = (PE_(image_import_directory)*)realloc (import_dir, ((1 + indx) * dir_size));
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
			if (r_buf_read_at (bin->b, import_dir_offset + (indx - 1) * dir_size, (ut8*) (curr_import_dir), dir_size) < 1) {
				bprintf ("Warning: read (import directory)\n");
				free (import_dir);
				import_dir = NULL;
				break; //return false;
			}
			count++;
		} while (curr_import_dir->FirstThunk != 0 || curr_import_dir->Name != 0 ||
		curr_import_dir->TimeDateStamp != 0 || curr_import_dir->Characteristics != 0 ||
		curr_import_dir->ForwarderChain != 0);

		bin->import_directory = import_dir;
		bin->import_directory_size = import_dir_size;
	}

	indx = 0;
	if (bin->b->length > 0) {
		if ((delay_import_dir_offset != 0) && (delay_import_dir_offset < (ut32) bin->b->length)) {
			ut64 off;
			bin->delay_import_directory_offset = delay_import_dir_offset;
			do {
				indx++;
				off = indx * delay_import_size;
				if (off >= bin->b->length) {
					bprintf ("Warning: Cannot find end of import symbols\n");
					break;
				}
				delay_import_dir = (PE_(image_delay_import_directory)*)realloc (
					delay_import_dir, (indx * delay_import_size) + 1);
				if (delay_import_dir == 0) {
					r_sys_perror ("malloc (delay import directory)");
					free (delay_import_dir);
					return false;
				}

				curr_delay_import_dir = delay_import_dir + (indx - 1);
				rr = r_buf_read_at (bin->b, delay_import_dir_offset + (indx - 1) * delay_import_size,
					(ut8*) (curr_delay_import_dir), dir_size);
				if (rr != dir_size) {
					bprintf ("Warning: read (delay import directory)\n");
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

static int bin_pe_init_exports(struct PE_(r_bin_pe_obj_t)* bin) {
	PE_(image_data_directory) * data_dir_export = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_EXPORT];
	PE_DWord export_dir_paddr = bin_pe_rva_to_paddr (bin, data_dir_export->VirtualAddress);
	if (!export_dir_paddr) {
		// This export-dir-paddr should only appear in DLL files
		// bprintf ("Warning: Cannot find the paddr of the export directory\n");
		return false;
	}
	// sdb_setn (DB, "hdr.exports_directory", export_dir_paddr);
	// bprintf ("Pexports paddr at 0x%"PFMT64x"\n", export_dir_paddr);
	if (!(bin->export_directory = malloc (sizeof(PE_(image_export_directory))))) {
		r_sys_perror ("malloc (export directory)");
		return false;
	}
	if (r_buf_read_at (bin->b, export_dir_paddr, (ut8*) bin->export_directory, sizeof (PE_(image_export_directory))) == -1) {
		bprintf ("Warning: read (export directory)\n");
		free (bin->export_directory);
		bin->export_directory = NULL;
		return false;
	}
	return true;
}

static void _free_resources(r_pe_resource *rs) {
	if (rs) {
		free (rs->timestr);
		free (rs->data);
		free (rs->type);
		free (rs->language);
		free (rs);
	}
}


static int bin_pe_init_resource(struct PE_(r_bin_pe_obj_t)* bin) {
	PE_(image_data_directory) * resource_dir = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_RESOURCE];
	PE_DWord resource_dir_paddr = bin_pe_rva_to_paddr (bin, resource_dir->VirtualAddress);
	if (!resource_dir_paddr) {
		return false;
	}

	bin->resources = r_list_newf ((RListFree)_free_resources);
	if (!bin->resources) {
		return false;
	}
	if (!(bin->resource_directory = malloc (sizeof(*bin->resource_directory)))) {
		r_sys_perror ("malloc (resource directory)");
		return false;
	}
	if (r_buf_read_at (bin->b, resource_dir_paddr, (ut8*) bin->resource_directory,
		sizeof (*bin->resource_directory)) != sizeof (*bin->resource_directory)) {
		bprintf ("Warning: read (resource directory)\n");
		free (bin->resource_directory);
		bin->resource_directory = NULL;
		return false;
	}
	bin->resource_directory_offset = resource_dir_paddr;
	return true;
}



static void bin_pe_store_tls_callbacks(struct PE_(r_bin_pe_obj_t)* bin, PE_DWord callbacks) {
	PE_DWord paddr, haddr;
	int count = 0;
	PE_DWord addressOfTLSCallback = 1;
	char* key;

	while (addressOfTLSCallback != 0) {
		if (r_buf_read_at (bin->b, callbacks, (ut8*) &addressOfTLSCallback, sizeof(addressOfTLSCallback)) != sizeof (addressOfTLSCallback)) {
			bprintf ("Warning: read (tls_callback)\n");
			return;
		}
		if (!addressOfTLSCallback) {
			break;
		}
		if (bin->optional_header->SizeOfImage) {
			int rva_callback = bin_pe_va_to_rva (bin, (PE_DWord) addressOfTLSCallback);
			if (rva_callback > bin->optional_header->SizeOfImage) {
				break;
			}
		}
		key = sdb_fmt (0, "pe.tls_callback%d_vaddr", count);
		sdb_num_set (bin->kv, key, addressOfTLSCallback, 0);
		key = sdb_fmt (0, "pe.tls_callback%d_paddr", count);
		paddr = bin_pe_rva_to_paddr (bin, bin_pe_va_to_rva (bin, (PE_DWord) addressOfTLSCallback));
		sdb_num_set (bin->kv, key, paddr,                0);
		key = sdb_fmt (0, "pe.tls_callback%d_haddr", count);
		haddr = callbacks;
		sdb_num_set (bin->kv, key, haddr,                0);
		count++;
		callbacks += sizeof (addressOfTLSCallback);
	}
}

static int bin_pe_init_tls(struct PE_(r_bin_pe_obj_t)* bin) {
	PE_(image_tls_directory) * image_tls_directory;
	PE_(image_data_directory) * data_dir_tls = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_TLS];
	PE_DWord tls_paddr = bin_pe_rva_to_paddr (bin, data_dir_tls->VirtualAddress);

	image_tls_directory = R_NEW0 (PE_(image_tls_directory));
	if (r_buf_read_at (bin->b, tls_paddr, (ut8*) image_tls_directory, sizeof (PE_(image_tls_directory))) != sizeof (PE_(image_tls_directory))) {
		bprintf ("Warning: read (image_tls_directory)\n");
		free (image_tls_directory);
		return 0;
	}
	bin->tls_directory = image_tls_directory;
	if (!image_tls_directory->AddressOfCallBacks) {
		return 0;
	}
	if (image_tls_directory->EndAddressOfRawData < image_tls_directory->StartAddressOfRawData) {
		return 0;
	}
	PE_DWord callbacks_paddr = bin_pe_rva_to_paddr (bin, bin_pe_va_to_rva (bin,
			(PE_DWord) image_tls_directory->AddressOfCallBacks));
	bin_pe_store_tls_callbacks (bin, callbacks_paddr);
	return 0;
}

static void free_Var(Var* var) {
	if (var) {
		free (var->szKey);
		free (var->Value);
		free (var);
	}
}

static void free_VarFileInfo(VarFileInfo* varFileInfo) {
	if (varFileInfo) {
		free (varFileInfo->szKey);
		if (varFileInfo->Children) {
			ut32 children = 0;
			for (; children < varFileInfo->numOfChildren; children++) {
				free_Var (varFileInfo->Children[children]);
			}
			free (varFileInfo->Children);
		}
		free (varFileInfo);
	}
}

static void free_String(String* string) {
	if (string) {
		free (string->szKey);
		free (string->Value);
		free (string);
	}
}

static void free_StringTable(StringTable* stringTable) {
	if (stringTable) {
		free (stringTable->szKey);
		if (stringTable->Children) {
			ut32 childrenST = 0;
			for (; childrenST < stringTable->numOfChildren; childrenST++) {
				free_String (stringTable->Children[childrenST]);
			}
			free (stringTable->Children);
		}
		free (stringTable);
	}
}

static void free_StringFileInfo(StringFileInfo* stringFileInfo) {
	if (stringFileInfo) {
		free (stringFileInfo->szKey);
		if (stringFileInfo->Children) {
			ut32 childrenSFI = 0;
			for (; childrenSFI < stringFileInfo->numOfChildren; childrenSFI++) {
				free_StringTable (stringFileInfo->Children[childrenSFI]);
			}
			free (stringFileInfo->Children);
		}
		free (stringFileInfo);
	}
}

#define align32(x) x = ((x & 0x3) == 0)? x: (x & ~0x3) + 0x4;

static void free_VS_VERSIONINFO(PE_VS_VERSIONINFO* vs_VersionInfo) {
	if (vs_VersionInfo) {
		free (vs_VersionInfo->szKey);
		free (vs_VersionInfo->Value);
		free_VarFileInfo (vs_VersionInfo->varFileInfo);
		free_StringFileInfo (vs_VersionInfo->stringFileInfo);
		free (vs_VersionInfo);
	}
}

void PE_(free_VS_VERSIONINFO)(PE_VS_VERSIONINFO * vs_VersionInfo) {
	free_VS_VERSIONINFO (vs_VersionInfo);
}

static Var* Pe_r_bin_pe_parse_var(struct PE_(r_bin_pe_obj_t)* bin, PE_DWord* curAddr) {
	Var* var = calloc (1, sizeof(*var));
	if (!var) {
		bprintf ("Warning: calloc (Var)\n");
		return NULL;
	}
	if (r_buf_read_at (bin->b, *curAddr, (ut8*) &var->wLength, sizeof(var->wLength)) != sizeof(var->wLength)) {
		bprintf ("Warning: read (Var wLength)\n");
		free_Var (var);
		return NULL;
	}
	*curAddr += sizeof(var->wLength);
	if (r_buf_read_at (bin->b, *curAddr, (ut8*) &var->wValueLength, sizeof(var->wValueLength)) != sizeof(var->wValueLength)) {
		bprintf ("Warning: read (Var wValueLength)\n");
		free_Var (var);
		return NULL;
	}
	*curAddr += sizeof(var->wValueLength);
	if (r_buf_read_at (bin->b, *curAddr, (ut8*) &var->wType, sizeof(var->wType)) != sizeof(var->wType)) {
		bprintf ("Warning: read (Var wType)\n");
		free_Var (var);
		return NULL;
	}
	*curAddr += sizeof(var->wType);
	if (var->wType != 0 && var->wType != 1) {
		bprintf ("Warning: check (Var wType)\n");
		free_Var (var);
		return NULL;
	}

	var->szKey = (ut16*) malloc (UT16_ALIGN (TRANSLATION_UTF_16_LEN));  //L"Translation"
	if (!var->szKey) {
		bprintf ("Warning: malloc (Var szKey)\n");
		free_Var (var);
		return NULL;
	}
	if (r_buf_read_at (bin->b, *curAddr, (ut8*) var->szKey, TRANSLATION_UTF_16_LEN) < 1) {
		bprintf ("Warning: read (Var szKey)\n");
		free_Var (var);
		return NULL;
	}
	*curAddr += TRANSLATION_UTF_16_LEN;
	if (memcmp (var->szKey, TRANSLATION_UTF_16, TRANSLATION_UTF_16_LEN)) {
		bprintf ("Warning: check (Var szKey)\n");
		free_Var (var);
		return NULL;
	}
	align32 (*curAddr);
	var->numOfValues = var->wValueLength / 4;
	if (!var->numOfValues) {
		bprintf ("Warning: check (Var numOfValues)\n");
		free_Var (var);
		return NULL;
	}
	var->Value = (ut32*) malloc (var->wValueLength);
	if (!var->Value) {
		bprintf ("Warning: malloc (Var Value)\n");
		free_Var (var);
		return NULL;
	}
	if (r_buf_read_at (bin->b, *curAddr, (ut8*) var->Value, var->wValueLength) != var->wValueLength) {
		bprintf ("Warning: read (Var Value)\n");
		free_Var (var);
		return NULL;
	}
	*curAddr += var->wValueLength;
	return var;
}

static VarFileInfo* Pe_r_bin_pe_parse_var_file_info(struct PE_(r_bin_pe_obj_t)* bin, PE_DWord* curAddr) {
	VarFileInfo* varFileInfo = calloc (1, sizeof(*varFileInfo));
	if (!varFileInfo) {
		bprintf ("Warning: calloc (VarFileInfo)\n");
		return NULL;
	}
	PE_DWord startAddr = *curAddr;
	if (r_buf_read_at (bin->b, *curAddr, (ut8*) &varFileInfo->wLength, sizeof(varFileInfo->wLength)) != sizeof(varFileInfo->wLength)) {
		bprintf ("Warning: read (VarFileInfo wLength)\n");
		free_VarFileInfo (varFileInfo);
		return NULL;
	}
	*curAddr += sizeof(varFileInfo->wLength);

	if (r_buf_read_at (bin->b, *curAddr, (ut8*) &varFileInfo->wValueLength, sizeof(varFileInfo->wValueLength)) != sizeof(varFileInfo->wValueLength)) {
		bprintf ("Warning: read (VarFileInfo wValueLength)\n");
		free_VarFileInfo (varFileInfo);
		return NULL;
	}
	*curAddr += sizeof(varFileInfo->wValueLength);

	if (varFileInfo->wValueLength != 0) {
		bprintf ("Warning: check (VarFileInfo wValueLength)\n");
		free_VarFileInfo (varFileInfo);
		return NULL;
	}

	if (r_buf_read_at (bin->b, *curAddr, (ut8*) &varFileInfo->wType, sizeof(varFileInfo->wType)) != sizeof(varFileInfo->wType)) {
		bprintf ("Warning: read (VarFileInfo wType)\n");
		free_VarFileInfo (varFileInfo);
		return NULL;
	}
	*curAddr += sizeof(varFileInfo->wType);
	if (varFileInfo->wType && varFileInfo->wType != 1) {
		bprintf ("Warning: check (VarFileInfo wType)\n");
		free_VarFileInfo (varFileInfo);
		return NULL;
	}

	varFileInfo->szKey = (ut16*) malloc (UT16_ALIGN (VARFILEINFO_UTF_16_LEN ));  //L"VarFileInfo"
	if (!varFileInfo->szKey) {
		bprintf ("Warning: malloc (VarFileInfo szKey)\n");
		free_VarFileInfo (varFileInfo);
		return NULL;
	}

	if (r_buf_read_at (bin->b, *curAddr, (ut8*) varFileInfo->szKey, VARFILEINFO_UTF_16_LEN) != VARFILEINFO_UTF_16_LEN) {
		bprintf ("Warning: read (VarFileInfo szKey)\n");
		free_VarFileInfo (varFileInfo);
		return NULL;
	}
	*curAddr += VARFILEINFO_UTF_16_LEN;

	if (memcmp (varFileInfo->szKey, VARFILEINFO_UTF_16, VARFILEINFO_UTF_16_LEN)) {
		bprintf ("Warning: check (VarFileInfo szKey)\n");
		free_VarFileInfo (varFileInfo);
		return NULL;
	}
	align32 (*curAddr);
	while (startAddr + varFileInfo->wLength > *curAddr) {
		Var** tmp = (Var**) realloc (varFileInfo->Children, (varFileInfo->numOfChildren + 1) * sizeof(*varFileInfo->Children));
		if (!tmp) {
			bprintf ("Warning: realloc (VarFileInfo Children)\n");
			free_VarFileInfo (varFileInfo);
			return NULL;
		}
		varFileInfo->Children = tmp;
		if (!(varFileInfo->Children[varFileInfo->numOfChildren] = Pe_r_bin_pe_parse_var (bin, curAddr))) {
			bprintf ("Warning: bad parsing Var\n");
			free_VarFileInfo (varFileInfo);
			return NULL;
		}
		varFileInfo->numOfChildren++;
		align32 (*curAddr);
	}
	return varFileInfo;
}

static String* Pe_r_bin_pe_parse_string(struct PE_(r_bin_pe_obj_t)* bin, PE_DWord* curAddr) {
	String* string = calloc (1, sizeof(*string));
	PE_DWord begAddr = *curAddr;
	int len_value = 0;
	int i = 0;
	if (!string) {
		bprintf ("Warning: calloc (String)\n");
		return NULL;
	}
	if (begAddr > bin->size || begAddr + sizeof(string->wLength) > bin->size) {
		free_String (string);
		return NULL;
	}
	if (r_buf_read_at (bin->b, *curAddr, (ut8*) &string->wLength, sizeof(string->wLength)) != sizeof(string->wLength)) {
		bprintf ("Warning: read (String wLength)\n");
		goto out_error;
	}
	*curAddr += sizeof(string->wLength);
	if (*curAddr > bin->size || *curAddr + sizeof(string->wValueLength) > bin->size) {
		goto out_error;
	}
	if (r_buf_read_at (bin->b, *curAddr, (ut8*) &string->wValueLength, sizeof(string->wValueLength)) != sizeof(string->wValueLength)) {
		bprintf ("Warning: read (String wValueLength)\n");
		goto out_error;
	}
	*curAddr += sizeof(string->wValueLength);

	if (*curAddr > bin->size || *curAddr + sizeof(string->wType) > bin->size) {
		goto out_error;
	}
	if (r_buf_read_at (bin->b, *curAddr, (ut8*) &string->wType, sizeof(string->wType)) != sizeof(string->wType)) {
		bprintf ("Warning: read (String wType)\n");
		goto out_error;
	}
	*curAddr += sizeof(string->wType);
	if (string->wType != 0 && string->wType != 1) {
		bprintf ("Warning: check (String wType)\n");
		goto out_error;
	}

	for (i = 0; *curAddr < begAddr + string->wLength; ++i, *curAddr += sizeof (ut16)) {
		ut16 utf16_char;
		if (*curAddr > bin->size || *curAddr + sizeof (ut16) > bin->size) {
			goto out_error;
		}
		if (r_buf_read_at (bin->b, *curAddr, (ut8*) &utf16_char, sizeof (ut16)) != sizeof (ut16)) {
			bprintf ("Warning: check (String szKey)\n");
			goto out_error;
		}
		string->szKey = (ut16*) realloc (string->szKey, (i + 1) * sizeof (ut16));
		string->szKey[i] = utf16_char;
		string->wKeyLen += sizeof (ut16);
		if (!utf16_char) {
			*curAddr += sizeof (ut16);
			break;
		}
	}
	align32 (*curAddr);
	len_value = R_MIN (string->wValueLength * 2, string->wLength - (*curAddr - begAddr));
	string->wValueLength = len_value;
	if (len_value < 0) {
		len_value = 0;
	}
	string->Value = (ut16*) calloc (len_value + 1, 1);
	if (!string->Value) {
		bprintf ("Warning: malloc (String Value)\n");
		goto out_error;
	}
	if (*curAddr > bin->size || *curAddr + len_value > bin->size) {
		goto out_error;
	}
	if (r_buf_read_at (bin->b, *curAddr, (ut8*) string->Value, len_value) != len_value) {
		bprintf ("Warning: read (String Value)\n");
		goto out_error;
	}
	*curAddr += len_value;
	return string;
out_error:
	free_String (string);
	return NULL;
}

static StringTable* Pe_r_bin_pe_parse_string_table(struct PE_(r_bin_pe_obj_t)* bin, PE_DWord* curAddr) {
	StringTable* stringTable = calloc (1, sizeof(*stringTable));
	if (!stringTable) {
		bprintf ("Warning: calloc (stringTable)\n");
		return NULL;
	}

	PE_DWord startAddr = *curAddr;
	if (r_buf_read_at (bin->b, *curAddr, (ut8*) &stringTable->wLength, sizeof(stringTable->wLength)) != sizeof(stringTable->wLength)) {
		bprintf ("Warning: read (StringTable wLength)\n");
		free_StringTable (stringTable);
		return NULL;
	}
	*curAddr += sizeof(stringTable->wLength);

	if (r_buf_read_at (bin->b, *curAddr, (ut8*) &stringTable->wValueLength, sizeof(stringTable->wValueLength)) != sizeof(stringTable->wValueLength)) {
		bprintf ("Warning: read (StringTable wValueLength)\n");
		free_StringTable (stringTable);
		return NULL;
	}
	*curAddr += sizeof(stringTable->wValueLength);

	if (stringTable->wValueLength) {
		bprintf ("Warning: check (StringTable wValueLength)\n");
		free_StringTable (stringTable);
		return NULL;
	}

	if (r_buf_read_at (bin->b, *curAddr, (ut8*) &stringTable->wType, sizeof(stringTable->wType)) != sizeof(stringTable->wType)) {
		bprintf ("Warning: read (StringTable wType)\n");
		free_StringTable (stringTable);
		return NULL;
	}
	*curAddr += sizeof(stringTable->wType);
	if (stringTable->wType && stringTable->wType != 1) {
		bprintf ("Warning: check (StringTable wType)\n");
		free_StringTable (stringTable);
		return NULL;
	}
	stringTable->szKey = (ut16*) malloc (UT16_ALIGN (EIGHT_HEX_DIG_UTF_16_LEN));  //EIGHT_HEX_DIG_UTF_16_LEN
	if (!stringTable->szKey) {
		bprintf ("Warning: malloc (stringTable szKey)\n");
		free_StringTable (stringTable);
		return NULL;
	}

	if (r_buf_read_at (bin->b, *curAddr, (ut8*) stringTable->szKey, EIGHT_HEX_DIG_UTF_16_LEN) != EIGHT_HEX_DIG_UTF_16_LEN) {
		bprintf ("Warning: read (StringTable szKey)\n");
		free_StringTable (stringTable);
		return NULL;
	}
	*curAddr += EIGHT_HEX_DIG_UTF_16_LEN;
	align32 (*curAddr);
	while (startAddr + stringTable->wLength > *curAddr) {
		String** tmp = (String**) realloc (stringTable->Children, (stringTable->numOfChildren + 1) * sizeof(*stringTable->Children));
		if (!tmp) {
			bprintf ("Warning: realloc (StringTable Children)\n");
			free_StringTable (stringTable);
			return NULL;
		}
		stringTable->Children = tmp;
		if (!(stringTable->Children[stringTable->numOfChildren] = Pe_r_bin_pe_parse_string (bin, curAddr))) {
			bprintf ("Warning: bad parsing String\n");
			free_StringTable (stringTable);
			return NULL;
		}
		stringTable->numOfChildren++;
		align32 (*curAddr);
	}

	if (!stringTable->numOfChildren) {
		bprintf ("Warning: check (StringTable numOfChildren)\n");
		free_StringTable (stringTable);
		return NULL;
	}

	return stringTable;
}

static StringFileInfo* Pe_r_bin_pe_parse_string_file_info(struct PE_(r_bin_pe_obj_t)* bin, PE_DWord* curAddr) {
	StringFileInfo* stringFileInfo = calloc (1, sizeof(*stringFileInfo));
	if (!stringFileInfo) {
		bprintf ("Warning: calloc (StringFileInfo)\n");
		return NULL;
	}

	PE_DWord startAddr = *curAddr;

	if (r_buf_read_at (bin->b, *curAddr, (ut8*) &stringFileInfo->wLength, sizeof(stringFileInfo->wLength)) != sizeof(stringFileInfo->wLength)) {
		bprintf ("Warning: read (StringFileInfo wLength)\n");
		free_StringFileInfo (stringFileInfo);
		return NULL;
	}
	*curAddr += sizeof(stringFileInfo->wLength);

	if (r_buf_read_at (bin->b, *curAddr, (ut8*) &stringFileInfo->wValueLength, sizeof(stringFileInfo->wValueLength)) != sizeof(stringFileInfo->wValueLength)) {
		bprintf ("Warning: read (StringFileInfo wValueLength)\n");
		free_StringFileInfo (stringFileInfo);
		return NULL;
	}
	*curAddr += sizeof(stringFileInfo->wValueLength);

	if (stringFileInfo->wValueLength) {
		bprintf ("Warning: check (StringFileInfo wValueLength)\n");
		free_StringFileInfo (stringFileInfo);
		return NULL;
	}

	if (r_buf_read_at (bin->b, *curAddr, (ut8*) &stringFileInfo->wType, sizeof(stringFileInfo->wType)) != sizeof(stringFileInfo->wType)) {
		bprintf ("Warning: read (StringFileInfo wType)\n");
		free_StringFileInfo (stringFileInfo);
		return NULL;
	}
	*curAddr += sizeof(stringFileInfo->wType);

	if (stringFileInfo->wType && stringFileInfo->wType != 1) {
		bprintf ("Warning: check (StringFileInfo wType)\n");
		free_StringFileInfo (stringFileInfo);
		return NULL;
	}

	stringFileInfo->szKey = (ut16*) malloc (UT16_ALIGN (STRINGFILEINFO_UTF_16_LEN));  //L"StringFileInfo"
	if (!stringFileInfo->szKey) {
		bprintf ("Warning: malloc (StringFileInfo szKey)\n");
		free_StringFileInfo (stringFileInfo);
		return NULL;
	}

	if (r_buf_read_at (bin->b, *curAddr, (ut8*) stringFileInfo->szKey, STRINGFILEINFO_UTF_16_LEN) != STRINGFILEINFO_UTF_16_LEN) {
		bprintf ("Warning: read (StringFileInfo szKey)\n");
		free_StringFileInfo (stringFileInfo);
		return NULL;
	}
	*curAddr += STRINGFILEINFO_UTF_16_LEN;

	if (memcmp (stringFileInfo->szKey, STRINGFILEINFO_UTF_16, STRINGFILEINFO_UTF_16_LEN) != 0) {
		bprintf ("Warning: check (StringFileInfo szKey)\n");
		free_StringFileInfo (stringFileInfo);
		return NULL;
	}

	align32 (*curAddr);

	while (startAddr + stringFileInfo->wLength > *curAddr) {
		StringTable** tmp = (StringTable**) realloc (stringFileInfo->Children, (stringFileInfo->numOfChildren + 1) * sizeof(*stringFileInfo->Children));
		if (!tmp) {
			bprintf ("Warning: realloc (StringFileInfo Children)\n");
			free_StringFileInfo (stringFileInfo);
			return NULL;
		}
		stringFileInfo->Children = tmp;
		if (!(stringFileInfo->Children[stringFileInfo->numOfChildren] = Pe_r_bin_pe_parse_string_table (bin, curAddr))) {
			bprintf ("Warning: bad parsing StringTable\n");
			free_StringFileInfo (stringFileInfo);
			return NULL;
		}
		stringFileInfo->numOfChildren++;
		align32 (*curAddr);
	}

	if (!stringFileInfo->numOfChildren) {
		bprintf ("Warning: check (StringFileInfo numOfChildren)\n");
		free_StringFileInfo (stringFileInfo);
		return NULL;
	}

	return stringFileInfo;
}

#define EXIT_ON_OVERFLOW(S)\
	if (curAddr > bin->size || curAddr + (S) > bin->size) { \
		goto out_error; }
static PE_VS_VERSIONINFO* Pe_r_bin_pe_parse_version_info(struct PE_(r_bin_pe_obj_t)* bin, PE_DWord version_info_paddr) {
	ut32 sz;
	PE_VS_VERSIONINFO* vs_VersionInfo = calloc (1, sizeof(PE_VS_VERSIONINFO));
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
	EXIT_ON_OVERFLOW (sz);
	if (r_buf_read_at (bin->b, curAddr, (ut8*) &vs_VersionInfo->wLength, sz) != sz) {
		bprintf ("Warning: read (VS_VERSIONINFO wLength)\n");
		goto out_error;
	}
	curAddr += sz;
	EXIT_ON_OVERFLOW (sz);
	if (r_buf_read_at (bin->b, curAddr, (ut8*) &vs_VersionInfo->wValueLength, sz) != sz) {
		bprintf ("Warning: read (VS_VERSIONINFO wValueLength)\n");
		goto out_error;
	}
	curAddr += sz;
	EXIT_ON_OVERFLOW (sz);
	if (r_buf_read_at (bin->b, curAddr, (ut8*) &vs_VersionInfo->wType, sz) != sz) {
		bprintf ("Warning: read (VS_VERSIONINFO wType)\n");
		goto out_error;
	}
	curAddr += sz;
	if (vs_VersionInfo->wType && vs_VersionInfo->wType != 1) {
		bprintf ("Warning: check (VS_VERSIONINFO wType)\n");
		goto out_error;
	}

	vs_VersionInfo->szKey = (ut16*) malloc (UT16_ALIGN (VS_VERSION_INFO_UTF_16_LEN));  //L"VS_VERSION_INFO"
	if (!vs_VersionInfo->szKey) {
		bprintf ("Warning: malloc (VS_VERSIONINFO szKey)\n");
		goto out_error;
	}
	sz = VS_VERSION_INFO_UTF_16_LEN;
	EXIT_ON_OVERFLOW (sz);
	if (r_buf_read_at (bin->b, curAddr, (ut8*) vs_VersionInfo->szKey, sz) != sz) {
		bprintf ("Warning: read (VS_VERSIONINFO szKey)\n");
		goto out_error;
	}
	curAddr += sz;
	if (memcmp (vs_VersionInfo->szKey, VS_VERSION_INFO_UTF_16, sz)) {
		goto out_error;
	}
	align32 (curAddr);
	if (vs_VersionInfo->wValueLength) {
		if (vs_VersionInfo->wValueLength != sizeof (*vs_VersionInfo->Value)) {
			bprintf ("Warning: check (VS_VERSIONINFO wValueLength != sizeof PE_VS_FIXEDFILEINFO)\n");
			goto out_error;
		}

		vs_VersionInfo->Value = (PE_VS_FIXEDFILEINFO*) malloc (sizeof(*vs_VersionInfo->Value));
		if (!vs_VersionInfo->Value) {
			bprintf ("Warning: malloc (VS_VERSIONINFO Value)\n");
			goto out_error;
		}
		sz = sizeof(PE_VS_FIXEDFILEINFO);
		EXIT_ON_OVERFLOW (sz);
		if (r_buf_read_at (bin->b, curAddr, (ut8*) vs_VersionInfo->Value, sz) != sz) {
			bprintf ("Warning: read (VS_VERSIONINFO Value)\n");
			goto out_error;
		}

		if (vs_VersionInfo->Value->dwSignature != 0xFEEF04BD) {
			bprintf ("Warning: check (PE_VS_FIXEDFILEINFO signature) 0x%08x\n", vs_VersionInfo->Value->dwSignature);
			goto out_error;
		}
		curAddr += sz;
		align32 (curAddr);
	}

	if (startAddr + vs_VersionInfo->wLength > curAddr) {
		char t = '\0';
		if (curAddr + 3 * sizeof(ut16) > bin->size || curAddr + 3 + sizeof(ut64) + 1 > bin->size) {
			goto out_error;
		}
		if (r_buf_read_at (bin->b, curAddr + 3 * sizeof(ut16), (ut8*) &t, 1) != 1) {
			bprintf ("Warning: read (VS_VERSIONINFO Children V or S)\n");
			goto out_error;
		}
		if (!(t == 'S' || t == 'V')) {
			bprintf ("Warning: bad type (VS_VERSIONINFO Children)\n");
			goto out_error;
		}
		if (t == 'S') {
			if (!(vs_VersionInfo->stringFileInfo = Pe_r_bin_pe_parse_string_file_info (bin, &curAddr))) {
				bprintf ("Warning: bad parsing (VS_VERSIONINFO StringFileInfo)\n");
				goto out_error;
			}
		}
		if (t == 'V') {
			if (!(vs_VersionInfo->varFileInfo = Pe_r_bin_pe_parse_var_file_info (bin, &curAddr))) {
				bprintf ("Warning: bad parsing (VS_VERSIONINFO VarFileInfo)\n");
				goto out_error;
			}
		}

		align32 (curAddr);

		if (startAddr + vs_VersionInfo->wLength > curAddr) {
			if (t == 'V') {
				if (!(vs_VersionInfo->stringFileInfo = Pe_r_bin_pe_parse_string_file_info (bin, &curAddr))) {
					bprintf ("Warning: bad parsing (VS_VERSIONINFO StringFileInfo)\n");
					goto out_error;
				}
			} else if (t == 'S') {
				if (!(vs_VersionInfo->varFileInfo = Pe_r_bin_pe_parse_var_file_info (bin, &curAddr))) {
					bprintf ("Warning: bad parsing (VS_VERSIONINFO VarFileInfo)\n");
					goto out_error;
				}
			}
			if (startAddr + vs_VersionInfo->wLength > curAddr) {
				bprintf ("Warning: bad parsing (VS_VERSIONINFO wLength left)\n");
				goto out_error;
			}
		}
	}
	return vs_VersionInfo;
out_error:
	free_VS_VERSIONINFO (vs_VersionInfo);
	return NULL;

}

static Sdb* Pe_r_bin_store_var(Var* var) {
	unsigned int i = 0;
	char key[20];
	Sdb* sdb = NULL;
	if (var) {
		sdb = sdb_new0 ();
		if (sdb) {
			for (; i < var->numOfValues; i++) {
				snprintf (key, 20, "%d", i);
				sdb_num_set (sdb, key, var->Value[i], 0);
			}
		}
	}
	return sdb;
}

static Sdb* Pe_r_bin_store_var_file_info(VarFileInfo* varFileInfo) {
	char key[20];
	unsigned int i = 0;
	if (!varFileInfo) {
		return NULL;
	}
	Sdb* sdb = sdb_new0 ();
	if (!sdb) {
		return NULL;
	}
	for (; i < varFileInfo->numOfChildren; i++) {
		snprintf (key, 20, "var%d", i);
		sdb_ns_set (sdb, key, Pe_r_bin_store_var (varFileInfo->Children[i]));
	}
	return sdb;
}

static Sdb* Pe_r_bin_store_string(String* string) {
	Sdb* sdb = NULL;
	char* encodedVal = NULL, * encodedKey = NULL;
	if (!string) {
		return NULL;
	}
	sdb = sdb_new0 ();
	if (!sdb) {
		return NULL;
	}
	encodedKey = sdb_encode ((unsigned char*) string->szKey, string->wKeyLen);
	if (!encodedKey) {
		sdb_free (sdb);
		return NULL;
	}
	encodedVal = sdb_encode ((unsigned char*) string->Value, string->wValueLength);
	if (!encodedVal) {
		free (encodedKey);
		sdb_free (sdb);
		return NULL;
	}
	sdb_set (sdb, "key",   encodedKey, 0);
	sdb_set (sdb, "value", encodedVal, 0);
	free (encodedKey);
	free (encodedVal);
	return sdb;
}

static Sdb* Pe_r_bin_store_string_table(StringTable* stringTable) {
	char key[20];
	char* encodedKey = NULL;
	int i = 0;
	Sdb* sdb = NULL;
	if (!stringTable) {
		return NULL;
	}
	sdb = sdb_new0 ();
	if (!sdb) {
		return NULL;
	}
	encodedKey = sdb_encode ((unsigned char*) stringTable->szKey, EIGHT_HEX_DIG_UTF_16_LEN);
	if (!encodedKey) {
		sdb_free (sdb);
		return NULL;
	}
	sdb_set (sdb, "key", encodedKey, 0);
	free (encodedKey);
	for (; i < stringTable->numOfChildren; i++) {
		snprintf (key, 20, "string%d", i);
		sdb_ns_set (sdb, key, Pe_r_bin_store_string (stringTable->Children[i]));
	}
	return sdb;
}

static Sdb* Pe_r_bin_store_string_file_info(StringFileInfo* stringFileInfo) {
	char key[30];
	int i = 0;
	Sdb* sdb = NULL;
	if (!stringFileInfo) {
		return NULL;
	}
	sdb = sdb_new0 ();
	if (!sdb) {
		return NULL;
	}
	for (; i < stringFileInfo->numOfChildren; i++) {
		snprintf (key, 30, "stringtable%d", i);
		sdb_ns_set (sdb, key, Pe_r_bin_store_string_table (stringFileInfo->Children[i]));
	}
	return sdb;
}

static Sdb* Pe_r_bin_store_fixed_file_info(PE_VS_FIXEDFILEINFO* vs_fixedFileInfo) {
	Sdb* sdb = NULL;
	if (!vs_fixedFileInfo) {
		return NULL;
	}
	sdb = sdb_new0 ();
	if (!sdb) {
		return NULL;
	}
	sdb_num_set (sdb, "Signature",        vs_fixedFileInfo->dwSignature,        0);
	sdb_num_set (sdb, "StrucVersion",     vs_fixedFileInfo->dwStrucVersion,     0);
	sdb_num_set (sdb, "FileVersionMS",    vs_fixedFileInfo->dwFileVersionMS,    0);
	sdb_num_set (sdb, "FileVersionLS",    vs_fixedFileInfo->dwFileVersionLS,    0);
	sdb_num_set (sdb, "ProductVersionMS", vs_fixedFileInfo->dwProductVersionMS, 0);
	sdb_num_set (sdb, "ProductVersionLS", vs_fixedFileInfo->dwProductVersionLS, 0);
	sdb_num_set (sdb, "FileFlagsMask",    vs_fixedFileInfo->dwFileFlagsMask,    0);
	sdb_num_set (sdb, "FileFlags",        vs_fixedFileInfo->dwFileFlags,        0);
	sdb_num_set (sdb, "FileOS",           vs_fixedFileInfo->dwFileOS,           0);
	sdb_num_set (sdb, "FileType",         vs_fixedFileInfo->dwFileType,         0);
	sdb_num_set (sdb, "FileSubtype",      vs_fixedFileInfo->dwFileSubtype,      0);
	sdb_num_set (sdb, "FileDateMS",       vs_fixedFileInfo->dwFileDateMS,       0);
	sdb_num_set (sdb, "FileDateLS",       vs_fixedFileInfo->dwFileDateLS,       0);
	return sdb;
}

static Sdb* Pe_r_bin_store_resource_version_info(PE_VS_VERSIONINFO* vs_VersionInfo) {
	Sdb* sdb = NULL;
	if (!vs_VersionInfo) {
		return NULL;
	}
	sdb = sdb_new0 ();
	if (!sdb) {
		return NULL;
	}
	if (vs_VersionInfo->Value) {
		sdb_ns_set (sdb, "fixed_file_info", Pe_r_bin_store_fixed_file_info (vs_VersionInfo->Value));
	}
	if (vs_VersionInfo->varFileInfo) {
		sdb_ns_set (sdb, "var_file_info", Pe_r_bin_store_var_file_info (vs_VersionInfo->varFileInfo));
	}
	if (vs_VersionInfo->stringFileInfo) {
		sdb_ns_set (sdb, "string_file_info", Pe_r_bin_store_string_file_info (vs_VersionInfo->stringFileInfo));
	}
	return sdb;
}

static char* _resource_lang_str(int id) {
	switch(id) {
	case 0x00: return "LANG_NEUTRAL";
	case 0x7f: return "LANG_INVARIANT";
	case 0x36: return "LANG_AFRIKAANS";
	case 0x1c: return "LANG_ALBANIAN ";
	case 0x01: return "LANG_ARABIC";
	case 0x2b: return "LANG_ARMENIAN";
	case 0x4d: return "LANG_ASSAMESE";
	case 0x2c: return "LANG_AZERI";
	case 0x2d: return "LANG_BASQUE";
	case 0x23: return "LANG_BELARUSIAN";
	case 0x45: return "LANG_BENGALI";
	case 0x02: return "LANG_BULGARIAN";
	case 0x03: return "LANG_CATALAN";
	case 0x04: return "LANG_CHINESE";
	case 0x1a: return "LANG_CROATIAN";
	case 0x05: return "LANG_CZECH";
	case 0x06: return "LANG_DANISH";
	case 0x65: return "LANG_DIVEHI";
	case 0x13: return "LANG_DUTCH";
	case 0x09: return "LANG_ENGLISH";
	case 0x25: return "LANG_ESTONIAN";
	case 0x38: return "LANG_FAEROESE";
	case 0x29: return "LANG_FARSI";
	case 0x0b: return "LANG_FINNISH";
	case 0x0c: return "LANG_FRENCH";
	case 0x56: return "LANG_GALICIAN";
	case 0x37: return "LANG_GEORGIAN";
	case 0x07: return "LANG_GERMAN";
	case 0x08: return "LANG_GREEK";
	case 0x47: return "LANG_GUJARATI";
	case 0x0d: return "LANG_HEBREW";
	case 0x39: return "LANG_HINDI";
	case 0x0e: return "LANG_HUNGARIAN";
	case 0x0f: return "LANG_ICELANDIC";
	case 0x21: return "LANG_INDONESIAN";
	case 0x10: return "LANG_ITALIAN";
	case 0x11: return "LANG_JAPANESE";
	case 0x4b: return "LANG_KANNADA";
	case 0x60: return "LANG_KASHMIRI";
	case 0x3f: return "LANG_KAZAK";
	case 0x57: return "LANG_KONKANI";
	case 0x12: return "LANG_KOREAN";
	case 0x40: return "LANG_KYRGYZ";
	case 0x26: return "LANG_LATVIAN";
	case 0x27: return "LANG_LITHUANIAN";
	case 0x2f: return "LANG_MACEDONIAN";
	case 0x3e: return "LANG_MALAY";
	case 0x4c: return "LANG_MALAYALAM";
	case 0x58: return "LANG_MANIPURI";
	case 0x4e: return "LANG_MARATHI";
	case 0x50: return "LANG_MONGOLIAN";
	case 0x61: return "LANG_NEPALI";
	case 0x14: return "LANG_NORWEGIAN";
	case 0x48: return "LANG_ORIYA";
	case 0x15: return "LANG_POLISH";
	case 0x16: return "LANG_PORTUGUESE";
	case 0x46: return "LANG_PUNJABI";
	case 0x18: return "LANG_ROMANIAN";
	case 0x19: return "LANG_RUSSIAN";
	case 0x4f: return "LANG_SANSKRIT";
	case 0x59: return "LANG_SINDHI";
	case 0x1b: return "LANG_SLOVAK";
	case 0x24: return "LANG_SLOVENIAN";
	case 0x0a: return "LANG_SPANISH ";
	case 0x41: return "LANG_SWAHILI";
	case 0x1d: return "LANG_SWEDISH";
	case 0x5a: return "LANG_SYRIAC";
	case 0x49: return "LANG_TAMIL";
	case 0x44: return "LANG_TATAR";
	case 0x4a: return "LANG_TELUGU";
	case 0x1e: return "LANG_THAI";
	case 0x1f: return "LANG_TURKISH";
	case 0x22: return "LANG_UKRAINIAN";
	case 0x20: return "LANG_URDU";
	case 0x43: return "LANG_UZBEK";
	case 0x2a: return "LANG_VIETNAMESE";
	case 0x3c: return "LANG_GAELIC";
	case 0x3a: return "LANG_MALTESE";
	case 0x28: return "LANG_MAORI";
	case 0x17: return "LANG_RHAETO_ROMANCE";
	case 0x3b: return "LANG_SAAMI";
	case 0x2e: return "LANG_SORBIAN";
	case 0x30: return "LANG_SUTU";
	case 0x31: return "LANG_TSONGA";
	case 0x32: return "LANG_TSWANA";
	case 0x33: return "LANG_VENDA";
	case 0x34: return "LANG_XHOSA";
	case 0x35: return "LANG_ZULU";
	case 0x8f: return "LANG_ESPERANTO";
	case 0x90: return "LANG_WALON";
	case 0x91: return "LANG_CORNISH";
	case 0x92: return "LANG_WELSH";
	case 0x93: return "LANG_BRETON";
	default: return "UNKNOWN";
	}
}

static char* _resource_type_str(int type) {
	switch (type) {
	case 1: return "CURSOR";
	case 2: return "BITMAP";
	case 3: return "ICON";
	case 4: return "MENU";
	case 5: return "DIALOG";
	case 6: return "STRING";
	case 7: return "FONTDIR";
	case 8: return "FONT";
	case 9: return "ACCELERATOR";
	case 10: return "RCDATA";
	case 11: return "MESSAGETABLE";
	case 12: return "GROUP_CURSOR";
	case 14: return "GROUP_ICON";
	case 16: return "VERSION";
	case 17: return "DLGINCLUDE";
	case 19: return "PLUGPLAY";
	case 20: return "VXD";
	case 21: return "ANICURSOR";
	case 22: return "ANIICON";
	case 23: return "HTML";
	case 24: return "MANIFEST";
	default: return "UNKNOWN";
	}
}

static void _parse_resource_directory(struct PE_(r_bin_pe_obj_t) *bin, Pe_image_resource_directory *dir, ut64 offDir, int type, int id, SdbHash *dirs) {
	int index = 0;
	ut32 totalRes = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
	ut64 rsrc_base = bin->resource_directory_offset;
	ut64 off;
	if (totalRes > R_PE_MAX_RESOURCES) {
		return;
	}
	for (index = 0; index < totalRes; index++) {
		Pe_image_resource_directory_entry entry;
		off = rsrc_base + offDir + sizeof(*dir) + index * sizeof(entry);
		char *key = sdb_fmt (0, "0x%08"PFMT64x, off);
		if (sdb_ht_find (dirs, key, NULL)) {
			break;
		}
		sdb_ht_insert (dirs, key, "1");
		if (off > bin->size || off + sizeof (entry) > bin->size) {
			break;
		}
		if (r_buf_read_at (bin->b, off, (ut8*)&entry, sizeof(entry)) < 1) {
			eprintf ("Warning: read resource entry\n");
			break;
		}
		if (entry.u2.s.DataIsDirectory) {
			//detect here malicious file trying to making us infinite loop
			Pe_image_resource_directory identEntry;
			off = rsrc_base + entry.u2.s.OffsetToDirectory;
			int len = r_buf_read_at (bin->b, off, (ut8*) &identEntry, sizeof (identEntry));
			if (len < 1 || len != sizeof (Pe_image_resource_directory)) {
				eprintf ("Warning: parsing resource directory\n");
			}
			_parse_resource_directory (bin, &identEntry,
				entry.u2.s.OffsetToDirectory, type, entry.u1.Id, dirs);
			continue;
		}

		Pe_image_resource_data_entry *data = R_NEW0 (Pe_image_resource_data_entry);
		if (!data) {
			break;
		}
		off = rsrc_base + entry.u2.OffsetToData;
		if (off > bin->size || off + sizeof (data) > bin->size) {
			free (data);
			break;
		}
		if (r_buf_read_at (bin->b, off, (ut8*)data, sizeof (*data)) != sizeof (*data)) {
			eprintf ("Warning: read (resource data entry)\n");
			free (data);
			break;
		}
		if (type == PE_RESOURCE_ENTRY_VERSION) {
			char key[64];
			int counter = 0;
			Sdb *sdb = sdb_new0 ();
			if (!sdb) {
				free (data);
				sdb_free (sdb);
				continue;
			}
			PE_DWord data_paddr = bin_pe_rva_to_paddr (bin, data->OffsetToData);
			if (!data_paddr) {
				bprintf ("Warning: bad RVA in resource data entry\n");
				free (data);
				sdb_free (sdb);
				continue;
			}
			PE_DWord cur_paddr = data_paddr;
			if ((cur_paddr & 0x3) != 0) {
				bprintf ("Warning: not aligned version info address\n");
				free (data);
				sdb_free (sdb);
				continue;
			}
			while (cur_paddr < (data_paddr + data->Size) && cur_paddr < bin->size) {
				PE_VS_VERSIONINFO* vs_VersionInfo = Pe_r_bin_pe_parse_version_info (bin, cur_paddr);
				if (vs_VersionInfo) {
					snprintf (key, 30, "VS_VERSIONINFO%d", counter++);
					sdb_ns_set (sdb, key, Pe_r_bin_store_resource_version_info (vs_VersionInfo));
				} else {
					break;
				}
				if (vs_VersionInfo->wLength < 1) {
					// Invalid version length
					break;
				}
				cur_paddr += vs_VersionInfo->wLength;
				free_VS_VERSIONINFO (vs_VersionInfo);
				align32 (cur_paddr);
			}
			sdb_ns_set (bin->kv, "vs_version_info", sdb);
		}
		r_pe_resource *rs = R_NEW0 (r_pe_resource);
		if (!rs) {
			free (data);
			break;
		}
		rs->timestr = _time_stamp_to_str (dir->TimeDateStamp);
		rs->type = strdup (_resource_type_str (type));
		rs->language = strdup (_resource_lang_str (entry.u1.Name & 0x3ff));
		rs->data = data;
		rs->name = id;
		r_list_append (bin->resources, rs);
	}
}

static void _store_resource_sdb(struct PE_(r_bin_pe_obj_t) *bin) {
	RListIter *iter;
	r_pe_resource *rs;
	int index = 0;
	ut64 vaddr = 0;
	char *key;
	Sdb *sdb = sdb_new0 ();
	if (!sdb) {
		return;
	}
	r_list_foreach (bin->resources, iter, rs) {
		key = sdb_fmt (0, "resource.%d.timestr", index);
		sdb_set (sdb, key, rs->timestr, 0);
		key = sdb_fmt (0, "resource.%d.vaddr", index);
		vaddr = bin_pe_rva_to_va (bin, rs->data->OffsetToData);
		sdb_num_set (sdb, key, vaddr, 0);
		key = sdb_fmt (0, "resource.%d.name", index);
		sdb_num_set (sdb, key, rs->name, 0);
		key = sdb_fmt (0, "resource.%d.size", index);
		sdb_num_set (sdb, key, rs->data->Size, 0);
		key = sdb_fmt (0, "resource.%d.type", index);
		sdb_set (sdb, key, rs->type, 0);
		key = sdb_fmt (0, "resource.%d.language", index);
		sdb_set (sdb, key, rs->language, 0);
		index++;
	}
	sdb_ns_set (bin->kv, "pe_resource", sdb);
}


R_API void PE_(bin_pe_parse_resource)(struct PE_(r_bin_pe_obj_t) *bin) {
	int index = 0;
	ut64 off = 0, rsrc_base = bin->resource_directory_offset;
	Pe_image_resource_directory *rs_directory = bin->resource_directory;
	ut32 curRes = 0;
	int totalRes = 0;
	SdbHash *dirs = sdb_ht_new (); //to avoid infinite loops
	if (!dirs) {
		return;
	}
	if (!rs_directory) {
		sdb_ht_free (dirs);
		return;
	}
	curRes = rs_directory->NumberOfNamedEntries;
	totalRes = curRes + rs_directory->NumberOfIdEntries;
	if (totalRes > R_PE_MAX_RESOURCES) {
		eprintf ("Error parsing resource directory\n");
		sdb_ht_free (dirs);
		return;
	}
	for (index = 0; index < totalRes; index++) {
		Pe_image_resource_directory_entry typeEntry;
		off = rsrc_base + sizeof (*rs_directory) + index * sizeof (typeEntry);
		sdb_ht_insert (dirs, sdb_fmt (0, "0x%08"PFMT64x, off), "1");
		if (off > bin->size || off + sizeof(typeEntry) > bin->size) {
			break;
		}
		if (r_buf_read_at (bin->b, off, (ut8*)&typeEntry, sizeof(typeEntry)) < 1) {
			eprintf ("Warning: read resource  directory entry\n");
			break;
		}
		if (typeEntry.u2.s.DataIsDirectory) {
			Pe_image_resource_directory identEntry;
			off = rsrc_base + typeEntry.u2.s.OffsetToDirectory;
			int len = r_buf_read_at (bin->b, off, (ut8*)&identEntry, sizeof(identEntry));
			if (len < 1 || len != sizeof (identEntry)) {
				eprintf ("Warning: parsing resource directory\n");
			}
			_parse_resource_directory (bin, &identEntry, typeEntry.u2.s.OffsetToDirectory, typeEntry.u1.Id, 0, dirs);
		}
	}
	sdb_ht_free (dirs);
	_store_resource_sdb (bin);
}

static void bin_pe_get_certificate(struct PE_ (r_bin_pe_obj_t) * bin) {
	ut64 size, vaddr;
	ut8 *data = NULL;
	int len;
	if (!bin || !bin->nt_headers) {
		return;
	}
	bin->cms = NULL;
	size = bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
	vaddr = bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
	data = calloc (1, size);
	if (!data) {
		return;
	}
	if (vaddr > bin->size || vaddr + size > bin->size) {
		bprintf ("vaddr greater than the file\n");
		free (data);
		return;
	}
	//skipping useless header..
	len = r_buf_read_at (bin->b, vaddr + 8, data, size - 8);
	if (len < 1) {
		R_FREE (data);
		return;
	}
	bin->cms = r_pkcs7_parse_cms (data, size);
	bin->is_signed = bin->cms != NULL;
	R_FREE (data);
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
	bin->big_endian = 0;
	if (!bin_pe_init_hdr (bin)) {
		eprintf ("Warning: File is not PE\n");
		return false;
	}
	if (!bin_pe_init_sections (bin)) {
		eprintf ("Warning: Cannot initialize sections\n");
		return false;
	}
	bin_pe_init_imports (bin);
	bin_pe_init_exports (bin);
	bin_pe_init_resource (bin);
	bin_pe_get_certificate(bin);

	bin->big_endian = PE_(r_bin_pe_is_big_endian) (bin);

	bin_pe_init_tls (bin);
	bin_pe_init_clr_hdr (bin);
	bin_pe_init_metadata_hdr (bin);
	bin_pe_init_overlay (bin);
	PE_(bin_pe_parse_resource) (bin);
	bin->relocs = NULL;
	return true;
}

char* PE_(r_bin_pe_get_arch)(struct PE_(r_bin_pe_obj_t)* bin) {
	char* arch;
	if (!bin || !bin->nt_headers) {
		return strdup ("x86");
	}
	switch (bin->nt_headers->file_header.Machine) {
	case PE_IMAGE_FILE_MACHINE_ALPHA:
	case PE_IMAGE_FILE_MACHINE_ALPHA64:
		arch = strdup ("alpha");
		break;
	case PE_IMAGE_FILE_MACHINE_RPI2: // 462
	case PE_IMAGE_FILE_MACHINE_ARM:
	case PE_IMAGE_FILE_MACHINE_THUMB:
		arch = strdup ("arm");
		break;
	case PE_IMAGE_FILE_MACHINE_M68K:
		arch = strdup ("m68k");
		break;
	case PE_IMAGE_FILE_MACHINE_MIPS16:
	case PE_IMAGE_FILE_MACHINE_MIPSFPU:
	case PE_IMAGE_FILE_MACHINE_MIPSFPU16:
	case PE_IMAGE_FILE_MACHINE_WCEMIPSV2:
		arch = strdup ("mips");
		break;
	case PE_IMAGE_FILE_MACHINE_POWERPC:
	case PE_IMAGE_FILE_MACHINE_POWERPCFP:
		arch = strdup ("ppc");
		break;
	case PE_IMAGE_FILE_MACHINE_EBC:
		arch = strdup ("ebc");
		break;
	case PE_IMAGE_FILE_MACHINE_ARM64:
		arch = strdup ("arm");
		break;
	default:
		arch = strdup ("x86");
	}
	return arch;
}

struct r_bin_pe_addr_t* PE_(r_bin_pe_get_entrypoint)(struct PE_(r_bin_pe_obj_t)* bin) {
	struct r_bin_pe_addr_t* entry = NULL;
	static bool debug = false;
	PE_DWord pe_entry;
	int i;
	ut64 base_addr = PE_(r_bin_pe_get_image_base) (bin);
	if (!bin || !bin->optional_header) {
		return NULL;
	}
	if (!(entry = malloc (sizeof (struct r_bin_pe_addr_t)))) {
		r_sys_perror ("malloc (entrypoint)");
		return NULL;
	}
	pe_entry = bin->optional_header->AddressOfEntryPoint;
	entry->vaddr = bin_pe_rva_to_va (bin, pe_entry);
	entry->paddr = bin_pe_rva_to_paddr (bin, pe_entry);
	// haddr is the address of AddressOfEntryPoint in header.
	entry->haddr = bin->dos_header->e_lfanew + 4 + sizeof (PE_(image_file_header)) + 16;

	if (entry->paddr >= bin->size) {
		struct r_bin_pe_section_t* sections = PE_(r_bin_pe_get_sections) (bin);
		ut64 paddr = 0;
		if (!debug) {
			bprintf ("Warning: Invalid entrypoint ... "
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
				int sa = R_MAX (bin->optional_header->SectionAlignment, 0x1000);
				entry->paddr = pe_entry & ((sa << 1) - 1);
				entry->vaddr = entry->paddr + base_addr;
			}
		}
		free (sections);

	}
	if (!entry->paddr) {
		if (!debug) {
			bprintf ("Warning: NULL entrypoint\n");
		}
		struct r_bin_pe_section_t* sections = PE_(r_bin_pe_get_sections) (bin);
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
	struct r_bin_pe_export_t* exp, * exports = NULL;
	PE_Word function_ordinal;
	PE_VWord functions_paddr, names_paddr, ordinals_paddr, function_rva, name_vaddr, name_paddr;
	char function_name[PE_NAME_LENGTH + 1], forwarder_name[PE_NAME_LENGTH + 1];
	char dll_name[PE_NAME_LENGTH + 1], export_name[256];
	PE_(image_data_directory) * data_dir_export;
	PE_VWord export_dir_rva;
	int n,i, export_dir_size;
	st64 exports_sz = 0;

	if (!bin || !bin->data_directory) {
		return NULL;
	}
	data_dir_export = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_EXPORT];
	export_dir_rva = data_dir_export->VirtualAddress;
	export_dir_size = data_dir_export->Size;
	if (bin->export_directory) {
		if (bin->export_directory->NumberOfFunctions + 1 <
		bin->export_directory->NumberOfFunctions) {
			// avoid integer overflow
			return NULL;
		}
		exports_sz = (bin->export_directory->NumberOfFunctions + 1) * sizeof (struct r_bin_pe_export_t);
		// we cant exit with export_sz > bin->size, us r_bin_pe_export_t is 256+256+8+8+8+4 bytes is easy get over file size
		// to avoid fuzzing we can abort on export_directory->NumberOfFunctions>0xffff
		if (exports_sz < 0 || bin->export_directory->NumberOfFunctions + 1 > 0xffff) {
			return NULL;
		}
		if (!(exports = malloc (exports_sz))) {
			return NULL;
		}
		if (r_buf_read_at (bin->b, bin_pe_rva_to_paddr (bin, bin->export_directory->Name), (ut8*) dll_name, PE_NAME_LENGTH) < 1) {
			bprintf ("Warning: read (dll name)\n");
			free (exports);
			return NULL;
		}
		functions_paddr = bin_pe_rva_to_paddr (bin, bin->export_directory->AddressOfFunctions);
		names_paddr = bin_pe_rva_to_paddr (bin, bin->export_directory->AddressOfNames);
		ordinals_paddr = bin_pe_rva_to_paddr (bin, bin->export_directory->AddressOfOrdinals);
		for (i = 0; i < bin->export_directory->NumberOfFunctions; i++) {
			// get vaddr from AddressOfFunctions array
			int ret = r_buf_read_at (bin->b, functions_paddr + i * sizeof(PE_VWord), (ut8*) &function_rva, sizeof(PE_VWord));
			if (ret < 1) {
				break;
			}
			// have exports by name?
			if (bin->export_directory->NumberOfNames != 0) {
				// search for value of i into AddressOfOrdinals
				name_vaddr = 0;
				for (n = 0; n < bin->export_directory->NumberOfNames; n++) {
					ret = r_buf_read_at (bin->b, ordinals_paddr + n * sizeof(PE_Word), (ut8*) &function_ordinal, sizeof (PE_Word));
					if (ret < 1) {
						break;
					}
					// if exist this index into AddressOfOrdinals
					if (i == function_ordinal) {
						// get the VA of export name  from AddressOfNames
						r_buf_read_at (bin->b, names_paddr + n * sizeof (PE_VWord), (ut8*) &name_vaddr, sizeof (PE_VWord));
						break;
					}
				}
				// have an address into name_vaddr?
				if (name_vaddr) {
					// get the name of the Export
					name_paddr = bin_pe_rva_to_paddr (bin, name_vaddr);
					if (r_buf_read_at (bin->b, name_paddr, (ut8*) function_name, PE_NAME_LENGTH) < 1) {
						bprintf ("Warning: read (function name)\n");
						exports[i].last = 1;
						return exports;
					}
				} else { // No name export, get the ordinal
					snprintf (function_name, PE_NAME_LENGTH, "Ordinal_%i", i + 1);
				}
			}else { // if dont export by name exist, get the ordinal taking in mind the Base value.
				function_ordinal = i + bin->export_directory->Base;
				snprintf (function_name, PE_NAME_LENGTH, "Ordinal_%i", function_ordinal);
			}
			// check if VA are into export directory, this mean a forwarder export
			if (function_rva >= export_dir_rva && function_rva < (export_dir_rva + export_dir_size)) {
				// if forwarder, the VA point to Forwarded name
				if (r_buf_read_at (bin->b, bin_pe_rva_to_paddr (bin, function_rva), (ut8*) forwarder_name, PE_NAME_LENGTH) < 1) {
					exports[i].last = 1;
					return exports;
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
			memcpy (exports[i].name,      export_name,    PE_NAME_LENGTH);
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

static void free_rsdr_hdr(SCV_RSDS_HEADER* rsds_hdr) {
	R_FREE (rsds_hdr->file_name);
}

static void init_rsdr_hdr(SCV_RSDS_HEADER* rsds_hdr) {
	memset (rsds_hdr, 0, sizeof (SCV_RSDS_HEADER));
	rsds_hdr->free = (void (*)(struct SCV_RSDS_HEADER*))free_rsdr_hdr;
}

static void free_cv_nb10_header(SCV_NB10_HEADER* cv_nb10_header) {
	R_FREE (cv_nb10_header->file_name);
}

static void init_cv_nb10_header(SCV_NB10_HEADER* cv_nb10_header) {
	memset (cv_nb10_header, 0, sizeof (SCV_NB10_HEADER));
	cv_nb10_header->free = (void (*)(struct SCV_NB10_HEADER*))free_cv_nb10_header;
}

static bool get_rsds(ut8* dbg_data, int dbg_data_len, SCV_RSDS_HEADER* res) {
	const int rsds_sz = 4 + sizeof (SGUID) + 4;
	if (dbg_data_len < rsds_sz) {
		return false;
	}
	memcpy (res, dbg_data, rsds_sz);
	res->file_name = (ut8*) strdup ((const char*) dbg_data + rsds_sz);
	return true;
}

static void get_nb10(ut8* dbg_data, SCV_NB10_HEADER* res) {
	const int nb10sz = 16;
	memcpy (res, dbg_data, nb10sz);
	res->file_name = (ut8*) strdup ((const char*) dbg_data + nb10sz);
}

static int get_debug_info(struct PE_(r_bin_pe_obj_t)* bin, PE_(image_debug_directory_entry)* dbg_dir_entry, ut8* dbg_data, int dbg_data_len, SDebugInfo* res) {
	#define SIZEOF_FILE_NAME 255
	int i = 0;
	const char* basename;
	if (!dbg_data) {
		return 0;
	}
	switch (dbg_dir_entry->Type) {
	case IMAGE_DEBUG_TYPE_CODEVIEW:
		if (!strncmp ((char*) dbg_data, "RSDS", 4)) {
			SCV_RSDS_HEADER rsds_hdr;
			init_rsdr_hdr (&rsds_hdr);
			if (!get_rsds (dbg_data, dbg_data_len, &rsds_hdr)) {
				bprintf ("Warning: Cannot read PE debug info\n");
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
			basename = r_file_basename ((char*) rsds_hdr.file_name);
			strncpy (res->file_name, (const char*)
				basename, sizeof (res->file_name));
			res->file_name[sizeof (res->file_name) - 1] = 0;
			rsds_hdr.free ((struct SCV_RSDS_HEADER*) &rsds_hdr);
		} else if (strncmp ((const char*) dbg_data, "NB10", 4) == 0) {
			SCV_NB10_HEADER nb10_hdr;
			init_cv_nb10_header (&nb10_hdr);
			get_nb10 (dbg_data, &nb10_hdr);
			snprintf (res->guidstr, sizeof (res->guidstr),
				"%x%x", nb10_hdr.timestamp, nb10_hdr.age);
			strncpy (res->file_name, (const char*)
				nb10_hdr.file_name, sizeof(res->file_name) - 1);
			res->file_name[sizeof (res->file_name) - 1] = 0;
			nb10_hdr.free ((struct SCV_NB10_HEADER*) &nb10_hdr);
		} else {
			bprintf ("CodeView section not NB10 or RSDS\n");
			return 0;
		}
		break;
	default:
		//bprintf("get_debug_info(): not supported type\n");
		return 0;
	}

	while (i < 33) {
		res->guidstr[i] = toupper ((int) res->guidstr[i]);
		i++;
	}

	return 1;
}

int PE_(r_bin_pe_get_debug_data)(struct PE_(r_bin_pe_obj_t)* bin, SDebugInfo* res) {
	PE_(image_debug_directory_entry)* img_dbg_dir_entry = NULL;
	PE_(image_data_directory) * dbg_dir;
	PE_DWord dbg_dir_offset;
	ut8* dbg_data = 0;
	int result = 0;
	if (!bin) {
		return 0;
	}
	dbg_dir = &bin->nt_headers->optional_header.DataDirectory[6 /*IMAGE_DIRECTORY_ENTRY_DEBUG*/];
	dbg_dir_offset = bin_pe_rva_to_paddr (bin, dbg_dir->VirtualAddress);
	if ((int) dbg_dir_offset < 0 || dbg_dir_offset >= bin->size) {
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
		if (dbg_data_len < 1) {
			return false;
		}
		dbg_data = (ut8*) calloc (1, dbg_data_len + 1);
		if (dbg_data) {
			r_buf_read_at (bin->b, dbg_data_poff, dbg_data, dbg_data_len);
			result = get_debug_info (bin, img_dbg_dir_entry, dbg_data, dbg_data_len, res);
			R_FREE (dbg_data);
		}
	}
	return result;
}

struct r_bin_pe_import_t* PE_(r_bin_pe_get_imports)(struct PE_(r_bin_pe_obj_t)* bin) {
	struct r_bin_pe_import_t* imps, * imports = NULL;
	char dll_name[PE_NAME_LENGTH + 1];
	int nimp = 0;
	ut64 off; //used to cache value
	PE_DWord dll_name_offset = 0;
	PE_DWord paddr = 0;
	PE_DWord import_func_name_offset;
	PE_(image_import_directory) * curr_import_dir = NULL;
	PE_(image_delay_import_directory) * curr_delay_import_dir = 0;

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
		void* last;
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
			bprintf ("Warning: read (import directory too big)\n");
			bin->import_directory_size = bin->size - bin->import_directory_offset;
		}
		last = (char*) curr_import_dir + bin->import_directory_size;
		while ((void*) (curr_import_dir + 1) <= last && (
			curr_import_dir->FirstThunk != 0 || curr_import_dir->Name != 0 ||
			curr_import_dir->TimeDateStamp != 0 || curr_import_dir->Characteristics != 0 ||
			curr_import_dir->ForwarderChain != 0)) {
			int rr;
			dll_name_offset = curr_import_dir->Name;
			paddr = bin_pe_rva_to_paddr (bin, dll_name_offset);
			if (paddr > bin->size) {
				goto beach;
			}
			if (paddr + PE_NAME_LENGTH > bin->size) {
				rr = r_buf_read_at (bin->b, paddr, (ut8*) dll_name, bin->size - paddr);
				if (rr != bin->size - paddr) {
					goto beach;
				}
				dll_name[bin->size - paddr] = '\0';
			}else {
				rr = r_buf_read_at (bin->b, paddr, (ut8*) dll_name, PE_NAME_LENGTH);
				if (rr != PE_NAME_LENGTH) {
					goto beach;
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
			goto beach;
		}
		curr_delay_import_dir = (PE_(image_delay_import_directory)*)(bin->b->buf + off);
		if (!curr_delay_import_dir->Attributes) {
			dll_name_offset = bin_pe_rva_to_paddr (bin,
				curr_delay_import_dir->Name - PE_(r_bin_pe_get_image_base)(bin));
			import_func_name_offset = curr_delay_import_dir->DelayImportNameTable -
			PE_(r_bin_pe_get_image_base)(bin);
		} else {
			dll_name_offset = bin_pe_rva_to_paddr (bin, curr_delay_import_dir->Name);
			import_func_name_offset = curr_delay_import_dir->DelayImportNameTable;
		}
		while ((curr_delay_import_dir->Name != 0) && (curr_delay_import_dir->DelayImportAddressTable !=0)) {
			if (dll_name_offset > bin->size || dll_name_offset + PE_NAME_LENGTH > bin->size) {
				goto beach;
			}
			int rr = r_buf_read_at (bin->b, dll_name_offset, (ut8*) dll_name, PE_NAME_LENGTH);
			if (rr < 5) {
				goto beach;
			}

			dll_name[PE_NAME_LENGTH] = '\0';
			if (!bin_pe_parse_imports (bin, &imports, &nimp, dll_name, import_func_name_offset,
				curr_delay_import_dir->DelayImportAddressTable)) {
				break;
			}
			if ((char*) (curr_delay_import_dir + 2) > (char*) (bin->b->buf + bin->size)) {
				goto beach;
			}
			curr_delay_import_dir++;
		}
	}
beach:
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

struct r_bin_pe_lib_t* PE_(r_bin_pe_get_libs)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin) {
		return NULL;
	}
	struct r_bin_pe_lib_t* libs = NULL;
	PE_(image_import_directory) * curr_import_dir = NULL;
	PE_(image_delay_import_directory) * curr_delay_import_dir = NULL;
	PE_DWord name_off = 0;
	SdbHash* lib_map = NULL;
	ut64 off; //cache value
	int index = 0;
	int len = 0;
	int max_libs = 20;
	libs = calloc (max_libs + 1, sizeof(struct r_bin_pe_lib_t));
	if (!libs) {
		r_sys_perror ("malloc (libs)");
		return NULL;
	}

	if (bin->import_directory_offset + bin->import_directory_size > bin->size) {
		bprintf ("import directory offset bigger than file\n");
		goto out_error;
	}
	lib_map = sdb_ht_new ();
	off = bin->import_directory_offset;
	if (off < bin->size && off > 0) {
		void* last = NULL;
		// normal imports
		if (off + sizeof (PE_(image_import_directory)) > bin->size) {
			goto out_error;
		}
		curr_import_dir = (PE_(image_import_directory)*)(bin->b->buf + off);
		last = (char*) curr_import_dir + bin->import_directory_size;
		while ((void*) (curr_import_dir + 1) <= last && (
			curr_import_dir->FirstThunk || curr_import_dir->Name ||
			curr_import_dir->TimeDateStamp || curr_import_dir->Characteristics ||
			curr_import_dir->ForwarderChain)) {
			name_off = bin_pe_rva_to_paddr (bin, curr_import_dir->Name);
			len = r_buf_read_at (bin->b, name_off, (ut8*) libs[index].name, PE_STRING_LENGTH);
			if (!libs[index].name[0]) { // minimum string length
				goto next;
			}
			if (len < 2 || libs[index].name[0] == 0) { // minimum string length
				bprintf ("Warning: read (libs - import dirs) %d\n", len);
				break;
			}
			libs[index].name[len - 1] = '\0';
			r_str_case (libs[index].name, 0);
			if (!sdb_ht_find (lib_map, libs[index].name, NULL)) {
				sdb_ht_insert (lib_map, libs[index].name, "a");
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
			name_off = bin_pe_rva_to_paddr (bin, curr_delay_import_dir->Name);
			if (name_off > bin->size || name_off + PE_STRING_LENGTH > bin->size) {
				goto out_error;
			}
			len = r_buf_read_at (bin->b, name_off, (ut8*) libs[index].name, PE_STRING_LENGTH);
			if (len != PE_STRING_LENGTH) {
				bprintf ("Warning: read (libs - delay import dirs)\n");
				break;
			}
			libs[index].name[len - 1] = '\0';
			r_str_case (libs[index].name, 0);
			if (!sdb_ht_find (lib_map, libs[index].name, NULL)) {
				sdb_ht_insert (lib_map, libs[index].name, "a");
				libs[index++].last = 0;
				if (index >= max_libs) {
					libs = realloc (libs, (max_libs * 2) * sizeof (struct r_bin_pe_lib_t));
					if (!libs) {
						sdb_ht_free (lib_map);
						r_sys_perror ("realloc (libs)");
						return NULL;
					}
					max_libs *= 2;
				}
			}
			curr_delay_import_dir++;
			if ((const ut8*) (curr_delay_import_dir + 1) >= (const ut8*) (bin->b->buf + bin->size)) {
				break;
			}
		}
	}
	sdb_ht_free (lib_map);
	libs[index].last = 1;
	return libs;
out_error:
	sdb_ht_free (lib_map);
	free (libs);
	return NULL;
}

int PE_(r_bin_pe_get_image_size)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->nt_headers->optional_header.SizeOfImage;
}

// TODO: make it const! like in elf
char* PE_(r_bin_pe_get_machine)(struct PE_(r_bin_pe_obj_t)* bin) {
	char* machine = NULL;

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
	char* os;
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
		case PE_IMAGE_FILE_TYPE_PE32: return strdup ("PE32");
		case PE_IMAGE_FILE_TYPE_PE32PLUS: return strdup ("PE32+");
		default: return strdup ("Unknown");
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

//This function try to detect anomalies within section
//we check if there is a section mapped at entrypoint, otherwise add it up
void PE_(r_bin_pe_check_sections)(struct PE_(r_bin_pe_obj_t)* bin, struct r_bin_pe_section_t* * sects) {
	int i = 0;
	struct r_bin_pe_section_t* sections = *sects;
	ut64 addr_beg, addr_end, new_section_size, new_perm, base_addr;
	struct r_bin_pe_addr_t* entry = PE_(r_bin_pe_get_entrypoint) (bin);

	if (!entry) {
		return;
	}
	new_section_size = bin->size;
	new_section_size -= entry->paddr > bin->size? 0: entry->paddr;
	new_perm = (PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_WRITE | PE_IMAGE_SCN_MEM_EXECUTE);
	base_addr = PE_(r_bin_pe_get_image_base) (bin);

	for (i = 0; !sections[i].last; i++) {
		//strcmp against .text doesn't work in somes cases
		if (strstr ((const char*) sections[i].name, "text")) {
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
				strcpy ((char*) sections[i].name, "blob");
				sections[i].paddr = entry->paddr;
				sections[i].vaddr = entry->vaddr - base_addr;
				sections[i].size = sections[i].vsize = new_section_size;
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
	strcpy ((char*) sections[i].name, "blob");
	sections[i].paddr = entry->paddr;
	sections[i].vaddr = entry->vaddr - base_addr;
	sections[i].size = sections[i].vsize = new_section_size;
	sections[i].flags = new_perm;
	sections[i + 1].last = 1;
	*sects = sections;
out_function:
	free (entry);
	return;

}

struct r_bin_pe_section_t* PE_(r_bin_pe_get_sections)(struct PE_(r_bin_pe_obj_t)* bin) {
	struct r_bin_pe_section_t* sections = NULL;
	PE_(image_section_header) * shdr;
	int i, j, section_count = 0;

	if (!bin || !bin->nt_headers) {
		return NULL;
	}
	shdr = bin->section_header;
	for (i = 0; i < bin->num_sections; i++) {
		//just allocate the needed
		if (shdr[i].SizeOfRawData || shdr[i].Misc.VirtualSize) {
			section_count++;
		}
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
			char* new_name = r_str_newf ("sect_%d", j);
			strncpy ((char*) sections[j].name, new_name, R_ARRAY_SIZE (sections[j].name) - 1);
			free (new_name);
		} else if (shdr[i].Name[0] == '/') {
			//long name is something deprecated but still used
			int idx = atoi ((const char *)shdr[i].Name + 1);
			ut64 sym_tbl_off = bin->nt_headers->file_header.PointerToSymbolTable;
			int num_symbols = bin->nt_headers->file_header.NumberOfSymbols;
			int off = num_symbols * COFF_SYMBOL_SIZE;
			if (sym_tbl_off &&
			    sym_tbl_off + off + idx < bin->size &&
			    sym_tbl_off + off + idx > off) {
				int sz = PE_IMAGE_SIZEOF_SHORT_NAME * 3;
				char* buf[64] = {0};
				if (r_buf_read_at (bin->b,
						   sym_tbl_off + off + idx,
						   (ut8*)buf, 64)) {
					memcpy (sections[j].name, buf, sz);
					sections[j].name[sz - 1] = '\0';
				}
			}
		} else {
			memcpy (sections[j].name, shdr[i].Name, PE_IMAGE_SIZEOF_SHORT_NAME);
			sections[j].name[PE_IMAGE_SIZEOF_SHORT_NAME - 1] = '\0';
		}
		sections[j].vaddr = shdr[i].VirtualAddress;
		sections[j].size = shdr[i].SizeOfRawData;
		sections[j].vsize = shdr[i].Misc.VirtualSize;
		if (bin->optional_header) {
			int sa = R_MAX (bin->optional_header->SectionAlignment, 0x1000);
			ut64 diff = sections[j].vsize % sa;
			if (diff) {
				sections[j].vsize += sa - diff;
			}
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
	char* subsystem = NULL;
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
		default:
			subsystem = "Unknown"; break;
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
//TODO: implement dep?
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
	free (bin->tls_directory);
	r_list_free (bin->resources);
	r_pkcs7_free_cms (bin->cms);
	r_buf_free (bin->b);
	bin->b = NULL;
	free (bin);
	return NULL;
}

struct PE_(r_bin_pe_obj_t)* PE_(r_bin_pe_new)(const char* file, bool verbose) {
	ut8* buf;
	struct PE_(r_bin_pe_obj_t)* bin = R_NEW0 (struct PE_(r_bin_pe_obj_t));
	if (!bin) {
		return NULL;
	}
	bin->file = file;
	if (!(buf = (ut8*) r_file_slurp (file, &bin->size))) {
		return PE_(r_bin_pe_free)(bin);
	}
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf, bin->size)) {
		free (buf);
		return PE_(r_bin_pe_free)(bin);
	}
	bin->verbose = verbose;
	free (buf);
	if (!bin_pe_init (bin)) {
		return PE_(r_bin_pe_free)(bin);
	}
	return bin;
}

struct PE_(r_bin_pe_obj_t)* PE_(r_bin_pe_new_buf)(RBuffer * buf, bool verbose) {
	struct PE_(r_bin_pe_obj_t)* bin = R_NEW0 (struct PE_(r_bin_pe_obj_t));
	if (!bin) {
		return NULL;
	}
	bin->kv = sdb_new0 ();
	bin->b = r_buf_new ();
	bin->verbose = verbose;
	bin->size = buf->length;
	if (!r_buf_set_bytes (bin->b, buf->buf, bin->size)) {
		return PE_(r_bin_pe_free)(bin);
	}
	if (!bin_pe_init (bin)) {
		return PE_(r_bin_pe_free)(bin);
	}
	return bin;
}
