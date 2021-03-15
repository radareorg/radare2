/* radare - LGPL - Copyright 2008-2019 nibble, pancake, inisider */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_hash.h>
#include <r_types.h>
#include <r_util.h>
#include "pe.h"
#include <time.h>
#include <ht_uu.h>

#define PE_IMAGE_FILE_MACHINE_RPI2 452
#define MAX_METADATA_STRING_LENGTH 256
#define bprintf if (bin->verbose) eprintf
#define COFF_SYMBOL_SIZE 18
#define PE_READ_STRUCT_FIELD(var, struct_type, field, size) var->field = r_read_le##size (buf + offsetof (struct_type, field))

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

static inline bool read_and_follow_jump(struct r_bin_pe_addr_t *entry, RBuffer *buf, ut8 *b, int len, bool big_endian) {
	if (!r_buf_read_at (buf, entry->paddr, b, len)) {
		return false;
	}
	if (b[0] != 0xe9) {
		return true;
	}
	const st32 jmp_dst = r_read_ble32 (b + 1, big_endian) + 5;
	entry->paddr += jmp_dst;
	entry->vaddr += jmp_dst;
	return r_buf_read_at (buf, entry->paddr, b, len) > 0;
}

static inline bool follow_offset(struct r_bin_pe_addr_t *entry, RBuffer *buf, ut8 *b, int len, bool big_endian, size_t instr_off) {
	const st32 dst_offset = r_read_ble32 (b + instr_off + 1, big_endian) + instr_off + 5;
	entry->paddr += dst_offset;
	entry->vaddr += dst_offset;
	return read_and_follow_jump (entry, buf, b, len, big_endian);
}

struct r_bin_pe_addr_t *PE_(check_msvcseh)(struct PE_(r_bin_pe_obj_t) *bin) {
	r_return_val_if_fail (bin && bin->b, NULL);
	ut8 b[512];
	size_t n = 0;
	struct r_bin_pe_addr_t* entry = PE_(r_bin_pe_get_entrypoint) (bin);
	ZERO_FILL (b);
	if (r_buf_read_at (bin->b, entry->paddr, b, sizeof (b)) < 0) {
		bprintf ("Warning: Cannot read entry at 0x%08"PFMT64x "\n", entry->paddr);
		free (entry);
		return NULL;
	}

	read_and_follow_jump (entry, bin->b, b, sizeof (b), bin->big_endian);

	// MSVC SEH
	// E8 13 09 00 00  call    0x44C388
	// E9 05 00 00 00  jmp     0x44BA7F
	if (b[0] == 0xe8 && b[5] == 0xe9) {
		if (follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, 5)) {
			// case1:
			// from des address of jmp search for 68 xx xx xx xx e8 and test xx xx xx xx = imagebase
			// 68 00 00 40 00  push    0x400000
			// E8 3E F9 FF FF  call    0x44B4FF
			ut32 imageBase = bin->nt_headers->optional_header.ImageBase;
			for (n = 0; n < sizeof (b) - 6; n++) {
				const ut32 tmp_imgbase = r_read_ble32 (b + n + 1, bin->big_endian);
				if (b[n] == 0x68 && tmp_imgbase == imageBase && b[n + 5] == 0xe8) {
					follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, n + 5);
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
					follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, n + 5);
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
					follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, n + 13);
					return entry;
				}
			}
			//case4:
			//50                                        push    eax
			//57                                        push    edi
			//FF 36                                     push    dword ptr[esi]
			//E8 D9 FD FF FF                            call    _main
			for (n = 0; n < sizeof (b) - 5; n++) {
				if (b[n] == 0x50 && b[n + 1] == 0x57 && b[n + 2] == 0xff && b[n + 4] == 0xe8) {
					follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, n + 4);
					return entry;
				}
			}
			//case5:
			//57                                        push    edi
			//56                                        push    esi
			//FF 36                                     push    dword ptr[eax]
			//E8 D9 FD FF FF                            call    _main
			for (n = 0; n < sizeof (b) - 5; n++) {
				if (b[n] == 0x57 && b[n + 1] == 0x56 && b[n + 2] == 0xff && b[n + 4] == 0xe8) {
					follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, n + 4);
					return entry;
				}
			}
		}
	}

	// MSVC 32bit debug 
	if (b[3] == 0xe8) {
		// 55                    push ebp
		// 8B EC                 mov ebp, esp
		// E8 xx xx xx xx        call xxxxxxxx
		// 5D                    pop ebp
		// C3                    ret
		follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, 3);
		if (b[8] == 0xe8) {
			// 55                    push ebp
			// 8B EC                 mov ebp, esp
			// E8 xx xx xx xx        call xxxxxxxx
			// E8 xx xx xx xx        call xxxxxxxx <- Follow this
			// 5D                    pop ebp
			// C3                    ret
			follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, 8);
			for (n = 0; n < sizeof (b) - 15; n++) {
				// E8 xx xx xx xx    call sub.ucrtbased.dll__register_thread_local_exe_atexit_callback
				// 83 C4 04          add esp, 4
				// E8 xx xx xx xx    call xxxxxxxx <- Follow this
				// 89 xx xx          mov dword [xxxx], eax
				// E8 xx xx xx xx    call xxxxxxxx
				if (b[n] == 0xe8 && !memcmp (b + n + 5, "\x83\xc4\x04", 3) 
					&& b[n + 8] == 0xe8 && b[n + 13] == 0x89 && b[n + 16] == 0xe8) {
					follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, n + 8);
					int j, calls = 0;
					for (j = 0; j < sizeof (b) - 4; j++) {
						if (b[j] == 0xe8) {
							// E8 xx xx xx xx        call xxxxxxxx
							calls++;
							if (calls == 4) {
								follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, j);
								return entry;
							}
						}
					}
				}
			}
		}
	}

	// MSVC AMD64
	if (b[4] == 0xe8) {
		bool found_caller = false;
		if (b[13] == 0xe9) {
			// 48 83 EC 28       sub     rsp, 0x28
			// E8 xx xx xx xx    call    xxxxxxxx
			// 48 83 C4 28       add     rsp, 0x28
			// E9 xx xx xx xx    jmp     xxxxxxxx <- Follow this
			found_caller = follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, 13);
		} else {
			// Debug
			// 48 83 EC 28       sub     rsp, 0x28
			// E8 xx xx xx xx    call    xxxxxxxx
			// 48 83 C4 28       add     rsp, 0x28
			// C3                ret
			follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, 4);
			if (b[9] == 0xe8) {
				// 48 83 EC 28       sub     rsp, 0x28
				// E8 xx xx xx xx    call    xxxxxxxx
				// E8 xx xx xx xx    call    xxxxxxxx <- Follow this
				// 48 83 C4 28       add     rsp, 0x28
				// C3                ret
				follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, 9);
				if (b[0x129] == 0xe8) {
					// E8 xx xx xx xx        call xxxxxxxx
					found_caller = follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, 0x129);
				}
			}
		}
		if (found_caller) {
			// from des address of jmp, search for 4C ... 48 ... 8B ... E8
			// 4C 8B C0                    mov     r8, rax
			// 48 8B 17                    mov     rdx, qword [rdi]
			// 8B 0B                       mov     ecx, dword [rbx]
			// E8 xx xx xx xx              call    main
			// or
			// 4C 8B 44 24 28              mov r8, qword [rsp + 0x28]
			// 48 8B 54 24 30              mov rdx, qword [rsp + 0x30]
			// 8B 4C 24 20                 mov ecx, dword [rsp + 0x20]
			// E8 xx xx xx xx              call    main
			for (n = 0; n < sizeof (b) - 13; n++) {
				if (b[n] == 0x4c && b[n + 3] == 0x48 && b[n + 6] == 0x8b && b[n + 8] == 0xe8) {
					follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, n + 8);
					return entry;
				} else if (b[n] == 0x4c && b [n + 5] == 0x48 && b[n + 10] == 0x8b && b[n + 14] == 0xe8) {
					follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, n + 14);
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
		follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, 201);
		return entry;
	}

	if (b[292] == 0x50 && b[303] == 0xe8) {
		follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, 303);
		return entry;
	}

	free (entry);
	return NULL;
}

struct r_bin_pe_addr_t *PE_(check_mingw)(struct PE_(r_bin_pe_obj_t) *bin) {
	struct r_bin_pe_addr_t* entry;
	bool sw = false;
	ut8 b[1024];
	size_t n = 0;
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
		sw = follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, 19);
	}
	//83 EC 1C                                   sub     esp, 1Ch
	//C7 04 24 01 00 00 00                       mov[esp + 1Ch + var_1C], 1
	//FF 15 F8 60 40 00                          call    ds : __imp____set_app_type
	//E8 6B FD FF FF                             call    ___mingw_CRTStartup
	if (b[0] == 0x83 && b[3] == 0xc7 && b[10] == 0xff && b[16] == 0xe8) {
		sw = follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, 16);
	}
	//83 EC 0C                                            sub     esp, 0Ch
	//C7 05 F4 0A 81 00 00 00 00 00                       mov     ds : _mingw_app_type, 0
	//ED E8 3E AD 24 00                                      call    ___security_init_cookie
	//F2 83 C4 0C                                            add     esp, 0Ch
	//F5 E9 86 FC FF FF                                      jmp     ___tmainCRTStartup
	if (b[0] == 0x83 && b[3] == 0xc7 && b[13] == 0xe8 && b[18] == 0x83 && b[21] == 0xe9) {
		sw = follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, 21);
	}
	if (sw) {
		// case1:
		// from des address of call search for a1 xx xx xx xx 89 xx xx e8 xx xx xx xx
		//A1 04 50 44 00                             mov     eax, ds:dword_445004
		//89 04 24                                   mov[esp + 28h + lpTopLevelExceptionFilter], eax
		//E8 A3 01 00 00                             call    sub_4013EE
		for (n = 0; n < sizeof (b) - 12; n++) {
			if (b[n] == 0xa1 && b[n + 5] == 0x89 && b[n + 8] == 0xe8) {
				sw = follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, n + 8);
				return entry;
			}
		}
	}
	free (entry);
	return NULL;
}

struct r_bin_pe_addr_t *PE_(check_unknow)(struct PE_(r_bin_pe_obj_t) *bin) {
	struct r_bin_pe_addr_t *entry;
	if (!bin || !bin->b) {
		return 0LL;
	}
	ut8 b[512];
	ZERO_FILL (b);
	entry = PE_ (r_bin_pe_get_entrypoint) (bin);
	// option2: /x 8bff558bec83ec20
	if (r_buf_read_at (bin->b, entry->paddr, b, 512) < 1) {
		bprintf ("Warning: Cannot read entry at 0x%08"PFMT64x"\n", entry->paddr);
		free (entry);
		return NULL;
	}
	/* Decode the jmp instruction, this gets the address of the 'main'
	   function for PE produced by a compiler whose name someone forgot to
	   write down. */
	// this is dirty only a single byte check, can return false positives
	if (b[367] == 0xe8) {
		follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, 367);
		return entry;
	}
	size_t i;
	for (i = 0; i < 512 - 16 ; i++) {
		// 5. ff 15 .. .. .. .. 50 e8 [main]
		if (!memcmp (b + i, "\xff\x15", 2)) {
			if (b[i + 6] == 0x50) {
				if (b[i + 7] == 0xe8) {
					follow_offset (entry, bin->b, b, sizeof (b), bin->big_endian, i + 7);
					return entry;
				}
			}
		}
	}
	free (entry);
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
		section_base = bin->sections[i].vaddr;
		section_size = bin->sections[i].vsize;
		if (rva >= section_base && rva < section_base + section_size) {
			return bin->sections[i].paddr + (rva - section_base);
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
	char* foo = sdb_get (db, sdb_fmt ("%d", ordinal), 0);
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
	char* symname = NULL;
	char* filename = NULL;
	char* symdllname = NULL;

	if (!dll_name || !*dll_name || *dll_name == '0') {
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
		import_table = R_BUF_READ_PE_DWORD_AT (bin->b, off + i * sizeof (PE_DWord));
		if (import_table == PE_DWORD_MAX) {
			bprintf ("Warning: read (import table)\n");
			goto error;
		} else if (import_table) {
			if (import_table & ILT_MASK1) {
				import_ordinal = import_table & ILT_MASK2;
				import_hint = 0;
				snprintf (import_name, PE_NAME_LENGTH, "Ordinal_%i", import_ordinal);
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
					filename = sdb_fmt ("%s.sdb", symdllname);
					if (filename && r_file_exists (filename)) {
						db = sdb_new (NULL, filename, 0);
					} else {
						const char *dirPrefix = r_sys_prefix (NULL);
						filename = sdb_fmt (R_JOIN_4_PATHS ("%s", R2_SDB_FORMAT, "dll", "%s.sdb"),
							dirPrefix, symdllname);
						if (r_file_exists (filename)) {
							db = sdb_new (NULL, filename, 0);
						}
					}
				}
				if (db) {
					symname = resolveModuleOrdinal (db, symdllname, import_ordinal);
					if (symname) {
						snprintf (import_name, PE_NAME_LENGTH, "%s", symname);
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
				import_hint = r_buf_read_le16_at (bin->b, off);
				if (import_hint == UT16_MAX) {
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
				int len = snprintf (import_name, sizeof (import_name), "%s" , name);
				if (len >= sizeof (import_name)) {
					eprintf ("Import name '%s' has been truncated.\n", import_name);
				}
			}
			struct r_bin_pe_import_t *new_importp = realloc (*importp, (*nimp + 1) * sizeof (struct r_bin_pe_import_t));
			if (!new_importp) {
				r_sys_perror ("realloc (import)");
				goto error;
			}
			*importp = new_importp;
			memcpy ((*importp)[*nimp].name, import_name, PE_NAME_LENGTH);
			(*importp)[*nimp].name[PE_NAME_LENGTH] = '\0';
			memcpy ((*importp)[*nimp].libname, dll_name, PE_NAME_LENGTH);
			(*importp)[*nimp].libname[PE_NAME_LENGTH] = '\0';
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

int PE_(read_dos_header)(RBuffer *b, PE_(image_dos_header) *header) {
	st64 o_addr = r_buf_seek (b, 0, R_BUF_CUR);
	if (r_buf_seek (b, 0, R_BUF_SET) < 0) {
		return -1;
	}
	header->e_magic = r_buf_read_le16 (b);
	header->e_cblp = r_buf_read_le16 (b);
	header->e_cp = r_buf_read_le16 (b);
	header->e_crlc = r_buf_read_le16 (b);
	header->e_cparhdr = r_buf_read_le16 (b);
	header->e_minalloc = r_buf_read_le16 (b);
	header->e_maxalloc = r_buf_read_le16 (b);
	header->e_ss = r_buf_read_le16 (b);
	header->e_sp = r_buf_read_le16 (b);
	header->e_csum = r_buf_read_le16 (b);
	header->e_ip = r_buf_read_le16 (b);
	header->e_cs = r_buf_read_le16 (b);
	header->e_lfarlc = r_buf_read_le16 (b);
	header->e_ovno = r_buf_read_le16 (b);
	int i;
	for (i = 0; i < 4; i++) {
		header->e_res[i] = r_buf_read_le16 (b);
	}
	header->e_oemid = r_buf_read_le16 (b);
	header->e_oeminfo = r_buf_read_le16 (b);
	for (i = 0; i < 10; i++) {
		header->e_res2[i] = r_buf_read_le16 (b);
	}
	header->e_lfanew = r_buf_read_le32 (b);
	if (r_buf_seek (b, o_addr, R_BUF_SET) < 0) {
		return -1;
	}
	return sizeof (PE_(image_dos_header));
}

int PE_(read_nt_headers)(RBuffer *b, ut64 addr, PE_(image_nt_headers) *headers) {
	st64 o_addr = r_buf_seek (b, 0, R_BUF_CUR);
	if (r_buf_seek (b, addr, R_BUF_SET) < 0) {
		return -1;
	}
	headers->Signature = r_buf_read_le32 (b);
	headers->file_header.Machine = r_buf_read_le16 (b);
	headers->file_header.NumberOfSections = r_buf_read_le16 (b);
	headers->file_header.TimeDateStamp = r_buf_read_le32 (b);
	headers->file_header.PointerToSymbolTable = r_buf_read_le32 (b);
	headers->file_header.NumberOfSymbols = r_buf_read_le32 (b);
	headers->file_header.SizeOfOptionalHeader = r_buf_read_le16 (b);
	headers->file_header.Characteristics = r_buf_read_le16 (b);
	headers->optional_header.Magic = r_buf_read_le16 (b);
	headers->optional_header.MajorLinkerVersion = r_buf_read8 (b);
	headers->optional_header.MinorLinkerVersion = r_buf_read8 (b);
	headers->optional_header.SizeOfCode = r_buf_read_le32 (b);
	headers->optional_header.SizeOfInitializedData = r_buf_read_le32 (b);
	headers->optional_header.SizeOfUninitializedData = r_buf_read_le32 (b);
	headers->optional_header.AddressOfEntryPoint = r_buf_read_le32 (b);
	headers->optional_header.BaseOfCode = r_buf_read_le32 (b);
#ifdef R_BIN_PE64
	headers->optional_header.ImageBase = r_buf_read_le64 (b);
#else
	headers->optional_header.BaseOfData = r_buf_read_le32 (b);
	headers->optional_header.ImageBase = r_buf_read_le32 (b);
#endif
	headers->optional_header.SectionAlignment = r_buf_read_le32 (b);
	headers->optional_header.FileAlignment = r_buf_read_le32 (b);
	headers->optional_header.MajorOperatingSystemVersion = r_buf_read_le16 (b);
	headers->optional_header.MinorOperatingSystemVersion = r_buf_read_le16 (b);
	headers->optional_header.MajorImageVersion = r_buf_read_le16 (b);
	headers->optional_header.MinorImageVersion = r_buf_read_le16 (b);
	headers->optional_header.MajorSubsystemVersion = r_buf_read_le16 (b);
	headers->optional_header.MinorSubsystemVersion = r_buf_read_le16 (b);
	headers->optional_header.Win32VersionValue = r_buf_read_le32 (b);
	headers->optional_header.SizeOfImage = r_buf_read_le32 (b);
	headers->optional_header.SizeOfHeaders = r_buf_read_le32 (b);
	headers->optional_header.CheckSum = r_buf_read_le32 (b);
	headers->optional_header.Subsystem = r_buf_read_le16 (b);
	headers->optional_header.DllCharacteristics = r_buf_read_le16 (b);
#ifdef R_BIN_PE64
	headers->optional_header.SizeOfStackReserve = r_buf_read_le64 (b);
	headers->optional_header.SizeOfStackCommit = r_buf_read_le64 (b);
	headers->optional_header.SizeOfHeapReserve = r_buf_read_le64 (b);
	headers->optional_header.SizeOfHeapCommit = r_buf_read_le64 (b);
#else
	headers->optional_header.SizeOfStackReserve = r_buf_read_le32 (b);
	headers->optional_header.SizeOfStackCommit = r_buf_read_le32 (b);
	headers->optional_header.SizeOfHeapReserve = r_buf_read_le32 (b);
	headers->optional_header.SizeOfHeapCommit = r_buf_read_le32 (b);
#endif
	headers->optional_header.LoaderFlags = r_buf_read_le32 (b);
	headers->optional_header.NumberOfRvaAndSizes = r_buf_read_le32 (b);
	int i;
	for (i = 0; i < PE_IMAGE_DIRECTORY_ENTRIES; i++) {
		headers->optional_header.DataDirectory[i].VirtualAddress = r_buf_read_le32 (b);
		headers->optional_header.DataDirectory[i].Size = r_buf_read_le32 (b);
	}
	if (r_buf_seek (b, o_addr, R_BUF_SET) < 0) {
		return -1;
	}
	return sizeof (PE_(image_nt_headers));
}

static int bin_pe_init_hdr(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!(bin->dos_header = malloc (sizeof(PE_(image_dos_header))))) {
		r_sys_perror ("malloc (dos header)");
		return false;
	}
	if (PE_(read_dos_header) (bin->b, bin->dos_header) < 0) {
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
	if (PE_(read_nt_headers) (bin->b, bin->dos_header->e_lfanew, bin->nt_headers) < 0) {
		bprintf ("Warning: read (nt header)\n");
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
		char *timestr = r_time_stamp_to_str (bin->nt_headers->file_header.TimeDateStamp);
		sdb_set_owned (bin->kv, "image_file_header.TimeDateStamp_string", timestr, 0);
	}
	bin->optional_header = &bin->nt_headers->optional_header;
	bin->data_directory = (PE_(image_data_directory*)) & bin->optional_header->DataDirectory;

	if (bin->dos_header->e_magic != 0x5a4d || // "MZ"
		(bin->nt_headers->Signature != 0x4550 && // "PE"
		/* Check also for Phar Lap TNT DOS extender PL executable */
		bin->nt_headers->Signature != 0x4c50)) { // "PL"
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
	struct r_bin_pe_export_t* new_exports = NULL;
	const size_t export_t_sz = sizeof (struct r_bin_pe_export_t);
	int bufsz, i, shsz;
	SymbolRecord sr;
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
	exports_sz = export_t_sz * num;
	if (exports) {
		int osz = sz;
		sz += exports_sz;
		new_exports = realloc (exports, sz + export_t_sz);
		if (!new_exports) {
			free (buf);
			return NULL;
		}
		exports = new_exports;
		new_exports = NULL;
		exp = (struct r_bin_pe_export_t*) (((const ut8*) exports) + osz);
	} else {
		sz = exports_sz;
		exports = malloc (sz + export_t_sz);
		exp = exports;
	}

	sections = bin->sections;
	for (i = 0; i < bin->num_sections; i++) {
		//XXX search by section with +x permission since the section can be left blank
		if (!strcmp ((char*) sections[i].name, ".text")) {
			text_rva = sections[i].vaddr;
			text_off = sections[i].paddr;
			textn = i + 1;
		}
	}
	symctr = 0;
	if (r_buf_read_at (bin->b, sym_tbl_off, (ut8*) buf, bufsz) > 0) {
		for (i = 0; i < shsz; i += srsz) {
			// sr = (SymbolRecord*) (buf + i);
			if (i + sizeof (sr) >= bufsz) {
				break;
			}
			memcpy (&sr, buf + i, sizeof (sr));
			//bprintf ("SECNUM %d\n", sr.secnum);
			if (sr.secnum == textn) {
				if (sr.symtype == 32) {
					char shortname[9];
					memcpy (shortname, &sr.shortname, 8);
					shortname[8] = 0;
					if (*shortname) {
						strncpy ((char*) exp[symctr].name, shortname, PE_NAME_LENGTH - 1);
					} else {
						char* longname, name[128];
						ut32 idx = r_read_le32 (buf + i + 4);
						if (r_buf_read_at (bin->b, sym_tbl_off + idx + shsz, (ut8*) name, 128)) { // == 128) {
							longname = name;
							name[sizeof(name) - 1] = 0;
							strncpy ((char*) exp[symctr].name, longname, PE_NAME_LENGTH - 1);
						} else {
							sprintf ((char*) exp[symctr].name, "unk_%d", symctr);
						}
					}
					exp[symctr].name[PE_NAME_LENGTH] = '\0';
					exp[symctr].libname[0] = '\0';
					exp[symctr].vaddr = bin_pe_rva_to_va (bin, text_rva + sr.value);
					exp[symctr].paddr = text_off + sr.value;
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

int PE_(read_image_section_header)(RBuffer *b, ut64 addr, PE_(image_section_header) *section_header) {
	st64 o_addr = r_buf_seek (b, 0, R_BUF_CUR);
	if (r_buf_seek (b, addr, R_BUF_SET) < 0) {
		return -1;
	}

	ut8 buf[sizeof (PE_(image_section_header))];
	r_buf_read (b, buf, sizeof (buf));
	memcpy (section_header->Name, buf, PE_IMAGE_SIZEOF_SHORT_NAME);
	PE_READ_STRUCT_FIELD (section_header, PE_(image_section_header), Misc.PhysicalAddress, 32);
	PE_READ_STRUCT_FIELD (section_header, PE_(image_section_header), VirtualAddress, 32);
	PE_READ_STRUCT_FIELD (section_header, PE_(image_section_header), SizeOfRawData, 32);
	PE_READ_STRUCT_FIELD (section_header, PE_(image_section_header), PointerToRawData, 32);
	PE_READ_STRUCT_FIELD (section_header, PE_(image_section_header), PointerToRelocations, 32);
	PE_READ_STRUCT_FIELD (section_header, PE_(image_section_header), PointerToLinenumbers, 32);
	PE_READ_STRUCT_FIELD (section_header, PE_(image_section_header), NumberOfRelocations, 16);
	PE_READ_STRUCT_FIELD (section_header, PE_(image_section_header), NumberOfLinenumbers, 16);
	PE_READ_STRUCT_FIELD (section_header, PE_(image_section_header), Characteristics, 32);
	r_buf_seek (b, o_addr, R_BUF_SET);
	return sizeof (PE_(image_section_header));
}

void PE_(write_image_section_header)(RBuffer *b, ut64 addr, PE_(image_section_header) *section_header) {
	ut8 buf[sizeof (PE_(image_section_header))];
	memcpy (buf, section_header->Name, PE_IMAGE_SIZEOF_SHORT_NAME);
	r_write_at_le32 (buf, section_header->Misc.PhysicalAddress, PE_IMAGE_SIZEOF_SHORT_NAME);
	r_write_at_le32 (buf, section_header->VirtualAddress, PE_IMAGE_SIZEOF_SHORT_NAME + 4);
	r_write_at_le32 (buf, section_header->SizeOfRawData, PE_IMAGE_SIZEOF_SHORT_NAME + 8);
	r_write_at_le32 (buf, section_header->PointerToRawData, PE_IMAGE_SIZEOF_SHORT_NAME + 12);
	r_write_at_le32 (buf, section_header->PointerToRelocations, PE_IMAGE_SIZEOF_SHORT_NAME + 16);
	r_write_at_le32 (buf, section_header->PointerToLinenumbers, PE_IMAGE_SIZEOF_SHORT_NAME + 20);
	r_write_at_le16 (buf, section_header->NumberOfRelocations, PE_IMAGE_SIZEOF_SHORT_NAME + 24);
	r_write_at_le16 (buf, section_header->NumberOfLinenumbers, PE_IMAGE_SIZEOF_SHORT_NAME + 26);
	r_write_at_le32 (buf, section_header->Characteristics, PE_IMAGE_SIZEOF_SHORT_NAME + 28);
	r_buf_write_at (b, addr, buf, sizeof (PE_(image_section_header)));
}

static struct r_bin_pe_section_t* PE_(r_bin_pe_get_sections)(struct PE_(r_bin_pe_obj_t)* bin);
static int bin_pe_init_sections(struct PE_(r_bin_pe_obj_t)* bin) {
	bin->num_sections = bin->nt_headers->file_header.NumberOfSections;
	if (bin->num_sections < 1) {
		return true;
	}
	int sections_size = sizeof (PE_(image_section_header)) * bin->num_sections;
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
	int i;
	for (i = 0; i < bin->num_sections; i++) {
		if (PE_(read_image_section_header) (bin->b, bin->section_header_offset + i * sizeof (PE_(image_section_header)),
			bin->section_header + i) < 0) {
			bprintf ("Warning: read (sections)\n");
			R_FREE (bin->section_header);
			goto out_error;
		}
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
	size_t i, j, checksum_offset = 0;
	ut64 computed_cs = 0;
	int remaining_bytes;
	int shift;
	ut32 cur;
	if (!bin || !bin->nt_header_offset) {
		return 0;
	}
	const size_t buf_sz = 0x1000;
	ut32 *buf = malloc (buf_sz);
	if (!buf) {
		return 0;
	}
	if (r_buf_read_at (bin->b, 0, (ut8 *)buf, buf_sz) < 0) {
		free (buf);
		return 0;
	}
	checksum_offset = bin->nt_header_offset + 4 + sizeof(PE_(image_file_header)) + 0x40;
	for (i = 0, j = 0; i < bin->size / 4; i++) {
		cur = r_read_at_ble32 (buf, j * 4, bin->endian);
		j++;
		// skip the checksum bytes
		if (i * 4 == checksum_offset) {
			continue;
		}

		computed_cs = (computed_cs & 0xFFFFFFFF) + cur + (computed_cs >> 32);
		if (computed_cs >> 32) {
			computed_cs = (computed_cs & 0xFFFFFFFF) + (computed_cs >> 32);
		}
		if (j == buf_sz / 4) {
			if (r_buf_read_at (bin->b, (i + 1) * 4, (ut8 *)buf, buf_sz) < 0) {
				break;
			}
			j = 0;
		}
	}

	// add resultant bytes to checksum
	remaining_bytes = bin->size % 4;
	i = i * 4;
	if (remaining_bytes != 0) {
		cur = r_buf_read8_at (bin->b, i);
		shift = 8;
		for (j = 1; j < remaining_bytes; j++, shift += 8) {
			cur |= r_buf_read8_at (bin->b, i + j) << shift;
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
	free (buf);
	return computed_cs;
}

static const char* PE_(bin_pe_get_claimed_authentihash)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin->spcinfo) {
		return NULL;
	}
	RASN1Binary *digest = bin->spcinfo->messageDigest.digest;
	return r_hex_bin2strdup (digest->binary, digest->length);
}

const char* PE_(bin_pe_compute_authentihash)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (!bin->spcinfo) {
		return NULL;
	}

	char *hashtype = strdup (bin->spcinfo->messageDigest.digestAlgorithm.algorithm->string);
	r_str_replace_char (hashtype, '-', 0);
	ut64 algobit = r_hash_name_to_bits (hashtype);
	if (!(algobit & (R_HASH_MD5 | R_HASH_SHA1 | R_HASH_SHA256))) {
		eprintf ("Authenticode only supports md5, sha1, sha256. This PE uses %s\n", hashtype);
		free (hashtype);
		return NULL;
	}
	free (hashtype);
	ut32 checksum_paddr = bin->nt_header_offset + 4 + sizeof (PE_(image_file_header)) + 0x40;
	ut32 security_entry_offset =  bin->nt_header_offset + sizeof (PE_(image_nt_headers)) - 96;
	PE_(image_data_directory) *data_dir_security = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_SECURITY];
	PE_DWord security_dir_offset = data_dir_security->VirtualAddress;
	ut32 security_dir_size = data_dir_security->Size;

	RBuffer *buf = r_buf_new ();
	r_buf_append_buf_slice (buf, bin->b, 0, checksum_paddr);
	r_buf_append_buf_slice (buf, bin->b,
		checksum_paddr + 4,
		security_entry_offset - checksum_paddr - 4);
	r_buf_append_buf_slice (buf, bin->b,
		security_entry_offset + 8,
		security_dir_offset - security_entry_offset - 8);
	r_buf_append_buf_slice (buf, bin->b,
		security_dir_offset + security_dir_size,
		r_buf_size (bin->b) - security_dir_offset - security_dir_size);

	ut64 len;
	const ut8 *data = r_buf_data (buf, &len);
	char *hashstr = NULL;
	RHash *ctx = r_hash_new (true, algobit);
	if (ctx) {
		r_hash_do_begin (ctx, algobit);
		int digest_size = r_hash_calculate (ctx, algobit, data, len);
		r_hash_do_end (ctx, algobit);
		hashstr = r_hex_bin2strdup (ctx->digest, digest_size);
		r_buf_free (buf);
		r_hash_free (ctx);
	}
	return hashstr;
}

const char* PE_(bin_pe_get_authentihash)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->authentihash;
}

int PE_(bin_pe_is_authhash_valid)(struct PE_(r_bin_pe_obj_t)* bin) {
	return bin->is_authhash_valid;
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

	struct r_bin_pe_section_t *sects = bin->sections;
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
		return largest_offset + largest_size;
	}
	return 0;
}

static int bin_pe_read_metadata_string(char* to, RBuffer *frombuf, int fromoff) {
	int covered = 0;
	while (covered < MAX_METADATA_STRING_LENGTH) {
		char covch = r_buf_read8_at (frombuf, covered);
		to[covered] = covch;
		if (covch == '\0') {
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

		rr = r_buf_read_at (bin->b, metadata_directory + 16, (ut8*)(metadata->VersionString), len);
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
		int c = bin_pe_read_metadata_string (stream_name, bin->b, start_of_stream + 8);
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

static int read_image_clr_header(RBuffer *b, ut64 addr, PE_(image_clr_header) *header) {
	st64 o_addr = r_buf_seek (b, 0, R_BUF_CUR);
	if (r_buf_seek (b, addr, R_BUF_SET) < 0) {
		return -1;
	}
	ut8 buf[sizeof (PE_(image_clr_header))];
	r_buf_read (b, buf, sizeof (buf));
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), HeaderSize, 32);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), MajorRuntimeVersion, 16);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), MinorRuntimeVersion, 16);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), MetaDataDirectoryAddress, 32);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), MetaDataDirectorySize, 32);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), Flags, 32);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), EntryPointToken, 32);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), ResourcesDirectoryAddress, 32);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), ResourcesDirectorySize, 32);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), StrongNameSignatureAddress, 32);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), StrongNameSignatureSize, 32);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), CodeManagerTableAddress, 32);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), CodeManagerTableSize, 32);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), VTableFixupsAddress, 32);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), VTableFixupsSize, 32);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), ExportAddressTableJumpsAddress, 32);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), ExportAddressTableJumpsSize, 32);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), ManagedNativeHeaderAddress, 32);
	PE_READ_STRUCT_FIELD (header, PE_(image_clr_header), ManagedNativeHeaderSize, 32);
	r_buf_seek (b, o_addr, R_BUF_SET);
	return sizeof (PE_(image_clr_header));
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
	rr = read_image_clr_header (bin->b, image_clr_hdr_paddr, clr_hdr);

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

static int read_image_import_directory(RBuffer *b, ut64 addr, PE_(image_import_directory) *import_dir) {
	st64 o_addr = r_buf_seek (b, 0, R_BUF_CUR);
	if (r_buf_seek (b, addr, R_BUF_SET) < 0) {
		return -1;
	}
	ut8 buf[sizeof (PE_(image_import_directory))];
	r_buf_read (b, buf, sizeof (buf));
	PE_READ_STRUCT_FIELD (import_dir, PE_(image_import_directory), Characteristics, 32);
	PE_READ_STRUCT_FIELD (import_dir, PE_(image_import_directory), TimeDateStamp, 32);
	PE_READ_STRUCT_FIELD (import_dir, PE_(image_import_directory), ForwarderChain, 32);
	PE_READ_STRUCT_FIELD (import_dir, PE_(image_import_directory), Name, 32);
	PE_READ_STRUCT_FIELD (import_dir, PE_(image_import_directory), FirstThunk, 32);
	r_buf_seek (b, o_addr, R_BUF_SET);
	return sizeof (PE_(image_import_directory));
}

static int read_image_delay_import_directory(RBuffer *b, ut64 addr, PE_(image_delay_import_directory) *directory) {
	st64 o_addr = r_buf_seek (b, 0, R_BUF_CUR);
	if (r_buf_seek (b, addr, R_BUF_SET) < 0) {
		return -1;
	}
	ut8 buf[sizeof (PE_(image_delay_import_directory))];
	r_buf_read (b, buf, sizeof (buf));
	PE_READ_STRUCT_FIELD (directory, PE_(image_delay_import_directory), Attributes, 32);
	PE_READ_STRUCT_FIELD (directory, PE_(image_delay_import_directory), Name, 32);
	PE_READ_STRUCT_FIELD (directory, PE_(image_delay_import_directory), ModulePlugin, 32);
	PE_READ_STRUCT_FIELD (directory, PE_(image_delay_import_directory), DelayImportAddressTable, 32);
	PE_READ_STRUCT_FIELD (directory, PE_(image_delay_import_directory), DelayImportNameTable, 32);
	PE_READ_STRUCT_FIELD (directory, PE_(image_delay_import_directory), BoundDelayImportTable, 32);
	PE_READ_STRUCT_FIELD (directory, PE_(image_delay_import_directory), UnloadDelayImportTable, 32);
	PE_READ_STRUCT_FIELD (directory, PE_(image_delay_import_directory), TimeStamp, 32);
	r_buf_seek (b, o_addr, R_BUF_SET);
	return sizeof (PE_(image_delay_import_directory));
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
	PE_(image_delay_import_directory) * new_delay_import_dir = NULL;
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

	R_FREE (bin->import_directory);
	if (import_dir_paddr != 0) {
		if (import_dir_size < 1 || import_dir_size > maxidsz) {
			bprintf ("Warning: Invalid import directory size: 0x%x is now 0x%x\n", import_dir_size, maxidsz);
			import_dir_size = maxidsz;
		}
		bin->import_directory_offset = import_dir_offset;
		count = 0;
		do {
			new_import_dir = (PE_(image_import_directory)*)realloc (import_dir, ((1 + indx) * dir_size));
			if (!new_import_dir) {
				r_sys_perror ("malloc (import directory)");
				R_FREE (import_dir);
				break; //
				//			goto fail;
			}
			import_dir = new_import_dir;
			new_import_dir = NULL;
			curr_import_dir = import_dir + indx;
			if (read_image_import_directory (bin->b, import_dir_offset + indx * dir_size, curr_import_dir) <= 0) {
				bprintf ("Warning: read (import directory)\n");
				R_FREE (import_dir);
				break; //return false;
			}
			if (((2 + indx) * dir_size) > import_dir_size) {
				break; //goto fail;
			}
			indx++;
			count++;
		} while (curr_import_dir->FirstThunk != 0 || curr_import_dir->Name != 0 ||
		curr_import_dir->TimeDateStamp != 0 || curr_import_dir->Characteristics != 0 ||
		curr_import_dir->ForwarderChain != 0);

		bin->import_directory = import_dir;
		bin->import_directory_size = import_dir_size;
	}

	indx = 0;
	if (r_buf_size (bin->b) > 0) {
		if ((delay_import_dir_offset != 0) && (delay_import_dir_offset < (ut32)r_buf_size (bin->b))) {
			ut64 off;
			bin->delay_import_directory_offset = delay_import_dir_offset;
			do {
				indx++;
				off = indx * delay_import_size;
				if (off >= r_buf_size (bin->b)) {
					bprintf ("Warning: Cannot find end of import symbols\n");
					break;
				}
				new_delay_import_dir = (PE_(image_delay_import_directory)*)realloc (
					delay_import_dir, (indx * delay_import_size) + 1);
				if (!new_delay_import_dir) {
					r_sys_perror ("malloc (delay import directory)");
					free (delay_import_dir);
					return false;
				}
				delay_import_dir = new_delay_import_dir;
				curr_delay_import_dir = delay_import_dir + (indx - 1);
				rr = read_image_delay_import_directory (bin->b, delay_import_dir_offset + (indx - 1) * delay_import_size,
					curr_delay_import_dir);
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
	R_FREE (import_dir);
	bin->import_directory = import_dir;
	free (delay_import_dir);
	return false;
}

static int read_image_export_directory(RBuffer *b, ut64 addr, PE_(image_export_directory) *export_dir) {
	st64 o_addr = r_buf_seek (b, 0, R_BUF_CUR);
	if (r_buf_seek (b, addr, R_BUF_SET) < 0) {
		return -1;
	}
	ut8 buf[sizeof (PE_(image_export_directory))];
	r_buf_read (b, buf, sizeof (buf));
	PE_READ_STRUCT_FIELD (export_dir, PE_(image_export_directory), Characteristics, 32);
	PE_READ_STRUCT_FIELD (export_dir, PE_(image_export_directory), TimeDateStamp, 32);
	PE_READ_STRUCT_FIELD (export_dir, PE_(image_export_directory), MajorVersion, 16);
	PE_READ_STRUCT_FIELD (export_dir, PE_(image_export_directory), MinorVersion, 16);
	PE_READ_STRUCT_FIELD (export_dir, PE_(image_export_directory), Name, 32);
	PE_READ_STRUCT_FIELD (export_dir, PE_(image_export_directory), Base, 32);
	PE_READ_STRUCT_FIELD (export_dir, PE_(image_export_directory), NumberOfFunctions, 32);
	PE_READ_STRUCT_FIELD (export_dir, PE_(image_export_directory), NumberOfNames, 32);
	PE_READ_STRUCT_FIELD (export_dir, PE_(image_export_directory), AddressOfFunctions, 32);
	PE_READ_STRUCT_FIELD (export_dir, PE_(image_export_directory), AddressOfNames, 32);
	PE_READ_STRUCT_FIELD (export_dir, PE_(image_export_directory), AddressOfOrdinals, 32);
	r_buf_seek (b, o_addr, R_BUF_SET);
	return sizeof (PE_(image_export_directory));
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
	if (read_image_export_directory (bin->b, export_dir_paddr, bin->export_directory) < 0) {
		bprintf ("Warning: read (export directory)\n");
		R_FREE (bin->export_directory);
		return false;
	}
	return true;
}

static void _free_resource(r_pe_resource *rs) {
	if (rs) {
		free (rs->name);
		free (rs->timestr);
		free (rs->data);
		free (rs->type);
		free (rs->language);
		free (rs);
	}
}

static int read_image_resource_directory(RBuffer *b, ut64 addr, Pe_image_resource_directory *dir) {
	st64 o_addr = r_buf_seek (b, 0, R_BUF_CUR);
	if (r_buf_seek (b, addr, R_BUF_SET) < 0) {
		return -1;
	}
	dir->Characteristics = r_buf_read_le32 (b);
	dir->TimeDateStamp = r_buf_read_le32 (b);
	dir->MajorVersion = r_buf_read_le16 (b);
	dir->MinorVersion = r_buf_read_le16 (b);
	dir->NumberOfNamedEntries = r_buf_read_le16 (b);
	dir->NumberOfIdEntries = r_buf_read_le16 (b);
	r_buf_seek (b, o_addr, R_BUF_SET);
	return sizeof (Pe_image_resource_directory);
}

static int bin_pe_init_resource(struct PE_(r_bin_pe_obj_t)* bin) {
	PE_(image_data_directory) * resource_dir = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_RESOURCE];
	PE_DWord resource_dir_paddr = bin_pe_rva_to_paddr (bin, resource_dir->VirtualAddress);
	if (!resource_dir_paddr) {
		return false;
	}

	bin->resources = r_list_newf ((RListFree)_free_resource);
	if (!bin->resources) {
		return false;
	}
	if (!(bin->resource_directory = malloc (sizeof(*bin->resource_directory)))) {
		r_sys_perror ("malloc (resource directory)");
		return false;
	}
	if (read_image_resource_directory (bin->b, resource_dir_paddr, bin->resource_directory) < 0) {
		bprintf ("Warning: read (resource directory)\n");
		R_FREE (bin->resource_directory);
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
		addressOfTLSCallback = R_BUF_READ_PE_DWORD_AT (bin->b, callbacks);
		if (addressOfTLSCallback == PE_DWORD_MAX) {
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
		key = sdb_fmt ("pe.tls_callback%d_vaddr", count);
		sdb_num_set (bin->kv, key, addressOfTLSCallback, 0);
		key = sdb_fmt ("pe.tls_callback%d_paddr", count);
		paddr = bin_pe_rva_to_paddr (bin, bin_pe_va_to_rva (bin, (PE_DWord) addressOfTLSCallback));
		sdb_num_set (bin->kv, key, paddr,                0);
		key = sdb_fmt ("pe.tls_callback%d_haddr", count);
		haddr = callbacks;
		sdb_num_set (bin->kv, key, haddr,                0);
		count++;
		callbacks += sizeof (addressOfTLSCallback);
	}
}

static int read_tls_directory(RBuffer *b, ut64 addr, PE_(image_tls_directory) *tls_directory) {
	st64 o_addr = r_buf_seek (b, 0, R_BUF_CUR);
	if (r_buf_seek (b, addr, R_BUF_SET) < 0) {
		return -1;
	}
	tls_directory->StartAddressOfRawData = r_buf_read_le32 (b);
	tls_directory->EndAddressOfRawData = r_buf_read_le32 (b);
	tls_directory->AddressOfIndex = r_buf_read_le32 (b);
	tls_directory->AddressOfCallBacks = r_buf_read_le32 (b);
	tls_directory->SizeOfZeroFill = r_buf_read_le32 (b);
	tls_directory->Characteristics = r_buf_read_le32 (b);
	r_buf_seek (b, o_addr, R_BUF_SET);
	return sizeof (PE_(image_tls_directory));
}

static int bin_pe_init_tls(struct PE_(r_bin_pe_obj_t)* bin) {
	PE_(image_tls_directory) * image_tls_directory;
	PE_(image_data_directory) * data_dir_tls = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_TLS];
	PE_DWord tls_paddr = bin_pe_rva_to_paddr (bin, data_dir_tls->VirtualAddress);

	image_tls_directory = R_NEW0 (PE_(image_tls_directory));
	if (read_tls_directory (bin->b, tls_paddr, image_tls_directory) < 0) {
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

#define align32(x) x = (((x) & 0x3) == 0)? (x): ((x) & ~0x3) + 0x4;

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
	if ((var->wLength = r_buf_read_le16_at (bin->b, *curAddr)) == UT16_MAX) {
		bprintf ("Warning: read (Var wLength)\n");
		free_Var (var);
		return NULL;
	}
	*curAddr += sizeof(var->wLength);
	if ((var->wValueLength = r_buf_read_le16_at (bin->b, *curAddr)) == UT16_MAX) {
		bprintf ("Warning: read (Var wValueLength)\n");
		free_Var (var);
		return NULL;
	}
	*curAddr += sizeof(var->wValueLength);
	if ((var->wType = r_buf_read_le16_at (bin->b, *curAddr)) == UT16_MAX) {
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
	if ((varFileInfo->wLength = r_buf_read_le16_at (bin->b, *curAddr)) == UT16_MAX) {
		bprintf ("Warning: read (VarFileInfo wLength)\n");
		free_VarFileInfo (varFileInfo);
		return NULL;
	}
	*curAddr += sizeof(varFileInfo->wLength);

	if ((varFileInfo->wValueLength = r_buf_read_le16_at (bin->b, *curAddr)) == UT16_MAX) {
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

	if ((varFileInfo->wType = r_buf_read_le16_at (bin->b, *curAddr)) == UT16_MAX) {
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
	if ((string->wLength = r_buf_read_le16_at (bin->b, *curAddr)) == UT16_MAX) {
		bprintf ("Warning: read (String wLength)\n");
		goto out_error;
	}
	*curAddr += sizeof(string->wLength);
	if (*curAddr > bin->size || *curAddr + sizeof(string->wValueLength) > bin->size) {
		goto out_error;
	}
	if ((string->wValueLength = r_buf_read_le16_at (bin->b, *curAddr)) == UT16_MAX) {
		bprintf ("Warning: read (String wValueLength)\n");
		goto out_error;
	}
	*curAddr += sizeof(string->wValueLength);

	if (*curAddr > bin->size || *curAddr + sizeof(string->wType) > bin->size) {
		goto out_error;
	}
	if ((string->wType = r_buf_read_le16_at (bin->b, *curAddr)) == UT16_MAX) {
		bprintf ("Warning: read (String wType)\n");
		goto out_error;
	}
	*curAddr += sizeof(string->wType);
	if (string->wType != 0 && string->wType != 1) {
		bprintf ("Warning: check (String wType)\n");
		goto out_error;
	}

	for (i = 0; *curAddr < begAddr + string->wLength; i++, *curAddr += sizeof (ut16)) {
		ut16 utf16_char;
		ut16 *tmpKey;
		if (*curAddr > bin->size || *curAddr + sizeof (ut16) > bin->size) {
			goto out_error;
		}
		if (r_buf_read_at (bin->b, *curAddr, (ut8*) &utf16_char, sizeof (ut16)) != sizeof (ut16)) {
			bprintf ("Warning: check (String szKey)\n");
			goto out_error;
		}
		tmpKey = (ut16*) realloc (string->szKey, (i + 1) * sizeof (ut16));
		if (!tmpKey) {
			bprintf ("Warning: realloc (String szKey)\n");
			goto out_error;
		}
		string->szKey = tmpKey;
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
	if ((stringTable->wLength = r_buf_read_le16_at (bin->b, *curAddr)) == UT16_MAX) {
		bprintf ("Warning: read (StringTable wLength)\n");
		free_StringTable (stringTable);
		return NULL;
	}
	*curAddr += sizeof(stringTable->wLength);

	if ((stringTable->wValueLength = r_buf_read_le16_at (bin->b, *curAddr)) == UT16_MAX) {
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

	if ((stringTable->wType = r_buf_read_le16_at (bin->b, *curAddr)) == UT16_MAX) {
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

	if ((stringFileInfo->wLength = r_buf_read_le16_at (bin->b, *curAddr)) == UT16_MAX) {
		bprintf ("Warning: read (StringFileInfo wLength)\n");
		free_StringFileInfo (stringFileInfo);
		return NULL;
	}
	*curAddr += sizeof(stringFileInfo->wLength);

	if ((stringFileInfo->wValueLength = r_buf_read_le16_at (bin->b, *curAddr)) == UT16_MAX) {
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

	if ((stringFileInfo->wType = r_buf_read_le16_at (bin->b, *curAddr)) == UT16_MAX) {
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
	if ((vs_VersionInfo->wLength = r_buf_read_le16_at (bin->b, curAddr)) == UT16_MAX) {
		bprintf ("Warning: read (VS_VERSIONINFO wLength)\n");
		goto out_error;
	}
	curAddr += sz;
	EXIT_ON_OVERFLOW (sz);
	if ((vs_VersionInfo->wValueLength = r_buf_read_le16_at (bin->b, curAddr)) == UT16_MAX) {
		bprintf ("Warning: read (VS_VERSIONINFO wValueLength)\n");
		goto out_error;
	}
	curAddr += sz;
	EXIT_ON_OVERFLOW (sz);
	if ((vs_VersionInfo->wType = r_buf_read_le16_at (bin->b, curAddr)) == UT16_MAX) {
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

static char* _known_product_ids(int id) {
	switch (id) {
	case 0: return  "Unknown";
	case 1: return  "Import0";
	case 2: return  "Linker510";
	case 3: return  "Cvtomf510";
	case 4: return  "Linker600";
	case 5: return  "Cvtomf600";
	case 6: return  "Cvtres500";
	case 7: return  "Utc11_Basic";
	case 8: return  "Utc11_C";
	case 9: return  "Utc12_Basic";
	case 10: return  "Utc12_C";
	case 11: return  "Utc12_CPP";
	case 12: return  "AliasObj60";
	case 13: return  "VisualBasic60";
	case 14: return  "Masm613";
	case 15: return  "Masm710";
	case 16: return  "Linker511";
	case 17: return  "Cvtomf511";
	case 18: return  "Masm614";
	case 19: return  "Linker512";
	case 20: return  "Cvtomf512";
	case 21: return  "Utc12_C_Std";
	case 22: return  "Utc12_CPP_Std";
	case 23: return  "Utc12_C_Book";
	case 24: return  "Utc12_CPP_Book";
	case 25: return  "Implib700";
	case 26: return  "Cvtomf700";
	case 27: return  "Utc13_Basic";
	case 28: return  "Utc13_C";
	case 29: return  "Utc13_CPP";
	case 30: return  "Linker610";
	case 31: return  "Cvtomf610";
	case 32: return  "Linker601";
	case 33: return  "Cvtomf601";
	case 34: return  "Utc12_1_Basic";
	case 35: return  "Utc12_1_C";
	case 36: return  "Utc12_1_CPP";
	case 37: return  "Linker620";
	case 38: return  "Cvtomf620";
	case 39: return  "AliasObj70";
	case 40: return  "Linker621";
	case 41: return  "Cvtomf621";
	case 42: return  "Masm615";
	case 43: return  "Utc13_LTCG_C";
	case 44: return  "Utc13_LTCG_CPP";
	case 45: return  "Masm620";
	case 46: return  "ILAsm100";
	case 47: return  "Utc12_2_Basic";
	case 48: return  "Utc12_2_C";
	case 49: return  "Utc12_2_CPP";
	case 50: return  "Utc12_2_C_Std";
	case 51: return  "Utc12_2_CPP_Std";
	case 52: return  "Utc12_2_C_Book";
	case 53: return  "Utc12_2_CPP_Book";
	case 54: return  "Implib622";
	case 55: return  "Cvtomf622";
	case 56: return  "Cvtres501";
	case 57: return  "Utc13_C_Std";
	case 58: return  "Utc13_CPP_Std";
	case 59: return  "Cvtpgd1300";
	case 60: return  "Linker622";
	case 61: return  "Linker700";
	case 62: return  "Export622";
	case 63: return  "Export700";
	case 64: return  "Masm700";
	case 65: return  "Utc13_POGO_I_C";
	case 66: return  "Utc13_POGO_I_CPP";
	case 67: return  "Utc13_POGO_O_C";
	case 68: return  "Utc13_POGO_O_CPP";
	case 69: return  "Cvtres700";
	case 70: return  "Cvtres710p";
	case 71: return  "Linker710p";
	case 72: return  "Cvtomf710p";
	case 73: return  "Export710p";
	case 74: return  "Implib710p";
	case 75: return  "Masm710p";
	case 76: return  "Utc1310p_C";
	case 77: return  "Utc1310p_CPP";
	case 78: return  "Utc1310p_C_Std";
	case 79: return  "Utc1310p_CPP_Std";
	case 80: return  "Utc1310p_LTCG_C";
	case 81: return  "Utc1310p_LTCG_CPP";
	case 82: return  "Utc1310p_POGO_I_C";
	case 83: return  "Utc1310p_POGO_I_CPP";
	case 84: return  "Utc1310p_POGO_O_C";
	case 85: return  "Utc1310p_POGO_O_CPP";
	case 86: return  "Linker624";
	case 87: return  "Cvtomf624";
	case 88: return  "Export624";
	case 89: return  "Implib624";
	case 90: return  "Linker710";
	case 91: return  "Cvtomf710";
	case 92: return  "Export710";
	case 93: return  "Implib710";
	case 94: return  "Cvtres710";
	case 95: return  "Utc1310_C";
	case 96: return  "Utc1310_CPP";
	case 97: return  "Utc1310_C_Std";
	case 98: return  "Utc1310_CPP_Std";
	case 99: return  "Utc1310_LTCG_C";
	case 100: return  "Utc1310_LTCG_CPP";
	case 101: return  "Utc1310_POGO_I_C";
	case 102: return  "Utc1310_POGO_I_CPP";
	case 103: return  "Utc1310_POGO_O_C";
	case 104: return  "Utc1310_POGO_O_CPP";
	case 105: return  "AliasObj710";
	case 106: return  "AliasObj710p";
	case 107: return  "Cvtpgd1310";
	case 108: return  "Cvtpgd1310p";
	case 109: return  "Utc1400_C";
	case 110: return  "Utc1400_CPP";
	case 111: return  "Utc1400_C_Std";
	case 112: return  "Utc1400_CPP_Std";
	case 113: return  "Utc1400_LTCG_C";
	case 114: return  "Utc1400_LTCG_CPP";
	case 115: return  "Utc1400_POGO_I_C";
	case 116: return  "Utc1400_POGO_I_CPP";
	case 117: return  "Utc1400_POGO_O_C";
	case 118: return  "Utc1400_POGO_O_CPP";
	case 119: return  "Cvtpgd1400";
	case 120: return  "Linker800";
	case 121: return  "Cvtomf800";
	case 122: return  "Export800";
	case 123: return  "Implib800";
	case 124: return  "Cvtres800";
	case 125: return  "Masm800";
	case 126: return  "AliasObj800";
	case 127: return  "PhoenixPrerelease";
	case 128: return  "Utc1400_CVTCIL_C";
	case 129: return  "Utc1400_CVTCIL_CPP";
	case 130: return  "Utc1400_LTCG_MSIL";
	case 131: return  "Utc1500_C";
	case 132: return  "Utc1500_CPP";
	case 133: return  "Utc1500_C_Std";
	case 134: return  "Utc1500_CPP_Std";
	case 135: return  "Utc1500_CVTCIL_C";
	case 136: return  "Utc1500_CVTCIL_CPP";
	case 137: return  "Utc1500_LTCG_C";
	case 138: return  "Utc1500_LTCG_CPP";
	case 139: return  "Utc1500_LTCG_MSIL";
	case 140: return  "Utc1500_POGO_I_C";
	case 141: return  "Utc1500_POGO_I_CPP";
	case 142: return  "Utc1500_POGO_O_C";
	case 143: return  "Utc1500_POGO_O_CPP";

	case 144: return  "Cvtpgd1500";
	case 145: return  "Linker900";
	case 146: return  "Export900";
	case 147: return  "Implib900";
	case 148: return  "Cvtres900";
	case 149: return  "Masm900";
	case 150: return  "AliasObj900";
	case 151: return  "Resource900";

	case 152: return  "AliasObj1000";
	case 154: return  "Cvtres1000";
	case 155: return  "Export1000";
	case 156: return  "Implib1000";
	case 157: return  "Linker1000";
	case 158: return  "Masm1000";

	case 170: return  "Utc1600_C";
	case 171: return  "Utc1600_CPP";
	case 172: return  "Utc1600_CVTCIL_C";
	case 173: return  "Utc1600_CVTCIL_CPP";
	case 174: return  "Utc1600_LTCG_C ";
	case 175: return  "Utc1600_LTCG_CPP";
	case 176: return  "Utc1600_LTCG_MSIL";
	case 177: return  "Utc1600_POGO_I_C";
	case 178: return  "Utc1600_POGO_I_CPP";
	case 179: return  "Utc1600_POGO_O_C";
	case 180: return  "Utc1600_POGO_O_CPP";

	case 183: return  "Linker1010";
	case 184: return  "Export1010";
	case 185: return  "Implib1010";
	case 186: return  "Cvtres1010";
	case 187: return  "Masm1010";
	case 188: return  "AliasObj1010";

	case 199: return  "AliasObj1100";
	case 201: return  "Cvtres1100";
	case 202: return  "Export1100";
	case 203: return  "Implib1100";
	case 204: return  "Linker1100";
	case 205: return  "Masm1100";

	case 206: return  "Utc1700_C";
	case 207: return  "Utc1700_CPP";
	case 208: return  "Utc1700_CVTCIL_C";
	case 209: return  "Utc1700_CVTCIL_CPP";
	case 210: return  "Utc1700_LTCG_C ";
	case 211: return  "Utc1700_LTCG_CPP";
	case 212: return  "Utc1700_LTCG_MSIL";
	case 213: return  "Utc1700_POGO_I_C";
	case 214: return  "Utc1700_POGO_I_CPP";
	case 215: return  "Utc1700_POGO_O_C";
	case 216: return  "Utc1700_POGO_O_CPP";

	case 219: return  "Cvtres1200";
	case 220: return  "Export1200";
	case 221: return  "Implib1200";
	case 222: return  "Linker1200";
	case 223: return  "Masm1200";
		// Speculation
	case 224: return  "AliasObj1200";

	case 237: return  "Cvtres1210";
	case 238: return  "Export1210";
	case 239: return  "Implib1210";
	case 240: return  "Linker1210";
	case 241: return  "Masm1210";
		// Speculation
	case 242: return  "Utc1810_C";
	case 243: return  "Utc1810_CPP";
	case 244: return  "Utc1810_CVTCIL_C";
	case 245: return  "Utc1810_CVTCIL_CPP";
	case 246: return  "Utc1810_LTCG_C ";
	case 247: return  "Utc1810_LTCG_CPP";
	case 248: return  "Utc1810_LTCG_MSIL";
	case 249: return  "Utc1810_POGO_I_C";
	case 250: return  "Utc1810_POGO_I_CPP";
	case 251: return  "Utc1810_POGO_O_C";
	case 252: return  "Utc1810_POGO_O_CPP";

	case 255: return  "Cvtres1400";
	case 256: return  "Export1400";
	case 257: return  "Implib1400";
	case 258: return  "Linker1400";
	case 259: return  "Masm1400";

	case 260: return  "Utc1900_C";
	case 261: return  "Utc1900_CPP";
		// Speculation
	case 262: return  "Utc1900_CVTCIL_C";
	case 263: return  "Utc1900_CVTCIL_CPP";
	case 264: return  "Utc1900_LTCG_C ";
	case 265: return  "Utc1900_LTCG_CPP";
	case 266: return  "Utc1900_LTCG_MSIL";
	case 267: return  "Utc1900_POGO_I_C";
	case 268: return  "Utc1900_POGO_I_CPP";
	case 269: return  "Utc1900_POGO_O_C";
	case 270: return  "Utc1900_POGO_O_CPP";
	default: return "Unknown";
	}
}

static void bin_pe_init_rich_info(struct PE_(r_bin_pe_obj_t) *bin) {
	if (!bin->rich_entries) {
		bin->rich_entries = r_list_newf (free);
	}
	bin->rich_header_offset = bin->nt_header_offset;
	ut64 off = bin->nt_header_offset - sizeof (ut32);
	ut32 magic = 0x68636952; // Rich
	while ((r_buf_read_le32_at (bin->b, off) != magic) && off) {
		off -= sizeof (ut32);
	}
	if (!off) {
		return;
	}
	ut32 mask = r_buf_read_le32_at (bin->b, off + sizeof (ut32));
	magic = 0x536E6144; // DanS
	int data;
	off -= sizeof (ut32);
	while (((data = r_buf_read_le32_at (bin->b, off)) != magic) && data ^ mask && off > 0x80) {
		Pe_image_rich_entry *entry = R_NEW0 (Pe_image_rich_entry);
		if (!entry) {
			return;
		}
		entry->timesUsed = data ^ mask;
		off -= sizeof (ut32);
		data = r_buf_read_le32_at (bin->b, off) ^ mask;
		entry->productId = data >> 16;
		entry->minVersion = data & 0xFFFF;
		entry->productName = _known_product_ids (entry->productId);
		off -= sizeof (ut32);
		r_list_append (bin->rich_entries, entry);
	}
	bin->rich_header_offset = off + sizeof (ut32);
}

static char* _resource_lang_str(int id) {
	switch (id) {
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
	const char * typeName;
	switch (type) {
	case 1:
		typeName = "CURSOR";
		break;
	case 2:
		typeName = "BITMAP";
		break;
	case 3:
		typeName = "ICON";
		break;
	case 4:
		typeName = "MENU";
		break;
	case 5:
		typeName = "DIALOG";
		break;
	case 6:
		typeName = "STRING";
		break;
	case 7:
		typeName = "FONTDIR";
		break;
	case 8:
		typeName = "FONT";
		break;
	case 9:
		typeName = "ACCELERATOR";
		break;
	case 10:
		typeName = "RCDATA";
		break;
	case 11:
		typeName = "MESSAGETABLE";
		break;
	case 12:
		typeName = "GROUP_CURSOR";
		break;
	case 14:
		typeName = "GROUP_ICON";
		break;
	case 16:
		typeName = "VERSION";
		break;
	case 17:
		typeName = "DLGINCLUDE";
		break;
	case 19:
		typeName = "PLUGPLAY";
		break;
	case 20:
		typeName = "VXD";
		break;
	case 21:
		typeName = "ANICURSOR";
		break;
	case 22:
		typeName = "ANIICON";
		break;
	case 23:
		typeName = "HTML";
		break;
	case 24:
		typeName = "MANIFEST";
		break;
	default: return r_str_newf ("UNKNOWN (%d)",type);
	}
	return strdup (typeName);
}

static int read_image_resource_directory_entry(RBuffer *b, ut64 addr, Pe_image_resource_directory_entry *entry) {
	st64 o_addr = r_buf_seek (b, 0, R_BUF_CUR);
	if (r_buf_seek (b, addr, R_BUF_SET) < 0) {
		return -1;
	}
	entry->u1.Name = r_buf_read_le32 (b);
	entry->u2.OffsetToData = r_buf_read_le32 (b);
	r_buf_seek (b, o_addr, R_BUF_SET);
	return sizeof (Pe_image_resource_directory_entry);
}

static int read_image_resource_data_entry(RBuffer *b, ut64 addr, Pe_image_resource_data_entry *entry) {
	st64 o_addr = r_buf_seek (b, 0, R_BUF_CUR);
	if (r_buf_seek (b, addr, R_BUF_SET) < 0) {
		return -1;
	}
	ut8 buf[sizeof (Pe_image_resource_data_entry)];
	r_buf_read (b, buf, sizeof (Pe_image_resource_data_entry));
	PE_READ_STRUCT_FIELD (entry, Pe_image_resource_data_entry, OffsetToData, 32);
	PE_READ_STRUCT_FIELD (entry, Pe_image_resource_data_entry, Size, 32);
	PE_READ_STRUCT_FIELD (entry, Pe_image_resource_data_entry, CodePage, 32);
	PE_READ_STRUCT_FIELD (entry, Pe_image_resource_data_entry, Reserved, 32);
	r_buf_seek (b, o_addr, R_BUF_SET);
	return sizeof (Pe_image_resource_data_entry);
}

static void _parse_resource_directory(struct PE_(r_bin_pe_obj_t) *bin, Pe_image_resource_directory *dir, ut64 offDir, int type, int id, HtUU *dirs, const char *resource_name) {
	char *resourceEntryName = NULL;
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
		if (ht_uu_find (dirs, off, NULL)) {
			break;
		}
		ht_uu_insert (dirs, off, 1);
		if (off > bin->size || off + sizeof (entry) > bin->size) {
			break;
		}
		if (read_image_resource_directory_entry (bin->b, off, &entry) < 0) {
			eprintf ("Warning: read resource entry\n");
			break;
		}
		if (entry.u1.Name >> 31) {
			int i;
			ut16 buf;
			ut32 NameOffset = entry.u1.Name & 0x7fffffff;
			if (r_buf_read_at (bin->b, bin->resource_directory_offset + NameOffset, (ut8*)&buf, sizeof (ut16)) != sizeof (ut16)) {
				break;
			}
			ut16 resourceEntryNameLength = r_read_le16 (&buf);
			resourceEntryName = calloc (resourceEntryNameLength + 1, 1);
			if (resourceEntryName) {
				for (i = 0; i < resourceEntryNameLength; i++) { /* Convert Unicode to ASCII */
					ut8 byte;
					int r = r_buf_read_at (bin->b, bin->resource_directory_offset + NameOffset + 2 + (i*2), &byte, sizeof (ut8));
					if (r != sizeof (ut8) || !byte) {
						R_FREE (resourceEntryName);
						break;
					}
					resourceEntryName[i] = byte;
				}
			}
		}
		if (entry.u2.OffsetToData >> 31) {
			//detect here malicious file trying to making us infinite loop
			Pe_image_resource_directory identEntry;
			ut32 OffsetToDirectory = entry.u2.OffsetToData & 0x7fffffff;
			off = rsrc_base + OffsetToDirectory;
			int len = read_image_resource_directory (bin->b, off, &identEntry);
			if (len < 1 || len != sizeof (Pe_image_resource_directory)) {
				eprintf ("Warning: parsing resource directory\n");
			}
			_parse_resource_directory (bin, &identEntry, OffsetToDirectory, type, entry.u1.Name & 0xffff, dirs, resourceEntryName);
			R_FREE (resourceEntryName);
			continue;
		}
		R_FREE (resourceEntryName);

		Pe_image_resource_data_entry *data = R_NEW0 (Pe_image_resource_data_entry);
		if (!data) {
			break;
		}
		off = rsrc_base + entry.u2.OffsetToData;
		if (off > bin->size || off + sizeof (*data) > bin->size) {
			free (data);
			break;
		}
		if (read_image_resource_data_entry (bin->b, off, data) != sizeof (*data)) {
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
		/* Compare compileTimeStamp to resource timestamp to figure out if DOS date or POSIX date */
		if (r_time_stamp_is_dos_format ((ut32) sdb_num_get (bin->kv, "image_file_header.TimeDateStamp", 0), dir->TimeDateStamp)) {
			rs->timestr = r_time_stamp_to_str ( r_time_dos_time_stamp_to_posix (dir->TimeDateStamp));
		} else {
			rs->timestr = r_time_stamp_to_str (dir->TimeDateStamp);
		}
		rs->type = _resource_type_str (type);
		rs->language = strdup (_resource_lang_str (entry.u1.Name & 0x3ff));
		rs->data = data;
		if (resource_name) {
			rs->name = strdup (resource_name);
		} else {
			rs->name = r_str_newf ("%d", id);
		}
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
		key = sdb_fmt ("resource.%d.timestr", index);
		sdb_set (sdb, key, rs->timestr, 0);
		key = sdb_fmt ("resource.%d.vaddr", index);
		vaddr = bin_pe_rva_to_va (bin, rs->data->OffsetToData);
		sdb_num_set (sdb, key, vaddr, 0);
		key = sdb_fmt ("resource.%d.name", index);
		sdb_set (sdb, key, rs->name, 0);
		key = sdb_fmt ("resource.%d.size", index);
		sdb_num_set (sdb, key, rs->data->Size, 0);
		key = sdb_fmt ("resource.%d.type", index);
		sdb_set (sdb, key, rs->type, 0);
		key = sdb_fmt ("resource.%d.language", index);
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
	HtUUOptions opt = { 0 };
	HtUU *dirs = ht_uu_new_opt (&opt); //to avoid infinite loops
	if (!dirs) {
		return;
	}
	if (!rs_directory) {
		ht_uu_free (dirs);
		return;
	}
	curRes = rs_directory->NumberOfNamedEntries;
	totalRes = curRes + rs_directory->NumberOfIdEntries;
	if (totalRes > R_PE_MAX_RESOURCES) {
		eprintf ("Error parsing resource directory\n");
		ht_uu_free (dirs);
		return;
	}
	for (index = 0; index < totalRes; index++) {
		Pe_image_resource_directory_entry typeEntry;
		off = rsrc_base + sizeof (*rs_directory) + index * sizeof (typeEntry);
		ht_uu_insert (dirs, off, 1);
		if (off > bin->size || off + sizeof(typeEntry) > bin->size) {
			break;
		}
		if (read_image_resource_directory_entry (bin->b, off, &typeEntry) < 0) {
			eprintf ("Warning: read resource directory entry\n");
			break;
		}
		if (typeEntry.u2.OffsetToData >> 31) {
			Pe_image_resource_directory identEntry;
			ut32 OffsetToDirectory = typeEntry.u2.OffsetToData & 0x7fffffff;
			off = rsrc_base + OffsetToDirectory;
			int len = read_image_resource_directory (bin->b, off, &identEntry);
			if (len != sizeof (identEntry)) {
				eprintf ("Warning: parsing resource directory\n");
			}
			(void)_parse_resource_directory (bin, &identEntry, OffsetToDirectory, typeEntry.u1.Name & 0xffff, 0, dirs, NULL);
		}
	}
	ht_uu_free (dirs);
	_store_resource_sdb (bin);
}

static int bin_pe_init_security(struct PE_(r_bin_pe_obj_t) * bin) {
	if (!bin || !bin->nt_headers) {
		return false;
	}
	if (bin->nt_headers->optional_header.NumberOfRvaAndSizes < 5) {
		return false;
	}
	PE_(image_data_directory) *data_dir_security = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_SECURITY];
	PE_DWord paddr = data_dir_security->VirtualAddress;
	ut32 size = data_dir_security->Size;
	if (size < 8 || paddr > bin->size || paddr + size > bin->size) {
		bprintf ("Invalid certificate table");
		return false;
	}

	Pe_image_security_directory *security_directory = R_NEW0 (Pe_image_security_directory);
	if (!security_directory) {
		return false;
	}
	bin->security_directory = security_directory;

	PE_DWord offset = paddr;
	while (offset < paddr + size) {
		Pe_certificate **tmp = (Pe_certificate **)realloc (security_directory->certificates, (security_directory->length + 1) * sizeof(Pe_certificate *));
		if (!tmp) {
			return false;
		}
		security_directory->certificates = tmp;
		Pe_certificate *cert = R_NEW0 (Pe_certificate);
		if (!cert) {
			return false;
		}
		cert->dwLength = r_buf_read_le32_at (bin->b, offset);
		cert->dwLength += (8 - (cert->dwLength & 7)) & 7; // align32
		if (offset + cert->dwLength > paddr + size) {
			bprintf ("Invalid certificate entry");
			R_FREE (cert);
			return false;
		}
		cert->wRevision = r_buf_read_le16_at (bin->b, offset + 4);
		cert->wCertificateType = r_buf_read_le16_at (bin->b, offset + 6);
		if (cert->dwLength < 6) {
			eprintf ("Cert.dwLength must be > 6\n");
			R_FREE (cert);
			return false;
		}
		if (!(cert->bCertificate = malloc (cert->dwLength - 6))) {
			R_FREE (cert);
			return false;
		}
		r_buf_read_at (bin->b, offset + 8, cert->bCertificate, cert->dwLength - 6);

		if (!bin->cms && cert->wCertificateType == PE_WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
			bin->cms = r_pkcs7_parse_cms (cert->bCertificate, cert->dwLength - 6);
			if (bin->cms) {
				bin->spcinfo = r_pkcs7_parse_spcinfo (bin->cms);
			}
		}

		security_directory->certificates[security_directory->length] = cert;
		security_directory->length++;
		offset += cert->dwLength;
	}

	if (bin->cms && bin->spcinfo) {
		const char *actual_authentihash = PE_(bin_pe_compute_authentihash) (bin);
		const char *claimed_authentihash = PE_(bin_pe_get_claimed_authentihash) (bin);
		if (actual_authentihash && claimed_authentihash) {
			bin->is_authhash_valid = !strcmp (actual_authentihash, claimed_authentihash);
		} else {
			bin->is_authhash_valid = false;
		}
		if (actual_authentihash) {
			free ((void *)actual_authentihash);
		}
		free ((void *)claimed_authentihash);
	}
	bin->is_signed = bin->cms != NULL;
	return true;
}

static void free_security_directory(Pe_image_security_directory *security_directory) {
	if (!security_directory) {
		return;
	}
	size_t numCert = 0;
	for (; numCert < security_directory->length; numCert++) {
		free (security_directory->certificates[numCert]);
	}
	free (security_directory->certificates);
	free (security_directory);
}

static int bin_pe_init(struct PE_(r_bin_pe_obj_t)* bin) {
	bin->dos_header = NULL;
	bin->nt_headers = NULL;
	bin->section_header = NULL;
	bin->export_directory = NULL;
	bin->import_directory = NULL;
	bin->resource_directory = NULL;
	bin->security_directory = NULL;
	bin->delay_import_directory = NULL;
	bin->optional_header = NULL;
	bin->data_directory = NULL;
	bin->big_endian = 0;
	bin->cms = NULL;
	bin->spcinfo = NULL;
	if (!bin_pe_init_hdr (bin)) {
		eprintf ("Warning: File is not PE\n");
		return false;
	}
	if (!bin_pe_init_sections (bin)) {
		eprintf ("Warning: Cannot initialize sections\n");
		return false;
	}
	bin->sections = PE_(r_bin_pe_get_sections) (bin);
	bin_pe_init_imports (bin);
	bin_pe_init_exports (bin);
	bin_pe_init_resource (bin);
	bin_pe_init_security (bin);

	bin->big_endian = PE_(r_bin_pe_is_big_endian) (bin);

	bin_pe_init_rich_info (bin);
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
	case PE_IMAGE_FILE_MACHINE_RISCV32:
	case PE_IMAGE_FILE_MACHINE_RISCV64:
	case PE_IMAGE_FILE_MACHINE_RISCV128:
		arch = strdup ("riscv");
		break;
	default:
		arch = strdup ("x86");
	}
	return arch;
}

struct r_bin_pe_addr_t* PE_(r_bin_pe_get_entrypoint)(struct PE_(r_bin_pe_obj_t)* bin) {
	struct r_bin_pe_addr_t* entry = NULL;
	static bool debug = false;
	int i;
	ut64 base_addr = PE_(r_bin_pe_get_image_base) (bin);
	if (!bin || !bin->optional_header) {
		return NULL;
	}
	if (!(entry = malloc (sizeof (struct r_bin_pe_addr_t)))) {
		r_sys_perror ("malloc (entrypoint)");
		return NULL;
	}
	PE_DWord pe_entry = bin->optional_header->AddressOfEntryPoint;
	entry->vaddr = bin_pe_rva_to_va (bin, pe_entry);
	entry->paddr = bin_pe_rva_to_paddr (bin, pe_entry);
	// haddr is the address of AddressOfEntryPoint in header.
	entry->haddr = bin->dos_header->e_lfanew + 4 + sizeof (PE_(image_file_header)) + 16;

	if (entry->paddr >= bin->size) {
		struct r_bin_pe_section_t* sections = bin->sections;
		ut64 paddr = 0;
		if (!debug) {
			bprintf ("Warning: Invalid entrypoint ... "
				"trying to fix it but i do not promise nothing\n");
		}
		for (i = 0; i < bin->num_sections; i++) {
			if (sections[i].perm & PE_IMAGE_SCN_MEM_EXECUTE) {
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
	}
	if (!entry->paddr) {
		if (!debug) {
			bprintf ("Warning: NULL entrypoint\n");
		}
		struct r_bin_pe_section_t* sections = bin->sections;
		for (i = 0; i < bin->num_sections; i++) {
			//If there is a section with x without w perm is a good candidate to be the entrypoint
			if (sections[i].perm & PE_IMAGE_SCN_MEM_EXECUTE && !(sections[i].perm & PE_IMAGE_SCN_MEM_WRITE)) {
				entry->paddr = sections[i].paddr;
				entry->vaddr = sections[i].vaddr + base_addr;
				break;
			}

		}
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
	r_return_val_if_fail (bin, NULL);
	struct r_bin_pe_export_t* exp, * exports = NULL;
	PE_Word function_ordinal = 0;
	PE_VWord functions_paddr, names_paddr, ordinals_paddr, function_rva, name_vaddr, name_paddr;
	char function_name[PE_NAME_LENGTH + 1], forwarder_name[PE_NAME_LENGTH + 1];
	char dll_name[PE_NAME_LENGTH + 1];
	PE_(image_data_directory) * data_dir_export;
	PE_VWord export_dir_rva;
	int n,i, export_dir_size;
	st64 exports_sz = 0;

	if (!bin->data_directory) {
		return NULL;
	}
	data_dir_export = &bin->data_directory[PE_IMAGE_DIRECTORY_ENTRY_EXPORT];
	export_dir_rva = data_dir_export->VirtualAddress;
	export_dir_size = data_dir_export->Size;
	PE_VWord *func_rvas = NULL;
	PE_Word *ordinals = NULL;
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
			// we dont stop if dll name cant be read, we set dllname to null and continue
			bprintf ("Warning: read (dll name)\n");
			dll_name[0] = '\0';
		}
		functions_paddr = bin_pe_rva_to_paddr (bin, bin->export_directory->AddressOfFunctions);
		names_paddr = bin_pe_rva_to_paddr (bin, bin->export_directory->AddressOfNames);
		ordinals_paddr = bin_pe_rva_to_paddr (bin, bin->export_directory->AddressOfOrdinals);

		const size_t names_sz = bin->export_directory->NumberOfNames * sizeof (PE_Word);
		const size_t funcs_sz = bin->export_directory->NumberOfFunctions * sizeof (PE_VWord);
		ordinals = malloc (names_sz);
		func_rvas = malloc (funcs_sz);
		if (!ordinals || !func_rvas) {
			goto beach;
		}
		int r = r_buf_read_at (bin->b, ordinals_paddr, (ut8 *)ordinals, names_sz);
		if (r != names_sz) {
			goto beach;
		}
		r = r_buf_read_at (bin->b, functions_paddr, (ut8 *)func_rvas, funcs_sz);
		if (r != funcs_sz) {
			goto beach;
		}
		for (i = 0; i < bin->export_directory->NumberOfFunctions; i++) {
			// get vaddr from AddressOfFunctions array
			function_rva = r_read_at_ble32 ((ut8 *)func_rvas, i * sizeof (PE_VWord), bin->endian);
			// have exports by name?
			if (bin->export_directory->NumberOfNames > 0) {
				// search for value of i into AddressOfOrdinals
				name_vaddr = 0;
				for (n = 0; n < bin->export_directory->NumberOfNames; n++) {
					PE_Word fo = r_read_at_ble16 ((ut8 *)ordinals, n * sizeof (PE_Word), bin->endian);
					// if exist this index into AddressOfOrdinals
					if (i == fo) {
						function_ordinal = fo;
						// get the VA of export name  from AddressOfNames
						name_vaddr = r_buf_read_le32_at (bin->b, names_paddr + n * sizeof (PE_VWord));
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
					function_ordinal = i;
					snprintf (function_name, PE_NAME_LENGTH, "Ordinal_%i", i + bin->export_directory->Base);
				}
			} else { // if export by name dont exist, get the ordinal taking in mind the Base value.
				snprintf (function_name, PE_NAME_LENGTH, "Ordinal_%i", i + bin->export_directory->Base);
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
			exports[i].vaddr = bin_pe_rva_to_va (bin, function_rva);
			exports[i].paddr = bin_pe_rva_to_paddr (bin, function_rva);
			exports[i].ordinal = function_ordinal + bin->export_directory->Base;
			memcpy (exports[i].forwarder, forwarder_name, PE_NAME_LENGTH);
			exports[i].forwarder[PE_NAME_LENGTH] = '\0';
			memcpy (exports[i].name, function_name, PE_NAME_LENGTH);
			exports[i].name[PE_NAME_LENGTH] = '\0';
			memcpy (exports[i].libname, dll_name, PE_NAME_LENGTH);
			exports[i].libname[PE_NAME_LENGTH] = '\0';
			exports[i].last = 0;
		}
		exports[i].last = 1;
		free (ordinals);
		free (func_rvas);
	}
	exp = parse_symbol_table (bin, exports, exports_sz - sizeof (struct r_bin_pe_export_t));
	if (exp) {
		exports = exp;
	}
	return exports;
beach:
	free (exports);
	free (ordinals);
	free (func_rvas);
	return NULL;
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

static void get_nb10(ut8* dbg_data, int dbg_data_len, SCV_NB10_HEADER* res) {
	const int nb10sz = 16;
	if (dbg_data_len < nb10sz) {
		return;
	}
	memcpy (res, dbg_data, nb10sz);
	res->file_name = (ut8*) strdup ((const char*) dbg_data + nb10sz);
}

static int get_debug_info(struct PE_(r_bin_pe_obj_t)* bin, PE_(image_debug_directory_entry)* dbg_dir_entry, ut8* dbg_data, int dbg_data_len, SDebugInfo* res) {
	#define SIZEOF_FILE_NAME 255
	int i = 0;
	const char* dbgname;
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
			dbgname = (char*) rsds_hdr.file_name;
			strncpy (res->file_name, (const char*)
				dbgname, sizeof (res->file_name));
			res->file_name[sizeof (res->file_name) - 1] = 0;
			rsds_hdr.free ((struct SCV_RSDS_HEADER*) &rsds_hdr);
		} else if (strncmp ((const char*) dbg_data, "NB10", 4) == 0) {
			if (dbg_data_len < 20) {
				eprintf ("Truncated NB10 entry, not enough data to parse\n");
				return 0;
			}
			SCV_NB10_HEADER nb10_hdr = {{0}};
			init_cv_nb10_header (&nb10_hdr);
			get_nb10 (dbg_data, dbg_data_len, &nb10_hdr);
			snprintf (res->guidstr, sizeof (res->guidstr),
				"%x%x", nb10_hdr.timestamp, nb10_hdr.age);
			res->file_name[0] = 0;
			if (nb10_hdr.file_name) {
				strncpy (res->file_name, (const char*)
						nb10_hdr.file_name, sizeof (res->file_name) - 1);
			}
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
		res->guidstr[i] = toupper ((ut8) res->guidstr[i]);
		i++;
	}

	return 1;
}

static int read_image_debug_directory_entry(RBuffer *b, ut64 addr, PE_(image_debug_directory_entry) *entry) {
	st64 o_addr = r_buf_seek (b, 0, R_BUF_CUR);
	if (r_buf_seek (b, addr, R_BUF_SET) < 0) {
		return -1;
	}
	ut8 buf[sizeof (PE_(image_debug_directory_entry))];
	r_buf_read (b, buf, sizeof (buf));
	PE_READ_STRUCT_FIELD (entry, PE_(image_debug_directory_entry), Characteristics, 32);
	PE_READ_STRUCT_FIELD (entry, PE_(image_debug_directory_entry), TimeDateStamp, 32);
	PE_READ_STRUCT_FIELD (entry, PE_(image_debug_directory_entry), MajorVersion, 16);
	PE_READ_STRUCT_FIELD (entry, PE_(image_debug_directory_entry), MinorVersion, 16);
	PE_READ_STRUCT_FIELD (entry, PE_(image_debug_directory_entry), Type, 32);
	PE_READ_STRUCT_FIELD (entry, PE_(image_debug_directory_entry), SizeOfData, 32);
	PE_READ_STRUCT_FIELD (entry, PE_(image_debug_directory_entry), AddressOfRawData, 32);
	PE_READ_STRUCT_FIELD (entry, PE_(image_debug_directory_entry), PointerToRawData, 32);
	r_buf_seek (b, o_addr, R_BUF_SET);
	return sizeof (PE_(image_debug_directory_entry));
}

int PE_(r_bin_pe_get_debug_data)(struct PE_(r_bin_pe_obj_t)* bin, SDebugInfo* res) {
	PE_(image_debug_directory_entry) img_dbg_dir_entry = {0};
	PE_(image_data_directory) *dbg_dir = NULL;
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
	if (dbg_dir_offset >= r_buf_size (bin->b)) {
		return false;
	}
	read_image_debug_directory_entry (bin->b, dbg_dir_offset, &img_dbg_dir_entry);
	if ((r_buf_size (bin->b) - dbg_dir_offset) < sizeof (PE_(image_debug_directory_entry))) {
		return false;
	}
	ut32 dbg_data_poff = R_MIN (img_dbg_dir_entry.PointerToRawData, r_buf_size (bin->b));
	int dbg_data_len = R_MIN (img_dbg_dir_entry.SizeOfData, r_buf_size (bin->b) - dbg_data_poff);
	if (dbg_data_len < 1) {
		return false;
	}
	dbg_data = (ut8*) calloc (1, dbg_data_len + 1);
	if (dbg_data) {
		r_buf_read_at (bin->b, dbg_data_poff, dbg_data, dbg_data_len);
		result = get_debug_info (bin, &img_dbg_dir_entry, dbg_data, dbg_data_len, res);
		R_FREE (dbg_data);
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
	PE_(image_import_directory) curr_import_dir;
	PE_(image_delay_import_directory) curr_delay_import_dir;

	if (!bin) {
		return NULL;
	}
	if (bin->import_directory_offset >= bin->size) {
		return NULL;
	}
	if (bin->import_directory_offset + 20 > bin->size) {
		return NULL;
	}

	off = bin->import_directory_offset;
	if (off < bin->size && off > 0) {
		ut64 last;
		int idi = 0;
		if (off + sizeof(PE_(image_import_directory)) > bin->size) {
			return NULL;
		}
		int r = read_image_import_directory (bin->b, bin->import_directory_offset +
			idi * sizeof (curr_import_dir), &curr_import_dir);
		if (r < 0) {
			return NULL;
		}

		if (bin->import_directory_size < 1) {
			return NULL;
		}
		if (off + bin->import_directory_size > bin->size) {
			//why chopping instead of returning and cleaning?
			bprintf ("Warning: read (import directory too big)\n");
			bin->import_directory_size = bin->size - bin->import_directory_offset;
		}
		last = bin->import_directory_offset + bin->import_directory_size;
		while (r == sizeof (curr_import_dir) && bin->import_directory_offset + (idi + 1) * sizeof (curr_import_dir) <= last && (
			curr_import_dir.FirstThunk != 0 || curr_import_dir.Name != 0 ||
			curr_import_dir.TimeDateStamp != 0 || curr_import_dir.Characteristics != 0 ||
			curr_import_dir.ForwarderChain != 0)) {
			int rr;
			dll_name_offset = curr_import_dir.Name;
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
			} else {
				rr = r_buf_read_at (bin->b, paddr, (ut8*) dll_name, PE_NAME_LENGTH);
				if (rr != PE_NAME_LENGTH) {
					goto beach;
				}
				dll_name[PE_NAME_LENGTH] = '\0';
			}
			if (!bin_pe_parse_imports (bin, &imports, &nimp, dll_name,
				curr_import_dir.Characteristics,
				curr_import_dir.FirstThunk)) {
				break;
			}
			idi++;
			r = read_image_import_directory (bin->b, bin->import_directory_offset +
				idi * sizeof (curr_import_dir), &curr_import_dir);
			if (r < 0) {
				free (imports);
				return NULL;
			}
		}
	}
	off = bin->delay_import_directory_offset;
	if (off < bin->size && off > 0) {
		if (off + sizeof (PE_(image_delay_import_directory)) > bin->size) {
			goto beach;
		}
		int didi;
		for (didi = 0;; didi++) {
			int r = read_image_delay_import_directory (bin->b, off + didi * sizeof (curr_delay_import_dir),
					&curr_delay_import_dir);
			if (r != sizeof (curr_delay_import_dir)) {
				goto beach;
			}
			if ((curr_delay_import_dir.Name == 0) || (curr_delay_import_dir.DelayImportAddressTable == 0)) {
				break;
			}
			if (!curr_delay_import_dir.Attributes) {
				dll_name_offset = bin_pe_rva_to_paddr (bin, curr_delay_import_dir.Name - PE_(r_bin_pe_get_image_base)(bin));
				import_func_name_offset = curr_delay_import_dir.DelayImportNameTable - PE_(r_bin_pe_get_image_base)(bin);
			} else {
				dll_name_offset = bin_pe_rva_to_paddr (bin, curr_delay_import_dir.Name);
				import_func_name_offset = curr_delay_import_dir.DelayImportNameTable;
			}
			if (dll_name_offset > bin->size || dll_name_offset + PE_NAME_LENGTH > bin->size) {
				goto beach;
			}
			int rr = r_buf_read_at (bin->b, dll_name_offset, (ut8*) dll_name, PE_NAME_LENGTH);
			if (rr < 5) {
				goto beach;
			}
			dll_name[PE_NAME_LENGTH] = '\0';
			if (!bin_pe_parse_imports (bin, &imports, &nimp, dll_name, import_func_name_offset,
				curr_delay_import_dir.DelayImportAddressTable)) {
				break;
			}
		}
	}
beach:
	if (nimp) {
		imps = realloc (imports, (nimp + 1) * sizeof(struct r_bin_pe_import_t));
		if (!imps) {
			r_sys_perror ("realloc (import)");
			free (imports);
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
	struct r_bin_pe_lib_t* new_libs = NULL;
	PE_(image_import_directory) curr_import_dir;
	PE_(image_delay_import_directory) curr_delay_import_dir;
	PE_DWord name_off = 0;
	HtPP *lib_map = NULL;
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
		ut64 last;
		int iidi = 0;
		// normal imports
		if (off + sizeof (PE_(image_import_directory)) > bin->size) {
			goto out_error;
		}
		int r = read_image_import_directory (bin->b, off + iidi * sizeof (curr_import_dir),
			&curr_import_dir);
		last = off + bin->import_directory_size;
		while (r == sizeof (curr_import_dir) && off + (iidi + 1) * sizeof (curr_import_dir) <= last && (
			curr_import_dir.FirstThunk || curr_import_dir.Name ||
			curr_import_dir.TimeDateStamp || curr_import_dir.Characteristics ||
			curr_import_dir.ForwarderChain)) {
			name_off = bin_pe_rva_to_paddr (bin, curr_import_dir.Name);
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
					new_libs = realloc (libs, (max_libs * 2) * sizeof (struct r_bin_pe_lib_t));
					if (!new_libs) {
						r_sys_perror ("realloc (libs)");
						goto out_error;
					}
					libs = new_libs;
					new_libs = NULL;
					max_libs *= 2;
				}
			}
next:
			iidi++;
			r = read_image_import_directory (bin->b, off + iidi * sizeof (curr_import_dir),
				&curr_import_dir);
		}
	}
	off = bin->delay_import_directory_offset;
	if (off < bin->size && off > 0) {
		ut64 did = 0;
		if (off + sizeof(PE_(image_delay_import_directory)) > bin->size) {
			goto out_error;
		}
		int r = read_image_delay_import_directory (bin->b, off, &curr_delay_import_dir);
		if (r != sizeof (curr_delay_import_dir)) {
			goto out_error;
		}
		while (r == sizeof (curr_delay_import_dir) &&
			curr_delay_import_dir.Name != 0 && curr_delay_import_dir.DelayImportNameTable != 0) {
			name_off = bin_pe_rva_to_paddr (bin, curr_delay_import_dir.Name);
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
					new_libs = realloc (libs, (max_libs * 2) * sizeof (struct r_bin_pe_lib_t));
					if (!new_libs) {
						r_sys_perror ("realloc (libs)");
						goto out_error;
					}
					libs = new_libs;
					new_libs = NULL;
					max_libs *= 2;
				}
			}
			did++;
			r = read_image_delay_import_directory (bin->b, off + did * sizeof (curr_delay_import_dir),
				&curr_delay_import_dir);
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
		case PE_IMAGE_FILE_MACHINE_RISCV32: machine = "RISC-V 32-bit"; break;
		case PE_IMAGE_FILE_MACHINE_RISCV64: machine = "RISC-V 64-bit"; break;
		case PE_IMAGE_FILE_MACHINE_RISCV128: machine = "RISC-V 128-bit"; break;
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

char *PE_(r_bin_pe_get_cc)(struct PE_(r_bin_pe_obj_t)* bin) {
	if (bin && bin->nt_headers) {
		if (is_arm (bin)) {
			if (is_thumb (bin)) {
				return strdup ("arm16");
			}
			switch (bin->nt_headers->optional_header.Magic) {
			case PE_IMAGE_FILE_TYPE_PE32: return strdup ("arm32");
			case PE_IMAGE_FILE_TYPE_PE32PLUS: return strdup ("arm64");
			}
		} else {
			switch (bin->nt_headers->optional_header.Magic) {
			case PE_IMAGE_FILE_TYPE_PE32: return strdup ("cdecl");
			case PE_IMAGE_FILE_TYPE_PE32PLUS: return strdup ("ms");
			}
		}
	}
	return NULL;
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
				addr_beg = sections[j].paddr;
				addr_end = addr_beg + sections[j].size;
				if (addr_beg <= entry->paddr && entry->paddr < addr_end) {
					if (!sections[j].vsize) {
						sections[j].vsize = sections[j].size;
					}
					addr_beg = sections[j].vaddr + base_addr;
					addr_end = addr_beg + sections[j].vsize;
					if (addr_beg <= entry->vaddr || entry->vaddr < addr_end) {
						if (!(sections[j].perm & PE_IMAGE_SCN_MEM_EXECUTE)) {
							if (bin->verbose) {
								eprintf ("Warning: Found entrypoint in non-executable section.\n");
							}
							sections[j].perm |= PE_IMAGE_SCN_MEM_EXECUTE;
						}
						fix = false;
						break;
					}
				}
			}
			//if either vaddr or paddr fail we should update this section
			if (fix) {
				strcpy ((char*) sections[i].name, "blob");
				sections[i].paddr = entry->paddr;
				sections[i].vaddr = entry->vaddr - base_addr;
				sections[i].size = sections[i].vsize = new_section_size;
				sections[i].perm = new_perm;
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
	void *ss = realloc (sections, (bin->num_sections + 2) * sizeof(struct r_bin_pe_section_t));
	if (!ss) {
		goto out_function;
	}
	bin->sections = sections = ss;
	i = bin->num_sections;
	sections[i].last = 0;
	strcpy ((char*) sections[i].name, "blob");
	sections[i].paddr = entry->paddr;
	sections[i].vaddr = entry->vaddr - base_addr;
	sections[i].size = sections[i].vsize = new_section_size;
	sections[i].perm = new_perm;
	sections[i + 1].last = 1;
	*sects = sections;
out_function:
	free (entry);
	return;

}

static struct r_bin_pe_section_t* PE_(r_bin_pe_get_sections)(struct PE_(r_bin_pe_obj_t)* bin) {
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
			st64 off = num_symbols * COFF_SYMBOL_SIZE;
			if (off > 0 && sym_tbl_off &&
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
			sections[j].name[PE_IMAGE_SIZEOF_SHORT_NAME] = '\0';
		}
		sections[j].vaddr = shdr[i].VirtualAddress;
		sections[j].size = shdr[i].SizeOfRawData;
		if (shdr[i].Misc.VirtualSize) {
			sections[j].vsize = shdr[i].Misc.VirtualSize;
		} else {
			sections[j].vsize = shdr[i].SizeOfRawData;
		}
		sections[j].paddr = shdr[i].PointerToRawData;
		if (bin->optional_header) {
			ut32 sa = bin->optional_header->SectionAlignment;
			if (sa) {
				ut64 diff = sections[j].vsize % sa;
				if (diff) {
					sections[j].vsize += sa - diff;
				}
				if (sections[j].vaddr % sa) {
					bprintf ("Warning: section %s not aligned to SectionAlignment.\n",
							sections[j].name);
				}
			}
			const ut32 fa = bin->optional_header->FileAlignment;
			if (fa) {
				const ut64 diff = sections[j].paddr % fa;
				if (diff) {
					bprintf ("Warning: section %s not aligned to FileAlignment.\n", sections[j].name);
					sections[j].paddr -= diff;
					sections[j].size += diff;	
				}
			}
		}
		sections[j].perm = shdr[i].Characteristics;
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

#define HASCHR(x) (bin->nt_headers->file_header.Characteristics & (x))

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
	free_security_directory (bin->security_directory);
	free (bin->delay_import_directory);
	free (bin->tls_directory);
	free (bin->sections);
	free (bin->authentihash);
	r_list_free (bin->rich_entries);
	r_list_free (bin->resources);
	r_pkcs7_free_cms (bin->cms);
	r_pkcs7_free_spcinfo (bin->spcinfo);
	r_buf_free (bin->b);
	bin->b = NULL;
	free (bin);
	return NULL;
}

struct PE_(r_bin_pe_obj_t)* PE_(r_bin_pe_new)(const char* file, bool verbose) {
	struct PE_(r_bin_pe_obj_t)* bin = R_NEW0 (struct PE_(r_bin_pe_obj_t));
	if (!bin) {
		return NULL;
	}
	bin->file = file;
	size_t binsz;
	ut8 *buf = (ut8*)r_file_slurp (file, &binsz);
	bin->size = binsz;
	if (!buf) {
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

struct PE_(r_bin_pe_obj_t)* PE_(r_bin_pe_new_buf)(RBuffer *buf, bool verbose) {
	struct PE_(r_bin_pe_obj_t)* bin = R_NEW0 (struct PE_(r_bin_pe_obj_t));
	if (!bin) {
		return NULL;
	}
	bin->kv = sdb_new0 ();
	bin->b = r_buf_ref (buf);
	bin->verbose = verbose;
	bin->size = r_buf_size (buf);
	if (!bin_pe_init (bin)) {
		return PE_(r_bin_pe_free)(bin);
	}
	return bin;
}
