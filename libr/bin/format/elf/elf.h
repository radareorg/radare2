/* radare - LGPL - Copyright 2008 nibble<.ds@gmail.com> */

#include <r_types.h>

#include "elf_specs.h"

#ifndef _INCLUDE_ELF_H_
#define _INCLUDE_ELF_H_

#define R_BIN_ELF_SCN_IS_EXECUTABLE(x) x & SHF_EXECINSTR
#define R_BIN_ELF_SCN_IS_READABLE(x)   x & SHF_ALLOC
#define R_BIN_ELF_SCN_IS_WRITABLE(x)   x & SHF_WRITE

#define R_BIN_ELF_SYMBOLS 0x0
#define R_BIN_ELF_IMPORTS 0x1

typedef struct r_bin_elf_section_t {
	ut64 offset;
	ut64 rva;
	ut64 size;
	ut64 align;
	ut32 flags;
	char name[ELF_STRING_LENGTH];
	int last;
} RBinElfSection;

typedef struct r_bin_elf_symbol_t {
	ut64 offset;
	ut64 size;
	int ordinal;
	char bind[ELF_STRING_LENGTH];
	char type[ELF_STRING_LENGTH];
	char name[ELF_STRING_LENGTH];
	int last;
} RBinElfSymbol;

typedef struct r_bin_elf_field_t {
	ut64 offset;
	char name[ELF_STRING_LENGTH];
	int last;
} RBinElfField;

typedef struct r_bin_elf_string_t {
	ut64 offset;
	ut64 size;
	char type;
	char string[ELF_STRING_LENGTH];
	int last;
} RBinElfString;

typedef struct r_bin_elf_lib_t {
	char name[ELF_STRING_LENGTH];
	int last;
} RBinElfLib;

struct Elf_(r_bin_elf_obj_t) {
	Elf_(Ehdr) ehdr;
	Elf_(Phdr)* phdr;
	Elf_(Shdr)* shdr;
	char* strtab;
	int bss;
	int size;
	ut64 baddr;
	int endian;
	const char* file;
	struct r_buf_t* b;
};

ut64 Elf_(r_bin_elf_get_baddr)(struct Elf_(r_bin_elf_obj_t) *bin);
ut64 Elf_(r_bin_elf_get_entry_offset)(struct Elf_(r_bin_elf_obj_t) *bin);
ut64 Elf_(r_bin_elf_get_main_offset)(struct Elf_(r_bin_elf_obj_t) *bin);
int Elf_(r_bin_elf_get_stripped)(struct Elf_(r_bin_elf_obj_t) *bin);
int Elf_(r_bin_elf_get_static)(struct Elf_(r_bin_elf_obj_t) *bin);
char* Elf_(r_bin_elf_get_data_encoding)(struct Elf_(r_bin_elf_obj_t) *bin);
char* Elf_(r_bin_elf_get_arch)(struct Elf_(r_bin_elf_obj_t) *bin);
char* Elf_(r_bin_elf_get_machine_name)(struct Elf_(r_bin_elf_obj_t) *bin);
char* Elf_(r_bin_elf_get_file_type)(struct Elf_(r_bin_elf_obj_t) *bin);
char* Elf_(r_bin_elf_get_elf_class)(struct Elf_(r_bin_elf_obj_t) *bin);
int Elf_(r_bin_elf_get_bits)(struct Elf_(r_bin_elf_obj_t) *bin);
char* Elf_(r_bin_elf_get_osabi_name)(struct Elf_(r_bin_elf_obj_t) *bin);
int Elf_(r_bin_elf_is_big_endian)(struct Elf_(r_bin_elf_obj_t) *bin);
struct r_bin_elf_lib_t* Elf_(r_bin_elf_get_libs)(struct Elf_(r_bin_elf_obj_t) *bin);
struct r_bin_elf_section_t* Elf_(r_bin_elf_get_sections)(struct Elf_(r_bin_elf_obj_t) *bin);
struct r_bin_elf_symbol_t* Elf_(r_bin_elf_get_symbols)(struct Elf_(r_bin_elf_obj_t) *bin, int type);
struct r_bin_elf_field_t* Elf_(r_bin_elf_get_fields)(struct Elf_(r_bin_elf_obj_t) *bin);
char *Elf_(r_bin_elf_get_rpath)(struct Elf_(r_bin_elf_obj_t) *bin);
void* Elf_(r_bin_elf_free)(struct Elf_(r_bin_elf_obj_t)* bin);
struct Elf_(r_bin_elf_obj_t)* Elf_(r_bin_elf_new)(const char* file);
ut64 Elf_(r_bin_elf_resize_section)(struct Elf_(r_bin_elf_obj_t) *bin, const char *name, ut64 size);
int Elf_(r_bin_elf_del_rpath)(struct Elf_(r_bin_elf_obj_t) *bin);

#endif

