/* radare - LGPL - Copyright 2008 nibble<.ds@gmail.com> */

#include <r_types.h>

#include "elf_specs.h"

#ifndef _INCLUDE_ELF_H_
#define _INCLUDE_ELF_H_

#define R_BIN_ELF_SCN_IS_EXECUTABLE(x) x & SHF_EXECINSTR
#define R_BIN_ELF_SCN_IS_READABLE(x)   x & SHF_ALLOC
#define R_BIN_ELF_SCN_IS_WRITABLE(x)   x & SHF_WRITE

typedef struct {
	u64 offset;
	u64 size;
	u64 align;
	u32 flags;
	char name[ELF_NAME_LENGTH];
} r_bin_elf_section;

typedef struct {
	u64 offset;
	char bind[ELF_NAME_LENGTH];
	char type[ELF_NAME_LENGTH];
	char name[ELF_NAME_LENGTH];
} r_bin_elf_import;

typedef struct {
	u64 offset;
	u64 size;
	char bind[ELF_NAME_LENGTH];
	char type[ELF_NAME_LENGTH];
	char name[ELF_NAME_LENGTH];
} r_bin_elf_symbol;

typedef struct {
	u64 offset;
	u64 size;
	char type;
	char string[ELF_STRING_LENGTH];
} r_bin_elf_string;

#endif

typedef struct {
    ELF_(Ehdr)  ehdr;
    ELF_(Phdr)* phdr;
    ELF_(Shdr)* shdr;
    int         plen;
    char**      section;
    char*       string;
    int         bss;
    u64         base_addr;
    const char* file;
	int			fd;
} ELF_(r_bin_elf_obj);

int   ELF_(r_bin_elf_close)(ELF_(r_bin_elf_obj)*);
const char* ELF_(r_bin_elf_get_arch)(ELF_(r_bin_elf_obj)*);
u64   ELF_(r_bin_elf_get_base_addr)(ELF_(r_bin_elf_obj)*);
const char* ELF_(r_bin_elf_get_data_encoding)(ELF_(r_bin_elf_obj)*);
const char* ELF_(r_bin_elf_get_elf_class)(ELF_(r_bin_elf_obj)*);
u64   ELF_(r_bin_elf_get_entry_offset)(ELF_(r_bin_elf_obj)*);
const char* ELF_(r_bin_elf_get_file_type)(ELF_(r_bin_elf_obj)*);
int   ELF_(r_bin_elf_get_imports)(ELF_(r_bin_elf_obj)*, r_bin_elf_import*);
int   ELF_(r_bin_elf_get_imports_count)(ELF_(r_bin_elf_obj)*);
int   ELF_(r_bin_elf_get_libs)(ELF_(r_bin_elf_obj)*, int, r_bin_elf_string*);
const char* ELF_(r_bin_elf_get_machine_name)(ELF_(r_bin_elf_obj)*);
const char* ELF_(r_bin_elf_get_osabi_name)(ELF_(r_bin_elf_obj)*);
int   ELF_(r_bin_elf_get_sections)(ELF_(r_bin_elf_obj)*, r_bin_elf_section*);
int   ELF_(r_bin_elf_get_sections_count)(ELF_(r_bin_elf_obj)*);
int   ELF_(r_bin_elf_get_static)(ELF_(r_bin_elf_obj)*);
int   ELF_(r_bin_elf_get_strings)(ELF_(r_bin_elf_obj)*, int, int, r_bin_elf_string*);
int   ELF_(r_bin_elf_get_stripped)(ELF_(r_bin_elf_obj)*);
int   ELF_(r_bin_elf_get_symbols)(ELF_(r_bin_elf_obj)*, r_bin_elf_symbol*);
int   ELF_(r_bin_elf_get_symbols_count)(ELF_(r_bin_elf_obj)*);
int   ELF_(r_bin_elf_is_big_endian)(ELF_(r_bin_elf_obj)*);
int   ELF_(r_bin_elf_open)(ELF_(r_bin_elf_obj)*, const char*, int);
u64   ELF_(r_bin_elf_resize_section)(ELF_(r_bin_elf_obj)*, const char*, u64);
