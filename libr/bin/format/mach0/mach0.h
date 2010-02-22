/* radare - LGPL - Copyright 2010 nibble at develsec.org */

#include <r_types.h>
#include "mach0_specs.h"

#ifndef _INCLUDE_R_BIN_MACH0_H_
#define _INCLUDE_R_BIN_MACH0_H_

#define R_BIN_MACH0_STRING_LENGTH 256

#if 0
#define R_BIN_MACH0_SECT_IS_SHAREABLE(x)   x
#define R_BIN_MACH0_SECT_IS_EXECUTABLE(x)  x
#define R_BIN_MACH0_SECT_IS_READABLE(x)    x
#define R_BIN_MACH0_SECT_IS_WRITABLE(x)    x
#endif

struct r_bin_mach0_section_t {
	ut64 offset;
	ut64 addr;
	ut64 size;
	ut32 align;
	ut32 flags;
	char name[R_BIN_MACH0_STRING_LENGTH];
	int last;
};

struct r_bin_mach0_symbol_t {
	ut64 offset;
	ut64 addr;
	ut64 size;
	char name[R_BIN_MACH0_STRING_LENGTH];
	int last;
};

struct r_bin_mach0_import_t {
	ut64 offset;
	ut64 addr;
	char name[R_BIN_MACH0_STRING_LENGTH];
	int last;
};

struct r_bin_mach0_entrypoint_t {
	ut64 offset;
	ut64 addr;
	int last;
};

#endif

struct MACH0_(r_bin_mach0_obj_t) {
	struct MACH0_(mach_header) hdr;
	struct MACH0_(segment_command)* segs;
	int nsegs;
	struct MACH0_(section)* sects;
	int nsects;
	struct MACH0_(nlist)* symtab;
	ut8* symstr;
	int nsymtab;
	struct dysymtab_command dysymtab;
	struct dylib_table_of_contents* toc;
	int ntoc;
	struct MACH0_(dylib_module)* modtab;
	int nmodtab;
	struct thread_command thread;
	int size;
    ut64 baddr;
	int	endian;
    const char* file;
	struct r_buf_t* b;
};

struct MACH0_(r_bin_mach0_obj_t)* MACH0_(r_bin_mach0_new)(const char* file);
void* MACH0_(r_bin_mach0_free)(struct MACH0_(r_bin_mach0_obj_t)* bin);
struct r_bin_mach0_section_t* MACH0_(r_bin_mach0_get_sections)(struct MACH0_(r_bin_mach0_obj_t)* bin);
struct r_bin_mach0_symbol_t* MACH0_(r_bin_mach0_get_symbols)(struct MACH0_(r_bin_mach0_obj_t)* bin);
struct r_bin_mach0_import_t* MACH0_(r_bin_mach0_get_imports)(struct MACH0_(r_bin_mach0_obj_t)* bin);
struct r_bin_mach0_entrypoint_t* MACH0_(r_bin_mach0_get_entrypoints)(struct MACH0_(r_bin_mach0_obj_t)* bin);
ut64 MACH0_(r_bin_mach0_get_baddr)(struct MACH0_(r_bin_mach0_obj_t)* bin);

#if 0
int r_bin_mach0_get_arch(r_bin_mach0_obj*, char*);
int r_bin_mach0_get_class(r_bin_mach0_obj*, char*);
int r_bin_mach0_get_file_alignment(r_bin_mach0_obj*);
int r_bin_mach0_get_image_size(r_bin_mach0_obj*);
int r_bin_mach0_get_libs(r_bin_mach0_obj*, int, r_bin_mach0_string*);
int r_bin_mach0_get_machine(r_bin_mach0_obj*, char*);
int r_bin_mach0_get_os(r_bin_mach0_obj*, char*);
int r_bin_mach0_get_section_alignment(r_bin_mach0_obj*);
int r_bin_mach0_get_strings(r_bin_mach0_obj*, int, int, r_bin_mach0_string*);
int r_bin_mach0_get_subsystem(r_bin_mach0_obj*, char*);
int r_bin_mach0_is_big_endian(r_bin_mach0_obj*);
int r_bin_mach0_is_stripped_relocs(r_bin_mach0_obj*);
int r_bin_mach0_is_stripped_line_nums(r_bin_mach0_obj*);
int r_bin_mach0_is_stripped_local_syms(r_bin_mach0_obj*);
int r_bin_mach0_is_stripped_debug(r_bin_mach0_obj*);
#endif
