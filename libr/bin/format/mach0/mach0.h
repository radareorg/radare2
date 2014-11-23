/* radare - LGPL - Copyright 2010-2014 - pancake, nibble */

#include <r_bin.h>
#include <r_types.h>
#include "mach0_specs.h"

#ifndef _INCLUDE_R_BIN_MACH0_H_
#define _INCLUDE_R_BIN_MACH0_H_

#define R_BIN_MACH0_STRING_LENGTH 256

struct section_t {
	ut64 offset;
	ut64 addr;
	ut64 size;
	ut32 align;
	ut32 flags;
	int srwx;
	char name[R_BIN_MACH0_STRING_LENGTH];
	int last;
};

struct symbol_t {
	ut64 offset;
	ut64 addr;
	ut64 size;
	int type;
	char name[R_BIN_MACH0_STRING_LENGTH];
	int last;
};

struct import_t {
	char name[R_BIN_MACH0_STRING_LENGTH];
	int ord;
	int last;
};

struct reloc_t {
	ut64 offset;
	ut64 addr;
	st64 addend;
	ut8 type;
	int ord;
	int last;
};

struct addr_t {
	ut64 offset;
	ut64 addr;
	int last;
};

struct lib_t {
	char name[R_BIN_MACH0_STRING_LENGTH];
	int last;
};

struct MACH0_(obj_t) {
	struct MACH0_(mach_header) hdr;
	struct MACH0_(segment_command)* segs;
	int nsegs;
	struct MACH0_(section)* sects;
	int nsects;
	struct MACH0_(nlist)* symtab;
	ut8* symstr;
	int symstrlen;
	int nsymtab;
	ut32* indirectsyms;
	int nindirectsyms;

	RBinImport **imports_by_ord;
	size_t imports_by_ord_size;

	struct dysymtab_command dysymtab;
	struct load_command main_cmd;
	struct dyld_info_command *dyld_info;
	struct dylib_table_of_contents* toc;
	int ntoc;
	struct MACH0_(dylib_module)* modtab;
	int nmodtab;
	struct thread_command thread;
	union {
		struct x86_thread_state32 x86_32;
		struct x86_thread_state64 x86_64;
		struct ppc_thread_state32 ppc_32;
		struct ppc_thread_state64 ppc_64;
		struct arm_thread_state32 arm_32;
		struct arm_thread_state64 arm_64;
	} thread_state;
	char (*libs)[R_BIN_MACH0_STRING_LENGTH];
	int nlibs;
	int size;
	ut64 baddr;
	ut64 entry;
	int endian;
	const char* file;
	RBuffer* b;
	int os;
	Sdb *kv;
	int has_crypto;
	int uuidn;
};

struct MACH0_(obj_t)* MACH0_(mach0_new)(const char* file);
struct MACH0_(obj_t)* MACH0_(new_buf)(struct r_buf_t *buf);
void* MACH0_(mach0_free)(struct MACH0_(obj_t)* bin);
struct section_t* MACH0_(get_sections)(struct MACH0_(obj_t)* bin);
struct symbol_t* MACH0_(get_symbols)(struct MACH0_(obj_t)* bin);
struct import_t* MACH0_(get_imports)(struct MACH0_(obj_t)* bin);
struct reloc_t* MACH0_(get_relocs)(struct MACH0_(obj_t)* bin);
struct addr_t* MACH0_(get_entrypoint)(struct MACH0_(obj_t)* bin);
struct lib_t* MACH0_(get_libs)(struct MACH0_(obj_t)* bin);
ut64 MACH0_(get_baddr)(struct MACH0_(obj_t)* bin);
char* MACH0_(get_class)(struct MACH0_(obj_t)* bin);
int MACH0_(get_bits)(struct MACH0_(obj_t)* bin);
int MACH0_(is_big_endian)(struct MACH0_(obj_t)* bin);
int MACH0_(is_pie)(struct MACH0_(obj_t)* bin);
const char* MACH0_(get_os)(struct MACH0_(obj_t)* bin);
char* MACH0_(get_cputype)(struct MACH0_(obj_t)* bin);
char* MACH0_(get_cpusubtype)(struct MACH0_(obj_t)* bin);
char* MACH0_(get_filetype)(struct MACH0_(obj_t)* bin);
ut64 MACH0_(get_main)(struct MACH0_(obj_t)* bin);

#if 0
int r_bin_mach0_get_file_alignment(r_bin_mach0_obj*);
int r_bin_mach0_get_image_size(r_bin_mach0_obj*);
int r_bin_mach0_get_os(r_bin_mach0_obj*, char*);
int r_bin_mach0_get_subsystem(r_bin_mach0_obj*, char*);
int r_bin_mach0_get_section_alignment(r_bin_mach0_obj*);
int r_bin_mach0_get_strings(r_bin_mach0_obj*, int, int, r_bin_mach0_string*);
int r_bin_mach0_is_stripped_relocs(r_bin_mach0_obj*);
int r_bin_mach0_is_stripped_line_nums(r_bin_mach0_obj*);
int r_bin_mach0_is_stripped_local_syms(r_bin_mach0_obj*);
int r_bin_mach0_is_stripped_debug(r_bin_mach0_obj*);
#endif

#endif
