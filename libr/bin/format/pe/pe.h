/* radare - LGPL - Copyright 2008 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "pe_specs.h"

#ifndef _INCLUDE_R_BIN_PE_H_
#define _INCLUDE_R_BIN_PE_H_

#define R_BIN_PE_SCN_IS_SHAREABLE(x)       x & PE_IMAGE_SCN_MEM_SHARED
#define R_BIN_PE_SCN_IS_EXECUTABLE(x)      x & PE_IMAGE_SCN_MEM_EXECUTE
#define R_BIN_PE_SCN_IS_READABLE(x)        x & PE_IMAGE_SCN_MEM_READ
#define R_BIN_PE_SCN_IS_WRITABLE(x)        x & PE_IMAGE_SCN_MEM_WRITE

struct r_bin_pe_addr_t {
	ut64 vaddr;
	ut64 paddr;
};

struct r_bin_pe_section_t {
	ut8  name[PE_IMAGE_SIZEOF_SHORT_NAME];
	ut64 size;
	ut64 vsize;
	ut64 vaddr;
	ut64 paddr;
	ut64 flags;
	int last;
};

struct r_bin_pe_import_t {
	ut8  name[PE_NAME_LENGTH + 1];
	ut64 vaddr;
	ut64 paddr;
	ut64 hint;
	ut64 ordinal;
	int last;
};

struct r_bin_pe_export_t {
	ut8  name[PE_NAME_LENGTH + 1];
	ut8  forwarder[PE_NAME_LENGTH + 1];
	ut64 vaddr;
	ut64 paddr;
	ut64 ordinal;
	int last;
};

struct r_bin_pe_string_t {
	char string[PE_STRING_LENGTH];
	ut64 vaddr;
	ut64 paddr;
	ut64 size;
	char type;
	int last;
};

struct r_bin_pe_lib_t {
	char name[PE_STRING_LENGTH];
	int last;
};

#endif

struct PE_(r_bin_pe_obj_t) {
	// these pointers contain a copy of the headers and sections!
	PE_(image_dos_header)             *dos_header;
	PE_(image_nt_headers)			  *nt_headers;
	PE_(image_section_header)         *section_header;
	PE_(image_export_directory)       *export_directory;
	PE_(image_import_directory)       *import_directory;
	PE_(image_delay_import_directory) *delay_import_directory;
	// these values define the real offset into the untouched binary
	ut64 nt_header_offset;
	ut64 import_directory_offset;
	ut64 export_directory_offset;
	ut64 delay_import_directory_offset;

	int import_directory_size;
	int size;
	int endian;
	RList *relocs;
	const char* file;
	struct r_buf_t* b;
	Sdb *kv;
};

#define GUIDSTR_LEN 34
#define DBG_FILE_NAME_LEN 255

typedef struct SDebugInfo{
	char guidstr[GUIDSTR_LEN];
	char file_name[DBG_FILE_NAME_LEN];
} SDebugInfo;

char* PE_(r_bin_pe_get_arch)(struct PE_(r_bin_pe_obj_t)* bin);
struct r_bin_pe_addr_t* PE_(r_bin_pe_get_entrypoint)(struct PE_(r_bin_pe_obj_t)* bin);
struct r_bin_pe_addr_t *PE_(r_bin_pe_get_main_vaddr)(struct PE_(r_bin_pe_obj_t) *bin);
struct r_bin_pe_export_t* PE_(r_bin_pe_get_exports)(struct PE_(r_bin_pe_obj_t)* bin); // TODO
int PE_(r_bin_pe_get_file_alignment)(struct PE_(r_bin_pe_obj_t)* bin);
ut64 PE_(r_bin_pe_get_image_base)(struct PE_(r_bin_pe_obj_t)* bin);
struct r_bin_pe_import_t* PE_(r_bin_pe_get_imports)(struct PE_(r_bin_pe_obj_t) *bin); // TODO
struct r_bin_pe_lib_t* PE_(r_bin_pe_get_libs)(struct PE_(r_bin_pe_obj_t) *bin);
int PE_(r_bin_pe_get_image_size)(struct PE_(r_bin_pe_obj_t)* bin);
char* PE_(r_bin_pe_get_machine)(struct PE_(r_bin_pe_obj_t)* bin);
char* PE_(r_bin_pe_get_os)(struct PE_(r_bin_pe_obj_t)* bin);
char* PE_(r_bin_pe_get_class)(struct PE_(r_bin_pe_obj_t)* bin);
int PE_(r_bin_pe_get_bits)(struct PE_(r_bin_pe_obj_t)* bin);
int PE_(r_bin_pe_get_section_alignment)(struct PE_(r_bin_pe_obj_t)* bin);
struct r_bin_pe_section_t* PE_(r_bin_pe_get_sections)(struct PE_(r_bin_pe_obj_t)* bin);
char* PE_(r_bin_pe_get_subsystem)(struct PE_(r_bin_pe_obj_t)* bin);
int PE_(r_bin_pe_is_dll)(struct PE_(r_bin_pe_obj_t)* bin);
int PE_(r_bin_pe_is_big_endian)(struct PE_(r_bin_pe_obj_t)* bin);
int PE_(r_bin_pe_is_stripped_relocs)(struct PE_(r_bin_pe_obj_t)* bin);
int PE_(r_bin_pe_is_stripped_line_nums)(struct PE_(r_bin_pe_obj_t)* bin);
int PE_(r_bin_pe_is_stripped_local_syms)(struct PE_(r_bin_pe_obj_t)* bin);
int PE_(r_bin_pe_is_stripped_debug)(struct PE_(r_bin_pe_obj_t)* bin);
void* PE_(r_bin_pe_free)(struct PE_(r_bin_pe_obj_t)* bin);
struct PE_(r_bin_pe_obj_t)* PE_(r_bin_pe_new)(const char* file);
struct PE_(r_bin_pe_obj_t)* PE_(r_bin_pe_new_buf)(struct r_buf_t *buf);
int PE_(r_bin_pe_get_debug_data)(struct PE_(r_bin_pe_obj_t) *bin, struct SDebugInfo *res);
