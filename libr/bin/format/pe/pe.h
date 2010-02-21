/* radare - LGPL - Copyright 2008 nibble<.ds@gmail.com> */

#include "r_types.h"
#include "pe_specs.h"

#ifndef _INCLUDE_R_BIN_PE_H_
#define _INCLUDE_R_BIN_PE_H_

#define R_BIN_PE_SCN_IS_SHAREABLE(x)       x & PE_IMAGE_SCN_MEM_SHARED
#define R_BIN_PE_SCN_IS_EXECUTABLE(x)      x & PE_IMAGE_SCN_MEM_EXECUTE
#define R_BIN_PE_SCN_IS_READABLE(x)        x & PE_IMAGE_SCN_MEM_READ
#define R_BIN_PE_SCN_IS_WRITABLE(x)        x & PE_IMAGE_SCN_MEM_WRITE

struct r_bin_pe_entrypoint_t {
	ut64 rva;
	ut64 offset;
};

struct r_bin_pe_section_t {
	ut8  name[PE_IMAGE_SIZEOF_SHORT_NAME];
	ut64 size;
	ut64 vsize;
	ut64 rva;
	ut64 offset;
	ut64 characteristics;
	int last;
};

struct r_bin_pe_import_t {
	ut8  name[PE_NAME_LENGTH];
	ut64 rva;
	ut64 offset;
	ut64 hint;
	ut64 ordinal;
	int last;
};

struct r_bin_pe_export_t {
	ut8  name[PE_NAME_LENGTH];
	ut8  forwarder[PE_NAME_LENGTH];
	ut64 rva;
	ut64 offset;
	ut64 ordinal;
	int last;
};

struct r_bin_pe_string_t {
	char string[PE_STRING_LENGTH];
	ut64 rva;
	ut64 offset;
	ut64 size;
	char type;
	int last;
};

#endif

struct PE_(r_bin_pe_obj_t) {
	PE_(image_dos_header)             *dos_header;
	PE_(image_nt_headers)			  *nt_headers;
	PE_(image_section_header)         *section_header;
	PE_(image_export_directory)       *export_directory;
	PE_(image_import_directory)       *import_directory;
	PE_(image_delay_import_directory) *delay_import_directory;
	int size;
	int	endian;
    const char* file;
	struct r_buf_t* b;
};

char* PE_(r_bin_pe_get_arch)(struct PE_(r_bin_pe_obj_t)* bin);
struct r_bin_pe_entrypoint_t* PE_(r_bin_pe_get_entrypoint)(struct PE_(r_bin_pe_obj_t)* bin);
struct r_bin_pe_export_t* PE_(r_bin_pe_get_exports)(struct PE_(r_bin_pe_obj_t)* bin); // TODO
int PE_(r_bin_pe_get_file_alignment)(struct PE_(r_bin_pe_obj_t)* bin);
ut64 PE_(r_bin_pe_get_image_base)(struct PE_(r_bin_pe_obj_t)* bin);
struct r_bin_pe_import_t* PE_(r_bin_pe_get_imports)(struct PE_(r_bin_pe_obj_t) *bin); // TODO
struct r_bin_pe_string_t* PE_(r_bin_pe_get_libs)(struct PE_(r_bin_pe_obj_t) *bin);
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
