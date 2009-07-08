/* radare - LGPL - Copyright 2008 nibble<.ds@gmail.com> */

#include "r_types.h"

#include "pe_specs.h"

#ifndef _INCLUDE_R_BIN_PE_H_
#define _INCLUDE_R_BIN_PE_H_

#define R_BIN_PE_SCN_IS_SHAREABLE(x)       x & PE_IMAGE_SCN_MEM_SHARED
#define R_BIN_PE_SCN_IS_EXECUTABLE(x)      x & PE_IMAGE_SCN_MEM_EXECUTE
#define R_BIN_PE_SCN_IS_READABLE(x)        x & PE_IMAGE_SCN_MEM_READ
#define R_BIN_PE_SCN_IS_WRITABLE(x)        x & PE_IMAGE_SCN_MEM_WRITE

#endif

typedef struct {
	PE_(image_dos_header)             *dos_header;
	PE_(image_nt_headers)			  *nt_headers;
	PE_(image_section_header)         *section_header;
	PE_(image_export_directory)       *export_directory;
	PE_(image_import_directory)       *import_directory;
	PE_(image_delay_import_directory) *delay_import_directory;
    const char* file;
	int fd;
} PE_(r_bin_pe_obj);

typedef struct {
	ut64 rva;
	ut64 offset;
} PE_(r_bin_pe_entrypoint);

typedef struct {
	ut8  name[PE_IMAGE_SIZEOF_SHORT_NAME];
	ut64 size;
	ut64 vsize;
	ut64 rva;
	ut64 offset;
	ut64 characteristics;
} PE_(r_bin_pe_section);

typedef struct {
	ut8  name[PE_NAME_LENGTH];
	ut64 rva;
	ut64 offset;
	ut64 hint;
	ut64 ordinal;
} PE_(r_bin_pe_import);

typedef struct {
	ut8  name[PE_NAME_LENGTH];
	ut8  forwarder[PE_NAME_LENGTH];
	ut64 rva;
	ut64 offset;
	ut64 ordinal;
} PE_(r_bin_pe_export);

typedef struct {
	ut64 rva;
	ut64 offset;
	ut64 size;
	char type;
	char string[PE_STRING_LENGTH];
} PE_(r_bin_pe_string);

int PE_(r_bin_pe_close)(PE_(r_bin_pe_obj)*);
int PE_(r_bin_pe_get_arch)(PE_(r_bin_pe_obj)*, char*);
int PE_(r_bin_pe_get_class)(PE_(r_bin_pe_obj)*, char*);
int PE_(r_bin_pe_get_entrypoint)(PE_(r_bin_pe_obj)*, PE_(r_bin_pe_entrypoint)*);
int PE_(r_bin_pe_get_exports)(PE_(r_bin_pe_obj)*, PE_(r_bin_pe_export)*);
int PE_(r_bin_pe_get_exports_count)(PE_(r_bin_pe_obj)*);
int PE_(r_bin_pe_get_file_alignment)(PE_(r_bin_pe_obj)*);
ut64 PE_(r_bin_pe_get_image_base)(PE_(r_bin_pe_obj)*);
int PE_(r_bin_pe_get_image_size)(PE_(r_bin_pe_obj)*);
int PE_(r_bin_pe_get_imports)(PE_(r_bin_pe_obj)*, PE_(r_bin_pe_import)*);
int PE_(r_bin_pe_get_imports_count)(PE_(r_bin_pe_obj)*);
int PE_(r_bin_pe_get_libs)(PE_(r_bin_pe_obj)*, int, PE_(r_bin_pe_string)*);
int PE_(r_bin_pe_get_machine)(PE_(r_bin_pe_obj)*, char*);
int PE_(r_bin_pe_get_os)(PE_(r_bin_pe_obj)*, char*);
int PE_(r_bin_pe_get_section_alignment)(PE_(r_bin_pe_obj)*);
int PE_(r_bin_pe_get_sections)(PE_(r_bin_pe_obj)*, PE_(r_bin_pe_section)*);
int PE_(r_bin_pe_get_sections_count)(PE_(r_bin_pe_obj)*);
int PE_(r_bin_pe_get_subsystem)(PE_(r_bin_pe_obj)*, char*);
int PE_(r_bin_pe_is_dll)(PE_(r_bin_pe_obj)*);
int PE_(r_bin_pe_is_big_endian)(PE_(r_bin_pe_obj)*);
int PE_(r_bin_pe_is_stripped_relocs)(PE_(r_bin_pe_obj)*);
int PE_(r_bin_pe_is_stripped_line_nums)(PE_(r_bin_pe_obj)*);
int PE_(r_bin_pe_is_stripped_local_syms)(PE_(r_bin_pe_obj)*);
int PE_(r_bin_pe_is_stripped_debug)(PE_(r_bin_pe_obj)*);
int PE_(r_bin_pe_open)(PE_(r_bin_pe_obj)*, const char*);
