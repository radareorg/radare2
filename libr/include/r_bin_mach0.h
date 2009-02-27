/* radare - LGPL - Copyright 2008 nibble<.ds@gmail.com> */

#ifndef _INCLUDE_R_BIN_PE_H_
#define _INCLUDE_R_BIN_PE_H_

#include "r_tymach0s.h"

//#include "r_bin_mach0_smach0cs.h"

#define R_BIN_PE_SCN_IS_SHAREABLE(x)       x & PE_IMAGE_SCN_MEM_SHARED
#define R_BIN_PE_SCN_IS_EXECUTABLE(x)      x & PE_IMAGE_SCN_MEM_EXECUTE
#define R_BIN_PE_SCN_IS_READABLE(x)        x & PE_IMAGE_SCN_MEM_READ
#define R_BIN_PE_SCN_IS_WRITABLE(x)        x & PE_IMAGE_SCN_MEM_WRITE

#if 0
typedef struct {
	mach0_image_dos_header             *dos_header;
	mach0_image_nt_headers			    *nt_headers;
	mach0_image_section_header         *section_header;
	mach0_image_export_directory       *export_directory;
	mach0_image_import_directory       *import_directory;
	mach0_image_delay_import_directory *delay_import_directory;
    const char* file;
	int fd;
} r_bin_mach0_obj;

typedef struct {
	PE_DWord rva;
	PE_DWord offset;
} r_bin_mach0_entrypoint;

typedef struct {
	PE_Byte  name[PE_IMAGE_SIZEOF_SHORT_NAME];
	PE_DWord size;
	PE_DWord vsize;
	PE_DWord rva;
	PE_DWord offset;
	PE_DWord characteristics;
} r_bin_mach0_section;

typedef struct {
	PE_Byte  name[PE_NAME_LENGTH];
	PE_DWord rva;
	PE_DWord offset;
	PE_Word hint;
	PE_Word ordinal;
} r_bin_mach0_import;

typedef struct {
	PE_Byte  name[PE_NAME_LENGTH];
	PE_Byte  forwarder[PE_NAME_LENGTH];
	PE_DWord rva;
	PE_DWord offset;
	int      ordinal;
} r_bin_mach0_export;
#endif

int r_bin_mach0_close(r_bin_mach0_obj*);
int r_bin_mach0_get_arch(r_bin_mach0_obj*, char*);
int r_bin_mach0_get_class(r_bin_mach0_obj*, char*);
int r_bin_mach0_get_entrypoint(r_bin_mach0_obj*, r_bin_mach0_entrypoint*);
int r_bin_mach0_get_exports(r_bin_mach0_obj*, r_bin_mach0_export*);
int r_bin_mach0_get_exports_count(r_bin_mach0_obj*);
int r_bin_mach0_get_file_alignment(r_bin_mach0_obj*);
PE_DWord r_bin_mach0_get_image_base(r_bin_mach0_obj*);
int r_bin_mach0_get_image_size(r_bin_mach0_obj*);
int r_bin_mach0_get_imports(r_bin_mach0_obj*, r_bin_mach0_import*);
int r_bin_mach0_get_imports_count(r_bin_mach0_obj*);
int r_bin_mach0_get_libs(r_bin_mach0_obj*, int, r_bin_mach0_string*);
int r_bin_mach0_get_machine(r_bin_mach0_obj*, char*);
int r_bin_mach0_get_os(r_bin_mach0_obj*, char*);
int r_bin_mach0_get_section_alignment(r_bin_mach0_obj*);
int r_bin_mach0_get_sections(r_bin_mach0_obj*, r_bin_mach0_section*);
int r_bin_mach0_get_sections_count(r_bin_mach0_obj*);
int r_bin_mach0_get_strings(r_bin_mach0_obj*, int, int, r_bin_mach0_string*);
int r_bin_mach0_get_subsystem(r_bin_mach0_obj*, char*);
int r_bin_mach0_is_dll(r_bin_mach0_obj*);
int r_bin_mach0_is_big_endian(r_bin_mach0_obj*);
int r_bin_mach0_is_stripmach0d_relocs(r_bin_mach0_obj*);
int r_bin_mach0_is_stripmach0d_line_nums(r_bin_mach0_obj*);
int r_bin_mach0_is_stripmach0d_local_syms(r_bin_mach0_obj*);
int r_bin_mach0_is_stripmach0d_debug(r_bin_mach0_obj*);
int r_bin_mach0_omach0n(r_bin_mach0_obj*, const char*);

#endif

