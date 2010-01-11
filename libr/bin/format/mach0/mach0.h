/* radare - LGPL - Copyright 2010 nibble at develsec.org */

#ifndef _INCLUDE_R_BIN_MACH0_H_
#define _INCLUDE_R_BIN_MACH0_H_

#include <r_types.h>
#include "mach0_specs.h"

#define MACH0_STRING_LENGTH 256

#if 0
#define R_BIN_MACH0_SCN_IS_SHAREABLE(x)   x
#define R_BIN_MACH0_SCN_IS_EXECUTABLE(x)  x
#define R_BIN_MACH0_SCN_IS_READABLE(x)    x
#define R_BIN_MACH0_SCN_IS_WRITABLE(x)    x
#endif

struct r_bin_mach0_section_t {
	ut64 offset;
	ut64 addr;
	ut64 size;
	ut32 align;
	ut32 flags;
	char name[MACH0_STRING_LENGTH];
};

struct r_bin_mach0_obj_t {
	struct mach_header hdr;
	struct segment_command* segs;
	int nsegs;
	struct section* scns;
	int nscns;
	ut32		size;
    ut64        baddr;
	int	        endian;
    const char* file;
	int			fd;
};

struct r_bin_mach0_obj_t* r_bin_mach0_new(const char* file);
void* r_bin_mach0_free(struct r_bin_mach0_obj_t* bin);
struct r_bin_mach0_section_t* r_bin_mach0_get_sections(struct r_bin_mach0_obj_t* bin);

#if 0
int r_bin_mach0_get_arch(r_bin_mach0_obj*, char*);
int r_bin_mach0_get_class(r_bin_mach0_obj*, char*);
int r_bin_mach0_get_entrypoint(r_bin_mach0_obj*, r_bin_mach0_entrypoint*);
int r_bin_mach0_get_exports(r_bin_mach0_obj*, r_bin_mach0_export*);
int r_bin_mach0_get_file_alignment(r_bin_mach0_obj*);
int r_bin_mach0_get_image_size(r_bin_mach0_obj*);
int r_bin_mach0_get_imports(r_bin_mach0_obj*, r_bin_mach0_import*);
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

#endif
