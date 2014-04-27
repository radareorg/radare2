/* radare - LGPL - Copyright 2009-2011 nibble<.ds@gmail.com> */

#include <r_types.h>
#include "mach0_specs.h"

#ifndef _INCLUDE_R_BIN_FATMACH0_H_
#define _INCLUDE_R_BIN_FATMACH0_H_

struct r_bin_fatmach0_obj_t {
	const char *file;
	int size;
	int nfat_arch;
	struct fat_header hdr;
	struct fat_arch *archs;
	struct r_buf_t* b;
};

struct r_bin_fatmach0_arch_t {
	int size;
	int offset;
	struct r_buf_t *b; 
	int last;
};

struct r_bin_fatmach0_arch_t *r_bin_fatmach0_extract(struct r_bin_fatmach0_obj_t* bin, int idx, int *narch);
void* r_bin_fatmach0_free(struct r_bin_fatmach0_obj_t* bin);
struct r_bin_fatmach0_obj_t* r_bin_fatmach0_new(const char* file);
struct r_bin_fatmach0_obj_t* r_bin_fatmach0_from_bytes_new(const ut8* buf, ut64 size);

#endif
