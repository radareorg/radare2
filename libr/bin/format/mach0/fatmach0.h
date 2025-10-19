#include <r_types.h>
#include "mach0_specs.h"

#ifndef _INCLUDE_R_BIN_FATMACH0_H_
#define _INCLUDE_R_BIN_FATMACH0_H_

struct r_bin_fatmach0_obj_t {
	const char *file;
	ut64 size;
	int nfat_arch;
	struct fat_header hdr;
	struct fat_arch *archs;
	RBuffer* b;
};

struct r_bin_fatmach0_arch_t {
	ut64 size;
	ut64 offset;
	RBuffer *b;
	int last;
};

struct r_bin_fatmach0_arch_t *r_bin_fatmach0_extract(struct r_bin_fatmach0_obj_t* bin, int idx, int *narch);
void* r_bin_fatmach0_free(struct r_bin_fatmach0_obj_t* bin);
struct r_bin_fatmach0_obj_t* r_bin_fatmach0_new(const char* file);
struct r_bin_fatmach0_obj_t* r_bin_fatmach0_from_bytes_new(const ut8* buf, ut64 size);
struct r_bin_fatmach0_obj_t* r_bin_fatmach0_from_buffer_new(RBuffer *b);
#endif
