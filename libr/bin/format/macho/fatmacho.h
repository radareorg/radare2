#include <r_types.h>
#include "macho_specs.h"

#ifndef _INCLUDE_R_BIN_FATMACHO_H_
#define _INCLUDE_R_BIN_FATMACHO_H_

struct r_bin_fatmacho_obj_t {
	const char *file;
	ut64 size;
	int nfat_arch;
	struct fat_header hdr;
	struct fat_arch *archs;
	RBuffer* b;
};

struct r_bin_fatmacho_arch_t {
	ut64 size;
	ut64 offset;
	RBuffer *b;
	int last;
};

struct r_bin_fatmacho_arch_t *r_bin_fatmacho_extract(struct r_bin_fatmacho_obj_t* bin, int idx, int *narch);
void* r_bin_fatmacho_free(struct r_bin_fatmacho_obj_t* bin);
struct r_bin_fatmacho_obj_t* r_bin_fatmacho_new(const char* file);
struct r_bin_fatmacho_obj_t* r_bin_fatmacho_from_bytes_new(const ut8* buf, ut64 size);
struct r_bin_fatmacho_obj_t* r_bin_fatmacho_from_buffer_new(RBuffer *b);
#endif
