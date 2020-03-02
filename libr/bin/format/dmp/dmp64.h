/* radare2 - LGPL - Copyright 2020 - abcSup */

#ifndef DMP64_H
#define DMP64_H

#include <r_util.h>

#include "dmp_specs.h"

typedef struct {
	ut64 start;
	ut64 file_offset;
} dmp_page_desc;

struct r_bin_dmp64_obj_t {
	dmp64_header *header;
	dmp_bmp_header *bmp_header;

	dmp_p_memory_run *runs;
	ut8 *bitmap;
	ut64 dtb;
	RList *pages;

	RBuffer* b;
	int size;
	Sdb *kv;
};

void r_bin_dmp64_free(struct r_bin_dmp64_obj_t *obj);
struct r_bin_dmp64_obj_t *r_bin_dmp64_new_buf(RBuffer* buf);

#endif /* DMP64_H */
