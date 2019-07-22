#ifndef NE_H
#define NE_H
#include <r_types.h>
#include <r_list.h>
#include <r_util.h>
#include <r_bin.h>
#include "ne_specs.h"

typedef struct {
	char *name;
	ut32 offset;
	ut32 size;
} r_ne_resource_entry;

typedef struct {
	char *name;
	RList /*<r_ne_resource_entry>*/ *entry;
} r_ne_resource;

typedef struct {
	NE_image_header *ne_header;
	ut16 header_offset;
	ut16 alignment;
	NE_image_segment_entry *segment_entries;
	ut8 *entry_table;
	ut8 *resident_name_table;
	RBuffer *buf;
	RList *segments;
	RList *entries;
	RList *resources;
	RList *imports;
	RList *symbols;
	char *os;
} r_bin_ne_obj_t;

void r_bin_ne_free(r_bin_ne_obj_t *bin);
r_bin_ne_obj_t *r_bin_ne_new_buf(RBuffer *buf, bool verbose);
RList *r_bin_ne_get_relocs(r_bin_ne_obj_t *bin);
RList *r_bin_ne_get_imports(r_bin_ne_obj_t *bin);
RList *r_bin_ne_get_symbols(r_bin_ne_obj_t *bin);
RList *r_bin_ne_get_segments(r_bin_ne_obj_t *bin);
RList *r_bin_ne_get_entrypoints(r_bin_ne_obj_t *bin);

#endif
