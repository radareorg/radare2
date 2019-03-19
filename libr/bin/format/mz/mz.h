/* radare - LGPL - Copyright 2015 nodepad */

#include <r_types.h>
#include <r_list.h>
#include <r_util.h>
#include <r_bin.h>
#include "mz_specs.h"

struct r_bin_mz_segment_t {
	ut64 paddr;
	ut64 vaddr;
	ut64 size;
	int last;
};

struct r_bin_mz_reloc_t {
	ut64 paddr;
	ut64 vaddr;
	int last;
};

struct r_bin_mz_obj_t {
	const MZ_image_dos_header *dos_header;
	const void *dos_extended_header;
	MZ_image_relocation_entry *relocation_entries;

	int dos_extended_header_size;

	int size;
	int dos_file_size; /* Size of dos file from dos executable header */
	int load_module_size; /* Size of load module: dos_file_size - header size */
	const char *file;
	RBuffer *b;
	Sdb *kv;
};

RBinAddr *r_bin_mz_get_entrypoint (const struct r_bin_mz_obj_t *bin);
RList *r_bin_mz_get_segments (const struct r_bin_mz_obj_t *bin);
struct r_bin_mz_reloc_t *r_bin_mz_get_relocs (const struct r_bin_mz_obj_t *bin);
void *r_bin_mz_free (struct r_bin_mz_obj_t *bin);
struct r_bin_mz_obj_t *r_bin_mz_new (const char *file);
struct r_bin_mz_obj_t *r_bin_mz_new_buf(RBuffer *buf);
RBinAddr *r_bin_mz_get_main_vaddr (struct r_bin_mz_obj_t *bin);
