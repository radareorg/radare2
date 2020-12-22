#ifndef OMF_H_
#define OMF_H_

#include <r_util.h>
#include <r_types.h>
#include <r_bin.h>

#include "omf_specs.h"

typedef struct OMF_record_handler {
	OMF_record record;
	struct OMF_record_handler *next;
} OMF_record_handler;

typedef struct {
	ut32 nb_elem;
	void *elems;
} OMF_multi_datas;

typedef struct OMF_DATA{
	ut64 paddr; // offset in file
	ut64 size;
	ut32 offset;
	ut16 seg_idx;
	struct OMF_DATA	*next;
} OMF_data;

// sections return by the plugin are the addr of datas because sections are 
// separate on non contiguous block on the omf file
typedef struct {
	ut32 name_idx;
	ut64 size;
	ut8 bits;
	ut64 vaddr;
	OMF_data *data;
} OMF_segment;

typedef struct {
	char *name;
	ut16 seg_idx;
	ut32 offset;
} OMF_symbol;

typedef struct {
	ut8 bits;
	char **names;
	ut32 nb_name;
	OMF_segment **sections;
	ut32 nb_section;
	OMF_symbol **symbols;
	ut32 nb_symbol;
	OMF_record_handler *records;
} r_bin_omf_obj;

// this value was chosen arbitrarily to made the loader work correctly
// if someone want to implement rellocation for omf he has to remove this
#define OMF_BASE_ADDR 0x1000

bool r_bin_checksum_omf_ok(const ut8 *buf, ut64 buf_size);
r_bin_omf_obj *r_bin_internal_omf_load(const ut8 *buf, ut64 size);
void r_bin_free_all_omf_obj(r_bin_omf_obj *obj);
bool r_bin_omf_get_entry(r_bin_omf_obj *obj, RBinAddr *addr);
int r_bin_omf_get_bits(r_bin_omf_obj *obj);
int r_bin_omf_send_sections(RList *list, OMF_segment *section, r_bin_omf_obj *obj);
ut64 r_bin_omf_get_paddr_sym(r_bin_omf_obj *obj, OMF_symbol *sym);
ut64 r_bin_omf_get_vaddr_sym(r_bin_omf_obj *obj, OMF_symbol *sym);

#endif
