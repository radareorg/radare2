/* radare - LGPL - Copyright 2014 Fedor Sakharov <fedor.sakharov@gmail.com> */

#ifndef COFF_H
#define COFF_H

#include <r_bin.h>
#include <r_types.h>

#include "coff_specs.h"

struct coff_scn_hdr {
	char	name[9];
	ut32	virtual_size;
	ut32	virtual_addr;
	ut32	raw_data_size;
	ut32	raw_data_pointer;
	ut32	reloc_pointer;
	ut32	linenum_pointer;
	ut16	reloc_num;
	ut16	linenum_num;
	ut32	flags;
};

struct coff_symbol {
	char	*name;
	ut32	value;
	ut16	scn_num;
	ut16	type;
	ut8	storage_class;
	ut8	aux_sym_num;
};

struct r_bin_coff_obj {
	struct coff_hdr	hdr;
	struct coff_opt_hdr opt_hdr;
	struct coff_scn_hdr *scn_hdrs;
	struct coff_symbol *symbols;

	struct r_buf_t *b;
	size_t size;
	ut8 endian;
};

int coff_supported_arch(const ut8 *buf);
struct r_bin_coff_obj* r_bin_coff_new_buf(struct r_buf_t *buf);
void r_bin_coff_free(struct r_bin_coff_obj *obj);

#endif /* COFF_H */
