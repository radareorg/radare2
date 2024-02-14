/* radare - LGPL - Copyright 2014 Fedor Sakharov <fedor.sakharov@gmail.com> */

#ifndef COFF_H
#define COFF_H

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "coff_specs.h"

typedef struct r_bin_coff_obj {
	struct coff_hdr	hdr;

	struct coff_opt_hdr opt_hdr;
	struct coff_scn_hdr *scn_hdrs;
	struct coff_symbol *symbols;

	/* XCOFF specific */
	struct xcoff32_opt_hdr x_opt_hdr;
	struct xcoff32_ldhdr x_ldhdr;
	struct xcoff32_ldsym *x_ldsyms;

	/* BIGOBJ specific */
	struct coff_bigobj_hdr bigobj_hdr;
	struct coff_bigobj_symbol *bigobj_symbols;

	ut16 target_id; /* TI COFF specific */

	RBuffer *b;
	size_t size;
	coff_type type;
	ut8 endian;
	Sdb *kv;
	bool verbose;
	HtUP *sym_ht;
	HtUP *imp_ht;
	ut64 *scn_va;
} RBinCoffObj;

R_IPI bool r_coff_supported_arch(const ut8 *buf); /* Reads two bytes from buf. */
R_IPI RBinCoffObj *r_bin_coff_new_buf(RBuffer *buf, bool verbose);
R_IPI void r_bin_coff_free(RBinCoffObj *obj);
R_IPI RBinAddr *r_coff_get_entry(RBinCoffObj *obj);
R_IPI char *r_coff_symbol_name(RBinCoffObj *obj, void *ptr);

#endif /* COFF_H */
