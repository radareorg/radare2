/* radare - LGPL - Copyright 2014 Fedor Sakharov <fedor.sakharov@gmail.com> */

#ifndef COFF_H
#define COFF_H

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <ht_up.h>

#define COFF_IS_BIG_ENDIAN 1
#define COFF_IS_LITTLE_ENDIAN 0

#include "coff_specs.h"

typedef struct r_bin_coff_obj {
	struct coff_hdr	hdr;
	struct coff_opt_hdr opt_hdr;
	struct coff_scn_hdr *scn_hdrs;
	struct coff_symbol *symbols;

	ut16 target_id; /* TI COFF specific */

	RBuffer *b;
	size_t size;
	ut8 endian;
	Sdb *kv;
	bool verbose;
	HtUP *sym_ht;
	HtUP *imp_ht;
	ut64 *scn_va;
} RBinCoffObj;

R_IPI bool r_coff_supported_arch(const ut8 *buf); /* Reads two bytes from buf. */
R_IPI RBinCoffObj* r_bin_coff_new_buf(RBuffer *buf, bool verbose);
R_IPI void r_bin_coff_free(RBinCoffObj *obj);
R_IPI RBinAddr *r_coff_get_entry(RBinCoffObj *obj);
R_IPI char *r_coff_symbol_name(RBinCoffObj *obj, void *ptr);

#endif /* COFF_H */
