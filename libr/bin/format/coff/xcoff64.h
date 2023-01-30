/* radare - LGPL - Copyright 2023 terorie */

#ifndef XCOFF_H
#define XCOFF_H

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "coff_specs.h"

typedef struct r_bin_xcoff64_obj {
	/* File headers */
	struct xcoff64_hdr hdr;
	struct xcoff64_opt_hdr opt_hdr;
	struct xcoff64_scn_hdr *scn_hdrs;

	/* Symbol table contains a mix of symbols and auxiliary entries.
	 * The actual type only becomes apparent when walking the table. */
	union xcoff64_syment *symbols;

	/* File offset of symbol name table */
	ut64 nametbl_off;

	RBuffer *b;
	size_t size;
	ut8 endian;
	Sdb *kv;
	bool verbose;
	HtUP *sym_ht;
	HtUP *imp_ht;
	ut64 *scn_va;
} RBinXCoff64Obj;

R_IPI bool r_xcoff64_supported_arch(const ut8 *arch);
R_IPI RBinXCoff64Obj *r_bin_xcoff64_new_buf(RBuffer *buf, bool verbose);
R_IPI void r_bin_xcoff64_free(RBinXCoff64Obj *obj);
R_IPI RBinAddr *r_xcoff64_get_entry(RBinXCoff64Obj *obj);
R_IPI char *r_xcoff64_symbol_name(RBinXCoff64Obj *obj, ut32 offset);

#endif /* XCOFF_H */
