/* radare - LGPL3 - Copyright 2016-2025 - c0riolis, x0urc3 */

#ifndef PYC_H
#define PYC_H

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "pyc_magic.h"
#include "marshal.h"

// RBinPycObj holds all per-file state for the pyc bin plugin.
// This struct is stored in bf->bo->bin_obj and accessed by the arch plugin.
typedef struct {
	ut64 code_start_offset;
	struct pyc_version version;
	RList *sections_cache;     // RList<RBinSection*>
	RList *interned_table;     // RList<char*>
	RList *cobjs;              // RList<pyc_code_object*>
} RBinPycObj;

bool pyc_get_sections_symbols(RList *sections, RList *symbols, RList *mem, RBuffer *buf, ut32 magic, RList *interned_table);
bool pyc_is_code(ut8 b, ut32 magic);

#endif
