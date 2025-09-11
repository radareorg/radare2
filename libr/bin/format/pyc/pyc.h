/* radare - LGPL3 - Copyright 2016-2020 - c0riolis, x0urc3 */

#ifndef PYC_H
#define PYC_H

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "pyc_magic.h"
#include "marshal.h"

bool pyc_get_sections_symbols(RList *sections, RList *symbols, RList *mem, RBuffer *buf, ut32 magic, RList *interned_table);
ut64 pyc_get_code_object_addr(RBuffer *buf, ut32 magic);
bool pyc_is_code(ut8 b, ut32 magic);

#endif
