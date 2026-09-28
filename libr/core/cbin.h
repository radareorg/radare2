/* radare2 - LGPL - Copyright 2026 - pancake */

#ifndef R2_CORE_CBIN_H
#define R2_CORE_CBIN_H

#include <r_core.h>

// internal API of cbin.c shared with other compilation units of libr_core
R_IPI bool bin_strings(RCore *core, PJ *pj, int mode, int va, ut64 skip, ut64 count, int type_filter);
R_IPI bool bin_raw_strings(RCore *core, PJ *pj, int mode, int va, ut64 skip, ut64 count, int type_filter);
R_IPI void bin_trycatch_flag(RCore *core, const RBinTrycatch *tc, size_t index, bool set);
R_IPI int bin_trycatch_json(PJ *pj, const RVecRBinTrycatch *tcs, ut64 source);

#endif