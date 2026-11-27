#ifndef R2_CORE_REFSEARCH_H
#define R2_CORE_REFSEARCH_H

#include "../anal/refsearch.h"

R_IPI void r_core_ref_search(RCore *core, RefSearch *search, ut64 from, ut64 to, int mode);
R_IPI void r_core_esil_ref_search(RCore *core, RefSearch *search, ut64 from, ut64 to, bool strings);
R_IPI int r_core_anal_search_calls(RCore *core, ut64 from, ut64 to, RVecRefSearchAddr *targets);

#endif
