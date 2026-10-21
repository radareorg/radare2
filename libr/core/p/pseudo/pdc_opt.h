/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R2_PDC_OPT_H
#define R2_PDC_OPT_H

#include <r_core.h>

const char *pdc_skip_quoted(const char *s);
char *pdc_optimize(RCore *core, char *code);

#endif
