/* radare - LGPL - Copyright 2014-2026 - pancake */

#include <r_core.h>

static RCore *core = NULL;

#if R2__UNIX__
#include "libr2_unx.inc.c"
#elif R2__WINDOWS__
#include "libr2_win.inc.c"
#endif
