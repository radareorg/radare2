/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R_MAIN_PRIVATE_H
#define R_MAIN_PRIVATE_H

#include <r_core.h>

R_IPI RCons *r_main_cons(void);
R_IPI RCons *r_main_cons_new(void);
R_IPI void r_main_cons_free(RCons *cons);
R_IPI void r_main_cons_flush(RCons *cons);
R_IPI int r_main_printf(RCons *cons, const char *format, ...) R_PRINTF_CHECK(2, 3);
R_IPI int r_main_gprintf(const char *format, ...) R_PRINTF_CHECK(1, 2);
R_IPI st64 r_main_write(RCons *cons, const void *buf, size_t len);
R_IPI RPrint *r_main_print_new(void);
R_IPI bool r_main_core_init(RCore *core);
R_IPI RCore *r_main_core_new(void);
R_IPI void r_main_core_fini(RCore *core);
R_IPI void r_main_core_free(RCore *core);

#endif
