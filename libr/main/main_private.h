/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R_MAIN_PRIVATE_H
#define R_MAIN_PRIVATE_H

#include <r_core.h>

R_IPI RCons *r_main_cons_new(RCons *parent);
R_IPI void r_main_cons_free(RCons *parent, RCons *cons);
R_IPI void r_main_cons_flush(RCons *parent, RCons *cons);
R_IPI RCons *r_main_cons_open(RCons *parent, int fd);
R_IPI bool r_main_cons_close(RCons *cons);
R_IPI st64 r_main_write(RCons *cons, const void *buf, size_t len);
R_IPI RPrint *r_main_print_new(RCons *cons);
R_IPI bool r_main_core_init(RCons *parent, RCore *core);
R_IPI RCore *r_main_core_new(RCons *parent);
R_IPI void r_main_core_fini(RCons *parent, RCore *core);
R_IPI void r_main_core_free(RCons *parent, RCore *core);

#endif
