/* radare2 - LGPL - Copyright 2024 - pancake */

#define R_LOG_ORIGIN "esil.forth"

#include <r_lib.h>
#include <r_anal.h>

#if 0
static bool esil_forth_interrupt_handler(REsil *esil, ut32 intr, void *user) {
	R_LOG_INFO ("Dummy: Interrupt %d fired", intr);
	return true;
}

static bool esil_forth_syscall_handler(REsil *esil, ut32 sysc, void *user) {
	R_LOG_INFO ("Dummy: Syscall %d called", sysc);
	return true;
}
#endif

static bool esil_over(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	char *a = r_esil_pop (esil);
	char *b = r_esil_pop (esil);
	r_esil_push (esil, b);
	r_esil_push (esil, a);
	r_esil_push (esil, b);
	return true;
}

static void *r_esil_forth_init(REsil *esil) {
	r_esil_set_op (esil, "OVER", esil_over,
		2, 3, R_ESIL_OP_TYPE_CUSTOM);
#if 0
	r_esil_set_interrupt (esil, 1337,
		esil_forth_interrupt_handler, NULL);
	r_esil_set_syscall (esil, 1337,
		esil_forth_syscall_handler, NULL);
#endif
	R_LOG_INFO ("esil.forth: Activated");
	return NULL;
}

static void r_esil_forth_fini(REsil *esil, void *user) {
	REsilOp *op = r_esil_get_op (esil, "OVER");
	if (op && op->code == esil_over) {
		r_esil_del_op (esil, "OVER");
	}
#if 0
	if (r_esil_get_interrupt (esil, 1337) == esil_forth_interrupt_handler) {
		r_esil_del_interrupt (esil, 1337);
	}
	if (r_esil_get_syscall (esil, 1337) == esil_forth_syscall_handler) {
		r_esil_del_syscall (esil, 1337);
	}
#endif
	R_LOG_INFO ("esil.forth: Deactivated");
}

REsilPlugin r_esil_plugin_forth = {
	.meta = {
		.name = "forth",
		.desc = "forth for esil",
		.author = "pancake",
		.license = "MIT",
	},
	.init = r_esil_forth_init,
	.fini = r_esil_forth_fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ESIL,
	.data = &r_esil_plugin_forth,
	.version = R2_VERSION
};
#endif
