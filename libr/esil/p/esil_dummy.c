/* radare2 - LGPL - Copyright 2021-2023 - pancake */

#define R_LOG_ORIGIN "esil.dummy"

#include <r_lib.h>
#include <r_anal.h>

static bool esil_dummy_operation(REsil *esil) {
	R_LOG_INFO ("Dummy: Operation executed");
	return true;
}

static bool esil_dummy_interrupt_handler(REsil *esil, ut32 intr, void *user) {
	R_LOG_INFO ("Dummy: Interrupt %d fired", intr);
	return true;
}

static bool esil_dummy_syscall_handler(REsil *esil, ut32 sysc, void *user) {
	R_LOG_INFO ("Dummy: Syscall %d called", sysc);
	return true;
}

static void *r_esil_dummy_init(REsil *esil) {
	r_esil_set_op (esil, "dummy_op", esil_dummy_operation,
		0, 0, R_ESIL_OP_TYPE_CUSTOM);
	r_esil_set_interrupt (esil, 1337,
		esil_dummy_interrupt_handler, NULL);
	r_esil_set_syscall (esil, 1337,
		esil_dummy_syscall_handler, NULL);
	R_LOG_INFO ("esil.dummy: Activated");
	return NULL;
}

static void r_esil_dummy_fini(REsil *esil, void *user) {
	REsilOp *op = r_esil_get_op (esil, "dummy_op");
	if (op && op->code == esil_dummy_operation) {
		r_esil_del_op (esil, "dummy_op");
	}
	if (r_esil_get_interrupt (esil, 1337) == esil_dummy_interrupt_handler) {
		r_esil_del_interrupt (esil, 1337);
	}
	if (r_esil_get_syscall (esil, 1337) == esil_dummy_syscall_handler) {
		r_esil_del_syscall (esil, 1337);
	}
	R_LOG_INFO ("esil.dummy: Deactivated");
}

REsilPlugin r_esil_plugin_dummy = {
	.meta = {
		.name = "dummy",
		.desc = "dummy esil plugin",
		.author = "pancake",
		.license = "LGPL3",
	},
	.init = r_esil_dummy_init,
	.fini = r_esil_dummy_fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ESIL,
	.data = &r_esil_plugin_dummy,
	.version = R2_VERSION
};
#endif
