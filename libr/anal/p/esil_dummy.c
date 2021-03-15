/* radare2 - LGPL - Copyright 2021 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_anal.h>

static bool esil_dummy_operation(RAnalEsil *esil) {
	eprintf ("Dummy: Operation executed\n");
	return true;
}

static bool esil_dummy_interrupt_handler(RAnalEsil *esil, ut32 intr, void *user) {
	eprintf ("Dummy: Interrupt %d fired\n", intr);
	return true;
}

static bool esil_dummy_syscall_handler(RAnalEsil *esil, ut32 sysc, void *user) {
	eprintf ("Dummy: Syscall %d called\n", sysc);
	return true;
}

static void *r_esil_dummy_init(RAnalEsil *esil) {
	r_anal_esil_set_op (esil, "dummy_op", esil_dummy_operation,
		0, 0, R_ANAL_ESIL_OP_TYPE_CUSTOM);
	r_anal_esil_set_interrupt (esil, 1337,
		esil_dummy_interrupt_handler, NULL);
	r_anal_esil_set_syscall (esil, 1337,
		esil_dummy_syscall_handler, NULL);
	eprintf ("Dummy: Activated\n");
	return NULL;
}

static void r_esil_dummy_fini(RAnalEsil *esil, void *user) {
	RAnalEsilOp *op = r_anal_esil_get_op (esil, "dummy_op");
	if (op && op->code == esil_dummy_operation) {
		r_anal_esil_del_op (esil, "dummy_op");
	}
	if (r_anal_esil_get_interrupt (esil, 1337) == esil_dummy_interrupt_handler) {
		r_anal_esil_del_interrupt (esil, 1337);
	}
	if (r_anal_esil_get_syscall (esil, 1337) == esil_dummy_syscall_handler) {
		r_anal_esil_del_syscall (esil, 1337);
	}
	eprintf ("Dummy: Deactivated\n");
}

RAnalEsilPlugin r_esil_plugin_dummy = {
	.name = "dummy",
	.desc = "dummy esil plugin",
	.license = "LGPL3",
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
