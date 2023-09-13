/* radare2 - LGPL - Copyright 2021-2023 - pancake */

#define R_LOG_ORIGIN "esil.banksy"

#include <r_lib.h>
#include <r_core.h>
#include <r_anal.h>

char *obank = NULL;

static bool esil_banksy_operation(REsil *esil) {
	RCore *core = (RCore *)esil->user;
	int obank = core->io->bank;
	char *src = r_esil_pop (esil);
	if (src) {
		RIOBank *b = r_io_bank_use_byname (core->io, src);
		if (!b) {
			R_LOG_WARN ("iobank mode on");
		}
	}
	R_LOG_INFO ("BANK: Switch to bank %s from %s", src);
	return true;
}

static void *r_esil_banksy_init(REsil *esil) {
	r_esil_set_op (esil, "BANK", esil_banksy_operation,
		0, 0, R_ESIL_OP_TYPE_CUSTOM);
	R_LOG_INFO ("esil.banksy: Activated");
	return NULL;
}

static void r_esil_banksy_fini(REsil *esil, void *user) {
	REsilOp *op = r_esil_get_op (esil, "BANK");
	if (op && op->code == esil_banksy_operation) {
		r_esil_del_op (esil, "BANK");
	}
	R_LOG_INFO ("esil.banksy: Deactivated");
}

REsilPlugin r_esil_plugin_banksy = {
	.meta = {
		.name = "banky",
		.desc = "switch banks",
		.license = "LGPL3",
	},
	.init = r_esil_banksy_init,
	.fini = r_esil_banksy_fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ESIL,
	.data = &r_esil_plugin_banksy,
	.version = R2_VERSION
};
#endif
