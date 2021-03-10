/* radare2 - LGPL - Copyright 2021 - condret */

#include <r_io.h>
#include <r_util.h>

R_API RIOBank *r_io_bank_new() {
	RIOBank *bank = R_NEW0 (RIOBank);
	if (!bank) {
		return NULL;
	}
	bank->submaps = r_rbtree_cont_newf (free);
	if (!bank->submaps) {
		free (bank);
		return NULL;
	}
	bank->maprefs = r_list_newf (free);
	if (!bank->maprefs) {
		r_rbtree_cont_free (bank->submaps);
		free (bank);
		return NULL;
	}
	bank->todo = r_queue_new (8);
	if (!bank->todo) {
		r_list_free (bank->maprefs);
		r_rbtree_cont_free (bank->submaps);
		free (bank);
		return NULL;
	}
	return bank;
}
