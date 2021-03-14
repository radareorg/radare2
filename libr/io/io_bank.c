/* radare2 - LGPL - Copyright 2021 - condret */

#include <r_io.h>
#include <r_util.h>

R_API RIOBank *r_io_bank_new(void) {
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

R_API void r_io_bank_free(RIOBank *bank) {
	if (!bank) {
		return;
	}
	r_queue_free (bank->todo);
	r_list_free (bank->maprefs);
	r_rbtree_cont_free (bank->submaps);
	free (bank);
}

static bool _bank_free_cb(void *user, void *data, ut32 id) {
	r_io_bank_free ((RIOBank *)data);
	return true;
}

R_API void r_io_bank_init(RIO *io) {
	r_return_if_fail (io);
	r_io_bank_fini (io);
	io->banks = r_id_storage_new (0, UT32_MAX);
}

R_API void r_io_bank_fini(RIO *io) {
	r_return_if_fail (io);
	if (io->banks) {
		r_id_storage_foreach (io->banks, _bank_free_cb, NULL);
		r_id_storage_free (io->banks);
		io->banks = NULL;
	}
}
