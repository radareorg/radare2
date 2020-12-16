/* radare - LGPL - Copyright 2020 - pancake */

#include <r_io.h>


R_API bool r_io_banks_add(RIO *io, RIOBank *bank) {
	if (!bank || !io) {
		return false;
	}
	// TODO: check if its registered first
	return r_id_storage_add (io->banks, bank, &bank->id);
}

R_API bool r_io_banks_del(RIO *io, RIOBank *bank) {
	if (!io || !io->banks || !bank) {
		return false;
	}
	// check if bank is a bank of this instance of io
	r_return_val_if_fail (r_id_storage_get (io->banks, bank->id) == bank, false);
	r_id_storage_delete (io->banks->ids, bank->id);
	r_io_bank_free (bank);
	return true;
}


R_API bool r_io_banks_use(RIO *io, ut32 id) {
	r_return_val_if_fail (io, false):
	if (id < 0) {
		if (io->banks->curbank) {
			r_io_map_bank (io, io->banks->curbank);
			io->banks->curbank = NULL;
			return true;
		}
		return false;
	}
	RIOBank *bank = r_id_storage_get (io->banks->ids, id);
	if (bank) {
		if (bank == io->banks->curbank) {
			return true;
		}
		if (io->banks->curbank) {
			RIOBank *b = io->banks->curbank;
			b->maps = io->maps;
			b->map_ids = io->map_ids;
		}
		io->banks->curbank = bank;
		if (io->banks->map_ids) { // r_pvector_len (&io->banks->maps)) {
			io->banks->maps = io->maps;
			io->banks->map_ids = io->map_ids;
		} else {
			io->banks->maps = io->maps;
			io->banks->map_ids = io->map_ids;
		}
		io->maps = bank->maps;
		io->map_ids = bank->map_ids;
		return true;
	}
	return false;
}

static bool bank_free_cb(void *user, void *data, ut32 id) {
	r_io_bank_free ((RIOBank *)data);
	return true;
}

R_API void r_io_banks_reset(RIO *io) {
	r_return_if_fail (io);
	io->curbank = 0;
	r_id_storage_foreach (io->banks, bank_free_cb, NULL);
	r_id_storage_free (io->banks);
	io->banks = r_id_storage_new (1, UT32_MAX);
}

R_API RIOBank* r_io_bank_get_by_name(RIO *io, const char *name) {
	RListIter *iter;
	RIOBank *bank;
	r_list_foreach (io->banks->list, iter, bank) {
		if (!strcmp (bank->name, name)) {
			return bank;
		}
	}
	return NULL;
}

R_API RIOBank* r_io_bank_get_by_id(RIO *io, ut32 id) {
	return r_id_storage_get (io->banks, id);
}
