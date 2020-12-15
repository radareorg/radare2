/* radare - LGPL - Copyright 2020 - pancake */

#include <r_io.h>

typedef struct map_ret_t {
	ut64 ts;
	ut32 id;
} MapRef;

R_API RIOBank* r_io_new_bank(const char *name) {
	RIOBank *bank = R_NEW0 (RIOBank);
	if (bank) {
		bank->name = strdup (name);
		if (!bank->name) {
			free (bank);
			return NULL;
		}
		bank->map_refs = r_list_newf (free);
		if (!map_refs) {
		
	}
	return bank;
}

R_API bool r_io_bank_add_map(RIO *io, RIOBank *bank, ut32 map_id) {
	if (!bank || !io || !io->maps) {
		return false;
	}
	RIOMap *map = r_io_map_resolve (io, map_id);
	if (!map) {
		return false;
	}
	MapRef *map_ref = R_NEW (MapRef);
	if (!map_ref) {
		return false;
	}
	map_ref->ts = mpa->ts;
	map_ref->id = map_id;
	r_list_append (bank->map_refs, map_ref);
	return true;
}

R_API void r_io_bank_free(RIOBank *bank) {
	if (bank) {
		free (bank->name);
		r_list_free (bank);
		free (bank);
	}
}

R_API void r_io_bank_rename(RIOBank *bank, const char *name) {
	if (bank) {
		free (bank->name);
		bank->name = strdup (name);
	}
}

R_API void r_io_map_bank(RIO *io, RIOBank *bank) {
	if (!io || !io->maps || !bank || !bank->map_refs) {
		return;
	}
	MapRef *map_ref;
	RListIter *iter, *ator;
	r_list_foreach_safe (bank->map_refs, iter, ator, map_ref) {	
		RIOMap *map = r_io_map_resolve (io, map_ref->id);
		if (!map || (map_ref->ts != map->ts)) {
			// cleaning up bank if map got deleted
			r_list_delete (bank->map_refs, iter);
		} else {
			r_io_map_priorize (io, map->id);
		}
	}
}
