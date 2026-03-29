/* radare - LGPL - Copyright 2026 - pancake */

#include <r_util.h>
#include <r_lib.h>

R_API RLibStore *r_libstore_new(void *user, RList *plugins, RLibStoreLoadCallback load) {
	RLibStore *store = R_NEW0 (RLibStore);
	store->user = user;
	store->plugins = plugins;
	store->load = load;
	return store;
}

R_API void r_libstore_free(RLibStore *store) {
	if (store) {
		r_list_free (store->plugins);
		r_list_free (store->xtrs);
		r_list_free (store->ldrs);
	}
	free (store);
}

R_API bool r_libstore_load(RLibStore *store) {
	R_RETURN_VAL_IF_FAIL (store && store->load, false);
	if (store->loaded) {
		return true;
	}
	if (!store->load (store->user)) {
		return false;
	}
	store->loaded = true;
	return true;
}

R_API bool r_libstore_loaded(RLibStore *store) {
	return store? store->loaded: false;
}
