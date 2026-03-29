/* radare - LGPL - Copyright 2026 - pancake */

#include <r_util.h>
#include <r_lib.h>

R_API RLibStore *r_libstore_new(void *user, const void *static_plugins, RListFree freefn, RLibStoreLoadCallback load, RLibPluginAddCb add) {
	RLibStore *store = R_NEW0 (RLibStore);
	store->user = user;
	store->free = freefn;
	store->plugins = r_list_newf (freefn);
	store->add = add;
	store->load = load;
	store->static_plugins = static_plugins;
	return store;
}

R_API void r_libstore_free(RLibStore *store) {
	if (store) {
		if (store->fini && store->plugins) {
			RListIter *iter;
			void *plugin;
			r_list_foreach (store->plugins, iter, plugin) {
				store->fini (store->user, plugin);
			}
		}
		r_list_free (store->plugins);
		r_list_free (store->xtrs);
		r_list_free (store->ldrs);
	}
	free (store);
}

R_API bool r_libstore_load(RLibStore *store) {
	R_RETURN_VAL_IF_FAIL (store, false);
	if (store->loaded) {
		return true;
	}
	if (store->load) {
		if (!store->load (store)) {
			return false;
		}
	} else if (store->static_plugins && store->add) {
		if (!r_lib_add_static (store->user, store->static_plugins, store->add)) {
			return false;
		}
	} else {
		return false;
	}
	store->loaded = true;
	return true;
}

R_API bool r_libstore_loaded(RLibStore *store) {
	return store? store->loaded: false;
}
