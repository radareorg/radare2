/* radare - LGPL - Copyright 2026 - pancake */

#include <r_util.h>
#include <r_lib.h>

typedef struct {
	RPluginMeta meta;
} RLibStoreNamedPlugin;

static int plugin_cmp_name(const void *a, const void *b) {
	const RLibStoreNamedPlugin *plugin = a;
	const char *name = b;
	return (plugin && plugin->meta.name && name)? strcmp (plugin->meta.name, name): 1;
}

R_API RLibStore *r_libstore_new(RLibStore **dest, void *user, const void *static_plugins, RListFree freefn, RLibStoreLoadCallback load, RLibPluginAddCb add, RLibPluginAddCb remove) {
	RLibStore *store = R_NEW0 (RLibStore);
	store->user = user;
	store->free = freefn;
	store->plugins = r_list_newf (freefn);
	store->add = add;
	store->remove = remove;
	store->load = load;
	store->static_plugins = static_plugins;
	if (dest) {
		*dest = store;
	}
	if (r_lib_defaults ()) {
		r_libstore_load (store);
	}
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

R_API void *r_libstore_find_name_in(const RLibStore *store, RList *list, const char *name) {
	R_RETURN_VAL_IF_FAIL (name, NULL);
	return r_libstore_find_in (store, list, name, plugin_cmp_name);
}

R_API void *r_libstore_find_name(const RLibStore *store, const char *name) {
	R_RETURN_VAL_IF_FAIL (name, NULL);
	return r_libstore_find (store, name, plugin_cmp_name);
}

R_API void *r_libstore_find_in(const RLibStore *store, RList *list, const void *needle, RListComparator cmp) {
	R_RETURN_VAL_IF_FAIL (store && cmp, NULL);
	RListIter *iter;
	void *plugin;
	r_list_foreach (list, iter, plugin) {
		if (!cmp (plugin, needle)) {
			return plugin;
		}
	}
	return NULL;
}

R_API void *r_libstore_find(const RLibStore *store, const void *needle, RListComparator cmp) {
	R_RETURN_VAL_IF_FAIL (store && cmp, NULL);
	return r_libstore_find_in (store, store->plugins, needle, cmp);
}

R_API bool r_libstore_add(RLibStore *store, void *plugin) {
	R_RETURN_VAL_IF_FAIL (store && plugin, false);
	if (store->add) {
		return store->add (store->user, plugin);
	}
	const RLibStoreNamedPlugin *np = plugin;
	if (!np->meta.name) {
		return false;
	}
	if (r_libstore_find_name (store, np->meta.name)) {
		return false;
	}
	return r_list_append (store->plugins, plugin) != NULL;
}

R_API bool r_libstore_remove(RLibStore *store, void *plugin) {
	R_RETURN_VAL_IF_FAIL (store && plugin, false);
	if (store->remove) {
		return store->remove (store->user, plugin);
	}
	return r_list_delete_data (store->plugins, plugin);
}

static bool libstore_add_static(RLibStore *store) {
	const void *const *plugins = store->static_plugins;
	R_RETURN_VAL_IF_FAIL (plugins, false);
	size_t i;
	for (i = 0; plugins[i]; i++) {
		r_libstore_add (store, (void *)plugins[i]);
	}
	return true;
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
	} else if (store->static_plugins) {
		if (!libstore_add_static (store)) {
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
