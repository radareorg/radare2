/* radare2 - LGPL - Copyright 2021 - condret */

#include <r_anal.h>
#include <r_list.h>
#include <config.h>
#include "../config.h"

static REsilPlugin *esil_static_plugins[] = {
	R_ESIL_STATIC_PLUGINS
};

R_API void r_esil_plugins_init(REsil *esil) {
	r_return_if_fail (esil);
	esil->plugins = r_list_new ();
	esil->active_plugins = r_list_new ();
	size_t i = 0;
	while (esil_static_plugins[i]) {
		r_esil_plugin_add (esil, esil_static_plugins[i]);
		i++;
	}
}

R_API void r_esil_plugins_fini(REsil *esil) {
	r_return_if_fail (esil);
	if (!esil->plugins || !esil->active_plugins) {
		return;
	}
	while (r_list_length (esil->active_plugins)) {
		REsilActivePlugin *eap = (REsilActivePlugin *)r_list_pop (esil->active_plugins);
		eap->plugin->fini (esil, eap->user);
		free (eap);
	}
	r_list_free (esil->active_plugins);
	r_list_free (esil->plugins);
	esil->active_plugins = NULL;
	esil->plugins = NULL;
}

R_API bool r_esil_plugin_add(REsil *esil, REsilPlugin *plugin) {
	r_return_val_if_fail (esil && esil->plugins && plugin, false);
	r_list_append (esil->plugins, plugin);
	return true;
}

static REsilActivePlugin *_get_active_plugin(REsil *esil, const char *name) {
	RListIter *iter;
	REsilActivePlugin *eap;
	r_list_foreach (esil->active_plugins, iter, eap) {
		if (!strcmp (eap->plugin->name, name)) {
			return eap;
		}
	}
	return NULL;
}

R_API bool r_esil_plugin_activate(REsil *esil, const char *name) {
	r_return_val_if_fail (esil && esil->plugins &&
				esil->active_plugins && name, false);
	// check if plugin is already activated
	if (_get_active_plugin (esil, name)) {
		return false;
	}
	RListIter *iter;
	REsilPlugin *ep;
	r_list_foreach (esil->plugins, iter, ep) {
		if (!strcmp (ep->name, name)) {
			REsilActivePlugin *eap = R_NEW (REsilActivePlugin);
			if (!eap) {
				return false;
			}
			eap->plugin = ep;
			eap->user = ep->init (esil);
			r_list_append (esil->active_plugins, eap);
			return true;
		}
	}
	return false;
}

R_API void r_esil_plugin_deactivate(REsil *esil, const char *name) {
	r_return_if_fail (esil && esil->active_plugins && name);
	RListIter *iter;
	REsilActivePlugin *eap;
	r_list_foreach (esil->active_plugins, iter, eap) {
		if (!strcmp (eap->plugin->name, name)) {
			eap->plugin->fini (esil, eap->user);
			r_list_delete (esil->active_plugins, iter);
			free (eap);
			break;
		}
	}
}
