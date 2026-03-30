/* radare2 - LGPL - Copyright 2021-2023 - condret */

#include <r_anal.h>
#include "../config.h"

// R2R db/cmd/cmd_aes

static REsilPlugin *esil_static_plugins[] = {
	R_ESIL_STATIC_PLUGINS
};

R_IPI bool r_esil_plugins_init(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, false);
	esil->active_plugins = r_list_new ();
	if (R_UNLIKELY (!esil->active_plugins)) {
		return false;
	}
	r_libstore_new (&esil->libstore, esil, esil_static_plugins, NULL, NULL, NULL, (RLibPluginAddCb)r_esil_plugin_remove);
	return true;
}

R_IPI void r_esil_plugins_fini(REsil *esil) {
	R_RETURN_IF_FAIL (esil);
	if (!esil->libstore->plugins || !esil->active_plugins) {
		r_libstore_free (esil->libstore);
		esil->libstore = NULL;
		return;
	}
	while (r_list_length (esil->active_plugins)) {
		REsilActivePlugin *eap = (REsilActivePlugin *)r_list_pop (esil->active_plugins);
		eap->plugin->fini (esil, eap->user);
		free (eap);
	}
	r_list_free (esil->active_plugins);
	esil->active_plugins = NULL;
	r_libstore_free (esil->libstore);
	esil->libstore = NULL;
}


R_API void r_esil_plugin_del(REsil *esil, const char *name) {
	R_RETURN_IF_FAIL (esil && esil->libstore->plugins && name);
	r_esil_plugin_deactivate (esil, name);
	REsilPlugin *ep = r_libstore_find_name (esil->libstore, name);
	if (ep) {
		r_list_delete_data (esil->libstore->plugins, ep);
	}
}

//this crap solely exists for trash generics in core
R_API bool r_esil_plugin_remove(REsil *esil, REsilPlugin *plugin) {
	R_RETURN_VAL_IF_FAIL (esil && esil->libstore->plugins && plugin && plugin->meta.name, false);
	if (r_libstore_find_name (esil->libstore, plugin->meta.name)) {
		r_esil_plugin_del (esil, plugin->meta.name);
		return true;
	}
	return false;
}

static REsilActivePlugin *_get_active_plugin(REsil *esil, const char *name) {
	RListIter *iter;
	REsilActivePlugin *eap;
	r_list_foreach (esil->active_plugins, iter, eap) {
		if (!strcmp (eap->plugin->meta.name, name)) {
			return eap;
		}
	}
	return NULL;
}

R_API bool r_esil_plugin_activate(REsil *esil, const char *name) {
	R_RETURN_VAL_IF_FAIL (esil && esil->libstore->plugins &&
				esil->active_plugins && name, false);
	// check if plugin is already activated
	if (_get_active_plugin (esil, name)) {
		return false;
	}
	REsilPlugin *ep = r_libstore_find_name (esil->libstore, name);
	if (ep) {
		REsilActivePlugin *eap = R_NEW (REsilActivePlugin);
		if (!eap) {
			return false;
		}
		eap->plugin = ep;
		eap->user = ep->init (esil);
		r_list_append (esil->active_plugins, eap);
		return true;
	}
	return false;
}

R_API void r_esil_plugin_deactivate(REsil *esil, const char *name) {
	R_RETURN_IF_FAIL (esil && esil->active_plugins && name);
	RListIter *iter;
	REsilActivePlugin *eap;
	r_list_foreach (esil->active_plugins, iter, eap) {
		if (!strcmp (eap->plugin->meta.name, name)) {
			eap->plugin->fini (esil, eap->user);
			r_list_delete (esil->active_plugins, iter);
			free (eap);
			break;
		}
	}
}
