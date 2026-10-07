/* radare - LGPL - Copyright 2024-2025 - pancake */

#include <r_core.h>

static bool print_plugin_details(RCore *core, const RPluginMeta *meta, PJ *pj, int mode) {
	if (mode == 'q') {
		r_cons_printf (core->cons, "%s\n", meta->name);
	} else if (mode) {
		pj_o (pj);
		pj_ks (pj, "name", meta->name);
		pj_ks (pj, "description", meta->desc);
		pj_ks (pj, "license", r_str_get_fail (meta->license, "???"));
		pj_end (pj);
	} else {
		r_cons_printf (core->cons, "Name: %s\n", meta->name);
		r_cons_printf (core->cons, "Description: %s\n", meta->desc);
		if (meta->license) {
			r_cons_printf (core->cons, "License: %s\n", meta->license);
		}
		if (meta->version) {
			r_cons_printf (core->cons, "Version: %s\n", meta->version);
		}
		if (meta->author) {
			r_cons_printf (core->cons, "Author: %s\n", meta->author);
		}
	}
	return true;
}

R_API bool r_core_list_bin_plugin(RCore *core, const char *name, PJ *pj, int json) {
	R_RETURN_VAL_IF_FAIL (core && core->bin && name, false);
	RBin *bin = core->bin;
	RList *plugins = bin->libstore->plugins;
	RList *xtrs = bin->libstore->xtrs;
	RListIter *it;
	RBinXtrPlugin *bx;
	RBinDemanglePlugin *dem;
	RBinPlugin *prefix_bp = NULL;
	RBinXtrPlugin *prefix_bx = NULL;
	RBinDemanglePlugin *prefix_dem = NULL;

	RBinPlugin *bp = r_libstore_find_name (bin->libstore, name);
	if (bp) {
		return print_plugin_details (core, &bp->meta, pj, json);
	}
	r_list_foreach (plugins, it, bp) {
		if (!prefix_bp && r_str_startswith (bp->meta.name, name)) {
			prefix_bp = bp;
		}
	}
	if (prefix_bp) {
		return print_plugin_details (core, &prefix_bp->meta, pj, json);
	}
	bx = r_libstore_find_name_in (bin->libstore, bin->libstore->xtrs, name);
	if (bx) {
		return print_plugin_details (core, &bx->meta, pj, json);
	}
	r_list_foreach (xtrs, it, bx) {
		if (!prefix_bx && r_str_startswith (bx->meta.name, name)) {
			prefix_bx = bx;
		}
	}
	if (prefix_bx) {
		return print_plugin_details (core, &prefix_bx->meta, pj, json);
	}
	dem = r_bin_demangle_plugin_find (bin, name);
	if (dem) {
		return print_plugin_details (core, &dem->meta, pj, json);
	}
	r_list_foreach (bin->demangle_plugins, it, dem) {
		if (!prefix_dem && r_str_startswith (dem->meta.name, name)) {
			prefix_dem = dem;
		}
	}
	if (prefix_dem) {
		return print_plugin_details (core, &prefix_dem->meta, pj, json);
	}

	R_LOG_ERROR ("Cannot find plugin %s", name);
	return false;
}

R_API void r_core_list_lang(RCore *core, int mode) {
	RLang *lang = core->lang;
	RListIter *iter;
	RLangPlugin *h;
	if (!lang) {
		return;
	}
	PJ *pj = NULL;
	RTable *table = NULL;
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		pj_a (pj);
	} else if (mode == ',') {
		table = r_core_table_new (core, "langs");
		RTableColumnType *typeString = r_table_type ("string");
		r_table_add_column (table, typeString, "name", 0);
		r_table_add_column (table, typeString, "license", 0);
		r_table_add_column (table, typeString, "desc", 0);
	}
	r_list_foreach (lang->libstore->plugins, iter, h) {
		const char *license = h->meta.license
			? h->meta.license : "???";
		if (mode == 'j') {
			pj_o (pj);
			r_lib_meta_pj (pj, &h->meta);
			pj_end (pj);
		} else if (mode == 'q') {
			print_plugin_details (core, &h->meta, NULL, mode);
		} else if (mode == ',') {
			r_table_add_row (table,
				r_str_get (h->meta.name),
				r_str_get (h->meta.license),
				r_str_get (h->meta.desc), 0);
		} else {
			r_cons_printf (core->cons, "%-8s %6s  %s\n",
				h->meta.name, license, h->meta.desc);
		}
	}
	if (pj) {
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_printf (core->cons, "%s\n", s);
		free (s);
	} else if (table) {
		char *s = r_table_tostring (table);
		r_cons_printf (core->cons, "%s", s);
		free (s);
		r_table_free (table);
	}
}

R_API int r_core_list_io(RCore *core, const char *name, int mode) {
	RCons *cons = core->cons;
	RIOPlugin *plugin;
	RListIter *iter;
	char str[4];
	int n = 0;
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		pj_a (pj);
	}

	r_list_foreach (core->io->libstore->plugins, iter, plugin) {
		const char *plugin_name = r_str_get (plugin->meta.name);
		if (name && strcmp (plugin_name, name)) {
			continue;
		}
		str[0] = 'r';
		str[1] = plugin->write ? 'w' : '_';
		str[2] = plugin->isdbg ? 'd' : '_';
		str[3] = 0;
		if (mode == 'j') {
			pj_o (pj);
			pj_ks (pj, "permissions", str);
			r_lib_meta_pj (pj, &plugin->meta);
			if (plugin->uris) {
				char *uri;
				char *uris = strdup (plugin->uris);
				RList *plist = r_str_split_list (uris, ",",  0);
				RListIter *piter;
				pj_k (pj, "uris");
				pj_a (pj);
				r_list_foreach (plist, piter, uri) {
					pj_s (pj, uri);
				}
				pj_end (pj);
				r_list_free (plist);
				free (uris);
			}
			pj_end (pj);
		} else if (name) {
			print_plugin_details (core, &plugin->meta, NULL, 0);
			r_cons_printf (cons, "uris: %s\n", plugin->uris);
			if (*str) {
				r_cons_printf (cons, "perm: %s\n", str);
			}
			r_cons_printf (cons, "sysc: %s\n", r_str_bool (plugin->system));
		} else {
			r_cons_printf (cons, "%s  %-8s %s.", str,
				r_str_get (plugin->meta.name),
				r_str_get (plugin->meta.desc));
			if (plugin->uris) {
				r_cons_printf (cons, " %s", plugin->uris);
			}
			r_cons_printf (cons, "\n");
		}
		n++;
	}
	if (pj) {
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_printf (cons, "%s\n", s);
		free (s);
	}
	return n;
}
