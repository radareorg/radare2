/* radare - LGPL - Copyright 2024-2025 - pancake */

#include <r_core.h>

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
		pj = pj_new ();
		pj_a (pj);
	} else if (mode == ',') {
		table = r_core_table_new (core, "langs");
		RTableColumnType *typeString = r_table_type ("string");
		r_table_add_column (table, typeString, "name", 0);
		r_table_add_column (table, typeString, "desc", 0);
		// r_table_add_column (table, typeString, "license", 0);
	}
	r_list_foreach (lang->langs, iter, h) {
		const char *license = h->meta.license
			? h->meta.license : "???";
		if (mode == 'j') {
			pj_o (pj);
			r_lib_meta_pj (pj, &h->meta);
			pj_end (pj);
		} else if (mode == 'q') {
			lang->cb_printf ("%s\n", h->meta.name);
		} else if (mode == ',') {
			r_table_add_row (table,
				r_str_get (h->meta.name),
				r_str_get (h->meta.license),
				r_str_get (h->meta.desc), 0);
		} else {
			lang->cb_printf ("%-8s %6s  %s\n",
				h->meta.name, license, h->meta.desc);
		}
	}
	if (pj) {
		pj_end (pj);
		char *s = pj_drain (pj);
		lang->cb_printf ("%s\n", s);
		free (s);
	} else if (table) {
		char *s = r_table_tostring (table);
		lang->cb_printf ("%s", s);
		free (s);
		r_table_free (table);
	}
}

R_API int r_core_list_io(RCore *core, const char *name, int mode) {
	RCons *cons = core->cons;
	RIOPlugin *plugin;
	SdbListIter *iter;
	char str[4];
	int n = 0;
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		pj_a (pj);
	}

	ls_foreach (core->io->plugins, iter, plugin) {
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
			r_kons_printf (cons, "name: %s\n", plugin->meta.name);
			r_kons_printf (cons, "auth: %s\n", plugin->meta.author);
			r_kons_printf (cons, "lice: %s\n", plugin->meta.license);
			r_kons_printf (cons, "desc: %s\n", plugin->meta.desc);
			r_kons_printf (cons, "uris: %s\n", plugin->uris);
			if (*str) {
				r_kons_printf (cons, "perm: %s\n", str);
			}
			r_kons_printf (cons, "sysc: %s\n", r_str_bool (plugin->system));
		} else {
			r_kons_printf (cons, "%s  %-8s %s.", str,
				r_str_get (plugin->meta.name),
				r_str_get (plugin->meta.desc));
			if (plugin->uris) {
				r_kons_printf (cons, " %s", plugin->uris);
			}
			r_kons_printf (cons, "\n");
		}
		n++;
	}
	if (pj) {
		pj_end (pj);
		char *s = pj_drain (pj);
		r_kons_printf (cons, "%s\n", s);
		free (s);
	}
	return n;
}
