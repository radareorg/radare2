/* radare - LGPL - Copyright 2024 - pancake */

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
