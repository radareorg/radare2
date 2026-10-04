/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

#ifndef R_CORE_PANELS_FREE_H
#define R_CORE_PANELS_FREE_H

#include <r_core.h>

#define PANEL_NUM_LIMIT 16

static inline void r_panels_free_panel(RPanel *panel) {
	if (!panel) {
		return;
	}
	RPanelModel *model = panel->model;
	if (model) {
		free (model->cmd);
		free (model->title);
		free (model->bgcolor);
		free (model->cmdStrCache);
		free (model->readOnly);
		free (model->funcName);
		if (model->filter) {
			int i;
			for (i = 0; i < model->n_filter; i++) {
				free (model->filter[i]);
			}
			free (model->filter);
		}
		free (model);
	}
	free (panel->view);
	free (panel);
}

static inline void r_panels_free_menu_item(RPanelsMenuItem *item) {
	if (!item) {
		return;
	}
	size_t i;
	free (item->name);
	free (item->desc);
	free (item->args);
	for (i = 0; i < item->n_sub; i++) {
		r_panels_free_menu_item (item->sub[i]);
	}
	free (item->sub);
	r_panels_free_panel (item->p);
	free (item);
}

static inline void r_panels_free_root_menu(RPanelsMenu *menu) {
	if (!menu) {
		return;
	}
	// items are freed here; mht must already be freed or cleared before this
	r_panels_free_menu_item (menu->root);
	r_panels_free_menu_item (menu->frame);
	free (menu->history);
	free (menu->refreshPanels);
	free (menu);
}

static inline void r_panels_free_partial(RPanels *panels) {
	if (!panels) {
		return;
	}
	if (panels->mht) {
		// free hashtable first: it only owns keys, values are borrowed from the menu tree
		ht_pp_free (panels->mht);
		panels->mht = NULL;
	}
	// then free the menu tree which owns all RPanelsMenuItem objects
	r_panels_free_root_menu (panels->panels_menu);
	if (panels->panel) {
		int i;
		for (i = 0; i < PANEL_NUM_LIMIT; i++) {
			r_panels_free_panel (panels->panel[i]);
		}
		free (panels->panel);
	}
	r_cons_canvas_free (panels->can);
	r_list_free (panels->snows);
	free (panels->name);
	free (panels);
}

#endif
