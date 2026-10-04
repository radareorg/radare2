/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

#ifndef R_CORE_PANELS_FREE_H
#define R_CORE_PANELS_FREE_H

#include <r_core.h>

#define PANEL_NUM_LIMIT 16

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
	if (item->p) {
		if (item->p->model) {
			free (item->p->model->cmd);
			free (item->p->model->title);
			free (item->p->model->bgcolor);
			free (item->p->model->cmdStrCache);
			free (item->p->model->readOnly);
			free (item->p->model->funcName);
			if (item->p->model->filter) {
				for (i = 0; i < item->p->model->n_filter; i++) {
					free (item->p->model->filter[i]);
				}
				free (item->p->model->filter);
			}
			free (item->p->model);
		}
		free (item->p->view);
		free (item->p);
	}
	free (item);
}

static inline void r_panels_free_root_menu(RPanelsMenu *menu) {
	if (!menu) {
		return;
	}
	// items are freed here; mht must already be freed or cleared before this
	if (menu->root) {
		r_panels_free_menu_item (menu->root);
	}
	r_panels_free_menu_item (menu->frame);
	free (menu->history);
	free (menu->refreshPanels);
	free (menu);
}

static inline void r_panels_free_panel(RPanel *panel) {
	if (!panel) {
		return;
	}
	if (panel->model) {
		free (panel->model->cmd);
		free (panel->model->title);
		free (panel->model->bgcolor);
		free (panel->model->cmdStrCache);
		free (panel->model->readOnly);
		free (panel->model->funcName);
		if (panel->model->filter) {
			int i;
			for (i = 0; i < panel->model->n_filter; i++) {
				free (panel->model->filter[i]);
			}
			free (panel->model->filter);
		}
		free (panel->model);
	}
	free (panel->view);
	free (panel);
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
