/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

static void r_panels_update_edge_x(RCore *core, int delta) {
	RPanels *panels = core->panels;
	const int edge = panels->mouse_orig_x;
	int min_delta = INT_MIN;
	int max_delta = INT_MAX;
	bool has_left = false;
	bool has_right = false;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!p) {
			continue;
		}
		RPanelPos *pos = &p->view->pos;
		if (pos->x == edge) {
			has_right = true;
			max_delta = R_MIN (max_delta, pos->w - PANEL_CONFIG_MIN_SIZE);
		}
		if (pos->x + pos->w - 1 == edge) {
			has_left = true;
			min_delta = R_MAX (min_delta, PANEL_CONFIG_MIN_SIZE - pos->w);
		}
	}
	if (!has_left || !has_right) {
		return;
	}
	delta = R_MAX (min_delta, R_MIN (delta, max_delta));
	if (!delta) {
		return;
	}
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!p) {
			continue;
		}
		RPanelPos *pos = &p->view->pos;
		if (pos->x == edge) {
			pos->x += delta;
			pos->w -= delta;
			p->view->refresh = true;
		} else if (pos->x + pos->w - 1 == edge) {
			pos->w += delta;
			p->view->refresh = true;
		}
	}
	panels->mouse_orig_x += delta;
}

static void r_panels_update_edge_y(RCore *core, int delta) {
	RPanels *panels = core->panels;
	const int edge = panels->mouse_orig_y;
	int min_delta = INT_MIN;
	int max_delta = INT_MAX;
	bool has_above = false;
	bool has_below = false;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!p) {
			continue;
		}
		RPanelPos *pos = &p->view->pos;
		if (pos->y == edge) {
			has_below = true;
			max_delta = R_MIN (max_delta, pos->h - PANEL_CONFIG_MIN_SIZE);
		}
		if (pos->y + pos->h - 1 == edge) {
			has_above = true;
			min_delta = R_MAX (min_delta, PANEL_CONFIG_MIN_SIZE - pos->h);
		}
	}
	if (!has_above || !has_below) {
		return;
	}
	delta = R_MAX (min_delta, R_MIN (delta, max_delta));
	if (!delta) {
		return;
	}
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!p) {
			continue;
		}
		RPanelPos *pos = &p->view->pos;
		if (pos->y == edge) {
			pos->y += delta;
			pos->h -= delta;
			p->view->refresh = true;
		} else if (pos->y + pos->h - 1 == edge) {
			pos->h += delta;
			p->view->refresh = true;
		}
	}
	panels->mouse_orig_y += delta;
}

static bool r_panels_check_if_mouse_x_illegal(RCore *core, int x) {
	int w = core->panels->can->w;
	return x <= 1 || w - 1 <= x;
}

static bool r_panels_check_if_mouse_y_illegal(RCore *core, int y) {
	return y <= 0 || core->panels->can->h <= y;
}

static bool r_panels_check_if_mouse_x_on_edge(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	const int e = r_config_get_i (core->config, "scr.panelborder") ? 3 : 1;
	int i, j;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *right = r_panels_get_panel (panels, i);
		if (!right) {
			continue;
		}
		RPanelPos *rpos = &right->view->pos;
		if (y < rpos->y || y >= rpos->y + rpos->h ||
				x <= rpos->x - (e - 1) || x > rpos->x + e) {
			continue;
		}
		for (j = 0; j < panels->n_panels; j++) {
			RPanel *left = r_panels_get_panel (panels, j);
			if (!left) {
				continue;
			}
			RPanelPos *lpos = &left->view->pos;
			if (lpos->x + lpos->w - 1 == rpos->x &&
					y >= lpos->y && y < lpos->y + lpos->h) {
				panels->mouse_on_edge_x = true;
				panels->mouse_orig_x = rpos->x;
				return true;
			}
		}
	}
	return false;
}

static bool r_panels_check_if_mouse_y_on_edge(RCore *core, int x, int y) {
	RPanels *panels = core->panels;
	const int e = r_config_get_i (core->config, "scr.panelborder") ? 3 : 1;
	int i, j;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *below = r_panels_get_panel (panels, i);
		if (!below) {
			continue;
		}
		RPanelPos *bpos = &below->view->pos;
		if (x < bpos->x || x >= bpos->x + bpos->w ||
				y <= bpos->y - (e - 1) || y > bpos->y + e) {
			continue;
		}
		for (j = 0; j < panels->n_panels; j++) {
			RPanel *above = r_panels_get_panel (panels, j);
			if (!above) {
				continue;
			}
			RPanelPos *apos = &above->view->pos;
			if (apos->y + apos->h - 1 == bpos->y &&
					x >= apos->x && x < apos->x + apos->w) {
				panels->mouse_on_edge_y = true;
				panels->mouse_orig_y = bpos->y;
				return true;
			}
		}
	}
	return false;
}

static void r_panels_check_edge(RCore *core) {
	RPanels *panels = core->panels;
	RConsCanvas *can = panels->can;
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!p) {
			continue;
		}
		RPanelPos *pos = &p->view->pos;
		if (pos->x + pos->w == can->w) {
			p->view->edge |= (1 << PANEL_EDGE_RIGHT);
		} else {
			p->view->edge &= ~(1 << PANEL_EDGE_RIGHT);
		}
		if (pos->y + pos->h == can->h - PANEL_FOOTER_H) {
			p->view->edge |= (1 << PANEL_EDGE_BOTTOM);
		} else {
			p->view->edge &= ~(1 << PANEL_EDGE_BOTTOM);
		}
	}
}

static void r_panels_shrink_panels_forward(RCore *core, int target) {
	RPanels *panels = core->panels;
	int i = target;
	for (; i < panels->n_panels - 1; i++) {
		panels->panel[i] = panels->panel[i + 1];
	}
}

static void r_panels_shrink_panels_backward(RCore *core, int target) {
	RPanels *panels = core->panels;
	int i = target;
	for (; i > 0; i--) {
		panels->panel[i] = panels->panel[i - 1];
	}
}

static void r_panels_set_pos(RPanelPos *pos, int x, int y) {
	pos->x = x;
	pos->y = y;
}

static void r_panels_set_size(RPanelPos *pos, int w, int h) {
	pos->w = w;
	pos->h = h;
}

static void r_panels_set_geometry(RPanelPos *pos, int x, int y, int w, int h) {
	r_panels_set_pos (pos, x, y);
	r_panels_set_size (pos, w, h);
}

static void r_panels_layout_default(RCore *core, RPanels *panels) {
	RPanel *p0 = r_panels_get_panel (panels, 0);
	if (!p0) {
		R_LOG_ERROR ("_get_panel (...,0) return null");
		return;
	}
	int h, w = r_cons_get_size (core->cons, &h);
	h -= PANEL_FOOTER_H;
	if (panels->n_panels <= 1) {
		r_panels_set_geometry (&p0->view->pos, 0, PANEL_HEADER_H, w, h - PANEL_HEADER_H);
		return;
	}

	int ph = (h - PANEL_HEADER_H) / (panels->n_panels - 1);
	int colpos = w - panels->columnWidth;
	r_panels_set_geometry (&p0->view->pos, 0, PANEL_HEADER_H, colpos + 1, h - PANEL_HEADER_H);

	int pos_x = p0->view->pos.x + p0->view->pos.w - 1;
	int i;
	for (i = 1; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!p) {
			continue;
		}
		int tmp_w = R_MAX (w - colpos, 0);
		int pos_y = PANEL_HEADER_H + (ph * (i - 1));
		int tmp_h = i + 1 == panels->n_panels? h - pos_y: ph + 1;
		r_panels_set_geometry (&p->view->pos, pos_x, pos_y, tmp_w, tmp_h);
	}
}

static void r_panels_layout(RCore *core, RPanels *panels) {
	panels->can->sx = 0;
	panels->can->sy = 0;
	r_panels_layout_default (core, panels);
}

static void r_panels_layout_equal_hor(RCore *core, RPanels *panels) {
	int h, w = r_cons_get_size (core->cons, &h);
	h -= PANEL_FOOTER_H;
	int pw = w / panels->n_panels;
	int i, cw = 0;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!p) {
			continue;
		}
		r_panels_set_geometry (&p->view->pos, cw, PANEL_HEADER_H, pw, h - PANEL_HEADER_H);
		cw += pw - 1;
		if (i == panels->n_panels - 2) {
			pw = w - cw;
		}
	}
}

/* makes space for a side panel, returns the amount of space made*/
static unsigned int r_panels_adjust_side_panels(RCore *core) {
	r_panels_prepare_layout (core);
	RPanels *panels = core->panels;
	int i, h;
	unsigned int smallest = INT32_MAX;
	(void)r_cons_get_size (core->cons, &h);
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (p && p->view->pos.x == 0 && smallest > p->view->pos.w) {
			smallest = p->view->pos.w;
		}
	}
	unsigned int space = (smallest > PANEL_CONFIG_SIDEPANEL_W + PANEL_CONFIG_MIN_SIZE)
		? PANEL_CONFIG_SIDEPANEL_W : smallest / 2;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (p && p->view->pos.x == 0) {
			p->view->pos.x += space;
			p->view->pos.w -= space;
		}
	}
	return space;
}

static void r_panels_fix_layout_axis(RCore *core, bool horizontal) {
	RPanels *panels = core->panels;
	size_t op = horizontal ? offsetof (RPanelPos, x) : offsetof (RPanelPos, y);
	size_t os = horizontal ? offsetof (RPanelPos, w) : offsetof (RPanelPos, h);
	int edges[PANEL_NUM_LIMIT];
	int n_edges = 0;
	int skip_pos = 0, skip_sz = 0;
	if (!horizontal) {
		int h;
		(void)r_cons_get_size (core->cons, &h);
		skip_pos = PANEL_HEADER_H;
		skip_sz = h - PANEL_HEADER_H - PANEL_FOOTER_H;
	}
	int i;
	for (i = 0; i < panels->n_panels - 1 && n_edges < PANEL_NUM_LIMIT; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (p) {
			edges[n_edges++] = PP (p->view->pos, op) + PP (p->view->pos, os);
		}
	}
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *p = r_panels_get_panel (panels, i);
		if (!p) {
			continue;
		}
		int tpos = PP (p->view->pos, op);
		int tsz = PP (p->view->pos, os);
		if (horizontal ? (tpos == 0) : (tpos == skip_pos || tsz == skip_sz)) {
			continue;
		}
		int min = INT32_MAX;
		int target_num = INT32_MAX;
		bool found = false;
		int j;
		for (j = 0; j < n_edges; j++) {
			if (edges[j] - 1 == tpos) {
				found = true;
				break;
			}
			int sub = edges[j] - tpos;
			if (min > R_ABS (sub)) {
				min = R_ABS (sub);
				target_num = edges[j];
			}
		}
		if (!found) {
			int t = PP (p->view->pos, op) - target_num + 1;
			PP (p->view->pos, op) = target_num - 1;
			PP (p->view->pos, os) += t;
		}
	}
}

static void r_panels_fix_layout(RCore *core) {
	r_panels_fix_layout_axis (core, true);
	r_panels_fix_layout_axis (core, false);
}

static void r_panels_split_panel(RCore *core, RPanel *p, const char *name, const char *cmd, bool vertical) {
	RPanels *panels = core->panels;
	if (!r_panels_check_panel_num (core)) {
		return;
	}
	r_panels_insert_panel (core, panels->curnode + 1, name, cmd);
	RPanel *next = r_panels_get_panel (panels, panels->curnode + 1);
	if (!strcmp (next->model->cmd, p->model->cmd) && !strcmp (next->model->title, p->model->title)) {
		next->model->cache = p->model->cache;
	}
	RPanelPos *pos = &p->view->pos;
	if (vertical) {
		int ow = pos->w;
		pos->w = ow / 2 + 1;
		r_panels_set_geometry (&next->view->pos, pos->x + pos->w - 1, pos->y, ow - pos->w + 1, pos->h);
	} else {
		int oh = pos->h;
		p->view->curpos = 0;
		pos->h = oh / 2 + 1;
		r_panels_set_geometry (&next->view->pos, pos->x, pos->y + pos->h - 1, pos->w, oh - pos->h + 1);
	}
	r_panels_fix_layout (core);
	r_panels_set_refresh_all (core, false, true);
}

static void r_panels_del_panel(RCore *core, int pi) {
	int i;
	RPanels *panels = core->panels;
	RPanel *tmp = r_panels_get_panel (panels, pi);
	if (!tmp) {
		return;
	}
	if (pi == panels->curnode) {
		r_panels_set_cursor (core, false);
	}
	for (i = pi; i < (panels->n_panels - 1); i++) {
		panels->panel[i] = panels->panel[i + 1];
	}
	panels->panel[panels->n_panels - 1] = tmp;
	panels->n_panels--;
	r_panels_set_curnode (core, panels->curnode);
}

static void r_panels_del_invalid_panels(RCore *core) {
	RPanels *panels = core->panels;
	bool found;
	do {
		found = false;
		int i;
		for (i = 1; i < panels->n_panels; i++) {
			RPanel *panel = r_panels_get_panel (panels, i);
			if (panel && (panel->view->pos.w < PANEL_CONFIG_MIN_SIZE
					|| panel->view->pos.h < PANEL_CONFIG_MIN_SIZE)) {
				r_panels_del_panel (core, i);
				found = true;
				break;
			}
		}
	} while (found);
}

static void r_panels_layout_refresh(RCore *core) {
	r_panels_del_invalid_panels (core);
	r_panels_check_edge (core);
	r_panels_check_stackbase (core);
	r_panels_refresh (core);
}

static void r_panels_reset_scroll_pos(RPanel *p) {
	p->view->sx = 0;
	p->view->sy = 0;
}

static void r_panels_save_panel_pos(RPanel* panel) {
	if (!panel) {
		return;
	}
	r_panels_set_geometry (&panel->view->prevPos, panel->view->pos.x, panel->view->pos.y,
			panel->view->pos.w, panel->view->pos.h);
}

static void r_panels_restore_panel_pos(RPanel* panel) {
	if (!panel) {
		return;
	}
	r_panels_set_geometry (&panel->view->pos, panel->view->prevPos.x, panel->view->prevPos.y,
			panel->view->prevPos.w, panel->view->prevPos.h);
}

static void r_panels_maximize_panel_size(RPanels *panels) {
	RPanel *cur = r_panels_get_cur_panel (panels);
	if (!cur) {
		return;
	}
	r_panels_set_geometry (&cur->view->pos, 0, PANEL_HEADER_H, panels->can->w, panels->can->h - PANEL_HEADER_H - PANEL_FOOTER_H);
	cur->view->refresh = true;
}

static void r_panels_dismantle_panel(RPanels *ps, RPanel *p) {
	if (!p) {
		return;
	}
	RPanel *jL = NULL, *jR = NULL, *jU = NULL, *jD = NULL;
	bool lu = false, ld = false, ru = false, rd = false, ul = false, ur = false, dl = false, dr = false;
	int L[PANEL_NUM_LIMIT], R[PANEL_NUM_LIMIT], U[PANEL_NUM_LIMIT], D[PANEL_NUM_LIMIT];
	memset (L, -1, sizeof (L));
	memset (R, -1, sizeof (R));
	memset (U, -1, sizeof (U));
	memset (D, -1, sizeof (D));
	int i;
	int ox = p->view->pos.x, oy = p->view->pos.y;
	int ow = p->view->pos.w, oh = p->view->pos.h;
	for (i = 0; i < ps->n_panels; i++) {
		RPanel *t = r_panels_get_panel (ps, i);
		if (!t) {
			continue;
		}
		RPanelPos *tp = &t->view->pos;
		if (tp->x + tp->w - 1 == ox) {
			L[i] = 1;
			if (oy == tp->y) {
				lu = true;
				if (oh == tp->h) { jL = t; break; }
			}
			if (oy + oh == tp->y + tp->h) { ld = true; }
		}
		if (tp->x == ox + ow - 1) {
			R[i] = 1;
			if (oy == tp->y) {
				ru = true;
				if (oh == tp->h) { rd = true; jR = t; }
			}
			if (oy + oh == tp->y + tp->h) { rd = true; }
		}
		if (tp->y + tp->h - 1 == oy) {
			U[i] = 1;
			if (ox == tp->x) {
				ul = true;
				if (ow == tp->w) { ur = true; jU = t; }
			}
			if (ox + ow == tp->x + tp->w) { ur = true; }
		}
		if (tp->y == oy + oh - 1) {
			D[i] = 1;
			if (ox == tp->x) {
				dl = true;
				if (ow == tp->w) { dr = true; jD = t; }
			}
			if (ox + ow == tp->x + tp->w) { dr = true; }
		}
	}
	if (jL) {
		RPanelPos *jp = &jL->view->pos;
		jp->w += ox + ow - (jp->x + jp->w);
	} else if (jR) {
		RPanelPos *jp = &jR->view->pos;
		jp->w = jp->x + jp->w - ox;
		jp->x = ox;
	} else if (jU) {
		RPanelPos *jp = &jU->view->pos;
		jp->h += oy + oh - (jp->y + jp->h);
	} else if (jD) {
		RPanelPos *jp = &jD->view->pos;
		jp->h = oh + jp->y + jp->h - (oy + oh);
		jp->y = oy;
	} else if (lu && ld) {
		for (i = 0; i < ps->n_panels; i++) {
			if (L[i] != -1) {
				RPanelPos *tp = &r_panels_get_panel (ps, i)->view->pos;
				tp->w += ox + ow - (tp->x + tp->w);
			}
		}
	} else if (ru && rd) {
		for (i = 0; i < ps->n_panels; i++) {
			if (R[i] != -1) {
				RPanelPos *tp = &r_panels_get_panel (ps, i)->view->pos;
				tp->w = tp->x + tp->w - ox;
				tp->x = ox;
			}
		}
	} else if (ul && ur) {
		for (i = 0; i < ps->n_panels; i++) {
			if (U[i] != -1) {
				RPanelPos *tp = &r_panels_get_panel (ps, i)->view->pos;
				tp->h += oy + oh - (tp->y + tp->h);
			}
		}
	} else if (dl && dr) {
		for (i = 0; i < ps->n_panels; i++) {
			if (D[i] != -1) {
				RPanelPos *tp = &r_panels_get_panel (ps, i)->view->pos;
				tp->h = oh + tp->y + tp->h - (oy + oh);
				tp->y = oy;
			}
		}
	}
}

static void r_panels_dismantle_del_panel(RCore *core, RPanel *p, int pi) {
	RPanels *panels = core->panels;
	if (panels->n_panels <= 1) {
		return;
	}
	r_panels_dismantle_panel (panels, p);
	r_panels_del_panel (core, pi);
}

static void r_panels_prepare_layout(RCore *core) {
	if (core->panels->mode == PANEL_MODE_MENU) {
		r_panels_close_menu (core);
	}
	if (core->panels->mode == PANEL_MODE_ZOOM) {
		r_panels_toggle_zoom_mode (core);
	}
}

static void r_panels_move_panel_to(RCore *core, RPanel *panel, int src, Direction dir) {
	RPanels *panels = core->panels;
	bool neg = (dir == 'h' || dir == 'k');
	bool horiz = (dir == 'h' || dir == 'l');
	if (neg) {
		r_panels_shrink_panels_backward (core, src);
		panels->panel[0] = panel;
	} else {
		r_panels_shrink_panels_forward (core, src);
		panels->panel[panels->n_panels - 1] = panel;
	}
	int h, w = r_cons_get_size (core->cons, &h);
	h -= PANEL_FOOTER_H;
	if (w < 1) {
		w = 1;
	}
	if (h < 1) {
		h = 1;
	}
	int start = neg ? 1 : 0;
	int end = neg ? panels->n_panels : panels->n_panels - 1;
	int i;
	if (horiz) {
		int p_w = (w - panels->columnWidth) / 2;
		int new_w = w - p_w;
		if (neg) {
			r_panels_set_geometry (&panel->view->pos, 0, PANEL_HEADER_H, p_w + 1, h - PANEL_HEADER_H);
		} else {
			r_panels_set_geometry (&panel->view->pos, w - p_w - 1, PANEL_HEADER_H, p_w + 1, h - PANEL_HEADER_H);
		}
		for (i = start; i < end; i++) {
			RPanel *tmp = r_panels_get_panel (panels, i);
			int t_x = (int)((double)tmp->view->pos.x / w * new_w + (neg ? p_w : 0));
			int t_w = (int)((double)tmp->view->pos.w / w * new_w + 1);
			r_panels_set_geometry (&tmp->view->pos, t_x, tmp->view->pos.y, t_w, tmp->view->pos.h);
		}
	} else {
		int p_h = h / 2;
		int new_h = h - p_h;
		if (neg) {
			r_panels_set_geometry (&panel->view->pos, 0, PANEL_HEADER_H, w, p_h - PANEL_HEADER_H);
		} else {
			r_panels_set_geometry (&panel->view->pos, 0, new_h, w, p_h);
		}
		for (i = start; i < end; i++) {
			RPanel *tmp = r_panels_get_panel (panels, i);
			int t_y, t_h;
			if (neg) {
				t_y = (int)((double)tmp->view->pos.y / h * new_h + p_h);
				t_h = (int)((double)tmp->view->pos.h / h * new_h + 1);
			} else {
				t_y = (int)(tmp->view->pos.y * new_h / h) + PANEL_HEADER_H;
				t_h = (tmp->view->edge & (1 << PANEL_EDGE_BOTTOM))
					? new_h - t_y
					: (int)(tmp->view->pos.h * new_h / h);
			}
			r_panels_set_geometry (&tmp->view->pos, tmp->view->pos.x, t_y, tmp->view->pos.w, t_h);
		}
	}
	r_panels_fix_layout (core);
	r_panels_set_curnode (core, neg ? 0 : panels->n_panels - 1);
}

static void r_panels_move_panel_to_dir(RCore *core, RPanel *panel, int src) {
	r_panels_dismantle_panel (core->panels, panel);
	int key = r_panels_show_status (core, "Move the current panel to direction (h/j/k/l): ");
	key = r_cons_arrow_to_hjkl (core->cons, key);
	r_panels_set_refresh_all (core, false, true);
	if (key == 'h' || key == 'j' || key == 'k' || key == 'l') {
		r_panels_move_panel_to (core, panel, src, key);
	}
}

static void r_panels_swap_panels(RPanels *panels, int p0, int p1) {
	RPanel *panel0 = r_panels_get_panel (panels, p0);
	RPanel *panel1 = r_panels_get_panel (panels, p1);
	RPanelModel *tmp = panel0->model;

	panel0->model = panel1->model;
	panel1->model = tmp;
}

static int r_panels_scale_edge(int value, int old_max, int new_max) {
	if (old_max < 1 || new_max < 1) {
		return 0;
	}
	return (int)(((st64)value * new_max + (old_max / 2)) / old_max);
}

static void r_panels_resize_layout(RPanels *panels, int width, int height) {
	if (!panels->can || width < 1 || height < 1) {
		return;
	}
	int old_width = panels->can->w;
	int old_height = panels->can->h;
	if (old_width == width && old_height == height) {
		return;
	}
	int old_x_max = R_MAX (old_width - 1, 0);
	int new_x_max = R_MAX (width - 1, 0);
	int old_y_max = R_MAX (old_height - PANEL_HEADER_H - PANEL_FOOTER_H - 1, 0);
	int new_y_max = R_MAX (height - PANEL_HEADER_H - PANEL_FOOTER_H - 1, 0);
	int i;
	for (i = 0; i < panels->n_panels; i++) {
		RPanel *panel = r_panels_get_panel (panels, i);
		if (!panel) {
			continue;
		}
		RPanelPos *pos = &panel->view->pos;
		int left = R_MIN (R_MAX (pos->x, 0), old_x_max);
		int right = R_MIN (R_MAX (pos->x + pos->w - 1, left), old_x_max);
		int top = R_MIN (R_MAX (pos->y - PANEL_HEADER_H, 0), old_y_max);
		int bottom = R_MIN (R_MAX (pos->y + pos->h - PANEL_HEADER_H - 1, top), old_y_max);
		int new_left = r_panels_scale_edge (left, old_x_max, new_x_max);
		int new_right = r_panels_scale_edge (right, old_x_max, new_x_max);
		int new_top = r_panels_scale_edge (top, old_y_max, new_y_max);
		int new_bottom = r_panels_scale_edge (bottom, old_y_max, new_y_max);
		r_panels_set_geometry (pos, new_left, new_top + PANEL_HEADER_H,
			R_MAX (new_right - new_left + 1, 1), R_MAX (new_bottom - new_top + 1, 1));
		panel->view->refresh = true;
	}
}

static void r_panels_do_panels_resize(RCore *core) {
	RPanels *panels = core->panels;
	int h, w = r_panels_get_size (core, &h);
	r_panels_resize_layout (panels, w, h);
	(void)r_cons_canvas_resize (panels->can, w, h);
	r_panels_do_panels_refresh (core);
}

static void r_panels_rotate_panels(RCore *core, bool rev) {
	RPanels *panels = core->panels;
	RPanel *first = r_panels_get_panel (panels, 0);
	RPanel *last = r_panels_get_panel (panels, panels->n_panels - 1);
	int i;
	RPanelModel *tmp_model;
	if (!rev) {
		tmp_model = first->model;
		for (i = 0; i < panels->n_panels - 1; i++) {
			RPanel *p0 = r_panels_get_panel (panels, i);
			RPanel *p1 = r_panels_get_panel (panels, i + 1);
			p0->model = p1->model;
		}
		last->model = tmp_model;
	} else {
		tmp_model = last->model;
		for (i = panels->n_panels - 1; i > 0; i--) {
			RPanel *p0 = r_panels_get_panel (panels, i);
			RPanel *p1 = r_panels_get_panel (panels, i - 1);
			p0->model = p1->model;
		}
		first->model = tmp_model;
	}
	r_panels_set_refresh_all (core, false, true);
}
