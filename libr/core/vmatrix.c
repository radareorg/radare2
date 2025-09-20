/* radare - LGPL - Copyright 2025 - pancake */

#include <r_core.h>

static const char *level0_categories[] = {
	"flags", "flagspaces", "functions", "symbols", "imports", "comments", "sections", NULL
};

typedef struct {
	RCore *core;
	RConsCanvas *can;
	int cols;
	int rows;
	int box_h;
	int w;
	int h;
	int scroll_x;
	int scroll_y; // Current scroll position
	int level; // Current navigation level (0, 1, 2)
	int selected; // Selected box index
	int selected_item; // Selected item index within category (for level 1)
	ut64 selected_addr; // Selected address for disassembly
	ut64 original_addr; // Original address when entering level 2
	char *selected_flagspace; // Selected flagspace name for level 2 flagspace view
	char *filter; // Filter string for boxes
	int scroll_y_level[3]; // Separate scroll positions for each level
} RVMatrix;

// Global pointer to current vmatrix instance for event callbacks
static RVMatrix *g_rvm = NULL;

static void clamp_scroll_position(RVMatrix *rvm) {
	if (rvm->scroll_y < 0) {
		rvm->scroll_y = 0;
	}
	int max_scroll = rvm->rows * rvm->box_h - 1;
	if (max_scroll < 0) {
		max_scroll = 0;
	}
	if (rvm->scroll_y > max_scroll) {
		rvm->scroll_y = max_scroll;
	}
}

static void switch_level(RVMatrix *rvm, int new_level) {
	if (new_level >= 0 && new_level <= 2) {
		// Save current scroll position
		rvm->scroll_y_level[rvm->level] = rvm->scroll_y;
		// Switch to new level
		rvm->level = new_level;
		// Restore scroll position for new level
		rvm->scroll_y = rvm->scroll_y_level[new_level];
		if (new_level == 2) {
			rvm->original_addr = rvm->selected_addr;
		}
		clamp_scroll_position (rvm);
	}
}

static char *get_selected_box_title(RVMatrix *rvm) {
	static char title[256];
	const char *cat = level0_categories[rvm->selected];

	// Ensure selected index is within bounds
	int max_categories = 0;
	while (level0_categories[max_categories]) {
		max_categories++;
	}
	if (rvm->selected >= max_categories) {
		rvm->selected = max_categories - 1;
	}
	if (rvm->selected < 0) {
		rvm->selected = 0;
	}

	switch (rvm->level) {
	case 0:
		if (cat) {
			if (rvm->filter) {
				snprintf (title, sizeof (title), "%s [filter: %s]", cat, rvm->filter);
			} else {
				snprintf (title, sizeof (title), "%s", cat);
			}
		} else {
			if (rvm->filter) {
				snprintf (title, sizeof (title), "unknown [filter: %s]", rvm->filter);
			} else {
				snprintf (title, sizeof (title), "unknown");
			}
		}
		break;
	case 1:
		if (cat) {
			if (rvm->filter) {
				snprintf (title, sizeof (title), "%s item:%d [filter: %s]", cat, rvm->selected_item, rvm->filter);
			} else {
				snprintf (title, sizeof (title), "%s item:%d", cat, rvm->selected_item);
			}
		} else {
			if (rvm->filter) {
				snprintf (title, sizeof (title), "unknown item:%d [filter: %s]", rvm->selected_item, rvm->filter);
			} else {
				snprintf (title, sizeof (title), "unknown item:%d", rvm->selected_item);
			}
		}
		break;
	case 2:
		if (strcmp (cat, "flagspaces") == 0 && rvm->selected_flagspace) {
			if (rvm->filter) {
				snprintf (title, sizeof (title), "flagspace:%s [filter: %s]", rvm->selected_flagspace, rvm->filter);
			} else {
				snprintf (title, sizeof (title), "flagspace:%s", rvm->selected_flagspace);
			}
		} else {
			if (rvm->filter) {
				snprintf (title, sizeof (title), "0x%" PFMT64x " [filter: %s]", rvm->selected_addr, rvm->filter);
			} else {
				snprintf (title, sizeof (title), "0x%" PFMT64x, rvm->selected_addr);
			}
		}
		break;
	default:
		if (rvm->filter) {
			snprintf (title, sizeof (title), "unknown [filter: %s]", rvm->filter);
		} else {
			snprintf (title, sizeof (title), "unknown");
		}
		break;
	}

	return title;
}

static void draw_scrollbar(RVMatrix *rvm) {
	RConsCanvas *can = rvm->can;
	if (!can) {
		return;
	}
	int i;
	int w = rvm->w - 3;
	int h = rvm->h - 2;
	int total_h = rvm->rows * rvm->box_h;
	int sbpos = rvm->scroll_y * rvm->h / total_h;
	if (sbpos < 1) {
		sbpos = 1;
	}
	if (sbpos >= h - 1) {
		sbpos = h - 2;
	}
	for (i = 1; i < h; i++) {
		const char *box = (i == sbpos) ? "|#|" : "|.|";
		r_cons_canvas_write_at (can, box, w, i);
	}
	r_cons_canvas_write_at (can, "[^]", w, 0);
	r_cons_canvas_write_at (can, Color_INVERT "[v]" Color_RESET, w, h - 1);
}

static void draw_highlighted_box(RConsCanvas *can, int xpos, int ypos, int boxwidth, int boxheight, bool is_selected) {
	if (!can || boxwidth <= 0 || boxheight <= 0) {
		return;
	}
	const char *box_color = is_selected ? Color_RED : "";
	r_cons_canvas_box (can, xpos, ypos, boxwidth, boxheight, box_color);

	// Fill top line with #### for selected boxes (between the borders)
	if (is_selected && boxwidth > 2) {
		char *top_line = r_str_newf ("%s", "");
		if (top_line) {
			int j, len = boxwidth - 2; // Leave space for left and right borders
			for (j = 0; j < len; j++) {
				char *new_line = r_str_append (top_line, "#");
				if (!new_line) {
					break; // Allocation failed
				}
				top_line = new_line;
			}
			r_cons_canvas_write_at (can, top_line, xpos + 1, ypos);
			free (top_line);
		}
	}
}

static void draw_level0_boxes(RVMatrix *rvm) {
	RConsCanvas *can = rvm->can;
	if (!can) {
		return;
	}
	int w = rvm->w - 6;
	int boxwidth = w / rvm->cols;
	int xpos = 0;
	int ypos = -rvm->scroll_y;
	int col = 0;
	int i = 0;

	while (level0_categories[i]) {
		const char *cat = level0_categories[i];
		if (rvm->filter && !strstr (cat, rvm->filter)) {
			i++;
			continue;
		}
		bool is_selected = (i == rvm->selected);
		draw_highlighted_box (can, xpos, ypos, boxwidth, rvm->box_h, is_selected);

		char *title = r_str_ndup (cat, boxwidth - 4);
		r_cons_canvas_write_at (can, title, xpos + 2, ypos + 1);
		free (title);
		xpos += boxwidth + 1;
		col++;
		if (col >= rvm->cols) {
			ypos += rvm->box_h;
			xpos = 0;
			col = 0;
		}
		i++;
	}
	rvm->rows = (i + rvm->cols - 1) / rvm->cols;
}

static void draw_level1_boxes(RVMatrix *rvm) {
	RConsCanvas *can = rvm->can;
	if (!can) {
		return;
	}
	const char *cat = level0_categories[rvm->selected];
	int w = rvm->w - 6;
	int boxwidth = w / rvm->cols;
	int xpos = 0;
	int col = 0;
	int item_count = 0;
	int max_items = 100; // Allow more items since we're using boxes

	int ypos = -rvm->scroll_y; // Start from top with scroll offset

	if (strcmp (cat, "functions") == 0) {
		RListIter *iter;
		RAnalFunction *f;
		RList *fcns = rvm->core->anal->fcns;
		r_list_foreach (fcns, iter, f) {
			if (item_count >= max_items) {
				break;
			}
			if (rvm->filter && !strstr (f->name, rvm->filter)) {
				continue;
			}
			bool is_selected = (item_count == rvm->selected_item);
			draw_highlighted_box (can, xpos, ypos, boxwidth, rvm->box_h, is_selected);
			char item[256];
			snprintf (item, sizeof (item), "0x%" PFMT64x, f->addr);
			char *name = r_str_ndup (f->name, boxwidth - 4 - strlen (item));
			r_cons_canvas_write_at (can, item, xpos + 2, ypos + 1);
			r_cons_canvas_write_at (can, name, xpos + 2, ypos + 2);
			free (name);

			xpos += boxwidth + 1;
			col++;
			if (col >= rvm->cols) {
				ypos += rvm->box_h;
				xpos = 0;
				col = 0;
			}
			item_count++;
		}
	} else if (strcmp (cat, "flagspaces") == 0) {
		RSpace *space;
		RSpaceIter *it;
		r_flag_space_foreach (rvm->core->flags, it, space) {
			if (item_count >= max_items) {
				break;
			}
			if (rvm->filter && !strstr (space->name, rvm->filter)) {
				continue;
			}
			bool is_selected = (item_count == rvm->selected_item);
			draw_highlighted_box (can, xpos, ypos, boxwidth, rvm->box_h, is_selected);
			char item[256];
			int count = r_flag_space_count (rvm->core->flags, space->name);
#if 0
			snprintf (item, sizeof (item), "%d flags", count);
			char *name = r_str_ndup (space->name, boxwidth - 4 - strlen (item));
			r_cons_canvas_write_at (can, item, xpos + 2, ypos + 1);
			r_cons_canvas_write_at (can, name, xpos + 2, ypos + 2);
#else
			snprintf (item, sizeof (item), "%d", count);
			char *name = r_str_ndup (space->name, boxwidth - 4 - strlen (item));
			snprintf (item, sizeof (item), "%d %s", count, name);
			r_cons_canvas_write_at (can, item, xpos + 2, ypos + 1);
#endif
			free (name);

			xpos += boxwidth + 1;
			col++;
			if (col >= rvm->cols) {
				ypos += rvm->box_h;
				xpos = 0;
				col = 0;
			}
			item_count++;
		}
	} else if (strcmp (cat, "flags") == 0) {
		RListIter *iter;
		RFlagItem *flag;
		const RList *flags = r_flag_get_list (rvm->core->flags, 0);
		r_list_foreach (flags, iter, flag) {
			if (item_count >= max_items) {
				break;
			}
			if (rvm->filter && !strstr (flag->name, rvm->filter)) {
				continue;
			}
			bool is_selected = (item_count == rvm->selected_item);
			draw_highlighted_box (can, xpos, ypos, boxwidth, rvm->box_h, is_selected);
			char item[256];
			snprintf (item, sizeof (item), "0x%" PFMT64x, flag->addr);
			char *name = r_str_ndup (flag->name, boxwidth - 4 - strlen (item));
			r_cons_canvas_write_at (can, item, xpos + 2, ypos + 1);
			r_cons_canvas_write_at (can, name, xpos + 2, ypos + 2);
			free (name);

			xpos += boxwidth + 1;
			col++;
			if (col >= rvm->cols) {
				ypos += rvm->box_h;
				xpos = 0;
				col = 0;
			}
			item_count++;
		}
	} else if (strcmp (cat, "symbols") == 0) {
		RBinSymbol *sym;
		RListIter *iter;
		const RList *symbols = r_bin_get_symbols (rvm->core->bin);
		r_list_foreach (symbols, iter, sym) {
			if (item_count >= max_items) {
				break;
			}
			char *name_str = r_bin_name_tostring (sym->name);
			if (rvm->filter && !strstr (name_str, rvm->filter)) {
				continue;
			}
			bool is_selected = (item_count == rvm->selected_item);
			draw_highlighted_box (can, xpos, ypos, boxwidth, rvm->box_h, is_selected);
			char item[256];
			snprintf (item, sizeof (item), "0x%" PFMT64x, sym->vaddr);
			char *name = r_str_ndup (name_str, boxwidth - 4 - strlen (item));
			r_cons_canvas_write_at (can, item, xpos + 2, ypos + 1);
			r_cons_canvas_write_at (can, name, xpos + 2, ypos + 2);
			free (name);

			xpos += boxwidth + 1;
			col++;
			if (col >= rvm->cols) {
				ypos += rvm->box_h;
				xpos = 0;
				col = 0;
			}
			item_count++;
		}
	} else if (strcmp (cat, "imports") == 0) {
		RBinImport *imp;
		RListIter *iter;
		const RList *imports = r_bin_get_imports (rvm->core->bin);
		r_list_foreach (imports, iter, imp) {
			if (item_count >= max_items) {
				break;
			}
			char *name_str = r_bin_name_tostring (imp->name);
			if (rvm->filter && !strstr (name_str, rvm->filter)) {
				continue;
			}
			bool is_selected = (item_count == rvm->selected_item);
			draw_highlighted_box (can, xpos, ypos, boxwidth, rvm->box_h, is_selected);
			char item[256];
			snprintf (item, sizeof (item), "0x%08" PFMT64x, (ut64)0);
			char *name = r_str_ndup (name_str, boxwidth - 4 - strlen (item));
			r_cons_canvas_write_at (can, item, xpos + 2, ypos + 1);
			r_cons_canvas_write_at (can, name, xpos + 2, ypos + 2);
			free (name);

			xpos += boxwidth + 1;
			col++;
			if (col >= rvm->cols) {
				ypos += rvm->box_h;
				xpos = 0;
				col = 0;
			}
			item_count++;
		}
	} else if (strcmp (cat, "comments") == 0) {
		RIntervalTreeIter it;
		RAnalMetaItem *item;
		r_interval_tree_foreach (&rvm->core->anal->meta, it, item) {
			if (item_count >= max_items) {
				break;
			}
			if (item->type != R_META_TYPE_COMMENT) {
				continue;
			}
			if (rvm->filter && !strstr (item->str, rvm->filter)) {
				continue;
			}
			bool is_selected = (item_count == rvm->selected_item);
			draw_highlighted_box (can, xpos, ypos, boxwidth, rvm->box_h, is_selected);
			char addr_str[256];
			snprintf (addr_str, sizeof (addr_str), "0x%" PFMT64x, r_interval_tree_iter_get (&it)->start);
			char *comment = r_str_ndup (item->str, boxwidth - 4 - strlen (addr_str));
			r_cons_canvas_write_at (can, addr_str, xpos + 2, ypos + 1);
			r_cons_canvas_write_at (can, comment, xpos + 2, ypos + 2);
			free (comment);

			xpos += boxwidth + 1;
			col++;
			if (col >= rvm->cols) {
				ypos += rvm->box_h;
				xpos = 0;
				col = 0;
			}
			item_count++;
		}
	} else if (strcmp (cat, "sections") == 0) {
		RBinSection *section;
		RListIter *iter;
		const RList *sections = r_bin_get_sections (rvm->core->bin);
		r_list_foreach (sections, iter, section) {
			if (item_count >= max_items) {
				break;
			}
			if (rvm->filter && !strstr (section->name, rvm->filter)) {
				continue;
			}
			bool is_selected = (item_count == rvm->selected_item);
			draw_highlighted_box (can, xpos, ypos, boxwidth, rvm->box_h, is_selected);
			char addr_str[256];
			snprintf (addr_str, sizeof (addr_str), "0x%" PFMT64x, section->vaddr);
			char *name = r_str_ndup (section->name, boxwidth - 4 - strlen (addr_str));
			r_cons_canvas_write_at (can, addr_str, xpos + 2, ypos + 1);
			r_cons_canvas_write_at (can, name, xpos + 2, ypos + 2);
			free (name);

			xpos += boxwidth + 1;
			col++;
			if (col >= rvm->cols) {
				ypos += rvm->box_h;
				xpos = 0;
				col = 0;
			}
			item_count++;
		}
	} else {
		r_cons_canvas_write_at (can, "Category not implemented yet", 2, ypos);
	}

	rvm->rows = (item_count + rvm->cols - 1) / rvm->cols;
}

static void draw_level2_disassembly(RVMatrix *rvm) {
	RConsCanvas *can = rvm->can;
	if (!can) {
		return;
	}
	const char *cat = level0_categories[rvm->selected];

	if (strcmp (cat, "flagspaces") == 0 && rvm->selected_flagspace) {
		// Show flags in the selected flagspace in boxed matrix
		int w = rvm->w - 6;
		int boxwidth = w / rvm->cols;
		int xpos = 0;
		int col = 0;
		int item_count = 0;
		int max_items = 100;

		int ypos = -rvm->scroll_y;

		// Get flags from the selected flagspace
		RCore *core = rvm->core;
		RList *all_flags = r_flag_all_list (core->flags, true);
		if (all_flags) {
			RListIter *iter;
			RFlagItem *flag;
			r_list_foreach (all_flags, iter, flag) {
				if (item_count >= max_items) {
					break;
				}
				if (flag->space && strcmp (flag->space->name, rvm->selected_flagspace) == 0) {
					bool is_selected = (item_count == rvm->selected_item);
					draw_highlighted_box (can, xpos, ypos, boxwidth, rvm->box_h, is_selected);
					char item[256];
					snprintf (item, sizeof (item), "0x%" PFMT64x, flag->addr);
					char *name = r_str_ndup (flag->name, boxwidth - 4 - strlen (item));
					r_cons_canvas_write_at (can, item, xpos + 2, ypos + 1);
					r_cons_canvas_write_at (can, name, xpos + 2, ypos + 2);
					free (name);

					xpos += boxwidth + 1;
					col++;
					if (col >= rvm->cols) {
						ypos += rvm->box_h;
						xpos = 0;
						col = 0;
					}
					item_count++;
				}
			}
			r_list_free (all_flags);
		}
		rvm->rows = (item_count + rvm->cols - 1) / rvm->cols;
	} else {
		// Original disassembly view
		int disasm_w = (rvm->w * 70) / 100;
		int disasm_h = (rvm->h * 90) / 100;
		int disasm_x = (rvm->w - disasm_w) / 2;
		int disasm_y = (rvm->h - disasm_h) / 2;

		if (disasm_w > 0 && disasm_h > 0) {
			r_cons_canvas_box (can, disasm_x, disasm_y, disasm_w, disasm_h, Color_YELLOW);
		}
		char title[256];
		char *header_line = r_str_newf ("%s", "");
		if (header_line) {
			int j, header_len = disasm_w - 4;
			for (j = 0; j < header_len && j < 30; j++) {
				char *new_line = r_str_append (header_line, "-");
				if (!new_line) {
					break; // Allocation failed
				}
				header_line = new_line;
			}
			r_cons_canvas_write_at (can, header_line, disasm_x + 2, disasm_y);
			free (header_line);
		}

		snprintf (title, sizeof (title), "Disassembly at 0x%" PFMT64x, rvm->selected_addr);
		// Crop the title to fit within the disassembly box boundaries
		int max_title_width = disasm_w - 4; // Leave space for borders
		char *cropped_title = r_str_ansi_crop (title, 0, 0, max_title_width, -1);
		if (cropped_title) {
			r_cons_canvas_write_at (can, cropped_title, disasm_x + 2, disasm_y + 1);
			free (cropped_title);
		} else {
			r_cons_canvas_write_at (can, title, disasm_x + 2, disasm_y + 1);
		}

		// Get disassembly content
		RCore *core = rvm->core;
		char *disasm = r_core_cmd_strf (core, "pd 20 @ 0x%" PFMT64x, rvm->selected_addr);
		if (disasm) {
			char *line = disasm;
			char *next_line;
			int i, line_y = disasm_y + 3;
			int max_lines = disasm_h - 4;

			for (i = 0; i < max_lines && line; i++) {
				next_line = strchr (line, '\n');
				if (next_line) {
					*next_line = '\0';
					next_line++;
				}
				if (strlen (line) > 0) {
					// Crop the line to fit within the disassembly box boundaries
					int max_line_width = disasm_w - 4; // Leave space for borders
					char *cropped_line = r_str_ansi_crop (line, 0, 0, max_line_width, -1);
					if (cropped_line) {
						r_cons_canvas_write_at (can, cropped_line, disasm_x + 2, line_y++);
						free (cropped_line);
					} else {
						r_cons_canvas_write_at (can, line, disasm_x + 2, line_y++);
					}
				}
				line = next_line;
			}
			free (disasm);
		}
	}
}

static void vmatrix_refresh(RVMatrix *rvm) {
	if (!rvm || !rvm->core || !rvm->core->cons) {
		return;
	}
	RCons *cons = rvm->core->cons;
	int h, w = r_cons_get_size (cons, &h);
	rvm->h = h;
	rvm->w = w;

	// Check for valid dimensions
	if (w <= 0 || h <= 1) {
		return; // Invalid dimensions, skip refresh
	}

	// Ensure scroll position is within valid bounds
	clamp_scroll_position (rvm);
	RConsCanvas *can = r_cons_canvas_new (cons, w, h - 1, -2);
	if (!can) {
		return; // Canvas creation failed, skip refresh
	}
	r_cons_canvas_fill (can, 0, 0, w, h - 1, ' ');
	can->linemode = r_config_get_i (rvm->core->config, "graph.linemode");
	can->color = r_config_get_i (rvm->core->config, "scr.color");
	rvm->can = can;

	switch (rvm->level) {
	case 0:
		draw_level0_boxes (rvm);
		break;
	case 1:
		draw_level1_boxes (rvm);
		break;
	case 2:
		draw_level2_disassembly (rvm);
		break;
	}

	if (rvm->level == 0 || rvm->level == 1 || (rvm->level == 2 && strcmp (level0_categories[rvm->selected], "flagspaces") == 0)) {
		draw_scrollbar (rvm);
	}

	char *s = r_cons_canvas_tostring (can);
	if (!s) {
		r_cons_canvas_free (can);
		rvm->can = NULL;
		return; // Canvas tostring failed, skip display
	}
	r_cons_clear00 (cons);
	char *selected_title = get_selected_box_title (rvm);
	const char *cursor_status = rvm->core->print->cur_enabled ? "CURSOR" : "NORMAL";
	r_cons_printf (cons, "[0x%08" PFMT64x " Level:%d Cols:%d %s | %s]\n%s",
		rvm->core->addr, rvm->level, rvm->cols, cursor_status, selected_title, s);
	r_cons_visual_flush (cons);
	free (s);
	r_cons_canvas_free (can);
	rvm->can = NULL;
}

static void vmatrix_show_help(RCore *core) {
	const char *help_text =
		"Visual Matrix Mode Help\n"
		"======================\n\n"
		"Navigation:\n"
		"  h/l       - Move left/right (level 0)\n"
		"  j/k       - Move down/up (scrolling)\n"
		"  J/K       - Page down/up\n"
		"  g/G       - Go to top/bottom\n"
		"  Tab/Z     - Next/previous item (level 1)\n\n"
		"Level Navigation:\n"
		"  d/Enter   - Go down one level (activate selected item)\n"
		"  u         - Go up one level\n"
		"  q         - Quit or go up one level\n\n"
		"Layout Control:\n"
		"  1-9       - Set number of columns (1-9)\n"
		"  [/]       - Decrease/increase columns\n"
		"  +/-       - Decrease/increase box height\n\n"
		"Mouse Controls:\n"
		"  Left click - Select item\n"
		"  Double click - Activate selected item (go down)\n"
		"  Title bar - Go up one level\n"
		"  Scrollbar - Jump to position\n\n"
		"Special Commands:\n"
		"  :         - Run r2 command\n"
		"  !         - Open panels mode\n"
		"  /         - Set highlight from clipboard\n"
		"  |         - Filter boxes by text\n"
		"  .         - Go back to original address (level 2)\n"
		"  _         - Filter (reserved for future use)\n"
		"  ?         - Show this help\n\n";
	r_cons_less_str (core->cons, help_text, NULL);
}

static void vmatrix_refresh_oneshot(void *user) {
	// Use the global pointer for safety
	if (!g_rvm || !g_rvm->core || !g_rvm->core->cons) {
		return;
	}
	vmatrix_refresh (g_rvm);
}

R_API void r_core_visual_matrix(RCore *core) {
	RVMatrix rvm = {
		.core = core,
		.cols = 4,
		.box_h = 10,
		.level = 0,
		.selected = 0,
		.selected_item = 0,
		.selected_addr = core->addr,
		.original_addr = core->addr,
		.selected_flagspace = NULL,
		.filter = NULL,
		.scroll_y_level = { 0, 0, 0 },
	};

	// Save original event callbacks
	RConsEvent old_event_resize = core->cons->event_resize;
	RConsEvent old_event_interrupt = core->cons->context->event_interrupt;
	void *old_event_data = core->cons->event_data;

	// Set up vmatrix event callbacks
	r_cons_set_raw (core->cons, true);
	r_cons_enable_mouse (core->cons, r_config_get_i (core->config, "scr.wheel"));
	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->context->event_interrupt = NULL;
	g_rvm = &rvm; // Set global pointer
	core->cons->event_data = &rvm;
	core->cons->event_resize = vmatrix_refresh_oneshot;
	core->cons->context->event_interrupt = vmatrix_refresh_oneshot;

	// Initial refresh to display the matrix
	vmatrix_refresh (&rvm);

	// Ensure global pointer is still valid
	if (!g_rvm) {
		g_rvm = &rvm;
	}

	bool leave = false;
	while (!leave) {
		char ch = r_cons_readchar (core->cons);
		ch = r_cons_arrow_to_hjkl (core->cons, ch);
		switch (ch) {
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			rvm.cols = ch - '0';
			clamp_scroll_position (&rvm);
			break;
		case '[':
			if (rvm.cols > 1) {
				rvm.cols--;
				clamp_scroll_position (&rvm);
			}
			break;
		case ']':
			if (rvm.cols < 9) {
				rvm.cols++;
				clamp_scroll_position (&rvm);
			}
			break;
		case '+':
			rvm.box_h++;
			break;
		case '-':
			rvm.box_h--;
			if (rvm.box_h < 2) {
				rvm.box_h = 2;
			}
			break;
		case '_':
			// filter
			break;
		case 'j':
			if (rvm.level == 2 && strcmp (level0_categories[rvm.selected], "flagspaces") == 0 && rvm.selected_flagspace) {
				// Scroll flagspace boxes down
				rvm.scroll_y++;
				clamp_scroll_position (&rvm);
			} else if (rvm.level == 2) {
				// Scroll disassembly down
				rvm.selected_addr += 4; // Simple scroll by instruction
			} else {
				rvm.scroll_y++;
				clamp_scroll_position (&rvm);
			}
			break;
		case 'k':
			if (rvm.level == 2 && strcmp (level0_categories[rvm.selected], "flagspaces") == 0 && rvm.selected_flagspace) {
				// Scroll flagspace boxes up
				rvm.scroll_y--;
				clamp_scroll_position (&rvm);
			} else if (rvm.level == 2) {
				// Scroll disassembly up
				if (rvm.selected_addr >= 4) {
					rvm.selected_addr -= 4; // Simple scroll by instruction
				}
			} else {
				rvm.scroll_y--;
				clamp_scroll_position (&rvm);
			}
			break;
		case 'J':
			if (rvm.level == 2 && strcmp (level0_categories[rvm.selected], "flagspaces") == 0 && rvm.selected_flagspace) {
				rvm.scroll_y += rvm.box_h;
				clamp_scroll_position (&rvm);
			} else if (rvm.level == 2) {
				rvm.selected_addr += 16; // Page scroll disassembly down
			} else {
				rvm.scroll_y += rvm.box_h;
				clamp_scroll_position (&rvm);
			}
			break;
		case 'K':
			if (rvm.level == 2 && strcmp (level0_categories[rvm.selected], "flagspaces") == 0 && rvm.selected_flagspace) {
				rvm.scroll_y -= rvm.box_h;
				clamp_scroll_position (&rvm);
			} else if (rvm.level == 2) {
				if (rvm.selected_addr >= 16) {
					rvm.selected_addr -= 16; // Page scroll disassembly up
				}
			} else {
				rvm.scroll_y -= rvm.box_h;
				clamp_scroll_position (&rvm);
			}
			break;
		case 'g':
			if (rvm.level == 2 && strcmp (level0_categories[rvm.selected], "flagspaces") == 0 && rvm.selected_flagspace) {
				rvm.scroll_y = 0;
			} else if (rvm.level == 2) {
				rvm.selected_addr = rvm.original_addr;
			} else {
				rvm.scroll_y = 0;
			}
			break;
		case 'G':
			if (rvm.level == 2 && strcmp (level0_categories[rvm.selected], "flagspaces") == 0 && rvm.selected_flagspace) {
				rvm.scroll_y = rvm.rows * rvm.box_h - 1;
				clamp_scroll_position (&rvm);
			} else if (rvm.level == 2) {
				// For disassembly, G could go to end, but for now keep as is
				rvm.selected_addr += 100; // Arbitrary large scroll
			} else {
				rvm.scroll_y = rvm.rows * rvm.box_h - 1;
				clamp_scroll_position (&rvm);
			}
			break;
		case 'h':
			if (rvm.level == 0) {
				rvm.selected--;
				if (rvm.selected < 0) {
					rvm.selected = 0;
				}
			} else if (rvm.level == 2 && strcmp (level0_categories[rvm.selected], "flagspaces") == 0 && rvm.selected_flagspace) {
				if (rvm.selected_item > 0) {
					rvm.selected_item--;
				}
			}
			break;
		case 'l':
			if (rvm.level == 0) {
				int max_selected = 0;
				while (level0_categories[max_selected]) {
					max_selected++;
				}
				max_selected--;
				rvm.selected++;
				if (rvm.selected > max_selected) {
					rvm.selected = max_selected;
				}
			} else if (rvm.level == 2 && strcmp (level0_categories[rvm.selected], "flagspaces") == 0 && rvm.selected_flagspace) {
				rvm.selected_item++;
				// Bounds checking will be done in refresh or mouse handling
			}
			break;
		case 'd':
			if (rvm.level == 2 && strcmp (level0_categories[rvm.selected], "flagspaces") == 0 && rvm.selected_flagspace) {
				// Go to disassembly of selected flag
				RList *all_flags = r_flag_all_list (rvm.core->flags, true);
				if (all_flags) {
					RListIter *iter;
					RFlagItem *flag;
					int count = 0;
					r_list_foreach (all_flags, iter, flag) {
						if (flag->space && strcmp (flag->space->name, rvm.selected_flagspace) == 0) {
							if (count == rvm.selected_item) {
								rvm.selected_addr = flag->addr;
								free (rvm.selected_flagspace);
								rvm.selected_flagspace = NULL;
								break;
							}
							count++;
						}
					}
					r_list_free (all_flags);
				}
			} else if (rvm.level < 2) {
				// Set selected_addr or selected_flagspace based on current selection before entering level 2
				if (rvm.level == 1) {
					const char *cat = level0_categories[rvm.selected];
					if (strcmp (cat, "functions") == 0) {
						RListIter *iter;
						RAnalFunction *f;
						RList *fcns = rvm.core->anal->fcns;
						int count = 0;
						r_list_foreach (fcns, iter, f) {
							if (count == rvm.selected_item) {
								rvm.selected_addr = f->addr;
								break;
							}
							count++;
						}
					} else if (strcmp (cat, "flagspaces") == 0) {
						// For flagspaces, set the selected flagspace
						RSpace *space;
						RSpaceIter *it;
						int count = 0;
						r_flag_space_foreach (rvm.core->flags, it, space) {
							if (count == rvm.selected_item) {
								free (rvm.selected_flagspace);
								rvm.selected_flagspace = strdup (space->name);
								break;
							}
							count++;
						}
					} else if (strcmp (cat, "flags") == 0) {
						RListIter *iter;
						RFlagItem *flag;
						const RList *flags = r_flag_get_list (rvm.core->flags, 0);
						int count = 0;
						r_list_foreach (flags, iter, flag) {
							if (count == rvm.selected_item) {
								rvm.selected_addr = flag->addr;
								break;
							}
							count++;
						}
					} else if (strcmp (cat, "symbols") == 0) {
						RBinSymbol *sym;
						RListIter *iter;
						const RList *symbols = r_bin_get_symbols (rvm.core->bin);
						int count = 0;
						r_list_foreach (symbols, iter, sym) {
							if (count == rvm.selected_item) {
								rvm.selected_addr = sym->vaddr;
								break;
							}
							count++;
						}
					} else if (strcmp (cat, "sections") == 0) {
						RBinSection *section;
						RListIter *iter;
						const RList *sections = r_bin_get_sections (rvm.core->bin);
						int count = 0;
						r_list_foreach (sections, iter, section) {
							if (count == rvm.selected_item) {
								rvm.selected_addr = section->vaddr;
								break;
							}
							count++;
						}
					}
					// For imports, keep current address
				}
				rvm.level++;
				clamp_scroll_position (&rvm);
			}
			break;
		case '\n': // Enter key - alias for 'd'
			if (rvm.level == 2 && strcmp (level0_categories[rvm.selected], "flagspaces") == 0 && rvm.selected_flagspace) {
				// Go to disassembly of selected flag
				RList *all_flags = r_flag_all_list (rvm.core->flags, true);
				if (all_flags) {
					RListIter *iter;
					RFlagItem *flag;
					int count = 0;
					r_list_foreach (all_flags, iter, flag) {
						if (flag->space && strcmp (flag->space->name, rvm.selected_flagspace) == 0) {
							if (count == rvm.selected_item) {
								rvm.selected_addr = flag->addr;
								free (rvm.selected_flagspace);
								rvm.selected_flagspace = NULL;
								break;
							}
							count++;
						}
					}
					r_list_free (all_flags);
				}
			} else if (rvm.level < 2) {
				// Set selected_addr or selected_flagspace based on current selection before entering level 2
				if (rvm.level == 1) {
					const char *cat = level0_categories[rvm.selected];
					if (strcmp (cat, "functions") == 0) {
						RListIter *iter;
						RAnalFunction *f;
						RList *fcns = rvm.core->anal->fcns;
						int count = 0;
						r_list_foreach (fcns, iter, f) {
							if (count == rvm.selected_item) {
								rvm.selected_addr = f->addr;
								break;
							}
							count++;
						}
					} else if (strcmp (cat, "flagspaces") == 0) {
						// For flagspaces, set the selected flagspace
						RSpace *space;
						RSpaceIter *it;
						int count = 0;
						r_flag_space_foreach (rvm.core->flags, it, space) {
							if (count == rvm.selected_item) {
								free (rvm.selected_flagspace);
								rvm.selected_flagspace = strdup (space->name);
								break;
							}
							count++;
						}
					} else if (strcmp (cat, "flags") == 0) {
						RListIter *iter;
						RFlagItem *flag;
						const RList *flags = r_flag_get_list (rvm.core->flags, 0);
						int count = 0;
						r_list_foreach (flags, iter, flag) {
							if (count == rvm.selected_item) {
								rvm.selected_addr = flag->addr;
								break;
							}
							count++;
						}
					} else if (strcmp (cat, "symbols") == 0) {
						RBinSymbol *sym;
						RListIter *iter;
						const RList *symbols = r_bin_get_symbols (rvm.core->bin);
						int count = 0;
						r_list_foreach (symbols, iter, sym) {
							if (count == rvm.selected_item) {
								rvm.selected_addr = sym->vaddr;
								break;
							}
							count++;
						}
					} else if (strcmp (cat, "sections") == 0) {
						RBinSection *section;
						RListIter *iter;
						const RList *sections = r_bin_get_sections (rvm.core->bin);
						int count = 0;
						r_list_foreach (sections, iter, section) {
							if (count == rvm.selected_item) {
								rvm.selected_addr = section->vaddr;
								break;
							}
							count++;
						}
					}
					// For imports, keep current address
				}
				switch_level (&rvm, rvm.level + 1);
			}
			break;
		case 'u':
			if (rvm.level > 0) {
				switch_level (&rvm, rvm.level - 1);
				// Clear selected_flagspace when leaving level 2
				if (rvm.level < 2) {
					free (rvm.selected_flagspace);
					rvm.selected_flagspace = NULL;
				}
			}
			break;
		case ':':
			r_core_visual_prompt_input (core);
			break;
		case '!':
			r_core_panels_root (core, core->panels_root);
			break;
		case '\n': // Enter key - alias for 'd'
			if (rvm.level < 2) {
				// Set selected_addr or selected_flagspace based on current selection before entering level 2
				if (rvm.level == 1) {
					const char *cat = level0_categories[rvm.selected];
					if (strcmp (cat, "functions") == 0) {
						RListIter *iter;
						RAnalFunction *f;
						RList *fcns = rvm.core->anal->fcns;
						int count = 0;
						r_list_foreach (fcns, iter, f) {
							if (count == rvm.selected_item) {
								rvm.selected_addr = f->addr;
								break;
							}
							count++;
						}
					} else if (strcmp (cat, "flagspaces") == 0) {
						// For flagspaces, set the selected flagspace
						RSpace *space;
						RSpaceIter *it;
						int count = 0;
						r_flag_space_foreach (rvm.core->flags, it, space) {
							if (count == rvm.selected_item) {
								free (rvm.selected_flagspace);
								rvm.selected_flagspace = strdup (space->name);
								break;
							}
							count++;
						}
					} else if (strcmp (cat, "flags") == 0) {
						RListIter *iter;
						RFlagItem *flag;
						const RList *flags = r_flag_get_list (rvm.core->flags, 0);
						int count = 0;
						r_list_foreach (flags, iter, flag) {
							if (count == rvm.selected_item) {
								rvm.selected_addr = flag->addr;
								break;
							}
							count++;
						}
					} else if (strcmp (cat, "symbols") == 0) {
						RBinSymbol *sym;
						RListIter *iter;
						const RList *symbols = r_bin_get_symbols (rvm.core->bin);
						int count = 0;
						r_list_foreach (symbols, iter, sym) {
							if (count == rvm.selected_item) {
								rvm.selected_addr = sym->vaddr;
								break;
							}
							count++;
						}
					} else if (strcmp (cat, "sections") == 0) {
						RBinSection *section;
						RListIter *iter;
						const RList *sections = r_bin_get_sections (rvm.core->bin);
						int count = 0;
						r_list_foreach (sections, iter, section) {
							if (count == rvm.selected_item) {
								rvm.selected_addr = section->vaddr;
								break;
							}
							count++;
						}
					}
					// For imports, keep current address
				}
				switch_level (&rvm, rvm.level + 1);
			}
			break;
		case '\t': // Tab key - navigate to next item in level 1
			if (rvm.level == 1) {
				rvm.selected_item++;
				// Add bounds checking for selected_item
				int max_items = 0;
				const char *cat = level0_categories[rvm.selected];
				if (strcmp (cat, "functions") == 0) {
					max_items = r_list_length (rvm.core->anal->fcns);
				} else if (strcmp (cat, "flagspaces") == 0) {
					RSpace *space;
					RSpaceIter *it;
					r_flag_space_foreach (rvm.core->flags, it, space) {
 (void)space;
						max_items++;
					}
				} else if (strcmp (cat, "flags") == 0) {
					const RList *flags = r_flag_get_list (rvm.core->flags, 0);
					max_items = r_list_length (flags);
				} else if (strcmp (cat, "symbols") == 0) {
					const RList *symbols = r_bin_get_symbols (rvm.core->bin);
					max_items = r_list_length (symbols);
				} else if (strcmp (cat, "imports") == 0) {
					const RList *imports = r_bin_get_imports (rvm.core->bin);
					max_items = r_list_length (imports);
				} else if (strcmp (cat, "sections") == 0) {
					const RList *sections = r_bin_get_sections (rvm.core->bin);
					max_items = r_list_length (sections);
				} else if (strcmp (cat, "comments") == 0) {
					RIntervalTreeIter it;
					RAnalMetaItem *item;
					r_interval_tree_foreach (&rvm.core->anal->meta, it, item) {
						if (item->type == R_META_TYPE_COMMENT) {
							max_items++;
						}
					}
				}
				if (rvm.selected_item >= max_items) {
					rvm.selected_item = 0; // Wrap around to first item
				}
			} else if (rvm.level == 2 && strcmp (level0_categories[rvm.selected], "flagspaces") == 0 && rvm.selected_flagspace) {
				rvm.selected_item++;
				// Count flags in the selected flagspace for bounds checking
				int max_items = 0;
				RList *all_flags = r_flag_all_list (rvm.core->flags, true);
				if (all_flags) {
					RListIter *iter;
					RFlagItem *flag;
					r_list_foreach (all_flags, iter, flag) {
						if (flag->space && strcmp (flag->space->name, rvm.selected_flagspace) == 0) {
							max_items++;
						}
					}
					r_list_free (all_flags);
				}
				if (rvm.selected_item >= max_items) {
					rvm.selected_item = 0; // Wrap around
				}
			} else if (rvm.level == 0) {
				int max_selected = 0;
				while (level0_categories[max_selected]) {
					max_selected++;
				}
				max_selected--;
				rvm.selected++;
				if (rvm.selected > max_selected) {
					rvm.selected = max_selected;
				}
			}
			break;
		case 'Z': // Shift-Tab alternative - navigate to previous item in level 1
			if (rvm.level == 1) {
				if (rvm.selected_item > 0) {
					rvm.selected_item--;
				} else {
					// Wrap around to last item
					int max_items = 0;
					const char *cat = level0_categories[rvm.selected];
					if (strcmp (cat, "functions") == 0) {
						max_items = r_list_length (rvm.core->anal->fcns);
					} else if (strcmp (cat, "flagspaces") == 0) {
						RSpace *space;
						RSpaceIter *it;
						r_flag_space_foreach (rvm.core->flags, it, space) {
							max_items++;
						}
					} else if (strcmp (cat, "flags") == 0) {
						const RList *flags = r_flag_get_list (rvm.core->flags, 0);
						max_items = r_list_length (flags);
					} else if (strcmp (cat, "symbols") == 0) {
						const RList *symbols = r_bin_get_symbols (rvm.core->bin);
						max_items = r_list_length (symbols);
					} else if (strcmp (cat, "imports") == 0) {
						const RList *imports = r_bin_get_imports (rvm.core->bin);
						max_items = r_list_length (imports);
					} else if (strcmp (cat, "sections") == 0) {
						const RList *sections = r_bin_get_sections (rvm.core->bin);
						max_items = r_list_length (sections);
					} else if (strcmp (cat, "comments") == 0) {
						RIntervalTreeIter it;
						RAnalMetaItem *item;
						r_interval_tree_foreach (&rvm.core->anal->meta, it, item) {
							if (item->type == R_META_TYPE_COMMENT) {
								max_items++;
							}
						}
					}
					if (max_items > 0) {
						rvm.selected_item = max_items - 1;
					}
				}
			} else if (rvm.level == 2 && strcmp (level0_categories[rvm.selected], "flagspaces") == 0 && rvm.selected_flagspace) {
				if (rvm.selected_item > 0) {
					rvm.selected_item--;
				} else {
					// Wrap around to last item
					int max_items = 0;
					RList *all_flags = r_flag_all_list (rvm.core->flags, true);
					if (all_flags) {
						RListIter *iter;
						RFlagItem *flag;
						r_list_foreach (all_flags, iter, flag) {
							if (flag->space && strcmp (flag->space->name, rvm.selected_flagspace) == 0) {
								max_items++;
							}
						}
						r_list_free (all_flags);
					}
					if (max_items > 0) {
						rvm.selected_item = max_items - 1;
					}
				}
			} else if (rvm.level == 0) {
				rvm.selected--;
				if (rvm.selected < 0) {
					rvm.selected = 0;
				}
			}
			break;
		case 'q':
			if (rvm.level > 0) {
				switch_level (&rvm, rvm.level - 1);
				// Clear selected_flagspace when leaving level 2
				if (rvm.level < 2) {
					free (rvm.selected_flagspace);
					rvm.selected_flagspace = NULL;
				}
			} else {
				leave = true;
			}
			break;
		case '/':
			r_core_cmd0 (core, "?i highlight;e scr.highlight=`yp`");
			break;
		case '|': {
			char *input = r_cons_input (core->cons, "Filter: ");
			if (input && *input) {
				free (rvm.filter);
				rvm.filter = strdup (input);
			} else {
				free (rvm.filter);
				rvm.filter = NULL;
			}
			free (input);
		} break;
		case '?':
			vmatrix_show_help (core);
			break;
		default:
			// Handle mouse clicks
			if (ch == 0) { // Mouse event
				int x, y;
				if (r_cons_get_click (core->cons, &x, &y)) {
					// Check if click is on title bar (first line)
					if (y == 0 || y == 1) {
						// Go up one level
						if (rvm.level > 0) {
							switch_level (&rvm, rvm.level - 1);
							// Clear selected_flagspace when leaving level 2
							if (rvm.level < 2) {
								free (rvm.selected_flagspace);
								rvm.selected_flagspace = NULL;
							}
						}
						break;
					}

					// Adjust for title offset (title takes 1 line)
					y -= 1;

					// Check if click is on scrollbar
					int scrollbar_x = rvm.w - 3;
					if (x >= scrollbar_x && x <= scrollbar_x + 2) {
						// Click on scrollbar area
						if (y >= 1 && y < rvm.h - 2) {
							// Calculate scroll position based on click position
							int total_h = rvm.rows * rvm.box_h;
							if (total_h > 0) {
								rvm.scroll_y = (y - 1) * total_h / (rvm.h - 3);
								clamp_scroll_position (&rvm);
							}
						}
					} else if (y >= 0) {
						// Click on boxes
						int boxwidth = (rvm.w - 6) / rvm.cols;
						int clicked_col = x / (boxwidth + 1);
						int clicked_row = (y + rvm.scroll_y) / rvm.box_h;

						if (rvm.level == 0) {
							// Level 0: select category
							int total_boxes = 0;
							while (level0_categories[total_boxes]) {
								total_boxes++;
							}

							if (clicked_col < rvm.cols && clicked_row >= 0) {
								int box_index = clicked_row * rvm.cols + clicked_col;
								if (box_index >= 0 && box_index < total_boxes) {
									if (rvm.selected == box_index) {
										// Same box clicked again, go down one level
										switch_level (&rvm, rvm.level + 1);
									} else {
										// Different box clicked, just select it
										rvm.selected = box_index;
									}
								}
							}
						} else if (rvm.level == 1) {
							// Level 1: select item
							int clicked_item = clicked_row * rvm.cols + clicked_col;
							if (clicked_item >= 0 && clicked_item < rvm.rows) {
								if (rvm.selected_item == clicked_item) {
									// Same item clicked again, go down one level
									// Set selected_addr or selected_flagspace based on current selection before entering level 2
									const char *cat = level0_categories[rvm.selected];
									if (strcmp (cat, "functions") == 0) {
										RListIter *iter;
										RAnalFunction *f;
										RList *fcns = rvm.core->anal->fcns;
										int count = 0;
										r_list_foreach (fcns, iter, f) {
											if (count == rvm.selected_item) {
												rvm.selected_addr = f->addr;
												break;
											}
											count++;
										}
									} else if (strcmp (cat, "flagspaces") == 0) {
										// For flagspaces, set the selected flagspace
										RSpace *space;
										RSpaceIter *it;
										int count = 0;
										r_flag_space_foreach (rvm.core->flags, it, space) {
											if (count == rvm.selected_item) {
												free (rvm.selected_flagspace);
												rvm.selected_flagspace = strdup (space->name);
												break;
											}
											count++;
										}
 (void)space;
									} else if (strcmp (cat, "flags") == 0) {
										RListIter *iter;
										RFlagItem *flag;
										const RList *flags = r_flag_get_list (rvm.core->flags, 0);
										int count = 0;
										r_list_foreach (flags, iter, flag) {
											if (count == rvm.selected_item) {
												rvm.selected_addr = flag->addr;
												break;
											}
											count++;
										}
									} else if (strcmp (cat, "symbols") == 0) {
										RBinSymbol *sym;
										RListIter *iter;
										const RList *symbols = r_bin_get_symbols (rvm.core->bin);
										int count = 0;
										r_list_foreach (symbols, iter, sym) {
											if (count == rvm.selected_item) {
												rvm.selected_addr = sym->vaddr;
												break;
											}
											count++;
										}
									} else if (strcmp (cat, "sections") == 0) {
										RBinSection *section;
										RListIter *iter;
										const RList *sections = r_bin_get_sections (rvm.core->bin);
										int count = 0;
										r_list_foreach (sections, iter, section) {
											if (count == rvm.selected_item) {
												rvm.selected_addr = section->vaddr;
												break;
											}
											count++;
										}
									} else if (strcmp (cat, "comments") == 0) {
										RIntervalTreeIter it;
										RAnalMetaItem *item;
										int count = 0;
										r_interval_tree_foreach (&rvm.core->anal->meta, it, item) {
											if (item->type != R_META_TYPE_COMMENT) {
												continue;
											}
											if (count == rvm.selected_item) {
												rvm.selected_addr = r_interval_tree_iter_get (&it)->start;
												break;
											}
											count++;
										}
									}
									// For imports, keep current address
									switch_level (&rvm, rvm.level + 1);
								} else {
									// Different item clicked, just select it
									rvm.selected_item = clicked_item;
								}
							}
						} else if (rvm.level == 2 && strcmp (level0_categories[rvm.selected], "flagspaces") == 0) {
							// Level 2 flagspaces: select flag
							int clicked_item = clicked_row * rvm.cols + clicked_col;
							if (clicked_item >= 0 && clicked_item < rvm.rows) {
								if (rvm.selected_item == clicked_item) {
									// Same flag clicked again, go to disassembly
									RList *all_flags = r_flag_all_list (rvm.core->flags, true);
									if (all_flags) {
										RListIter *iter;
										RFlagItem *flag;
										int count = 0;
										r_list_foreach (all_flags, iter, flag) {
											if (flag->space && strcmp (flag->space->name, rvm.selected_flagspace) == 0) {
												if (count == clicked_item) {
													rvm.selected_addr = flag->addr;
													free (rvm.selected_flagspace);
													rvm.selected_flagspace = NULL;
													break;
												}
												count++;
											}
										}
										r_list_free (all_flags);
									}
								} else {
									// Different flag clicked, just select it
									rvm.selected_item = clicked_item;
								}
							}
						}
					}
				}
			}
			break;
		}

		// Refresh the display after each key press
		vmatrix_refresh (&rvm);
	}

	// Restore original event callbacks
	core->cons->event_resize = old_event_resize;
	core->cons->context->event_interrupt = old_event_interrupt;
	core->cons->event_data = old_event_data;
	g_rvm = NULL; // Clear global pointer

	r_cons_enable_mouse (core->cons, false);
	r_cons_set_raw (core->cons, false);
	free (rvm.selected_flagspace);
	free (rvm.filter);
}
