/* radare - LGPL - Copyright 2025 - pancake */

#include <r_core.h>

static const char *level0_categories[] = {
	"flags", "flagspaces", "functions", "symbols", "imports", "comments", NULL
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
	int scroll_y;
	int level; // Current navigation level (0, 1, 2)
	int selected; // Selected box index
	int selected_item; // Selected item index within category (for level 1)
	ut64 selected_addr; // Selected address for disassembly
} RVMatrix;

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
			snprintf(title, sizeof(title), "%s", cat);
		} else {
			snprintf(title, sizeof(title), "unknown");
		}
		break;
	case 1:
		if (cat) {
			snprintf(title, sizeof(title), "%s [%d]", cat, rvm->selected_item);
		} else {
			snprintf(title, sizeof(title), "unknown [%d]", rvm->selected_item);
		}
		break;
	case 2:
		snprintf(title, sizeof(title), "0x%" PFMT64x, rvm->selected_addr);
		break;
	default:
		snprintf(title, sizeof(title), "unknown");
		break;
	}

	return title;
}

static void draw_scrollbar(RVMatrix *rvm) {
	RConsCanvas *can = rvm->can;
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
		r_cons_canvas_write_at(can, box, w, i);
	}
	r_cons_canvas_write_at(can, "[^]", w, 0);
	r_cons_canvas_write_at(can, Color_INVERT "[v]" Color_RESET, w, h - 1);
}

static void draw_level0_boxes(RVMatrix *rvm) {
	RConsCanvas *can = rvm->can;
	int w = rvm->w - 6;
	int boxwidth = w / rvm->cols;
	int xpos = 0;
	int ypos = -rvm->scroll_y;
	int col = 0;
	int i = 0;

	while (level0_categories[i]) {
		const char *cat = level0_categories[i];
		const char *color = (i == rvm->selected) ? Color_RED : "";
		r_cons_canvas_box(can, xpos, ypos, boxwidth, rvm->box_h, color);
		char *title = r_str_ndup(cat, boxwidth - 4);
		r_cons_canvas_write_at(can, title, xpos + 2, ypos + 1);
		free(title);
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

static void draw_level1_list(RVMatrix *rvm) {
	RConsCanvas *can = rvm->can;
	const char *cat = level0_categories[rvm->selected];
	char title[256];
	snprintf(title, sizeof(title), "%s - %s", cat, "list");
	r_cons_canvas_write_at(can, title, 0, 0);

	int ypos = 2;
	int max_items = 20; // Limit for display
	int item_count = 0;

	if (strcmp(cat, "functions") == 0) {
		RListIter *iter;
		RAnalFunction *f;
		RList *fcns = rvm->core->anal->fcns;
		r_list_foreach (fcns, iter, f) {
			if (item_count >= max_items) {
				break;
			}
			char item[256];
			snprintf(item, sizeof(item), "0x%" PFMT64x " %s", f->addr, f->name);
			r_cons_canvas_write_at(can, item, 2, ypos++);
			item_count++;
		}
	} else if (strcmp(cat, "flags") == 0) {
		RListIter *iter;
		RFlagItem *flag;
		const RList *flags = r_flag_get_list(rvm->core->flags, 0);
		r_list_foreach (flags, iter, flag) {
			if (item_count >= max_items) {
				break;
			}
			char item[256];
			snprintf(item, sizeof(item), "0x%" PFMT64x " %s", flag->addr, flag->name);
			r_cons_canvas_write_at(can, item, 2, ypos++);
			item_count++;
		}
	} else if (strcmp(cat, "symbols") == 0) {
		RBinSymbol *sym;
		RListIter *iter;
		const RList *symbols = r_bin_get_symbols(rvm->core->bin);
		r_list_foreach (symbols, iter, sym) {
			if (item_count >= max_items) {
				break;
			}
			char item[256];
			snprintf(item, sizeof(item), "0x%" PFMT64x " %s", sym->vaddr, r_bin_name_tostring(sym->name));
			r_cons_canvas_write_at(can, item, 2, ypos++);
			item_count++;
		}
	} else if (strcmp(cat, "imports") == 0) {
		RBinImport *imp;
		RListIter *iter;
		const RList *imports = r_bin_get_imports(rvm->core->bin);
		r_list_foreach (imports, iter, imp) {
			if (item_count >= max_items) {
				break;
			}
			char item[256];
			snprintf(item, sizeof(item), "0x%08" PFMT64x " %s", (ut64)0, r_bin_name_tostring(imp->name));
			r_cons_canvas_write_at(can, item, 2, ypos++);
			item_count++;
		}
	} else {
		r_cons_canvas_write_at(can, "Category not implemented yet", 2, ypos);
	}
}

static void draw_level2_disassembly(RVMatrix *rvm) {
	RConsCanvas *can = rvm->can;
	int disasm_w = (rvm->w * 70) / 100;
	int disasm_h = (rvm->h * 90) / 100;
	int disasm_x = (rvm->w - disasm_w) / 2;
	int disasm_y = (rvm->h - disasm_h) / 2;

	r_cons_canvas_box(can, disasm_x, disasm_y, disasm_w, disasm_h, Color_BLUE);
	char title[256];
	snprintf(title, sizeof(title), "Disassembly at 0x%" PFMT64x, rvm->selected_addr);
	r_cons_canvas_write_at(can, title, disasm_x + 2, disasm_y + 1);

	// Get disassembly content
	RCore *core = rvm->core;
	char *disasm = r_core_cmd_strf(core, "pd 20 @ 0x%" PFMT64x, rvm->selected_addr);
	if (disasm) {
		char *line = disasm;
		char *next_line;
		int line_y = disasm_y + 3;
		int max_lines = disasm_h - 4;

		for (int i = 0; i < max_lines && line; i++) {
			next_line = strchr(line, '\n');
			if (next_line) {
				*next_line = '\0';
				next_line++;
			}
			if (strlen(line) > 0) {
				r_cons_canvas_write_at(can, line, disasm_x + 2, line_y++);
			}
			line = next_line;
		}
		free(disasm);
	}
}

static void vmatrix_refresh(RVMatrix *rvm) {
	RCons *cons = rvm->core->cons;
	int h, w = r_cons_get_size(cons, &h);
	rvm->h = h;
	rvm->w = w;

	// Ensure scroll position is within valid bounds
	clamp_scroll_position(rvm);
	RConsCanvas *can = r_cons_canvas_new(cons, w, h - 1, -2);
	rvm->can = can;

	switch (rvm->level) {
	case 0:
		draw_level0_boxes(rvm);
		break;
	case 1:
		draw_level1_list(rvm);
		break;
	case 2:
		draw_level2_disassembly(rvm);
		break;
	}

	if (rvm->level == 0) {
		draw_scrollbar(rvm);
	}

	char *s = r_cons_canvas_tostring(can);
	r_cons_clear00(cons);
	char *selected_title = get_selected_box_title(rvm);
	const char *cursor_status = rvm->core->print->cur_enabled ? "CURSOR" : "NORMAL";
	r_cons_printf(cons, "[0x%08" PFMT64x " Level:%d Cols:%d %s | %s]\n%s",
		rvm->core->addr, rvm->level, rvm->cols, cursor_status, selected_title, s);
	r_cons_visual_flush(cons);
	free(s);
	r_cons_canvas_free(can);
	rvm->can = NULL;
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
	};
	r_cons_set_raw(core->cons, true);
	r_cons_enable_mouse(core->cons, r_config_get_i(core->config, "scr.wheel"));
	bool leave = false;
	while (!leave) {
		vmatrix_refresh(&rvm);
		char ch = r_cons_readchar(core->cons);
		ch = r_cons_arrow_to_hjkl(core->cons, ch);
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
			clamp_scroll_position(&rvm);
			break;
		case '[':
			if (rvm.cols > 1) {
				rvm.cols--;
				clamp_scroll_position(&rvm);
			}
			break;
		case ']':
			if (rvm.cols < 9) {
				rvm.cols++;
				clamp_scroll_position(&rvm);
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
			if (rvm.level == 2) {
				// Scroll disassembly down
				rvm.selected_addr += 4; // Simple scroll by instruction
			} else {
				rvm.scroll_y++;
				clamp_scroll_position(&rvm);
			}
			break;
		case 'k':
			if (rvm.level == 2) {
				// Scroll disassembly up
				if (rvm.selected_addr >= 4) {
					rvm.selected_addr -= 4; // Simple scroll by instruction
				}
			} else {
				rvm.scroll_y--;
				clamp_scroll_position(&rvm);
			}
			break;
		case 'J':
			rvm.scroll_y += rvm.box_h;
			clamp_scroll_position(&rvm);
			break;
		case 'K':
			rvm.scroll_y -= rvm.box_h;
			clamp_scroll_position(&rvm);
			break;
		case 'g':
			rvm.scroll_y = 0;
			break;
		case 'G':
			rvm.scroll_y = rvm.rows * rvm.box_h - 1;
			clamp_scroll_position(&rvm);
			break;
		case 'h':
			if (rvm.level == 0) {
				rvm.selected--;
				if (rvm.selected < 0) {
					rvm.selected = 0;
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
			}
			break;
		case 'd':
			if (rvm.level < 2) {
				rvm.level++;
				clamp_scroll_position(&rvm);
			}
			break;
		case 'u':
			if (rvm.level > 0) {
				rvm.level--;
				clamp_scroll_position(&rvm);
			}
			break;
		case ':':
			r_core_visual_prompt_input(core);
			break;
		case '\n': // Enter key - alias for 'd'
			if (rvm.level < 2) {
				rvm.level++;
				clamp_scroll_position(&rvm);
			}
			break;
		case '\t': // Tab key - alias for 'l'
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
			}
			break;
		case 'q':
			if (rvm.level > 0) {
				rvm.level--;
			} else {
				leave = true;
			}
			break;
		default:
			// Handle mouse clicks
			if (ch == 0) { // Mouse event
				int x, y;
				if (r_cons_get_click(core->cons, &x, &y)) {
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
								clamp_scroll_position(&rvm);
							}
						}
					} else if (rvm.level == 0 && y >= 0) {
						// Click on boxes (only in level 0)
						int boxwidth = (rvm.w - 6) / rvm.cols;
						int clicked_col = x / (boxwidth + 1);
						int clicked_row = (y + rvm.scroll_y) / rvm.box_h;
						int total_boxes = 0;
						while (level0_categories[total_boxes]) {
							total_boxes++;
						}

						if (clicked_col < rvm.cols && clicked_row >= 0) {
							int box_index = clicked_row * rvm.cols + clicked_col;
							if (box_index >= 0 && box_index < total_boxes) {
								rvm.selected = box_index;
								// Go down into the selected box (like pressing 'd')
								if (rvm.level < 2) {
									rvm.level++;
									clamp_scroll_position(&rvm);
								}
							}
						}
					}
				}
			}
			break;
		}
	}
	r_cons_enable_mouse(core->cons, false);
	r_cons_set_raw(core->cons, false);
}
