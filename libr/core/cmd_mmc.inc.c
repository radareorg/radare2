/* radare - LGPL - Copyright 2025 - MiKi (mikelloc) */

#if R_INCLUDE_BEGIN

#include <r_core.h>

#define MMC_COLOR_BG_FG        "\x1b[34m"
#define MMC_COLOR_BG_BLUE      "\x1b[44m"
#define MMC_COLOR_BG_CYAN      "\x1b[46m"
#define MMC_COLOR_FG           "\x1b[37m"
#define MMC_COLOR_FG_BLACK     "\x1b[30m"
#define MMC_COLOR_FG_YELLOW    "\x1b[33m"
#define MMC_COLOR_FG_RED       "\x1b[31m"
#define MMC_COLOR_SELECT_FG    "\x1b[36m"
#define MMC_COLOR_SELECT       "\x1b[46;30m"
#define MMC_COLOR_DIR          "\x1b[1;37m"
#define MMC_COLOR_FILE         "\x1b[37m"
#define MMC_COLOR_FRAME        "\x1b[36m"
#define MMC_COLOR_TITLE        "\x1b[1;33m"
#define MMC_COLOR_HOTKEY       "\x1b[1;33m"
#define MMC_COLOR_BOLD_CYAN    "\x1b[1;36m"
#define MMC_COLOR_RESET        "\x1b[0m"

#define MMC_GET_BG(state) ((state)->use_r2_theme ? (state)->core->cons->context->pal.widget_bg : MMC_COLOR_BG_BLUE)
#define MMC_GET_BG_PANE(state) ((state)->use_r2_theme ? (state)->core->cons->context->pal.gui_background : MMC_COLOR_BG_FG)
#define MMC_GET_SEL_BG(state) ((state)->use_r2_theme ? (state)->core->cons->context->pal.widget_sel : MMC_COLOR_BG_CYAN)
#define MMC_GET_SEL_FG(state) ((state)->use_r2_theme ? (state)->core->cons->context->pal.linehl : MMC_COLOR_SELECT_FG)
#define MMC_GET_FG(state) ((state)->use_r2_theme ? (state)->core->cons->context->pal.btext : MMC_COLOR_FG)
#define MMC_GET_FG_BLACK(state) ((state)->use_r2_theme ? (state)->core->cons->context->pal.other : MMC_COLOR_FG_BLACK)
#define MMC_GET_FG_YELLOW(state) ((state)->use_r2_theme ? (state)->core->cons->context->pal.num : MMC_COLOR_FG_YELLOW)
#define MMC_GET_FG_RED(state) ((state)->use_r2_theme ? (state)->core->cons->context->pal.invalid : MMC_COLOR_FG_RED)
#define MMC_GET_TITLE(state) ((state)->use_r2_theme ? (state)->core->cons->context->pal.prompt : MMC_COLOR_TITLE)
#define MMC_GET_DIR(state) ((state)->use_r2_theme ? (state)->core->cons->context->pal.fname : MMC_COLOR_DIR)
#define MMC_GET_BOLD_CYAN(state) ((state)->use_r2_theme ? (state)->core->cons->context->pal.addr : MMC_COLOR_BOLD_CYAN)
#define MMC_GET_RESET(state) ((state)->use_r2_theme ? (state)->core->cons->context->pal.reset : MMC_COLOR_RESET)

typedef enum {
	MMC_ORDER_NATURAL,
	MMC_ORDER_ALPHA,
	MMC_ORDER_SIZE
} MMCOrderMode;

typedef struct {
	char **entries;
	char *types;
	int count;
	int selected;
	int scroll_offset;
	char *path;
	bool is_fs_panel;
} MMCPanel;

typedef struct {
	RCore *core;
	MMCPanel left;
	MMCPanel right;
	MMCPanel *active;
	int width;
	int height;
	bool running;
	bool use_r2_theme;
	char *clipboard_path;
	bool clipboard_cut;
	MMCOrderMode ordering_mode;
} MMCState;

static void mmc_panel_sort(MMCPanel *panel, MMCOrderMode mode);
static void mmc_view_file(RCore *core, MMCState *state);

static void mmc_panel_free(MMCPanel *panel) {
	int i;
	if (panel->entries) {
		for (i = 0; i < panel->count; i++) {
			free (panel->entries[i]);
		}
		free (panel->entries);
	}
	free (panel->types);
	free (panel->path);
}

static void mmc_panel_load_fs(RCore *core, MMCPanel *panel, MMCOrderMode ordering_mode) {
	int i, start_idx = 0, fs_count, idx;
	RList *list;
	RListIter *iter;
	RFSFile *file;
	RFSRoot *root;
	char *base, *ls;

	if (panel->entries) {
		for (i = 0; i < panel->count; i++) {
			free (panel->entries[i]);
		}
		free (panel->entries);
	}
	free (panel->types);

	panel->entries = NULL;
	panel->types = NULL;
	panel->count = 0;
	panel->selected = 0;
	panel->scroll_offset = 0;

	if (strcmp (panel->path, "/") != 0) {
		panel->count = 1;
		panel->entries = R_NEWS (char *, 1);
		panel->types = R_NEWS (char, 1);
		panel->entries[0] = strdup ("..");
		panel->types[0] = 'd';
		start_idx = 1;
	}

	list = r_fs_dir (core->fs, panel->path);
	if (list) {
		fs_count = r_list_length (list);
		panel->count += fs_count;
		panel->entries = realloc (panel->entries, sizeof (char *) * panel->count);
		panel->types = realloc (panel->types, panel->count);

		idx = start_idx;
		r_list_foreach (list, iter, file) {
			panel->entries[idx] = strdup (file->name);
			panel->types[idx] = file->type;
			idx++;
		}
		r_list_free (list);
	}

	r_list_foreach (core->fs->roots, iter, root) {
		if (!strncmp (panel->path, root->path, strlen (panel->path))) {
			base = strdup (root->path);
			ls = (char *)r_str_lchr (base, '/');
			if (ls) {
				ls++;
				*ls = 0;
			}
			if (!strcmp (panel->path, base)) {
				panel->count++;
				panel->entries = realloc (panel->entries, sizeof (char *) * panel->count);
				panel->types = realloc (panel->types, panel->count);
				panel->entries[panel->count - 1] = strdup (root->path);
				panel->types[panel->count - 1] = 'm';
			}
			free (base);
		}
	}

	mmc_panel_sort (panel, ordering_mode);
}

static void mmc_panel_load_local(RCore *core, MMCPanel *panel, MMCOrderMode ordering_mode) {
	int i, start_idx = 0, valid_count, idx;
	RList *files;
	RListIter *iter;
	const char *name;
	char *fullpath;

	if (panel->entries) {
		for (i = 0; i < panel->count; i++) {
			free (panel->entries[i]);
		}
		free (panel->entries);
	}
	free (panel->types);

	panel->entries = NULL;
	panel->types = NULL;
	panel->count = 0;
	panel->selected = 0;
	panel->scroll_offset = 0;

	if (strcmp (panel->path, "/") != 0 && strcmp (panel->path, "") != 0) {
		panel->count = 1;
		panel->entries = R_NEWS (char *, 1);
		panel->types = R_NEWS (char, 1);
		panel->entries[0] = strdup ("..");
		panel->types[0] = 'd';
		start_idx = 1;
	}

	files = r_sys_dir (panel->path);
	if (files) {
		valid_count = 0;
		r_list_foreach (files, iter, name) {
			if (!strcmp (name, ".") || !strcmp (name, "..")) {
				continue;
			}
			valid_count++;
		}

		panel->count += valid_count;
		panel->entries = realloc (panel->entries, sizeof (char *) * panel->count);
		panel->types = realloc (panel->types, panel->count);

		idx = start_idx;
		r_list_foreach (files, iter, name) {
			if (!strcmp (name, ".") || !strcmp (name, "..")) {
				continue;
			}
			panel->entries[idx] = strdup (name);
			fullpath = r_str_newf ("%s/%s", panel->path, name);
			panel->types[idx] = r_file_is_directory (fullpath) ? 'd' : 'f';
			free (fullpath);
			idx++;
		}
		r_list_free (files);
	}

	mmc_panel_sort (panel, ordering_mode);
}

static void mmc_panel_sort(MMCPanel *panel, MMCOrderMode mode) {
	int i, j, start = 0;
	bool swap;
	char *tmp_entry;
	char tmp_type;

	if (!panel->entries || panel->count <= 1) {
		return;
	}

	if (mode == MMC_ORDER_NATURAL) {
		return;
	}

	// r_sort doesn't support parallel array sorting, use bubble sort to keep types array in sync
	if (panel->count > 0 && !strcmp (panel->entries[0], "..")) {
		start = 1;
	}

	if (mode == MMC_ORDER_ALPHA) {
		for (i = start; i < panel->count - 1; i++) {
			for (j = start; j < panel->count - 1 - (i - start); j++) {
				if (strcmp (panel->entries[j], panel->entries[j + 1]) > 0) {
					tmp_entry = panel->entries[j];
					panel->entries[j] = panel->entries[j + 1];
					panel->entries[j + 1] = tmp_entry;
					tmp_type = panel->types[j];
					panel->types[j] = panel->types[j + 1];
					panel->types[j + 1] = tmp_type;
				}
			}
		}
	} else if (mode == MMC_ORDER_SIZE) {
		for (i = start; i < panel->count - 1; i++) {
			for (j = start; j < panel->count - 1 - (i - start); j++) {
				swap = false;
				if (panel->types[j] != 'd' && panel->types[j + 1] == 'd') {
					swap = true;
				} else if (panel->types[j] == panel->types[j + 1]) {
					if (strcmp (panel->entries[j], panel->entries[j + 1]) > 0) {
						swap = true;
					}
				}
				if (swap) {
					tmp_entry = panel->entries[j];
					panel->entries[j] = panel->entries[j + 1];
					panel->entries[j + 1] = tmp_entry;
					tmp_type = panel->types[j];
					panel->types[j] = panel->types[j + 1];
					panel->types[j + 1] = tmp_type;
				}
			}
		}
	}
}

static void mmc_cycle_ordering(MMCState *state) {
	RCore *core = state->core;

	switch (state->ordering_mode) {
	case MMC_ORDER_NATURAL:
		state->ordering_mode = MMC_ORDER_ALPHA;
		break;
	case MMC_ORDER_ALPHA:
		state->ordering_mode = MMC_ORDER_SIZE;
		break;
	case MMC_ORDER_SIZE:
		state->ordering_mode = MMC_ORDER_NATURAL;
		break;
	}

	mmc_panel_load_fs (core, &state->left, state->ordering_mode);
	mmc_panel_load_local (core, &state->right, state->ordering_mode);
}

static void mmc_panel_draw(RCore *core, RConsCanvas *canvas, MMCPanel *panel, MMCState *state, int x, int y, int w, int h, bool active) {
	int max_title_len, title_x, max_visible, end_idx, i, line_y;
	char *safe_path, *colored_title, *indicator, *count_str, *line;
	bool is_selected;
	const char *name, *text_color, *bg_color;
	char type_char;

	r_cons_canvas_bgfill (canvas, x + 1, y + 1, w - 2, h - 2, MMC_GET_BG_PANE(state));
	r_cons_canvas_box (canvas, x, y, w, h, core->cons->context->pal.graph_box);

	max_title_len = w - 10;
	if (max_title_len < 3) {
		max_title_len = 3;
	}

	safe_path = r_str_ndup (panel->path, max_title_len);
	if (!safe_path) {
		safe_path = strdup ("?");
	}

	title_x = x + 2;
	colored_title = r_str_newf ("%s%s%s%s", MMC_GET_BG(state), MMC_GET_TITLE(state), safe_path, MMC_GET_RESET(state));
	r_cons_canvas_write_at (canvas, colored_title, title_x, y);
	free (colored_title);
	free (safe_path);

	if (active) {
		indicator = r_str_newf ("%s%s>%s", MMC_GET_BG(state), MMC_GET_TITLE(state), MMC_GET_RESET(state));
		r_cons_canvas_write_at (canvas, indicator, x, y);
		free (indicator);
	}

	count_str = r_str_newf ("%s%s(%d)%s", MMC_GET_BG(state), MMC_GET_FG(state), panel->count, MMC_GET_RESET(state));
	r_cons_canvas_write_at (canvas, count_str, x + w - 6, y);
	free (count_str);

	max_visible = h - 2;
	end_idx = R_MIN (panel->scroll_offset + max_visible, panel->count);

	for (i = panel->scroll_offset; i < end_idx; i++) {
		line_y = y + 1 + (i - panel->scroll_offset);
		is_selected = (i == panel->selected);

		name = panel->entries[i];
		type_char = panel->types[i];

		text_color = (type_char == 'd' || type_char == 'm') ? MMC_GET_DIR(state) : MMC_GET_FG(state);

		if (is_selected) {
			r_cons_canvas_bgfill (canvas, x + 1, line_y, w - 2, 1, MMC_GET_SEL_FG(state));
			bg_color = MMC_GET_SEL_BG(state);
			text_color = MMC_GET_FG_BLACK(state);
		} else {
			bg_color = MMC_GET_BG(state);
		}

		line = NULL;
		if (type_char == 'd' || type_char == 'm') {
			line = r_str_newf ("%s%s%-*s/%s", bg_color, text_color, w - 4, name, MMC_GET_RESET(state));
		} else {
			line = r_str_newf ("%s%s%-*s%s", bg_color, text_color, w - 3, name, MMC_GET_RESET(state));
		}

		r_cons_canvas_write_at (canvas, line, x + 1, line_y);
		free (line);
	}
}

static void mmc_panel_navigate_up(MMCPanel *panel, int visible_lines) {
	if (panel->selected > 0) {
		panel->selected--;
		if (panel->selected < panel->scroll_offset) {
			panel->scroll_offset = panel->selected;
		}
	}
}

static void mmc_panel_navigate_down(MMCPanel *panel, int visible_lines) {
	if (panel->selected < panel->count - 1) {
		panel->selected++;
		if (panel->selected >= panel->scroll_offset + visible_lines) {
			panel->scroll_offset = panel->selected - visible_lines + 1;
		}
	}
}

static void mmc_panel_navigate_enter(RCore *core, MMCPanel *panel, MMCOrderMode ordering_mode, MMCState *state) {
	if (panel->count == 0 || panel->selected >= panel->count) {
		return;
	}

	char *selected_name = panel->entries[panel->selected];
	char type = panel->types[panel->selected];

	if (type != 'd' && type != 'm') {
		mmc_view_file (core, state);
		return;
	}

	if (!strcmp (selected_name, "..")) {
		char *slash = (char *)r_str_rchr (panel->path, NULL, '/');
		if (slash && slash != panel->path) {
			*slash = 0;
		} else {
			free (panel->path);
			panel->path = strdup ("/");
		}
	} else {
		char *new_path;
		if (!strcmp (panel->path, "/")) {
			new_path = r_str_newf ("/%s", selected_name);
		} else {
			new_path = r_str_newf ("%s/%s", panel->path, selected_name);
		}
		free (panel->path);
		panel->path = new_path;
	}

	if (panel->is_fs_panel) {
		mmc_panel_load_fs (core, panel, ordering_mode);
	} else {
		mmc_panel_load_local (core, panel, ordering_mode);
	}
}

static void mmc_move_file(RCore *core, MMCState *state) {
	MMCPanel *src = state->active;
	MMCPanel *dst = (state->active == &state->left) ? &state->right : &state->left;

	if (src->count == 0 || src->selected >= src->count) {
		r_cons_message (core->cons, "No file selected");
		return;
	}

	char *selected_name = src->entries[src->selected];
	if (!strcmp (selected_name, "..")) {
		r_cons_message (core->cons, "Cannot move parent directory");
		return;
	}

	char *src_path;
	if (!strcmp (src->path, "/")) {
		src_path = r_str_newf ("/%s", selected_name);
	} else {
		src_path = r_str_newf ("%s/%s", src->path, selected_name);
	}

	char *dst_path;
	if (!strcmp (dst->path, "/")) {
		dst_path = r_str_newf ("/%s", selected_name);
	} else {
		dst_path = r_str_newf ("%s/%s", dst->path, selected_name);
	}

	char *msg = r_str_newf ("Move: %s -> %s (not implemented yet)", src_path, dst_path);
	r_cons_message (core->cons, msg);
	free (msg);
	free (src_path);
	free (dst_path);
}

static void mmc_view_file(RCore *core, MMCState *state) {
	MMCPanel *panel = state->active;
	char *selected_name, *fullpath;
	ut8 *data = NULL;
	size_t size = 0;
	ut64 start_addr = 0;
	time_t file_time = 0;
	bool has_timestamp = false;
	struct stat st;
	int offset, width, height, bytes_per_line;
	bool viewing, hex_mode;
	RFSFile *file;

	if (panel->count == 0 || panel->selected >= panel->count) {
		r_cons_message (core->cons, "No file selected");
		return;
	}

	selected_name = panel->entries[panel->selected];
	if (!strcmp (selected_name, "..")) {
		r_cons_message (core->cons, "Cannot view parent directory");
		return;
	}

	if (panel->types && panel->types[panel->selected] == 'd') {
		r_cons_message (core->cons, "Cannot view directory");
		return;
	}

	if (!strcmp (panel->path, "/")) {
		fullpath = r_str_newf ("/%s", selected_name);
	} else {
		fullpath = r_str_newf ("%s/%s", panel->path, selected_name);
	}

	if (panel->is_fs_panel) {
		file = r_fs_open (core->fs, fullpath, false);
		if (file) {
			size = file->size;
			start_addr = file->off;
			if (size > 0) {
				r_fs_read (core->fs, file, 0, file->size);
				data = malloc (size);
				if (data) {
					memcpy (data, file->data, size);
				}
			}
			r_fs_close (core->fs, file);
		}
	} else {
		data = (ut8 *)r_file_slurp (fullpath, &size);
		start_addr = 0;

		if (stat (fullpath, &st) == 0) {
			file_time = st.st_mtime;
			has_timestamp = true;
		}
	}

	if (!data || size == 0) {
		r_cons_message (core->cons, "Failed to read file or file is empty");
		free (fullpath);
		free (data);
		return;
	}

	if (size > 1024 * 1024) {
		size = 1024 * 1024;
	}

	offset = 0;
	width = state->width;
	height = state->height;
	bytes_per_line = 16;
	viewing = true;
	hex_mode = true;

	r_cons_set_raw (core->cons, true);
	r_cons_show_cursor (core->cons, false);

	while (viewing) {
		const char *title_text = "radare2 Miknight Commander";
		int title_len, padding_left, i, j, s, line;
		int pane_w, pane_h, pane_x, pane_y;
		int content_y, max_lines, lines_per_page;
		int line_offset, remaining, line_bytes;
		int chars_per_line, char_offset, text_pos, spaces;
		int num_shortcuts, footer_len, ch;
		char hex[64], ascii[20], text_line[512];
		char *hex_ptr, *ascii_ptr;
		ut8 byte;
		RConsCanvas *canvas;
		char *title, *info1, *info2, *pline;
		const char *mode_str;
		ut64 end_addr;
		const char *shortcuts[7];
		char time_str[64];
		struct tm *tm_info;
		int line_chars, line_start;

		r_cons_clear00 (core->cons);

		title_len = strlen (title_text);
		padding_left = (width - title_len) / 2;
		if (padding_left < 0) {
			padding_left = 0;
		}

		r_cons_printf (core->cons, "%s%s", MMC_GET_SEL_BG(state), MMC_GET_FG_BLACK(state));
		for (i = 0; i < padding_left; i++) {
			r_cons_printf (core->cons, " ");
		}
		r_cons_printf (core->cons, "%s", title_text);
		for (i = 0; i < width - title_len - padding_left; i++) {
			r_cons_printf (core->cons, " ");
		}
		r_cons_printf (core->cons, "%s\n", MMC_GET_RESET(state));

		canvas = r_cons_canvas_new (core->cons, width, height - 1, R_CONS_CANVAS_FLAG_INHERIT);
		if (!canvas) {
			break;
		}
		canvas->color = r_config_get_i (core->config, "scr.color");

		pane_w = width - 4;
		pane_h = height - 2;
		pane_x = 2;
		pane_y = 0;

		r_cons_canvas_bgfill (canvas, pane_x, pane_y, pane_w, pane_h, MMC_GET_BG_PANE(state));
		r_cons_canvas_box (canvas, pane_x, pane_y, pane_w, pane_h, core->cons->context->pal.graph_box);

		mode_str = hex_mode ? "Hex View" : "Text View";
		title = r_str_newf (" %s - %s ", selected_name, mode_str);
		r_cons_canvas_write_at (canvas, title, pane_x + 1, pane_y);
		free (title);

		info1 = r_str_newf ("%s%s File: %s (%s) ", MMC_GET_BG(state), MMC_GET_FG(state), selected_name, fullpath);

		end_addr = start_addr + (size > 0 ? size - 1 : 0);
		if (has_timestamp) {
			memset (time_str, 0, sizeof (time_str));
			tm_info = localtime (&file_time);
			strftime (time_str, sizeof (time_str), "%Y-%m-%d %H:%M:%S", tm_info);
			info2 = r_str_newf ("%s%s Size: %zu bytes | Start: 0x%08"PFMT64x" | End: 0x%08"PFMT64x" | Date: %s ", MMC_GET_BG(state), MMC_GET_FG(state),
				size, start_addr, end_addr, time_str);
		} else {
			info2 = r_str_newf ("%s%s Size: %zu bytes | Start: 0x%08"PFMT64x" | End: 0x%08"PFMT64x" ", MMC_GET_BG(state), MMC_GET_FG(state),
				size, start_addr, end_addr);
		}

		r_cons_canvas_write_at (canvas, info1, pane_x + 1, pane_y + 1);
		r_cons_canvas_write_at (canvas, info2, pane_x + 1, pane_y + 2);
		free (info1);
		free (info2);

		content_y = pane_y + 4;
		max_lines = pane_h - 6;
		lines_per_page = max_lines;

		if (hex_mode) {
			for (i = 0; i < max_lines && (offset + i * bytes_per_line) < (int)size; i++) {
				line_offset = offset + i * bytes_per_line;
				remaining = size - line_offset;
				line_bytes = (remaining < bytes_per_line) ? remaining : bytes_per_line;

				memset (hex, 0, sizeof (hex));
				memset (ascii, 0, sizeof (ascii));
				hex_ptr = hex;
				ascii_ptr = ascii;

				for (j = 0; j < line_bytes; j++) {
					byte = data[line_offset + j];
					hex_ptr += sprintf (hex_ptr, "%02x ", byte);
					ascii_ptr += sprintf (ascii_ptr, "%c", IS_PRINTABLE (byte) ? byte : '.');
				}

				pline = r_str_newf ("%s%s%08x%s: %s%-48s %s%s", MMC_GET_BG(state), MMC_GET_TITLE(state),
					line_offset, MMC_GET_DIR(state), MMC_GET_BOLD_CYAN(state), hex, MMC_GET_DIR(state), ascii);

				r_cons_canvas_write_at (canvas, pline, pane_x + 1, content_y + i);
				free (pline);
			}
		} else {
			chars_per_line = pane_w - 2;
			char_offset = offset;

			for (i = 0; i < max_lines && char_offset < (int)size; i++) {
				memset (text_line, 0, sizeof (text_line));
				text_pos = 0;

				while (text_pos < chars_per_line && char_offset < (int)size) {
					byte = data[char_offset++];
					if (IS_PRINTABLE (byte)) {
						text_line[text_pos++] = byte;
					} else if (byte == '\n') {
						break;
					} else if (byte == '\r') {
						// skip
					} else if (byte == '\t') {
						spaces = 4 - (text_pos % 4);
						for (s = 0; s < spaces && text_pos < chars_per_line; s++) {
							text_line[text_pos++] = ' ';
						}
					} else {
						text_line[text_pos++] = '.';
					}
				}

				text_line[text_pos] = '\0';
				pline = r_str_newf ("%s%s%s", MMC_GET_BG(state), MMC_GET_DIR(state), text_line);
				r_cons_canvas_write_at (canvas, pline, pane_x + 1, content_y + i);
				free (pline);
			}
		}

		r_cons_canvas_print (canvas);
		r_cons_canvas_free (canvas);

		shortcuts[0] = "t:Text";
		shortcuts[1] = "x:Hex";
		shortcuts[2] = "j:Down";
		shortcuts[3] = "k:Up";
		shortcuts[4] = "h:PgUp";
		shortcuts[5] = "l:PgDn";
		shortcuts[6] = "q:Quit";
		num_shortcuts = 7;

		r_cons_printf (core->cons, "%s%s", MMC_GET_SEL_BG(state), MMC_GET_FG_BLACK(state));
		footer_len = 0;
		for (i = 0; i < num_shortcuts; i++) {
			r_cons_printf (core->cons, " %s", shortcuts[i]);
			footer_len += strlen (shortcuts[i]) + 1;
		}
		for (i = footer_len; i < width; i++) {
			r_cons_printf (core->cons, " ");
		}
		r_cons_printf (core->cons, "%s\n", MMC_GET_RESET(state));

		r_cons_visual_flush (core->cons);

		ch = r_cons_readchar (core->cons);
		ch = r_cons_arrow_to_hjkl (core->cons, ch);

		switch (ch) {
		case 'q':
		case 'Q':
		case R_CONS_KEY_F4:
			viewing = false;
			break;
		case 't':
		case 'T':
			hex_mode = false;
			offset = 0;
			break;
		case 'x':
		case 'X':
			hex_mode = true;
			offset = 0;
			break;
		case 'j':
		case 'J':
			if (hex_mode) {
				if (offset + lines_per_page * bytes_per_line < (int)size) {
					offset += bytes_per_line;
				}
			} else {
				chars_per_line = pane_w - 4;
				char_offset = offset;
				line_chars = 0;

				while (char_offset < (int)size) {
					byte = data[char_offset++];
					if (byte == '\n') {
						break;
					}
					if (byte == '\r') {
						continue;
					}
					if (byte == '\t') {
						line_chars += 4 - (line_chars % 4);
					} else {
						line_chars++;
					}
					if (line_chars >= chars_per_line) {
						break;
					}
				}
				if (char_offset < (int)size) {
					offset = char_offset;
				}
			}
			break;
		case 'k':
		case 'K':
			if (hex_mode) {
				if (offset > 0) {
					offset -= bytes_per_line;
				}
			} else {
				if (offset > 0) {
					chars_per_line = pane_w - 4;
					char_offset = offset - 1;

					while (char_offset > 0 && data[char_offset - 1] != '\n') {
						char_offset--;
					}

					if (char_offset > 0) {
						char_offset--;
						line_start = char_offset;

						line_chars = 0;
						while (line_start > 0) {
							byte = data[line_start - 1];
							if (byte == '\n') {
								break;
							}
							line_start--;
						}

						offset = line_start;
					} else {
						offset = 0;
					}
				}
			}
			break;
		case 'l':
		case 'L':
			if (hex_mode) {
				if (offset + lines_per_page * bytes_per_line < (int)size) {
					offset += lines_per_page * bytes_per_line;
				}
			} else {
				chars_per_line = pane_w - 4;
				for (line = 0; line < lines_per_page && offset < (int)size; line++) {
					char_offset = offset;
					line_chars = 0;

					while (char_offset < (int)size) {
						ut8 byte = data[char_offset++];
						if (byte == '\n') {
							break;
						}
						if (byte == '\r') {
							continue;
						}
						if (byte == '\t') {
							line_chars += 4 - (line_chars % 4);
						} else {
							line_chars++;
						}
						if (line_chars >= chars_per_line) {
							break;
						}
					}
					offset = char_offset;
				}
			}
			break;
		case 'h':
		case 'H':
			if (hex_mode) {
				offset -= lines_per_page * bytes_per_line;
				if (offset < 0) {
					offset = 0;
				}
			} else {
				for (line = 0; line < lines_per_page && offset > 0; line++) {
					int char_offset = offset - 1;

					while (char_offset > 0 && data[char_offset - 1] != '\n') {
						char_offset--;
					}

					if (char_offset > 0) {
						char_offset--;
						int line_start = char_offset;

						while (line_start > 0 && data[line_start - 1] != '\n') {
							line_start--;
						}

						offset = line_start;
					} else {
						offset = 0;
						break;
					}
				}
			}
			break;
		}
	}

	r_cons_set_raw (core->cons, true);
	r_cons_show_cursor (core->cons, false);

	free (data);
	free (fullpath);
}

static void mmc_delete_file(RCore *core, MMCState *state) {
	MMCPanel *panel = state->active;
	if (panel->count == 0 || panel->selected >= panel->count) {
		R_LOG_ERROR ("No file selected");
		return;
	}

	char *selected_name = panel->entries[panel->selected];
	if (!strcmp (selected_name, "..")) {
		return;
	}

	char *fullpath;
	if (!strcmp (panel->path, "/")) {
		fullpath = r_str_newf ("/%s", selected_name);
	} else {
		fullpath = r_str_newf ("%s/%s", panel->path, selected_name);
	}

	char *prompt = r_str_newf ("Delete %s? (y/N) ", selected_name);
	char *answer = r_cons_input (core->cons, prompt);
	free (prompt);

	if (answer && (answer[0] == 'y' || answer[0] == 'Y')) {
		if (panel->is_fs_panel) {
			R_LOG_ERROR ("Delete from filesystem not implemented yet");
		} else {
			if (r_file_is_directory (fullpath)) {
				if (!r_file_rm_rf (fullpath)) {
					R_LOG_ERROR ("Failed to delete directory: %s", fullpath);
				}
			} else {
				if (!r_file_rm (fullpath)) {
					R_LOG_ERROR ("Failed to delete file: %s", fullpath);
				}
			}
			mmc_panel_load_local (core, panel, state->ordering_mode);
		}
	}

	free (answer);
	free (fullpath);
}

static void mmc_show_info(RCore *core, MMCState *state, int width, int height) {
	MMCPanel *panel = state->active;
	int i, title_len, padding_left;
	int pane_w, pane_h, pane_x, pane_y;
	const char *title_text;
	RConsCanvas *canvas;
	char *selected_name, *info_title, *fullpath;

	if (panel->count == 0 || panel->selected >= panel->count) {
		r_cons_message (core->cons, "No file selected");
		return;
	}

	selected_name = panel->entries[panel->selected];
	if (!strcmp (selected_name, "..")) {
		r_cons_message (core->cons, "Cannot show info for parent directory");
		return;
	}

	r_cons_clear00 (core->cons);

	title_text = "radare2 Miknight Commander";
	title_len = strlen (title_text);
	padding_left = (width - title_len) / 2;
	if (padding_left < 0) {
		padding_left = 0;
	}

	r_cons_printf (core->cons, "%s%s", MMC_GET_SEL_BG(state), MMC_GET_FG_BLACK(state));
	for (i = 0; i < padding_left; i++) {
		r_cons_printf (core->cons, " ");
	}
	r_cons_printf (core->cons, "%s", title_text);
	for (i = 0; i < width - title_len - padding_left; i++) {
		r_cons_printf (core->cons, " ");
	}
	r_cons_printf (core->cons, "%s\n", MMC_GET_RESET(state));

	pane_w = width - 8;
	pane_h = height - 2;
	pane_x = 4;
	pane_y = 0;

	canvas = r_cons_canvas_new (core->cons, width, height - 1, R_CONS_CANVAS_FLAG_INHERIT);
	if (!canvas) {
		return;
	}
	canvas->color = r_config_get_i (core->config, "scr.color");

	r_cons_canvas_bgfill (canvas, pane_x, pane_y, pane_w, pane_h, MMC_GET_BG(state));
	r_cons_canvas_box (canvas, pane_x, pane_y, pane_w, pane_h, core->cons->context->pal.graph_box);

	info_title = r_str_newf ("%s File Information: %s ", MMC_GET_DIR(state), selected_name);
	r_cons_canvas_write_at (canvas, info_title, pane_x + 2, pane_y);
	free (info_title);
	if (!strcmp (panel->path, "/")) {
		fullpath = r_str_newf ("/%s", selected_name);
	} else {
		fullpath = r_str_newf ("%s/%s", panel->path, selected_name);
	}

	int y = pane_y + 2;
	char *line;

	line = r_str_newf ("%s%s  Path: %s", MMC_GET_BG(state), MMC_GET_FG(state), fullpath);
	r_cons_canvas_write_at (canvas, line, pane_x + 2, y++);
	free (line);
	y++;

	if (panel->is_fs_panel) {
		RFSFile *file = r_fs_open (core->fs, fullpath, false);
		if (file) {
			line = r_str_newf ("%s%s  File Details:", MMC_GET_BG(state), MMC_GET_TITLE(state));
			r_cons_canvas_write_at (canvas, line, pane_x + 2, y++);
			free (line);

			line = r_str_newf ("%s%s    Type: %c", MMC_GET_BG(state), MMC_GET_FG(state), file->type);
			r_cons_canvas_write_at (canvas, line, pane_x + 2, y++);
			free (line);

			line = r_str_newf ("%s%s    Size: %d bytes", MMC_GET_BG(state), MMC_GET_FG(state), file->size);
			r_cons_canvas_write_at (canvas, line, pane_x + 2, y++);
			free (line);

			line = r_str_newf ("%s%s    Offset: 0x%08"PFMT64x, MMC_GET_BG(state), MMC_GET_FG(state), file->off);
			r_cons_canvas_write_at (canvas, line, pane_x + 2, y++);
			free (line);

			r_fs_close (core->fs, file);
		} else {
			line = r_str_newf ("%s%s  File Details:", MMC_GET_BG(state), MMC_GET_TITLE(state));
			r_cons_canvas_write_at (canvas, line, pane_x + 2, y++);
			free (line);

			char type = panel->types[panel->selected];
			const char *type_str = "Unknown";
			if (type == 'd') {
				type_str = "Directory";
			} else if (type == 'f') {
				type_str = "File";
			} else if (type == 'm') {
				type_str = "Mountpoint";
			}

			line = r_str_newf ("%s%s    Type: %s (type=%c)", MMC_GET_BG(state), MMC_GET_FG(state), type_str, type);
			r_cons_canvas_write_at (canvas, line, pane_x + 2, y++);
			free (line);

			line = r_str_newf ("%s%s    Cannot open file (may be symlink or special file)", MMC_GET_BG(state), MMC_GET_FG_YELLOW(state));
			r_cons_canvas_write_at (canvas, line, pane_x + 2, y++);
			free (line);
		}

		y++;

		line = r_str_newf ("%s%s  Filesystem Information:", MMC_GET_BG(state), MMC_GET_TITLE(state));
		r_cons_canvas_write_at (canvas, line, pane_x + 2, y++);
		free (line);

		r_cons_push (core->cons);
		r_core_cmd0 (core, "mn");
		const char *buffer = r_cons_get_buffer (core->cons, NULL);
		char *mn_output = buffer ? strdup (buffer) : NULL;
		r_cons_pop (core->cons);

		if (mn_output && *mn_output) {
			RList *lines = r_str_split_duplist (mn_output, "\n", true);
			RListIter *iter;
			char *mn_line;
			r_list_foreach (lines, iter, mn_line) {
				if (*mn_line && y < pane_y + pane_h - 2) {
					line = r_str_newf ("%s%s    %s", MMC_GET_BG(state), MMC_GET_FG(state), mn_line);
					r_cons_canvas_write_at (canvas, line, pane_x + 2, y++);
					free (line);
				}
			}
			r_list_free (lines);
		}
		free (mn_output);
	} else {
		struct stat st;
		if (stat (fullpath, &st) == 0) {
			line = r_str_newf ("%s%s  File Details:", MMC_GET_BG(state), MMC_GET_TITLE(state));
			r_cons_canvas_write_at (canvas, line, pane_x + 2, y++);
			free (line);

			line = r_str_newf ("%s%s    Type: %s", MMC_GET_BG(state), MMC_GET_FG(state), S_ISDIR(st.st_mode) ? "Directory" : "File");
			r_cons_canvas_write_at (canvas, line, pane_x + 2, y++);
			free (line);

			line = r_str_newf ("%s%s    Size: %lld bytes", MMC_GET_BG(state), MMC_GET_FG(state), (long long)st.st_size);
			r_cons_canvas_write_at (canvas, line, pane_x + 2, y++);
			free (line);

			char time_str[64] = {0};
			struct tm *tm_info = localtime (&st.st_mtime);
			strftime (time_str, sizeof (time_str), "%Y-%m-%d %H:%M:%S", tm_info);
			line = r_str_newf ("%s%s    Modified: %s", MMC_GET_BG(state), MMC_GET_FG(state), time_str);
			r_cons_canvas_write_at (canvas, line, pane_x + 2, y++);
			free (line);
		} else {
			line = r_str_newf ("%s%s  Cannot stat file", MMC_GET_BG(state), MMC_GET_FG_RED(state));
			r_cons_canvas_write_at (canvas, line, pane_x + 2, y++);
			free (line);
		}
	}

	free (fullpath);

	r_cons_canvas_print (canvas);
	r_cons_canvas_free (canvas);

	r_cons_printf (core->cons, "%s%s", MMC_GET_SEL_BG(state), MMC_GET_FG_BLACK(state));
	r_cons_printf (core->cons, " q:Close");
	for (i = 9; i < width; i++) {
		r_cons_printf (core->cons, " ");
	}
	r_cons_printf (core->cons, "%s\n", MMC_GET_RESET(state));

	r_cons_visual_flush (core->cons);

	r_cons_readchar (core->cons);
}

static void mmc_seek_to_file(RCore *core, MMCState *state) {
	MMCPanel *panel = state->active;

	if (panel->count == 0 || panel->selected >= panel->count) {
		r_cons_message (core->cons, "No file selected");
		return;
	}

	char *selected_name = panel->entries[panel->selected];
	if (!strcmp (selected_name, "..")) {
		r_cons_message (core->cons, "Cannot seek to parent directory");
		return;
	}

	if (panel->types && panel->types[panel->selected] == 'd') {
		r_cons_message (core->cons, "Cannot seek to directory");
		return;
	}

	if (!panel->is_fs_panel) {
		r_cons_message (core->cons, "Seek only works on mounted filesystem files");
		return;
	}

	char *fullpath;
	if (!strcmp (panel->path, "/")) {
		fullpath = r_str_newf ("/%s", selected_name);
	} else {
		fullpath = r_str_newf ("%s/%s", panel->path, selected_name);
	}

	RFSFile *file = r_fs_open (core->fs, fullpath, false);
	if (file) {
		ut64 addr = file->off;
		r_fs_close (core->fs, file);

		r_core_seek (core, addr, true);

		state->running = false;
	} else {
		r_cons_message (core->cons, "Failed to open file");
	}

	free (fullpath);
}

static void mmc_make_directory(RCore *core, MMCState *state) {
	MMCPanel *panel = state->active;

	if (panel->is_fs_panel) {
		r_cons_message (core->cons, "Cannot create directory in mounted filesystem");
		return;
	}

	char *dirname = r_cons_input (core->cons, "Directory name: ");
	if (!dirname || !*dirname) {
		free (dirname);
		return;
	}

	char *fullpath;
	if (!strcmp (panel->path, "/")) {
		fullpath = r_str_newf ("/%s", dirname);
	} else {
		fullpath = r_str_newf ("%s/%s", panel->path, dirname);
	}

	if (r_sys_mkdir (fullpath)) {
		char *msg = r_str_newf ("Created directory: %s", dirname);
		r_cons_message (core->cons, msg);
		free (msg);
		mmc_panel_load_local (core, panel, state->ordering_mode);
	} else {
		char *msg = r_str_newf ("Failed to create directory: %s", dirname);
		r_cons_message (core->cons, msg);
		free (msg);
	}

	free (dirname);
	free (fullpath);
}

static void mmc_copy_file_confirmed(RCore *core, MMCState *state) {
	MMCPanel *src = state->active;
	MMCPanel *dst = (state->active == &state->left) ? &state->right : &state->left;

	if (src->count == 0 || src->selected >= src->count) {
		r_cons_message (core->cons, "No file selected");
		return;
	}

	char *selected_name = src->entries[src->selected];
	if (!strcmp (selected_name, "..")) {
		r_cons_message (core->cons, "Cannot copy parent directory");
		return;
	}

	char *src_path;
	if (!strcmp (src->path, "/")) {
		src_path = r_str_newf ("/%s", selected_name);
	} else {
		src_path = r_str_newf ("%s/%s", src->path, selected_name);
	}

	char *dst_path;
	if (!strcmp (dst->path, "/")) {
		dst_path = r_str_newf ("/%s", selected_name);
	} else {
		dst_path = r_str_newf ("%s/%s", dst->path, selected_name);
	}

	char *prompt = r_str_newf ("Copy %s to %s? (y/N) ", src_path, dst_path);
	char *answer = r_cons_input (core->cons, prompt);
	free (prompt);

	if (answer && (answer[0] == 'y' || answer[0] == 'Y')) {
		if (dst->is_fs_panel) {
			r_cons_message (core->cons, "Cannot copy to mounted filesystem");
		} else if (src->is_fs_panel) {
			RFSFile *file = r_fs_open (core->fs, src_path, false);
			if (!file) {
				char *msg = r_str_newf ("Cannot open file: %s", src_path);
				r_cons_message (core->cons, msg);
				free (msg);
			} else {
				if (file->size > 0) {
					int len = r_fs_read (core->fs, file, 0, file->size);
					if (len > 0 && file->data) {
						FILE *fp = fopen (dst_path, "wb");
						if (!fp) {
							char *msg = r_str_newf ("Cannot create file: %s", dst_path);
							r_cons_message (core->cons, msg);
							free (msg);
						} else {
							fwrite (file->data, 1, len, fp);
							fclose (fp);
							char *msg = r_str_newf ("Copied %s -> %s (%d bytes)", selected_name, dst_path, len);
							r_cons_message (core->cons, msg);
							free (msg);
							mmc_panel_load_local (core, dst, state->ordering_mode);
						}
					} else {
						char *msg = r_str_newf ("Failed to read file: %s", src_path);
						r_cons_message (core->cons, msg);
						free (msg);
					}
				} else {
					FILE *fp = fopen (dst_path, "wb");
					if (fp) {
						fclose (fp);
						char *msg = r_str_newf ("Copied %s -> %s (0 bytes)", selected_name, dst_path);
						r_cons_message (core->cons, msg);
						free (msg);
						mmc_panel_load_local (core, dst, state->ordering_mode);
					}
				}
				r_fs_close (core->fs, file);
			}
		} else {
			size_t data_size;
			ut8 *data = (ut8 *)r_file_slurp (src_path, &data_size);
			if (!data) {
				char *msg = r_str_newf ("Cannot read file: %s", src_path);
				r_cons_message (core->cons, msg);
				free (msg);
			} else {
				FILE *fp = fopen (dst_path, "wb");
				if (!fp) {
					char *msg = r_str_newf ("Cannot create file: %s", dst_path);
					r_cons_message (core->cons, msg);
					free (msg);
				} else {
					fwrite (data, 1, data_size, fp);
					fclose (fp);
					char *msg = r_str_newf ("Copied %s -> %s (%zu bytes)", selected_name, dst_path, data_size);
					r_cons_message (core->cons, msg);
					free (msg);
					mmc_panel_load_local (core, dst, state->ordering_mode);
				}
				free (data);
			}
		}
	}

	free (answer);
	free (src_path);
	free (dst_path);
}

static void mmc_show_help(RCore *core, MMCState *state, int width, int height) {
	int i, title_len, padding_left;
	const char *title_text;

	r_cons_clear00 (core->cons);

	title_text = "radare2 Miknight Commander";
	title_len = strlen (title_text);
	padding_left = (width - title_len) / 2;
	if (padding_left < 0) {
		padding_left = 0;
	}

	r_cons_printf (core->cons, "%s%s", MMC_GET_SEL_BG(state), MMC_GET_FG_BLACK(state));
	for (i = 0; i < padding_left; i++) {
		r_cons_printf (core->cons, " ");
	}
	r_cons_printf (core->cons, "%s", title_text);
	for (i = 0; i < width - title_len - padding_left; i++) {
		r_cons_printf (core->cons, " ");
	}
	r_cons_printf (core->cons, "%s\n", MMC_GET_RESET(state));

	int pane_w = width - 8;
	int pane_h = height - 2;
	int pane_x = 4;
	int pane_y = 0;

	RConsCanvas *canvas = r_cons_canvas_new (core->cons, width, height - 1, R_CONS_CANVAS_FLAG_INHERIT);
	if (!canvas) {
		return;
	}
	canvas->color = r_config_get_i (core->config, "scr.color");

	r_cons_canvas_bgfill (canvas, pane_x, pane_y, pane_w, pane_h, MMC_GET_BG(state));
	r_cons_canvas_box (canvas, pane_x, pane_y, pane_w, pane_h, core->cons->context->pal.graph_box);

	char *help_title = r_str_newf ("%s Miknight Commander - Help ", MMC_GET_DIR(state));
	r_cons_canvas_write_at (canvas, help_title, pane_x + 2, pane_y);
	free (help_title);

	const char *help_lines[] = {
		"",
		"  NAVIGATION:",
		"    Arrows     Navigate files",
		"    Tab        Switch between panels",
		"    Enter      Enter directory / Open file",
		"",
		"  FILE OPERATIONS:",
		"    v          View file (hex/text viewer)",
		"    c          Copy file to other panel",
		"    d          Delete file/directory",
		"    m          Make new directory",
		"",
		"  PANEL OPERATIONS:",
		"    r          Refresh both panels",
		"    o          Change sort order (fs/name/size)",
		"",
		"  OTHER:",
		"    i          Show file/filesystem info",
		"    s          Seek to file address and quit to r2",
		"    t          Toggle theme (MC / r2 colors)",
		"    h          Show this help",
		"    q          Quit Miknight Commander",
	};

	int y = pane_y + 2;
	for (i = 0; i < (int)(sizeof (help_lines) / sizeof (help_lines[0])) && y < pane_h - 1; i++) {
		char *line = r_str_newf ("%s%s%s", MMC_GET_BG(state), MMC_GET_FG(state), help_lines[i]);
		r_cons_canvas_write_at (canvas, line, pane_x + 2, y++);
		free (line);
	}

	r_cons_canvas_print (canvas);
	r_cons_canvas_free (canvas);

	r_cons_printf (core->cons, "%s%s", MMC_GET_SEL_BG(state), MMC_GET_FG_BLACK(state));
	r_cons_printf (core->cons, " q:Close");
	for (i = 9; i < width; i++) {
		r_cons_printf (core->cons, " ");
	}
	r_cons_printf (core->cons, "%s\n", MMC_GET_RESET(state));

	r_cons_visual_flush (core->cons);

	r_cons_readchar (core->cons);
}

static int cmd_mmc(void *data, const char *input) {
	RCore *core = (RCore *)data;

	if (*input == '?') {
		r_cons_printf (core->cons,
			"Usage: mmc[?] [left_path] [right_path]\n"
			"mmc  Mountpoint Miknight Commander\n"
			"  Two-panel file manager interface\n"
			"  Left:  Mounted filesystem (r_fs) - optional path parameter\n"
			"  Right: Local filesystem - optional path parameter\n"
			"\n"
			"  Navigation:\n"
			"  Tab:    Switch panels\n"
			"  Arrows: Navigate files\n"
			"  Enter:  Enter directory / Open file\n"
			"\n"
			"  File Operations:\n"
			"  v: View file (hex/text with metadata)\n"
			"     In view: t=text mode, x=hex mode, j/k=scroll, h/l=page\n"
			"  c: Copy file to other panel\n"
			"  d: Delete file/directory\n"
			"  m: Make new directory\n"
			"\n"
			"  Other:\n"
			"  h: Show help\n"
			"  i: Show file/filesystem info\n"
			"  r: Refresh both panels\n"
			"  s: Seek to file address and quit to r2\n"
			"  o: Change sort order (fs/name/size)\n"
			"  q: Quit Miknight Commander\n"
		);
		return 0;
	}

	if (!r_config_get_b (core->config, "scr.interactive")) {
		R_LOG_ERROR ("mmc requires scr.interactive");
		return 1;
	}

	char *left_path_arg = NULL;
	char *right_path_arg = NULL;

	while (*input == ' ') {
		input++;
	}

	if (*input) {
		const char *space = strchr (input, ' ');
		if (space) {
			left_path_arg = r_str_ndup (input, space - input);
			input = space + 1;
			while (*input == ' ') {
				input++;
			}
			if (*input) {
				right_path_arg = strdup (input);
			}
		} else {
			left_path_arg = strdup (input);
		}
	}

	MMCState state = {0};
	state.core = core;
	state.running = true;
	state.use_r2_theme = true;
	state.ordering_mode = MMC_ORDER_NATURAL;

	state.width = r_cons_get_size (core->cons, &state.height);

	state.left.is_fs_panel = true;
	if (left_path_arg) {
		state.left.path = left_path_arg;
	} else {
		const char *fs_cwd = r_config_get (core->config, "fs.cwd");
		if (fs_cwd && *fs_cwd) {
			state.left.path = strdup (fs_cwd);
		} else {
			RFSRoot *root = r_list_first (core->fs->roots);
			if (root) {
				state.left.path = strdup (root->path);
			} else {
				state.left.path = strdup ("/");
			}
		}
	}
	mmc_panel_load_fs (core, &state.left, state.ordering_mode);

	state.right.is_fs_panel = false;
	if (right_path_arg) {
		state.right.path = right_path_arg;
	} else {
		state.right.path = r_sys_getdir ();
		if (!state.right.path || !*state.right.path) {
			free (state.right.path);
			state.right.path = strdup (".");
		}
	}
	mmc_panel_load_local (core, &state.right, state.ordering_mode);

	state.active = &state.left;

	r_cons_set_raw (core->cons, true);
	r_cons_show_cursor (core->cons, false);

	while (state.running) {
		int i, footer_len, panel_w, panel_h;
		bool left_active;
		RConsCanvas *canvas;

		r_cons_clear00 (core->cons);

		canvas = r_cons_canvas_new (core->cons, state.width, state.height, R_CONS_CANVAS_FLAG_INHERIT);
		if (!canvas) {
			break;
		}
		canvas->color = r_config_get_i (core->config, "scr.color");

		r_cons_canvas_background (canvas, MMC_GET_BG_PANE(&state));

		panel_w = state.width / 2;
		panel_h = state.height - 1;

		left_active = (state.active == &state.left);
		mmc_panel_draw (core, canvas, &state.left, &state, 0, 0, panel_w, panel_h, left_active);
		mmc_panel_draw (core, canvas, &state.right, &state, panel_w, 0, state.width - panel_w, panel_h, !left_active);

		r_cons_canvas_print (canvas);
		r_cons_canvas_free (canvas);

		const char *shortcuts[] = {
			"h:Help", "i:Info", "v:View", "c:Copy", "m:Mkdir",
			"d:Delete", "r:Refresh", "s:Seek", "o:Order", "q:Quit"
		};

		r_cons_printf (core->cons, "%s%s", MMC_GET_SEL_BG(&state), MMC_GET_FG_BLACK(&state));
		footer_len = 0;
		for (i = 0; i < 10; i++) {
			r_cons_printf (core->cons, " %s", shortcuts[i]);
			footer_len += strlen (shortcuts[i]) + 1;
		}
		for (i = footer_len; i < state.width; i++) {
			r_cons_printf (core->cons, " ");
		}
		r_cons_printf (core->cons, "%s\n", MMC_GET_RESET(&state));

		r_cons_visual_flush (core->cons);

		int ch = r_cons_readchar (core->cons);
		if (ch == -1 || ch == 4) {
			break;
		}

		int nav_ch = r_cons_arrow_to_hjkl (core->cons, ch);

		if (nav_ch == 'k') {
			mmc_panel_navigate_up (state.active, panel_h - 2);
			continue;
		} else if (nav_ch == 'j') {
			mmc_panel_navigate_down (state.active, panel_h - 2);
			continue;
		}

		switch (ch) {
		case 'q':
		case 'Q':
			state.running = false;
			break;
		case 't':
		case 'T':
			state.use_r2_theme = !state.use_r2_theme;
			break;
		case '\t':
			state.active = (state.active == &state.left) ? &state.right : &state.left;
			break;
		case '\n':
		case '\r':
			mmc_panel_navigate_enter (core, state.active, state.ordering_mode, &state);
			break;
		case 'h':
		case 'H':
			mmc_show_help (core, &state, state.width, state.height);
			break;
		case 'i':
		case 'I':
			mmc_show_info (core, &state, state.width, state.height);
			break;
		case 'v':
		case 'V':
			mmc_view_file (core, &state);
			break;
		case 'c':
		case 'C':
			mmc_copy_file_confirmed (core, &state);
			break;
		case 'm':
		case 'M':
			mmc_make_directory (core, &state);
			break;
		case 'd':
		case 'D':
			mmc_delete_file (core, &state);
			break;
		case 'r':
		case 'R':
			mmc_panel_load_fs (core, &state.left, state.ordering_mode);
			mmc_panel_load_local (core, &state.right, state.ordering_mode);
			break;
		case 's':
		case 'S':
			mmc_seek_to_file (core, &state);
			break;
		case 'o':
		case 'O':
			mmc_cycle_ordering (&state);
			break;
		default:
			break;
		}
	}

	r_cons_show_cursor (core->cons, true);
	r_cons_set_raw (core->cons, false);
	mmc_panel_free (&state.left);
	mmc_panel_free (&state.right);
	free (state.clipboard_path);

	return 0;
}

#endif
