/* radare - LGPL - Copyright 2008-2026 - pancake */

#include <r_cons.h>
#include <ctype.h>

typedef struct {
	RCons *cons;
	RLineHud *hud;
	char user_input[HUD_BUF_SIZE + 1];
	RList *list;
	char *selected_entry;
	int current_entry_n;
	RListIter iter;
} RHudData;

typedef struct {
	char text[HUD_BUF_SIZE + 1];
	RStringSlice tokens[HUD_BUF_SIZE / 2 + 1];
	int count;
} RHudFilter;

// TODO: move this into a libr/util/str.c
static void trim_repeated_spaces(char *str) {
	char *src = str;
	char *dst = str;
	bool in_space = false;

	while (*src) {
		if (isspace (*src)) {
			if (!in_space) {
				*dst++ = *src;
				in_space = true;
			}
		} else {
			*dst++ = *src;
			in_space = false;
		}
		src++;
	}
	*dst = '\0';
}

// Display the content of a file in the hud
R_API char *r_cons_hud_file(RCons *cons, const char *f) {
	R_RETURN_VAL_IF_FAIL (cons && f, NULL);
	char *s = r_file_slurp (f, NULL);
	if (s) {
		r_str_ansi_strip (s);
		char *ret = r_cons_hud_string (cons, s);
		free (s);
		return ret;
	}
	return NULL;
}

static char *hud_string(RCons *cons, const char *s, bool line_mode) {
	char *text = strdup (s);
	if (!text) {
		return NULL;
	}
	if (line_mode) {
		r_str_replace_ch (text, '\r', ' ', true);
		r_str_replace_ch (text, '\t', ' ', true);
	}
	r_str_ansi_strip (text);
	if (!line_mode) {
		trim_repeated_spaces (text);
	}
	RList *lines = r_list_new ();
	if (!lines) {
		free (text);
		return NULL;
	}
	char *line = text, *end;
	while ((end = strchr (line, '\n'))) {
		*end = 0;
		if (*line && *line != '#') {
			r_list_append (lines, line);
		}
		line = end + 1;
	}
	char *ret = r_cons_hud (cons, lines, NULL);
	r_list_free (lines);
	free (text);
	return ret;
}

// Display a buffer in the hud (splitting it line-by-line and ignoring
// the lines starting with # ) returns the selected line
R_API char *r_cons_hud_line_string(RCons *cons, const char *s) {
	R_RETURN_VAL_IF_FAIL (cons && s, NULL);
	if (!r_cons_is_interactive (cons)) {
		R_LOG_ERROR ("Hud mode requires scr.interactive=true");
		return NULL;
	}
	return hud_string (cons, s, true);
}

// Display a buffer in the hud (splitting it line-by-line and ignoring
// the lines starting with # )
R_API char *r_cons_hud_string(RCons *cons, const char *s) {
	R_RETURN_VAL_IF_FAIL (cons && s, NULL);
	if (!r_cons_is_interactive (cons)) {
		R_LOG_ERROR ("Hud mode requires scr.interactive=true");
		return NULL;
	}
	return hud_string (cons, s, false);
}

static void hud_filter_init(RHudFilter *filter, const char *input) {
	r_str_ncpy (filter->text, input, sizeof (filter->text));
	filter->count = 0;
	int count = r_str_split (filter->text, ' ');
	char *word = filter->text;
	int i;
	for (i = 0; i < count; i++) {
		size_t len = strlen (word);
		if (len) {
			RStringSlice *token = &filter->tokens[filter->count++];
			token->from = word - filter->text;
			token->to = token->from + len;
		}
		word += len + 1;
	}
}

static bool hud_match_entry(const char *entry, const RHudFilter *filter, char *mask, size_t mask_size) {
	char *ansi_filtered = NULL;
	int *cps = NULL;
	bool matched = false;
	if (strchr (entry, 0x1b)) {
		ansi_filtered = strdup (entry);
		if (!ansi_filtered) {
			return false;
		}
		if (r_str_ansi_filter (ansi_filtered, NULL, &cps, -1) < 0) {
			goto beach;
		}
		entry = ansi_filtered;
	}
	int i;
	for (i = 0; i < filter->count; i++) {
		const RStringSlice *token = &filter->tokens[i];
		size_t token_len = token->to - token->from;
		const char *entry_ptr = entry, *next_match;
		while ((next_match = r_str_casestr (entry_ptr, filter->text + token->from))) {
			size_t pos = next_match - entry;
			if (cps) {
				size_t end = pos + token_len;
				for (; pos < end && (size_t)cps[pos] < mask_size; pos++) {
					mask[cps[pos]] = 'x';
				}
			} else if (pos < mask_size) {
				memset (mask + pos, 'x', R_MIN (token_len, mask_size - pos));
			}
			entry_ptr += token_len;
		}
		if (entry_ptr == entry) {
			goto beach;
		}
	}
	matched = true;
beach:
	free (cps);
	free (ansi_filtered);
	return matched;
}

static RList *hud_filter(RHudData *data, const RHudFilter *filter, bool simple, int selected_index) {
	RListIter *iter;
	char *current_entry;
	// one mask byte per entry char, reused across entries
	char *mask = NULL;
	size_t mask_size = 0;
	char *p, *x;
	int j, rows;
	(void)r_cons_get_size (data->cons, &rows);
	int counter = 0;
	rows -= 1; // room for the prompt!
	bool first_line = true;
	int visible_index = 0;
	RList *res = r_list_newf (free);
	r_list_foreach (data->list, iter, current_entry) {
		const size_t entry_size = strlen (current_entry) + 1;
		if (entry_size > mask_size) {
			char *m = realloc (mask, entry_size);
			if (!m) {
				break;
			}
			mask = m;
			mask_size = entry_size;
		}
		memset (mask, 0, entry_size);
		if (filter->count && !hud_match_entry (current_entry, filter, mask, entry_size)) {
			continue;
		}
		if (++counter == rows + data->hud->top_entry_n) {
			break;
		}
		// if the user scrolled down the list, do not print the first entries
		if (!data->hud->top_entry_n || data->current_entry_n >= data->hud->top_entry_n) {
			// remove everything after a tab (in??, it contains the commands)
			x = strchr (current_entry, '\t');
			if (x) {
				*x = 0;
			}
			p = strdup (current_entry);
			char marker = (visible_index == selected_index) ? '>' : (first_line ? '-' : ' ');
			// if the filter is empty, print the entry and move on
			if (simple) {
				for (j = 0; p[j] && data->user_input[0]; j++) {
					if (mask[j]) {
						p[j] = toupper ((unsigned char)p[j]);
					}
				}
				r_list_append (res, r_str_newf ("%c %s", marker, p));
			} else if (!data->user_input[0]) {
				r_list_append (res, r_str_newf ("%c %s", marker, p));
			} else {
				// otherwise we need to emphasize the matching part
				if (data->cons->context->color_mode) {
					int last_color_change = 0;
					int last_mask = 0;
					RStrBuf *sb = r_strbuf_newf (" %c ", marker);
					// Instead of printing one char at the time
					// (which would be slow), we group substrings of the same color
					for (j = 0; p[j]; j++) {
						if (mask[j] != last_mask) {
							char tmp = p[j];
							p[j] = 0;
							if (mask[j]) {
								r_strbuf_appendf (sb, Color_RESET "%s", p + last_color_change);
							} else {
								r_strbuf_appendf (sb, Color_GREEN "%s", p + last_color_change);
							}
							p[j] = tmp;
							last_color_change = j;
							last_mask = mask[j];
						}
					}
					if (last_mask) {
						r_strbuf_appendf (sb, Color_GREEN "%s" Color_RESET, p + last_color_change);
					} else {
						r_strbuf_appendf (sb, Color_RESET "%s", p + last_color_change);
					}
					r_list_append (res, r_strbuf_drain (sb));
				} else {
					// Otherwise we print the matching characters uppercase
					for (j = 0; p[j]; j++) {
						if (mask[j]) {
							p[j] = toupper ((unsigned char)p[j]);
						}
					}
					r_list_append (res, r_str_newf (" %c %s", marker, p));
				}
			}
			// Clean up and restore the tab character (if any)
			free (p);
			if (x) {
				*x = '\t';
			}
			if (visible_index == selected_index) {
				free (data->selected_entry);
				data->selected_entry = strdup (current_entry);
			}
			visible_index++;
			first_line = false;
		}
		data->current_entry_n++;
	}
	free (mask);
	return res;
}

static void hud_render_prompt(RCons *cons, const char *user_input, RList *filtered_list) {
	int w = r_cons_get_size (cons, NULL);
	size_t ss = strlen (user_input);
	const char *s = user_input;
	if (ss + 12 > (size_t)w) {
		s = user_input + (ss - w + 12);
	}
	char *p = r_str_newf ("(%08d)> %s", r_list_length (filtered_list), s);
	if (strlen (p) > (size_t)w) {
		p[w] = 0;
	}
	r_cons_println (cons, p);
	free (p);
}

static void hud_render(RHudData *data) {
	RCons *cons = data->cons;
	RLineHud *hud = data->hud;
	char *user_input = data->user_input;

	r_cons_clear00 (cons);

	free (data->selected_entry);
	data->selected_entry = NULL;
	data->current_entry_n = 0;

	RHudFilter filter;
	hud_filter_init (&filter, user_input);
	RList *filtered_list = hud_filter (data, &filter, false, hud->current_entry_n);
	int len = r_list_length (filtered_list);
	if (hud->current_entry_n >= len && len > 0) {
		hud->current_entry_n = len - 1;
		r_list_free (filtered_list);
		filtered_list = hud_filter (data, &filter, false, hud->current_entry_n);
	}
	int w = r_cons_get_size (cons, NULL);
	RListIter *iter;
	char *row;
	hud_render_prompt (cons, user_input, filtered_list);
	r_list_foreach (filtered_list, iter, row) {
		int len = r_str_ansi_len (row);
		if (len > w) {
			char *p = (char *)r_str_ansi_chrn (row, w);
			*p = 0;
		}
		r_cons_printf (cons, "%s\n", row);
	}
	r_list_free (filtered_list);
	r_cons_flush (cons);
}

static void hud_refresh_callback(void *user) {
	RHudData *data = (RHudData *)user;
	hud_render (data);
}

R_API char *r_cons_hud(RCons *cons, RList *list, const char *prompt) {
	char user_input[HUD_BUF_SIZE + 1];

	// Save original event callbacks
	RConsEvent old_event_resize = cons->event_resize;
	RConsEvent old_event_interrupt = cons->context->event_interrupt;
	void *old_event_data = cons->event_data;

	RLineHud *hud = (RLineHud *)R_NEW0 (RLineHud);
	hud->activate = 0;
	hud->vi = 0;
	hud->current_entry_n = 0;
	cons->line->echo = false;
	cons->line->hud = hud;
	user_input[0] = 0;
	user_input[HUD_BUF_SIZE] = 0;
	hud->top_entry_n = 0;
	r_cons_show_cursor (cons, false);
	r_cons_enable_mouse (cons, false);
	r_cons_set_raw (cons, true);
	r_cons_clear00 (cons);

	RHudData *data = R_NEW (RHudData);
	data->cons = cons;
	data->hud = hud;
	data->list = list;
	data->selected_entry = NULL;
	data->current_entry_n = 0;
	memcpy (data->user_input, user_input, sizeof (user_input));

	// Set up hud event callbacks
	cons->event_data = data;
	cons->event_resize = hud_refresh_callback;

	char *se = NULL;
	// Repeat until the user exits the hud
	for (;;) {
		hud_render (data);
		(void)r_line_readline (cons);
		r_str_ncpy (user_input, cons->line->state.buffer.data, HUD_BUF_SIZE);
		memcpy (data->user_input, user_input, sizeof (data->user_input));
		if (!hud->activate) {
			hud->top_entry_n = 0;
			if (data->selected_entry) {
				se = data->selected_entry;
				data->selected_entry = NULL;
			}
			break;
		}
	}
	// restore
	cons->event_resize = old_event_resize;
	cons->context->event_interrupt = old_event_interrupt;
	cons->event_data = old_event_data;
	R_FREE (cons->line->hud);
	cons->line->echo = true;
	r_cons_show_cursor (cons, true);
	r_cons_enable_mouse (cons, false);
	r_cons_set_raw (cons, false);
	free (data->selected_entry);
	free (data);
	return se;
}

// Display the list of files in a directory
R_API char *r_cons_hud_path(RCons *cons, const char *path, int dir) {
	R_RETURN_VAL_IF_FAIL (cons && path, NULL);
	char *tmp, *ret = NULL;
	if (path) {
		path = r_str_trim_head_ro (path);
		tmp = strdup (*path? path: "./");
	} else {
		tmp = strdup ("./");
	}
	RList *files = r_sys_dir (tmp);
	if (files) {
		ret = r_cons_hud (cons, files, tmp);
		if (ret) {
			tmp = r_str_append (tmp, "/");
			tmp = r_str_append (tmp, ret);
			free (ret);
			ret = r_file_abspath (tmp);
			free (tmp);
			tmp = ret;
			if (r_file_is_directory (tmp)) {
				ret = r_cons_hud_path (cons, tmp, dir);
				free (tmp);
				tmp = ret;
			}
		}
		r_list_free (files);
	} else {
		R_LOG_ERROR ("No files found");
	}
	if (!ret) {
		free (tmp);
		return NULL;
	}
	return tmp;
}
