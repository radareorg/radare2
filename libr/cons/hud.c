/* radare - LGPL - Copyright 2008-2025 - pancake */

#include <r_cons.h>
#include <ctype.h>

typedef struct {
	RCons *cons;
	HtPP *ht;
	RLineHud *hud;
	char user_input[HUD_BUF_SIZE + 1];
	RList *list;
	char *selected_entry;
	int current_entry_n;
	RListIter iter;
} RHudData;

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

// Display a buffer in the hud (splitting it line-by-line and ignoring
// the lines starting with # ) returns the selected line
R_API char *r_cons_hud_line_string(RCons *cons, const char *s) {
	R_RETURN_VAL_IF_FAIL (cons && s, NULL);
	if (!r_cons_is_interactive (cons)) {
		R_LOG_ERROR ("Hud mode requires scr.interactive=true");
		return NULL;
	}
	char *os, *track, *ret, *o = strdup (s);
	if (!o) {
		return NULL;
	}
	r_str_replace_ch (o, '\r', ' ', true);
	r_str_replace_ch (o, '\t', ' ', true);
	r_str_ansi_strip (o);
	RList *fl = r_list_new ();
	int i;
	if (!fl) {
		free (o);
		return NULL;
	}
	fl->free = free;
	for (os = o, i = 0; o[i]; i++) {
		if (o[i] == '\n') {
			o[i] = 0;
			if (*os && *os != '#') {
				track = strdup (os);
				if (!r_list_append (fl, track)) {
					free (track);
					break;
				}
			}
			os = o + i + 1;
		}
	}
	ret = r_cons_hud (cons, fl, NULL);
	free (o);
	r_list_free (fl);
	return ret;
}

// Display a buffer in the hud (splitting it line-by-line and ignoring
// the lines starting with # )
R_API char *r_cons_hud_string(RCons *cons, const char *s) {
	R_RETURN_VAL_IF_FAIL (cons && s, NULL);
	if (!r_cons_is_interactive (cons)) {
		R_LOG_ERROR ("Hud mode requires scr.interactive=true");
		return NULL;
	}
	char *os, *track, *ret, *o = strdup (s);
	if (!o) {
		return NULL;
	}
	r_str_ansi_strip (o);
	r_str_replace_ch (o, '\r', ' ', true);
	r_str_replace_ch (o, '\t', ' ', true);
	// TODO: trim all repeated spaces in strings too
	RList *fl = r_list_new ();
	int i;
	if (!fl) {
		free (o);
		return NULL;
	}
	fl->free = free;
	for (os = o, i = 0; o[i]; i++) {
		if (o[i] == '\n') {
			o[i] = 0;
			if (*os && *os != '#') {
				track = strdup (os);
				if (!r_list_append (fl, track)) {
					free (track);
					break;
				}
			}
			os = o + i + 1;
		}
	}
	ret = r_cons_hud (cons, fl, NULL);
	free (o);
	r_list_free (fl);
	return ret;
}

#if 0
Match a filter on a line. A filter can contain multiple words
separated by spaces, which are all matched *in any order* over the target
entry. If all words are present, the function returns true.
The mask is a character buffer which is filled by 'x' to mark those characters
that match the filter
#endif
static bool __matchString(char *entry, char *filter, char *mask, const int mask_size) {
	char *p, *current_token = filter;
	const char *filter_end = filter + strlen (filter);
	char *ansi_filtered = strdup (entry);
	int *cps;
	r_str_ansi_filter (ansi_filtered, NULL, &cps, -1);
	entry = ansi_filtered;
	// first we separate the filter in words (include the terminator char
	// to avoid special handling of the last token)
	for (p = filter; p <= filter_end; p++) {
		if (*p == ' ' || *p == '\0') {
			const char *next_match, *entry_ptr = entry;
			char old_char = *p;
			int token_len;

			// Ignoring consecutive spaces
			if (p == current_token) {
				current_token++;
				continue;
			}
			*p = 0;
			token_len = strlen (current_token);
			// look for all matches of the current_token in this entry
			while ((next_match = r_str_casestr (entry_ptr, current_token))) {
				int real_pos, filtered_pos = next_match - entry;
				int end_pos = cps[filtered_pos + token_len];
				for (real_pos = cps[filtered_pos];
					real_pos < end_pos && real_pos < mask_size;
					real_pos = cps[++filtered_pos]) {
					mask[real_pos] = 'x';
				}
				entry_ptr += token_len;
			}
			*p = old_char;
			if (entry_ptr == entry) {
				// the word is not present in the target
				free (cps);
				free (ansi_filtered);
				return false;
			}
			current_token = p + 1;
		}
	}
	free (cps);
	free (ansi_filtered);
	return true;
}

static RList *hud_filter(RHudData *data, bool simple, int selected_index) {
	RListIter *iter;
	char *current_entry;
	char mask[HUD_BUF_SIZE];
	char *p, *x;
	int j, rows;
	(void)r_cons_get_size (data->cons, &rows);
	int counter = 0;
	rows -= 1; // room for the prompt!
	bool first_line = true;
	int visible_index = 0;
	RList *res = r_list_newf (free);
	r_list_foreach (data->list, iter, current_entry) {
		memset (mask, 0, HUD_BUF_SIZE);
		if (*data->user_input && !__matchString (current_entry, data->user_input, mask, HUD_BUF_SIZE)) {
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
			char marker = (visible_index == selected_index)? '>': (first_line? '-': ' ');
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
					char *str = r_str_newf (" %c ", marker);
					// Instead of printing one char at the time
					// (which would be slow), we group substrings of the same color
					for (j = 0; p[j] && j < HUD_BUF_SIZE; j++) {
						if (mask[j] != last_mask) {
							char tmp = p[j];
							p[j] = 0;
							if (mask[j]) {
								str = r_str_appendf (str, Color_RESET "%s", p + last_color_change);
							} else {
								str = r_str_appendf (str, Color_GREEN "%s", p + last_color_change);
							}
							p[j] = tmp;
							last_color_change = j;
							last_mask = mask[j];
						}
					}
					if (last_mask) {
						str = r_str_appendf (str, Color_GREEN "%s" Color_RESET, p + last_color_change);
					} else {
						str = r_str_appendf (str, Color_RESET "%s", p + last_color_change);
					}
					r_list_append (res, str);
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
	return res;
}

static void mht_free_kv(HtPPKv *kv) {
	free (kv->key);
	r_list_free (kv->value);
}

static void hud_render_prompt(RCons *cons, const char *user_input, RList *filtered_list) {
	char *s = strdup (user_input);
	int w = r_cons_get_size (cons, NULL);
	size_t ss = strlen (s);
	if (ss + 12 > w) {
		char *r = strdup (s + (ss - w + 12));
		free (s);
		s = r;
	}
	char *p = r_str_newf ("(%08d)> %s", r_list_length (filtered_list), s);
	if (strlen (p) > w) {
		p[w] = 0;
	}
	r_cons_println (cons, p);
	free (p);
	free (s);
}

static void hud_render(RHudData *data) {
	RCons *cons = data->cons;
	RLineHud *hud = data->hud;
	char *user_input = data->user_input;

	r_cons_clear00 (cons);

	free (data->selected_entry);
	data->selected_entry = NULL;
	data->current_entry_n = 0;

	RList *filtered_list = hud_filter (data, false, hud->current_entry_n);
	int len = r_list_length (filtered_list);
	if (hud->current_entry_n >= len && len > 0) {
		hud->current_entry_n = len - 1;
		r_list_free (filtered_list);
		filtered_list = hud_filter (data, false, hud->current_entry_n);
	}
	int w = r_cons_get_size (cons, NULL);
	RListIter *iter;
	char *row;
	hud_render_prompt (cons, user_input, filtered_list);
	r_list_foreach (filtered_list, iter, row) {
		int len = r_str_ansi_len (row);
		if (len > w) {
			char *trimmed = strdup (row);
			char *p = (char *)r_str_ansi_chrn (trimmed, w);
			*p = 0;
			r_cons_printf (cons, "%s\n", trimmed);
			free (trimmed);
		} else {
			r_cons_printf (cons, "%s\n", row);
		}
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

	HtPP *ht = ht_pp_new (NULL, (HtPPKvFreeFunc)mht_free_kv, (HtPPCalcSizeV)strlen);
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
	data->ht = ht;
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
		r_str_ncpy (user_input, cons->line->buffer.data, HUD_BUF_SIZE);
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
	ht_pp_free (ht);
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
