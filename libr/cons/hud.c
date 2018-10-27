/* radare - LGPL - Copyright 2008-2018 - pancake */

#include <r_cons.h>
#include <ctype.h>

#define I(x) r_cons_singleton ()->x

// Display the content of a file in the hud
R_API char *r_cons_hud_file(const char *f) {
	char *s = r_file_slurp (f, NULL);
	if (s) {
		char *ret = r_cons_hud_string (s);
		free (s);
		return ret;
	}
	return NULL;
}

// Display a buffer in the hud (splitting it line-by-line and ignoring
// the lines starting with # )
R_API char *r_cons_hud_string(const char *s) {
	char *os, *track, *ret, *o = strdup (s);
	if (!o) {
		return NULL;
	}
	r_str_replace_ch (o, '\r', 0, true);
	r_str_replace_ch (o, '\t', 0, true);
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
	ret = r_cons_hud (fl, NULL);
	free (o);
	r_list_free (fl);
	return ret;
}

/* Match a filter on a line. A filter can contain multiple words
   separated by spaces, which are all matched *in any order* over the target
   entry. If all words are present, the function returns true.
   The mask is a character buffer wich is filled by 'x' to mark those characters
   that match the filter */
static bool strmatch(char *entry, char *filter, char *mask, const int mask_size) {
	char *p, *current_token = filter;
	const char *filter_end = filter + strlen (filter);
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
				int i;
				for (i = next_match - entry;
				     (i < next_match - entry + token_len) && i < mask_size;
				     i++) {
					mask[i] = 'x';
				}
				entry_ptr += token_len;
			}
			*p = old_char;
			if (entry_ptr == entry) {
				// the word is not present in the target
				return false;
			}
			current_token = p + 1;
		}
	}
	return true;
}

#define HUD_BUF_SIZE 512

static RList *hud_filter(RList *list, char *user_input, int top_entry_n, int *current_entry_n, char **selected_entry) {
	RListIter *iter;
	void *current_entry;
	char mask[HUD_BUF_SIZE];
	char *p, *x;
	int j, rows;
	(void) r_cons_get_size (&rows);
	int counter = 0;
	bool first_line = true;
	RList *res = r_list_newf (free);
	r_list_foreach (list, iter, current_entry) {
		memset (mask, 0, HUD_BUF_SIZE);
		if (*user_input && !strmatch (current_entry, user_input, mask, HUD_BUF_SIZE)) {
			continue;
		}
		if (++counter == rows + top_entry_n) {
			break;
		}
		// if the user scrolled down the list, do not print the first entries
		if (!top_entry_n || *current_entry_n >= top_entry_n) {
			// remove everything after a tab (in ??, it contains the commands)
			x = strchr (current_entry, '\t');
			if (x) {
				*x = 0;
			}
			p = strdup (current_entry);
			// if the filter is empty, print the entry and move on
			if (!user_input[0]) {
				r_list_append (res, r_str_newf (" %c %s", first_line? '-': ' ', current_entry));
			} else {
				// otherwise we need to emphasize the matching part
				if (I (color)) {
					int last_color_change = 0;
					int last_mask = 0;
					char *str = r_str_newf (" %c ", first_line? '-': ' ');
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
						str = r_str_appendf (str, Color_GREEN "%s"Color_RESET, p + last_color_change);
					} else {
						str = r_str_appendf (str, Color_RESET "%s", p + last_color_change);
					}
					r_list_append (res, str);
				} else {
					// Otherwise we print the matching characters uppercase
					for (j = 0; p[j]; j++) {
						if (mask[j]) {
							p[j] = toupper ((unsigned char) p[j]);
						}
					}
					r_list_append (res, r_str_newf (" %c %s", first_line? '-': ' ', p));
				}
			}
			// Clean up and restore the tab character (if any)
			free (p);
			if (x) {
				*x = '\t';
			}
			if (first_line) {
				*selected_entry = current_entry;
			}
			first_line = false;
		}
		(*current_entry_n)++;

	}
	return res;
}

static void mht_free_kv(HtKv *kv) {
        free (kv->key);
        r_list_free (kv->value);
}

// Display a list of entries in the hud, filtered and emphasized based on the user input.

#define HUD_CACHE 0
R_API char *r_cons_hud(RList *list, const char *prompt) {
	int ch, nch, current_entry_n, i = 0;
	char user_input[HUD_BUF_SIZE];
	int top_entry_n = 0;
	char *selected_entry = NULL;
	RListIter *iter;

	SdbHt *ht = ht_new (NULL, (HtKvFreeFunc)mht_free_kv, (CalcSize)strlen);

	user_input[0] = 0;
	r_cons_clear ();
	// Repeat until the user exits the hud
	for (;;) {
		r_cons_gotoxy (0, 0);
		current_entry_n = 0;
		if (top_entry_n < 0) {
			top_entry_n = 0;
		}
		selected_entry = NULL;
		if (prompt && *prompt) {
			r_cons_print (">> ");
			r_cons_println (prompt);
		}
		r_cons_printf ("%d> %s|\n", top_entry_n, user_input);
		char *row;
		RList *filtered_list = NULL;

		bool found = false;
		HtKv *kv = ht_find_kv (ht, user_input, &found);
		if (found) {
			filtered_list = kv->value;
		} else {
			filtered_list = hud_filter (list, user_input,
				top_entry_n, &current_entry_n, &selected_entry);
#if HUD_CACHE
			ht_insert (ht, user_input, filtered_list);
#endif
		}
		r_list_foreach (filtered_list, iter, row) {
			r_cons_printf ("%s\n", row);
		}
#if !HUD_CACHE
		r_list_free (filtered_list);
#endif

		r_cons_visual_flush ();
		ch = r_cons_readchar ();
		nch = r_cons_arrow_to_hjkl (ch);
		int rows;
		(void) r_cons_get_size (&rows);
		if (nch == 'J' && ch != 'J') {
			top_entry_n += (rows - 1);
			if (top_entry_n + 1 >= current_entry_n) {
				top_entry_n = current_entry_n;
			}
		} else if (nch == 'K' && ch != 'K') {
			top_entry_n -= (rows - 1);
			if (top_entry_n < 0) {
				top_entry_n = 0;
			}
		} else if (nch == 'j' && ch != 'j') {
			if (top_entry_n + 1 < current_entry_n) {
				top_entry_n++;
			}
		} else if (nch == 'k' && ch != 'k') {
			if (top_entry_n >= 0) {
				top_entry_n--;
			}
		} else {
			switch (ch) {
			case 9:	// \t
				if (top_entry_n + 1 < current_entry_n) {
					top_entry_n++;
				} else {
					top_entry_n = 0;
				}
				break;
			case 10:// \n
			case 13:// \r
				top_entry_n = 0;
				// if (!*buf)
				// return NULL;
				if (current_entry_n >= 1) {
					// eprintf ("%s\n", buf);
					// i = buf[0] = 0;
					return strdup (selected_entry);
				}	// no match!
				break;
			case 23:// ^w
				top_entry_n = 0;
				i = user_input[0] = 0;
				break;
			case 0x1b:	// ESC
				return NULL;
			case 8:		// bs
			case 127:	// bs
				top_entry_n = 0;
				if (i < 1) {
					return NULL;
				}
				user_input[--i] = 0;
				break;
			default:
				if (IS_PRINTABLE (ch)) {
					if (i >= HUD_BUF_SIZE) {
						break;
					}
					top_entry_n = 0;
					if (i + 1 >= HUD_BUF_SIZE) {
						// too many
						break;
					}
					user_input[i++] = ch;
					user_input[i] = 0;
				}
				break;
			}
		}
	}
	ht_free (ht);
	return NULL;
}

// Display the list of files in a directory
R_API char *r_cons_hud_path(const char *path, int dir) {
	char *tmp, *ret = NULL;
	RList *files;
	if (path) {
		path = r_str_trim_ro (path);
		tmp = strdup (*path? path: "./");
	} else {
		tmp = strdup ("./");
	}
	files = r_sys_dir (tmp);
	if (files) {
		ret = r_cons_hud (files, tmp);
		if (ret) {
			tmp = r_str_append (tmp, "/");
			tmp = r_str_append (tmp, ret);
			ret = r_file_abspath (tmp);
			free (tmp);
			tmp = ret;
			if (r_file_is_directory (tmp)) {
				ret = r_cons_hud_path (tmp, dir);
				free (tmp);
				tmp = ret;
			}
		}
		r_list_free (files);
	} else {
		eprintf ("No files found\n");
	}
	if (!ret) {
		free (tmp);
		return NULL;
	}
	return tmp;
}

R_API char *r_cons_message(const char *msg) {
	int len = strlen (msg);
	int rows, cols = r_cons_get_size (&rows);
	r_cons_clear ();
	r_cons_gotoxy ((cols - len) / 2, rows / 2);
	r_cons_println (msg);
	r_cons_flush ();
	r_cons_gotoxy (0, rows - 2);
	r_cons_any_key (NULL);
	return NULL;
}
