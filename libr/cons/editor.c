/* radare - LGPL - Copyright 2008-2018 - pancake */

#include <r_cons.h>
#define I r_cons_singleton ()

/* TODO: remove global vars */
static char *lines = NULL;
static char *path = NULL;
static char prompt[32];
static int bytes, nlines, _n = 0;

static void setnewline(int old) {
	snprintf (prompt, sizeof (prompt), "%d: ", _n);
	r_line_set_prompt (prompt);
	strncpy (I->line->buffer.data, r_str_word_get0 (lines, _n),
		sizeof (I->line->buffer.data) - 1);
	I->line->buffer.data[sizeof (I->line->buffer.data) - 1] = '\0';
	I->line->buffer.index = I->line->buffer.length = strlen (I->line->buffer.data);
	I->line->contents = I->line->buffer.data;
}

static void saveline(int n, const char *str) {
	char *out;
	if (!str) {
		return;
	}
	out = r_str_word_get0set (lines, bytes, _n, str, &bytes);
	free (lines);
	lines = out;
}

static int up(void *n) {
	int old = _n;
	if (_n > 0) {
		_n--;
	}
	setnewline (old);
	return -1;
}

static int down(void *n) {
	int old = _n++;
	setnewline (old);
	return -1;
}

static void filesave() {
	char buf[128];
	int i;
	if (!path) {
		eprintf ("File: ");
		buf[0] = 0;
		if (fgets (buf, sizeof (buf) - 1, stdin)) {
			buf[sizeof (buf) - 1] = 0;
			i = strlen (buf);
			if (i > 0) {
				buf[i - 1] = 0;
				free (path);
				path = strdup (buf);
			}
		}
	}
	if (lines) {
		for (i = 0; i < bytes; i++) {
			if (lines[i] == '\0') {
				lines[i] = '\n';
			}
		}
	}
	if (r_file_dump (path, (const ut8 *)lines, bytes, 0)) {
		eprintf ("File '%s' saved (%d byte(s))\n", path, bytes);
	} else {
		eprintf ("Cannot save file\n");
	}
	nlines = r_str_split (lines, '\n');
}

R_API char *r_cons_editor(const char *file, const char *str) {
	const char *line;
	_n = 0;
	if (I->cb_editor) {
		return I->cb_editor (I->user, file, str);
	}
	free (path);
	if (file) {
		path = strdup (file);
		bytes = 0;
		lines = r_file_slurp (file, &bytes);
		if (!lines) {
			eprintf ("Failed to load '%s'.\n", file);
			R_FREE (path);
			return NULL;
		}
		nlines = r_str_split (lines, '\n');
		eprintf ("Loaded %d lines on %d byte(s)\n",
			(nlines? (nlines - 1): 0), bytes);
	} else {
		path = NULL;
	}
	I->line->hist_up = up;
	I->line->hist_down = down;
	I->line->contents = I->line->buffer.data;
	for (;;) {
		setnewline (_n);
		snprintf (prompt, sizeof (prompt), "%d: ", _n);
		r_line_set_prompt (prompt);
		line = r_line_readline ();
		saveline (_n, line);
		_n++;
		if (!line) {
			break;
		}
	}
	filesave ();
	I->line->hist_up = NULL;
	I->line->hist_down = NULL;
	I->line->contents = NULL;
	return lines;
}
