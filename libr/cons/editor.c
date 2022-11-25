/* radare - LGPL - Copyright 2008-2022 - pancake */

#include <r_cons.h>
#define I r_cons_singleton ()

/* TODO: remove global vars */
static R_TH_LOCAL char *lines = NULL;
static R_TH_LOCAL char *path = NULL;
static R_TH_LOCAL char prompt[32];
static R_TH_LOCAL int bytes = 0;
static R_TH_LOCAL int nlines = 0;
static R_TH_LOCAL int _n = 1;

static void setnewline(int old) {
	snprintf (prompt, sizeof (prompt), "%d: ", _n);
	r_line_set_prompt (prompt);
	char *curline = r_file_slurp_line (path, _n, 0);
	// const char *curline = r_str_word_get0 (lines, _n),
#if 1
	r_str_ncpy (I->line->buffer.data, r_str_get (curline), sizeof (I->line->buffer.data) - 1);
	I->line->buffer.data[sizeof (I->line->buffer.data) - 1] = '\0';
	I->line->buffer.index = I->line->buffer.length = strlen (I->line->buffer.data);
#endif
	I->line->contents = strdup (r_str_get (curline)); // I->line->buffer.data;
	free (curline);
}

static void saveline(int n, const char *str) {
	r_file_dump_line (path, _n, str, false);
#if 0
	char *out;
	if (!str) {
		return;
	}
	out = r_str_word_get0set (lines, bytes, _n, str, &bytes);
	free (lines);
	lines = out;
#endif
}

static int up(void *n) {
	int old = _n;
	if (_n > 1) {
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

#if 0
static void filesave(void) {
	char buf[128];
	int i;
	if (!path) {
		eprintf ("File: ");
		buf[0] = 0;
		if (fgets (buf, sizeof (buf), stdin)) {
			if (buf[0]) {
				r_str_trim_tail (buf);
				free (path);
				path = strdup (buf);
			}
		}
	}
	if (!path) {
		R_LOG_ERROR ("No file given");
		return;
	}
	if (lines) {
		for (i = 0; i < bytes; i++) {
			if (lines[i] == '\0') {
				lines[i] = '\n';
			}
		}
	}
	if (r_file_dump (path, (const ut8 *)lines, bytes, 0)) {
		R_LOG_INFO ("File '%s' saved (%d byte(s))", path, bytes);
	} else {
		R_LOG_ERROR ("Cannot save file");
	}
	nlines = r_str_split (lines, '\n');
}
#endif

R_API char *r_cons_editor(const char *file, const char *str) {
	const char *line;
	_n = 1;
	if (I->cb_editor) {
		return I->cb_editor (I->user, file, str);
	}
	free (path);
	if (file) {
		path = strdup (file);
		bytes = 0;
		size_t sz = 0;
		lines = r_file_slurp (file, &sz);
		bytes = (int)sz;
		if (!lines) {
			R_LOG_ERROR ("Failed to load '%s'", file);
			R_FREE (path);
			return NULL;
		}
		nlines = r_str_split (lines, '\n');
		R_LOG_INFO ("Loaded %d lines on %d byte(s)", (nlines? (nlines - 1): 0), bytes);
	} else {
		path = NULL;
	}
	I->line->hist_up = up;
	I->line->hist_down = down;
	I->line->contents = I->line->buffer.data;
	I->echo = false;
	down (NULL);
	up (NULL);
	for (;;) {
		char *curline = r_file_slurp_line (file, _n, 0);
		I->line->contents = curline;
		setnewline (_n);
		line = r_line_readline ();
		if (line && *line && curline && strcmp (curline, line)) {
			saveline (_n, line);
		}
		down (NULL);
		setnewline (_n);
		if (!line) {
			break;
		}
	}
	// filesave ();
	I->line->hist_up = NULL;
	I->line->hist_down = NULL;
	I->line->contents = NULL;
	return lines;
}
