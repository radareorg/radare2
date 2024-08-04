/* radare - LGPL - Copyright 2008-2024 - pancake */

#include <r_cons.h>
#define I r_cons_singleton ()

typedef struct {
	char *lines;
	char *path;
	char prompt[32];
	int bytes;
	int nlines;
	int n;
} RConsEditor;

/* TODO: remove global vars */
static R_TH_LOCAL RConsEditor G = {0};

static void r_cons_editor_init(void) {
	memset (&G, 0, sizeof (G));
	G.n = 1;
}

static void setnewline(int old) {
	snprintf (G.prompt, sizeof (G.prompt), "%d: ", G.n);
	r_line_set_prompt (G.prompt);
	char *curline = r_file_slurp_line (G.path, G.n, 0);
	// const char *curline = r_str_word_get0 (lines, G.n),
#if 1
	r_str_ncpy (I->line->buffer.data, r_str_get (curline), sizeof (I->line->buffer.data) - 1);
	I->line->buffer.data[sizeof (I->line->buffer.data) - 1] = '\0';
	I->line->buffer.index = I->line->buffer.length = strlen (I->line->buffer.data);
#endif
	I->line->contents = strdup (r_str_get (curline)); // I->line->buffer.data;
	free (curline);
}

static void saveline(int n, const char *str) {
	r_file_dump_line (G.path, G.n, str, false);
#if 0
	char *out;
	if (!str) {
		return;
	}
	out = r_str_word_get0set (lines, bytes, G.n, str, &bytes);
	free (lines);
	lines = out;
#endif
}

static int up(void *n) {
	int old = G.n;
	if (G.n > 1) {
		G.n--;
	}
	setnewline (old);
	return -1;
}

static int down(void *n) {
	int old = G.n++;
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
	G.nlines = r_str_split (lines, '\n');
}
#endif

R_API char *r_cons_editor(const char *file, const char *str) {
	if (I->cb_editor) {
		return I->cb_editor (I->user, file, str);
	}
	r_cons_editor_init ();
	if (R_STR_ISNOTEMPTY (file)) {
		G.path = strdup (file);
		G.bytes = 0;
		size_t sz = 0;
		G.lines = r_file_slurp (file, &sz);
		G.bytes = (int)sz;
		if (!G.lines) {
			R_LOG_ERROR ("Failed to load '%s'", file);
			R_FREE (G.path);
			return NULL;
		}
		G.nlines = r_str_split (G.lines, '\n');
		R_LOG_INFO ("Loaded %d lines on %d byte(s)", (G.nlines? (G.nlines - 1): 0), G.bytes);
	} else {
		G.path = NULL;
	}
	I->line->hist_up = up;
	I->line->hist_down = down;
	I->line->contents = I->line->buffer.data;
	I->echo = false;
	down (NULL);
	up (NULL);
	for (;;) {
		char *curline = r_file_slurp_line (file, G.n, 0);
		I->line->contents = curline;
		setnewline (G.n);
		const char *line = r_line_readline ();
		if (R_STR_ISNOTEMPTY (line) && curline && strcmp (curline, line)) {
			saveline (G.n, line);
		}
		down (NULL);
		setnewline (G.n);
		if (!line) {
			break;
		}
	}
	// filesave ();
	if (true) {
		int i;
		for (i = 0; i < G.bytes; i++) {
			if (G.lines[i] == '\0') {
				G.lines[i] = '\n';
			}
		}
	}
	r_str_trim (G.lines);
	I->line->hist_up = NULL;
	I->line->hist_down = NULL;
	I->line->contents = NULL;
	return G.lines;
}
