/* radare - LGPL - Copyright 2008-2014 - pancake */

#include <r_cons.h>
#define I r_cons_singleton()

/* TODO: remove global vars */
static char *path = NULL;
static char prompt[32];
static int _n;
static char *lines = NULL;
static int nlines;
static int bytes;

static void setnewline(int old) {
	snprintf (prompt, sizeof (prompt), "%d: ", _n);
	r_line_set_prompt (prompt);
	strncpy (I->line->buffer.data, r_str_word_get0 (lines, _n),
			sizeof (I->line->buffer.data) - 1);
	I->line->buffer.data[sizeof (I->line->buffer.data) - 1] = '\0';
	I->line->buffer.index = I->line->buffer.length = strlen (I->line->buffer.data);
	I->line->contents = I->line->buffer.data;
}

static void saveline (int n, const char *str) {
	char *out;
	if (!str) return;
	out = r_str_word_get0set (lines, bytes, _n, str, &bytes);
	free (lines);
	lines = out;
}

static int up(void *n) {
	int old = _n;
	if (_n>0) _n--;
	setnewline (old);
	return -1;
}

static int down(void *n) {
	int old = _n;
#if 0
	if (_n<(nlines-1))
#endif
		_n++;
	setnewline (old);
	return -1;
}

static void filesave () {
	char buf[128];
	int i;
	if (!path) {
		eprintf ("File: ");
		buf[0] = 0;
		fgets (buf, sizeof(buf), stdin);
		i = strlen (buf);
		if (i>0) {
			buf[i-1] = 0;
			free (path);
			path = strdup (buf);
		}
	}
	if (lines) {
		for (i=0; i<bytes; i++) {
			if (lines[i]=='\0')
				lines[i]='\n';
		}
	}
	if (r_file_dump (path, (const ut8*)lines, bytes))
		eprintf ("File '%s' saved (%d bytes)\n", path, bytes);
	else eprintf ("Cannot save file\n");
	// restore back zeroes
	nlines = r_str_split (lines, '\n');
}

R_API char *r_cons_editor (const char *file, const char *str) {
	char *line;
	_n = 0;
	if (I->editor) {
		return I->editor (I->user, file, str);
	}
	free (path);
	if (file) {
		path = strdup (file);
		bytes = 0;
		lines = r_file_slurp (file, &bytes);
		nlines = r_str_split (lines, '\n');
		eprintf ("Loaded %d lines on %d bytes\n",
			(nlines?(nlines-1):0), bytes);
	} else path = NULL;
	//r_cons_new ();
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
		if (!line) break;
	}
	filesave ();
	I->line->hist_up = 
	I->line->hist_down = NULL;
	I->line->contents = NULL;
	return lines;
}
