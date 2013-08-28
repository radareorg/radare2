/* radare - LGPL - Copyright 2007-2013 - pancake */

#include <r_cons.h>

static RLine r_line_instance;
#define I r_line_instance

/* definitions to be removed */
int r_line_dietline_init();
void r_line_hist_free();

R_API RLine *r_line_singleton () {
	return &r_line_instance;
}

R_API RLine *r_line_new () {
	I.hist_up = NULL;
	I.hist_down = NULL;
	I.prompt = strdup ("> ");
	I.contents = NULL;
	if (!r_line_dietline_init ())
		eprintf ("error: r_line_dietline_init\n");
	return &I;
}

R_API void r_line_free () {
	// XXX: prompt out of the heap?
	free ((void*)I.prompt);
	I.prompt = NULL;
	r_line_hist_free ();
}

// handle const or dynamic prompts?
R_API void r_line_set_prompt (const char *prompt) {
	free (I.prompt);
	I.prompt = strdup (prompt);
}

// handle const or dynamic prompts?
R_API char *r_line_get_prompt () {
	return strdup (I.prompt);
}

#include "dietline.c"
