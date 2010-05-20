/* radare - LGPL - Copyright 2007-2010 pancake<nopcode.org> */

#include <r_line.h>

static RLine r_line_instance;
#define I r_line_instance

/* definitions to be removed */
int r_line_dietline_init();
void r_line_hist_free();

R_API RLine *r_line_singleton () {
	return &r_line_instance;
}

R_API RLine *r_line_new () {
	I.prompt = strdup ("> ");
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

#include "dietline.c"
