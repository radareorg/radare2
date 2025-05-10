/* radare - LGPL - Copyright 2007-2025 - pancake */

#define R_LOG_ORIGIN "line"

#include <r_cons.h>

#if 0
// XXX kill this global NOW
static R_TH_LOCAL RLine r_line_instance = {0};

R_API RLine *r_line_singleton(void) {
	return &r_line_instance;
}
#endif

R_API RLine *r_line_new(RCons *cons) {
	RLine *line = R_NEW0 (RLine);
	line->cons = cons;

	line->cons = cons;
	line->hist_up = NULL;
	line->hist_down = NULL;
	line->prompt = strdup ("> ");
	line->contents = NULL;
	line->enable_vi_mode = false;
	line->clipboard = NULL;
	line->kill_ring = r_list_newf (free);
	line->kill_ring_ptr = -1;
#if R2__WINDOWS__
	line->vtmode = win_is_vtcompat ();
#else
	line->vtmode = 2;
#endif
	r_line_completion_init (&line->completion, 4096);
	return line;
}

R_API void r_line_free(RLine *line) {
#if R2_600
	if (line) {
		free ((void *)line->prompt);
		line->prompt = NULL;
		r_list_free (line->kill_ring);
		r_line_hist_free (line);
		r_line_completion_fini (&line->completion);
	}
#endif
}

R_API void r_line_clipboard_push(RLine *line, const char *str) {
	line->kill_ring_ptr += 1;
	r_list_insert (line->kill_ring, line->kill_ring_ptr, strdup (str));
}

// handle const or dynamic prompts?
R_API void r_line_set_prompt(RLine *line, const char *prompt) {
	free (line->prompt);
	line->prompt = strdup (prompt);
	line->cb_fkey = line->cons->cb_fkey;
}

// handle const or dynamic prompts?
R_API char *r_line_get_prompt(RLine *line) {
	return strdup (line->prompt);
}

R_API void r_line_completion_init(RLineCompletion *completion, size_t args_limit) {
	completion->run = NULL;
	completion->run_user = NULL;
	completion->args_limit = args_limit;
	r_pvector_init (&completion->args, free);
}

R_API void r_line_completion_fini(RLineCompletion *completion) {
	r_line_completion_clear (completion);
}

R_API void r_line_completion_push(RLineCompletion *completion, const char *str) {
	R_RETURN_IF_FAIL (completion && str);
	if (completion->quit) {
		return;
	}
	if (r_pvector_length (&completion->args) < completion->args_limit) {
		char *s = strdup (str);
		if (s) {
			r_pvector_push (&completion->args, (void *)s);
		}
	} else {
		completion->quit = true;
		R_LOG_WARN ("Maximum completion capacity reached, increase scr.maxtab");
	}
}

R_API void r_line_completion_set(RLineCompletion *completion, int argc, const char **argv) {
	R_RETURN_IF_FAIL (completion && (argc >= 0));
	r_line_completion_clear (completion);
	if (argc > completion->args_limit) {
		argc = completion->args_limit;
		R_LOG_DEBUG ("Maximum completion capacity reached, increase scr.maxtab (%d %d)",
				argc, completion->args_limit);
	}
	size_t count = R_MIN (argc, completion->args_limit);
	if (r_pvector_reserve (&completion->args, count)) {
		int i;
		for (i = 0; i < count; i++) {
			r_line_completion_push (completion, argv[i]);
		}
	}
}

R_API void r_line_completion_clear(RLineCompletion *completion) {
	R_RETURN_IF_FAIL (completion);
	completion->quit = false;
	r_pvector_clear (&completion->args);
}


#include "dietline.c"
