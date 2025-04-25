/* radare - LGPL - Copyright 2007-2024 - pancake */

#define R_LOG_ORIGIN "line"

#include <r_cons.h>

static R_TH_LOCAL RLine r_line_instance;
#define I r_line_instance

R_API RLine *r_line_singleton(void) {
	return &r_line_instance;
}

R_API RLine *r_line_new(void) {
	I.hist_up = NULL;
	I.hist_down = NULL;
	I.prompt = strdup ("> ");
	I.contents = NULL;
	I.enable_vi_mode = false;
	I.clipboard = NULL;
	I.kill_ring = r_list_newf (free);
	I.kill_ring_ptr = -1;
#if R2__WINDOWS__
	I.vtmode = w32_is_vtcompat ();
#else
	I.vtmode = 2;
#endif
	r_line_completion_init (&I.completion, 4096);
	return &I;
}

R_API void r_line_free(void) {
	// XXX: prompt out of the heap?
	free ((void *)I.prompt);
	I.prompt = NULL;
	r_list_free (I.kill_ring);
	r_line_hist_free ();
	r_line_completion_fini (&I.completion);
}

R_API void r_line_clipboard_push(const char *str) {
	I.kill_ring_ptr += 1;
	r_list_insert (I.kill_ring, I.kill_ring_ptr, strdup (str));
}

// handle const or dynamic prompts?
R_API void r_line_set_prompt(const char *prompt) {
	free (I.prompt);
	I.prompt = strdup (prompt);
	RCons *cons = r_cons_singleton ();
	I.cb_fkey = cons->cb_fkey;
}

// handle const or dynamic prompts?
R_API char *r_line_get_prompt(void) {
	return strdup (I.prompt);
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
