/* radare - LGPL - Copyright 2007-2017 - pancake */

#include <r_util.h>
#include <r_cons.h>

static RLine r_line_instance;
#define I r_line_instance

R_API RLine *r_line_singleton() {
	return &r_line_instance;
}

R_API RLine *r_line_new() {
	I.hist_up = NULL;
	I.hist_down = NULL;
	I.prompt = strdup ("> ");
	I.contents = NULL;
#if __WINDOWS__
	I.ansicon = r_sys_getenv ("ANSICON");
#endif
	if (!r_line_dietline_init ()) {
		eprintf ("error: r_line_dietline_init\n");
	}
	r_line_completion_init (&I.completion);
	return &I;
}

R_API void r_line_free() {
	// XXX: prompt out of the heap?
	free ((void *)I.prompt);
	I.prompt = NULL;
	r_line_hist_free ();
	r_line_completion_fini (&I.completion);
}

// handle const or dynamic prompts?
R_API void r_line_set_prompt(const char *prompt) {
	free (I.prompt);
	I.prompt = strdup (prompt);
}

// handle const or dynamic prompts?
R_API char *r_line_get_prompt() {
	return strdup (I.prompt);
}

R_API void r_line_completion_init(RLineCompletion *completion) {
	completion->run = NULL;
	completion->argc = 0;
	completion->argv = NULL;
	completion->args_weak = true;
	r_pvector_init (&completion->args, NULL);
}

R_API void r_line_completion_fini(RLineCompletion *completion) {
	r_line_completion_clear (completion);
}

R_API void r_line_completion_push_owned(RLineCompletion *completion, char *str) {
	r_return_if_fail (completion && str);
	if (completion->args_weak) {
		// weak to owned => must strdup all currently saved strings
		size_t i;
		for (i = 0; i < r_pvector_len (&completion->args); i++) {
			const char *weak_str = r_pvector_at (&completion->args, i);
			r_pvector_set (&completion->args, i, strdup (weak_str));
		}
	}
	r_pvector_push (&completion->args, str);
	completion->args_weak = false;
}

R_API void r_line_completion_push_weak(RLineCompletion *completion, const char *str) {
	r_return_if_fail (completion && str);
	if (!completion->args_weak) {
		str = strdup (str);
	}
	r_pvector_push (&completion->args, (void *)str);
}

R_API void r_line_completion_set_weak(RLineCompletion *completion, int argc, const char **argv) {
	r_return_if_fail (completion);
	r_line_completion_clear (completion);
	completion->argc = argc;
	completion->argv = argv;
}

R_API void r_line_completion_clear(RLineCompletion *completion) {
	r_return_if_fail (completion);
	r_pvector_set_free (&completion->args, completion->args_weak ? NULL : free);
	r_pvector_clear (&completion->args);
	completion->args_weak = true;
	completion->argc = 0;
	completion->argv = NULL;
}

#include "dietline.c"
