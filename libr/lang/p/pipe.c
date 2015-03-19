/* radare2 - LGPL - Copyright 2015 pancake */

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"

static int lang_pipe_run(RLang *lang, const char *code, int len);
static int lang_pipe_file(RLang *lang, const char *file) {
	return lang_pipe_run (lang, file, -1);
}

static void env(const char *s, int f) {
	char *a = r_str_newf ("%d", f);
	r_sys_setenv (s, a);
	eprintf ("%s %s\n", s, a);
	free (a);
}

static int lang_pipe_run(RLang *lang, const char *code, int len) {
	int safe_in = dup (0);
	int child, ret;
	int input[2];
	int output[2];
	pipe (input);
	pipe (output);

	env ("R2PIPE_IN", input[0]);
	env ("R2PIPE_OUT", output[1]);

#if __UNIX__
	child = fork ();
	if (child == -1) {
		/* error */
	} else if (child == 0) {
		/* children */
#if 1
		system (code);
#else
		/* DEMO */
		char buf[1024];
		/* kid stuff here */
		while (1) {
			write (output[1], "pd 3\n", 6);
			res = read (input[0], buf, sizeof (buf)-1);
			if (res <1) break;
			printf ("---> ((%s))\n", buf);
			sleep (1);
		}
#endif
		write (output[1], "", 1); // EOF
		close (input[0]);
		close (input[1]);
		close (output[0]);
		close (output[1]);
		exit (0);
		return R_FALSE;
	} else {
		/* parent */
		char *res, buf[1024];
		r_cons_break (NULL, NULL);
		for (;;) {
			if (r_cons_singleton ()->breaked)
				break;
			memset (buf, 0, sizeof (buf));
			ret = read (output[0], buf, sizeof (buf)-1);
			if (ret <1 || !buf[0])
				break;
			res = lang->cmd_str ((RCore*)lang->user, buf);
			eprintf ("%d %s\n", ret, buf);
			if (res) {
				write (input[1], res, strlen (res));
				free (res);
			} else {
				eprintf ("r_lang_pipe: NULL reply for (%s)\n", buf);
			}
			write (input[1], "", 1); // NULL byte
		}
		/* workaround to avoid stdin closed */
		if (safe_in != -1)
			close (safe_in);
		safe_in = open (ttyname(0), O_RDONLY);
		dup2 (safe_in, 0);
		r_cons_break_end ();
	}

	close (input[0]);
	close (input[1]);
	close (output[0]);
	close (output[1]);
	return R_TRUE;
#else
	eprintf ("Only supported on UNIX\n");
	return R_TRUE;
#endif
}

static struct r_lang_plugin_t r_lang_plugin_pipe = {
	.name = "pipe",
	.ext = "pipe",
	.desc = "Use #!pipe node script.js",
	.help = NULL,
	.run = lang_pipe_run,
	.init = NULL,
	.fini = NULL,
	.run_file = (void*)lang_pipe_file,
	.set_argv = NULL,
};
