/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_main.h>

#if EMSCRIPTEN__TODO
#include <emscripten.h>
static R_TH_LOCAL RCore *core = NULL;

void *r2_asmjs_new(const char *cmd) {
	return r_core_new ();
}

void r2_asmjs_free(void *core) {
	r_core_free (core);
}

char *r2_asmjs_cmd(void *kore, const char *cmd) {
	if (kore) {
		if (!cmd) {
			r_core_free (kore);
		}
	} else {
		if (core) {
			kore = core;
		} else {
			kore = core = r_core_new ();
		}
	}
	return r_core_cmd_str (kore, cmd);
}

static void wget_cb(const char *f) {
	r_core_cmdf (core, "'o %s", f);
}

void r2_asmjs_openurl(void *kore, const char *url) {
	const char *file = r_str_lchr (url, '/');
	if (kore) {
		core = kore;
	}
	if (file) {
		emscripten_async_wget (url, file + 1, wget_cb, NULL);
	}
}
#else

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

static void r2cmd(int in, int out, const char *cmd) {
	int cmd_len = strlen (cmd) + 1;
	if ((int)write (out, cmd, cmd_len) != cmd_len) {
		return;
	}
#if 0
	if (write (out, "\n", 1) != 1) {
		return;
	}
#endif
	int bufsz = (1024 * 64) - 1;
	ut8 *buf = malloc (bufsz + 1);
	if (R_UNLIKELY (!buf)) {
		return;
	}
	int n = read (in, buf, bufsz);
	if (R_LIKELY (n > 0)) {
		buf[R_MIN (n, bufsz)] = 0;
		int len = strlen ((const char *)buf);
		if (len > 0) {
			n = write (STDOUT_FILENO, buf, len);
			if (n != len) {
				R_LOG_ERROR ("Truncated output");
			}
		}
	}
	free (buf);
	R_UNUSED_RESULT(write (STDOUT_FILENO, "\n", 1));
}

static int r_main_r2pipe(int argc, const char **argv) {
	int i, rc = 0;
	char *_in = r_sys_getenv ("R2PIPE_IN");
	char *_out = r_sys_getenv ("R2PIPE_OUT");
	if (R_STR_ISNOTEMPTY (_in) && R_STR_ISNOTEMPTY (_out)) {
		int in = atoi (_in);
		int out = atoi (_out);
		for (i = 1; i < argc; i++) {
			r2cmd (in, out, argv[i]);
		}
	} else {
		R_LOG_ERROR ("R2PIPE_(IN|OUT) environment not set");
		R_LOG_INFO ("Usage: r2 -c '!*r2p x' # run commands via r2pipe");
		rc = 1;
	}
	free (_in);
	free (_out);
	return rc;
}

int main(int argc, const char **argv) {
	if (argc > 0 && strstr (argv[0], "r2p")) {
		return r_main_r2pipe (argc, argv);
	}
	char *ea = r_sys_getenv ("R2_ARGS");
	if (R_STR_ISNOTEMPTY (ea)) {
		R_LOG_INFO ("Using R2_ARGS: \"%s\"", ea);
		if (!r_str_startswith (ea, argv[0])) {
			R_LOG_WARN ("R2_ARGS should start with argv[0]=%s", argv[0]);
		}
		char **argv = r_str_argv (ea, &argc);
		r_sys_setenv ("R2_ARGS", NULL);
		int res = r_main_radare2 (argc, (const char **)argv);
		free (ea);
		free (argv);
		return res;
	}
	free (ea);
	return r_main_radare2 (argc, argv);
}

#endif
