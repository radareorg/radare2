/* radare - LGPL - Copyright 2009-2021 - pancake */

#include <r_main.h>
#include <r_util.h>

#if EMSCRIPTEN__TODO
#include <emscripten.h>
static RCore *core = NULL;

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
	r_core_cmdf (core, "o %s", f);
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
static void r2cmd(int in, int out, const char *cmd) {
        write (out, cmd, strlen (cmd) + 1);
        write (out, "\n", 1);
        int bufsz = (1024 * 64);
        unsigned char *buf = malloc (bufsz);
        if (!buf) {
                return;
        }
        while (1) {
                int n = read (in, buf, bufsz);
				buf[bufsz - 1] = '\0';
                int len = strlen ((const char *)buf);
                n = len;
                if (n < 1) {
                        break;
                }
                write (1, buf, n);
		if (n != bufsz) {
			break;
		}
        }
        free (buf);
        write (1, "\n", 1);
}

static int r_main_r2pipe(int argc, const char **argv) {
        int i, rc = 0;
        char *_in = r_sys_getenv ("R2PIPE_IN");
        char *_out = r_sys_getenv ("R2PIPE_OUT");
        if (_in && _out) {
		int in = atoi (_in);
		int out = atoi (_out);
		for (i = 1; i < argc; i++) {
			r2cmd (in, out, argv[i]);
		}
        } else {
		eprintf ("Error: R2PIPE_(IN|OUT) environment not set\n");
		eprintf ("Usage: r2 -c '!*r2p x' # run commands via r2pipe\n");
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
	return r_main_radare2 (argc, argv);
}

#endif
