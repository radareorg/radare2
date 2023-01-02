/* radare - LGPL - Copyright 2015-2022 - pancake */
/*
Usage Example:

	#include <r_core.h>
	int main() {
		RCoreBind rcb;
		RCore *core = r_core_new ();
		r_core_bind (core, &rcb);
		r2pipe_open_corebind (&rcb);
		char *clippy = r2pipe_cmd ("?E hello");
		eprintf ("%s\n", clippy);
		free (clippy);
		r2pipe_close (r2pipe);
		r_core_free (core);
	}
*/

#include <r_util.h>
#include <r_lib.h>
#include <r_socket.h>

#define R2P_PID(x) (((R2Pipe*)(x)->data)->pid)
#define R2P_INPUT(x) (((R2Pipe*)(x)->data)->input[0])
#define R2P_OUTPUT(x) (((R2Pipe*)(x)->data)->output[1])

#if R2__WINDOWS__
#define NO_CHILD 0
#else
#define NO_CHILD -1
#endif

#if defined(__wasi__) && __wasi__
#define HAVE_R2PIPE 0
#else
#define HAVE_R2PIPE 1
#endif

#if !R2__WINDOWS__
static void env(const char *s, int f) {
	char *a = r_str_newf ("%d", f);
	r_sys_setenv (s, a);
	free (a);
}
#endif

R_API int r2pipe_write(R2Pipe *r2pipe, const char *str) {
#if HAVE_R2PIPE
	char *cmd;
	int ret, len;
	if (!r2pipe || !str) {
		return -1;
	}
	len = strlen (str) + 2; /* include \n\x00 */
	cmd = malloc (len + 2);
	if (!cmd) {
		return 0;
	}
	memcpy (cmd, str, len - 1);
	strcpy (cmd + len - 2, "\n");
#if R2__WINDOWS__
	DWORD dwWritten = -1;
	WriteFile (r2pipe->pipe, cmd, len, &dwWritten, NULL);
	ret = (dwWritten == len);
#else
	ret = (write (r2pipe->input[1], cmd, len) == len);
#endif
	free (cmd);
	return ret;
#else
	return -1;
#endif
}

/* TODO: add timeout here ? */
R_API char *r2pipe_read(R2Pipe *r2pipe) {
	char *buf = NULL;
#if HAVE_R2PIPE
	int bufsz = 0;
	if (!r2pipe) {
		return NULL;
	}
	bufsz = 4096;
	buf = calloc (1, bufsz);
	if (!buf) {
		return NULL;
	}
#if R2__WINDOWS__
	BOOL bSuccess = FALSE;
	DWORD dwRead = 0;
	// TODO: handle > 4096 buffers here
	bSuccess = ReadFile (r2pipe->pipe, buf, bufsz, &dwRead, NULL);
	if (!bSuccess || !buf[0]) {
		return NULL;
	}
	if (dwRead > 0) {
		buf[dwRead] = 0;
	}
	buf[bufsz - 1] = 0;
#else
	char *newbuf;
	int i, rv;
	for (i = 0; i < bufsz; i++) {
		rv = read (r2pipe->output[0], buf + i, 1);
		if (i + 2 >= bufsz) {
			bufsz += 4096;
			newbuf = realloc (buf, bufsz);
			if (!newbuf) {
				R_FREE (buf);
				break;
			}
			buf = newbuf;
		}
		if (rv != 1 || !buf[i]) {
			break;
		}
	}
	if (buf) {
		int zpos = (i < bufsz)? i: i - 1;
		buf[zpos] = 0;
	}
#endif
#endif
	return buf;
}

R_API int r2pipe_close(R2Pipe *r2pipe) {
#if HAVE_R2PIPE
	if (!r2pipe) {
		return 0;
	}
	/*
	if (r2pipe->coreb.core && !r2pipe->coreb.puts) {
		void (*rfre)(void *c) = r_lib_dl_sym (libr, "r_core_free");
		if (rfre) {
			rfre (r2pipe->coreb.core);
		}
	}
	*/
#if R2__WINDOWS__
	if (r2pipe->pipe) {
		CloseHandle (r2pipe->pipe);
		r2pipe->pipe = NULL;
	}
#else
	if (r2pipe->input[0] != -1) {
		close (r2pipe->input[0]);
		r2pipe->input[0] = -1;
	}
	if (r2pipe->input[1] != -1) {
		close (r2pipe->input[1]);
		r2pipe->input[1] = -1;
	}
	if (r2pipe->output[0] != -1) {
		close (r2pipe->output[0]);
		r2pipe->output[0] = -1;
	}
	if (r2pipe->output[1] != -1) {
		close (r2pipe->output[1]);
		r2pipe->output[1] = -1;
	}
	if (r2pipe->child != NO_CHILD) {
		kill (r2pipe->child, SIGTERM);
		waitpid (r2pipe->child, NULL, 0);
		r2pipe->child = NO_CHILD;
	}
#endif
#endif
	free (r2pipe);
	return 0;
}

#if HAVE_R2PIPE && R2__WINDOWS__
static int w32_createPipe(R2Pipe *r2pipe, const char *cmd) {
	CHAR buf[1024];
	r2pipe->pipe = CreateNamedPipe (TEXT ("\\\\.\\pipe\\R2PIPE_IN"),
		PIPE_ACCESS_DUPLEX,PIPE_TYPE_MESSAGE | \
		PIPE_READMODE_MESSAGE | \
		PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
		sizeof (buf), sizeof (buf), 0, NULL);
	if (r_sys_create_child_proc_w32 (cmd, NULL, NULL, NULL)) {
		if (ConnectNamedPipe (r2pipe->pipe, NULL)) {
			return true;
		}
	}
	return false;
}
#endif

static R2Pipe* r2p_open_spawn(R2Pipe* r2p, const char *cmd) {
	r_return_val_if_fail (r2p, NULL);
#if HAVE_R2PIPE && (R2__UNIX__ || defined(__CYGWIN__))
	char *out = r_sys_getenv ("R2PIPE_IN");
	char *in = r_sys_getenv ("R2PIPE_OUT");
	int done = false;
	if (in && out) {
		int i_in = atoi (in);
		int i_out = atoi (out);
		if (i_in >= 0 && i_out >= 0) {
			r2p->input[0] = r2p->input[1] = i_in;
			r2p->output[0] = r2p->output[1] = i_out;
			done = true;
		}
	}
	if (!done) {
		R_LOG_ERROR ("Cannot find R2PIPE_IN or R2PIPE_OUT environment");
		R_FREE (r2p);
	}
	free (in);
	free (out);
	return r2p;
#else
	R_LOG_ERROR ("r2pipe_open(NULL) not supported on this platform");
	return NULL;
#endif
}

static R2Pipe *r2pipe_new(void) {
	R2Pipe *r2pipe = R_NEW0 (R2Pipe);
	if (r2pipe) {
#if HAVE_R2PIPE && R2__UNIX__
		r2pipe->input[0] = r2pipe->input[1] = -1;
		r2pipe->output[0] = r2pipe->output[1] = -1;
#endif
		r2pipe->child = NO_CHILD;
	}
	return r2pipe;
}

R_API R2Pipe *r2pipe_open_corebind(RCoreBind *coreb) {
	R2Pipe *r2pipe = r2pipe_new ();
	if (r2pipe) {
		memcpy (&r2pipe->coreb, coreb, sizeof (RCoreBind));
	}
	return r2pipe;
}

R_API R2Pipe *r2pipe_open_dl(const char *libr_path) {
#if HAVE_R2PIPE
	void *libr = r_lib_dl_open (libr_path);
	void* (*rnew)() = r_lib_dl_sym (libr, "r_core_new");
	char* (*rcmd)(void *c, const char *cmd) = r_lib_dl_sym (libr, "r_core_cmd_str");

	if (rnew && rcmd) {
		R2Pipe *r2pipe = r2pipe_new ();
		if (r2pipe) {
			r2pipe->coreb.core = rnew ();
			r2pipe->coreb.cmdstr = rcmd;
			// r2pipe->coreb.free = rfre;
		}
		return r2pipe;
	}
#endif
	R_LOG_ERROR ("Cannot resolve r_core_cmd, r_core_cmd_str, r_core_free");
	return NULL;
}

R_API R2Pipe *r2pipe_open(const char *cmd) {
#if HAVE_R2PIPE
	R2Pipe *r2p = r2pipe_new ();
	if (!r2p) {
		return NULL;
	}
	if (R_STR_ISEMPTY (cmd)) {
		r2p->child = NO_CHILD;
		return r2p_open_spawn (r2p, cmd);
	}
#if R2__WINDOWS__
	w32_createPipe (r2p, cmd);
	r2p->child = r2p->pipe;
#else
	int r = pipe (r2p->input);
	if (r != 0) {
		R_LOG_ERROR ("pipe failed on input");
		r2pipe_close (r2p);
		return NULL;
	}
	r = pipe (r2p->output);
	if (r != 0) {
		R_LOG_ERROR ("pipe failed on output");
		r2pipe_close (r2p);
		return NULL;
	}
	r2p->child = r_sys_fork ();
	if (r2p->child == NO_CHILD) {
		r2pipe_close (r2p);
		return NULL;
	}
	env ("R2PIPE_IN", r2p->input[0]);
	env ("R2PIPE_OUT", r2p->output[1]);

	if (r2p->child) {
		signed char ch = -1;
		// eprintf ("[+] r2pipeipe child is %d\n", r2pipe->child);
		if (read (r2p->output[0], &ch, 1) != 1) {
			R_LOG_ERROR ("Failed to read 1 byte");
			r2pipe_close (r2p);
			return NULL;
		}
		if (ch == -1) {
			R_LOG_ERROR ("[+] r2pipe link error");
			r2pipe_close (r2p);
			return NULL;
		}
		// Close parent's end of pipes
		close (r2p->input[0]);
		close (r2p->output[1]);
		r2p->input[0] = -1;
		r2p->output[1] = -1;
	} else {
		int rc = 0;
		if (cmd && *cmd) {
			close (0);
			close (1);
			dup2 (r2p->input[0], 0);
			dup2 (r2p->output[1], 1);
			close (r2p->input[1]);
			close (r2p->output[0]);
			r2p->input[1] = -1;
			r2p->output[0] = -1;
			rc = r_sandbox_system (cmd, 1);
			if (rc != 0) {
				R_LOG_ERROR ("return code %d for %s", rc, cmd);
			}
			// trigger the blocking read
			if (write (1, "\xff", 1) != 1) {
				rc = -1;
			}
			close (r2p->output[1]);
			close (0);
			close (1);
		}
		r2p->child = NO_CHILD;
		r2pipe_close (r2p);
		exit (rc);
		return NULL;
	}
#endif
	return r2p;
#else
	return NULL;
#endif
}

R_API char *r2pipe_cmd(R2Pipe *r2p, const char *str) {
#if HAVE_R2PIPE
	r_return_val_if_fail (r2p && str, NULL);
	if (!*str || !r2pipe_write (r2p, str)) {
		r_sys_perror ("r2pipe_write");
		return NULL;
	}
	return r2pipe_read (r2p);
#else
	return NULL;
#endif
}

R_API char *r2pipe_cmdf(R2Pipe *r2p, const char *fmt, ...) {
#if HAVE_R2PIPE
	int ret, ret2;
	char *p, string[1024];
	va_list ap, ap2;
	va_start (ap, fmt);
	va_start (ap2, fmt);
	ret = vsnprintf (string, sizeof (string) - 1, fmt, ap);
	if (ret < 1 || ret >= sizeof (string)) {
		p = malloc (ret + 2);
		if (!p) {
			va_end (ap2);
			va_end (ap);
			return NULL;
		}
		ret2 = vsnprintf (p, ret + 1, fmt, ap2);
		if (ret2 < 1 || ret2 > ret + 1) {
			free (p);
			va_end (ap2);
			va_end (ap);
			return NULL;
		}
		fmt = r2pipe_cmd (r2p, p);
		free (p);
	} else {
		fmt = r2pipe_cmd (r2p, string);
	}
	va_end (ap2);
	va_end (ap);
	return (char*)fmt;
#else
	return NULL;
#endif
}

