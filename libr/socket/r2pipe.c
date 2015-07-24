/* radare - LGPL - Copyright 2015 - pancake */

#include <r_util.h>
#include <r_socket.h>

#define R2P_MAGIC 0x329193
#define R2P_PID(x) (((R2Pipe*)x->data)->pid)
#define R2P_INPUT(x) (((R2Pipe*)x->data)->input[0])
#define R2P_OUTPUT(x) (((R2Pipe*)x->data)->output[1])

static void env(const char *s, int f) {
        char *a = r_str_newf ("%d", f);
        r_sys_setenv (s, a);
        free (a);
}

R_API int r2p_close(R2Pipe *r2p) {
#if __WINDOWS__
	if (r2p->pipe) {
		CloseHandle (r2p->pipe);
		r2p->pipe = NULL;
	}
#else
	if (r2p->input[0] != -1) {
		close (r2p->input[0]);
		close (r2p->input[1]);
		r2p->input[0] = -1;
		r2p->input[1] = -1;
	}
	if (r2p->output[0] != -1) {
		close (r2p->output[0]);
		close (r2p->output[1]);
		r2p->output[0] = -1;
		r2p->output[1] = -1;
	}
	if (r2p->child != -1) {
		kill (r2p->child, SIGTERM);
		waitpid (r2p->child, NULL, 0);
		r2p->child = -1;
	}
#endif
	free (r2p);
	return 0;
}

#if __WINDOWS__
static int w32_createChildProcess(const char * szCmdline) {
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE;
	DWORD dwWritten;
	ZeroMemory (&piProcInfo, sizeof (PROCESS_INFORMATION));
	ZeroMemory (&siStartInfo, sizeof (STARTUPINFO));
	siStartInfo.cb = sizeof (STARTUPINFO);
	bSuccess = CreateProcess (NULL, szCmdline, NULL, NULL,
		TRUE, 0, NULL, NULL, &siStartInfo, &piProcInfo);
	if (!bSuccess)
		return R_FALSE;
	CloseHandle (piProcInfo.hProcess);
	CloseHandle (piProcInfo.hThread);
	return R_TRUE;
}

static int w32_createPipe(R2Pipe *r2p, const char *cmd) {
	DWORD dwRead, dwWritten;
	CHAR buf[1024];
	BOOL bSuccess = FALSE;
	SECURITY_ATTRIBUTES saAttr;
	int res = 0;
	r2p->pipe = CreateNamedPipe ("\\\\.\\pipe\\R2PIPE_IN",
		PIPE_ACCESS_DUPLEX,PIPE_TYPE_MESSAGE | \
		PIPE_READMODE_MESSAGE | \
		PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
		sizeof (buf), sizeof (buf), 0, NULL);
	if (w32_createChildProcess (cmd) != R_TRUE) {
		//eprintf("Error spawning process: %s\n",code);
		return R_TRUE;
	}
	bSuccess = ConnectNamedPipe (r2p->pipe, NULL);
	if (!bSuccess) {
		//eprintf("Error connecting pipe.\n");
		return R_TRUE;
	}
	return R_TRUE;
}
#endif

R_API R2Pipe *r2p_open(const char *cmd) {
	R2Pipe *r2p = R_NEW0 (R2Pipe);
	r2p->magic = R2P_MAGIC;
#if __WINDOWS__
	w32_createPipe (r2p, cmd);
	r2p->child = (int)(r2p->pipe);
#else
	pipe (r2p->input);
	pipe (r2p->output);
	r2p->child = fork ();
	if (r2p->child == -1) {
		r2p_close (r2p);
		return NULL;
	}
	env ("R2PIPE_IN", r2p->input[0]);
	env ("R2PIPE_OUT", r2p->output[1]);

	if (r2p->child) {
		eprintf ("Child is %d\n", r2p->child);
	} else {
		int rc;
		rc = r_sandbox_system (cmd, 1);
		eprintf ("Child was %d with %d\n", r2p->child, rc);
		r2p_close (r2p);
		exit (0);
		return NULL;
	}
#endif
	return r2p;
}

R_API int r2p_write(R2Pipe *r2p, const char *str) {
	int len = strlen (str)+1; /* include \x00 */
#if __WINDOWS__
	DWORD dwWritten = -1;
	WriteFile (r2p->pipe, str, len, &dwWritten, NULL);
	return dwWritten;
#else
	return write (r2p->input[1], str, len);
#endif
}

/* TODO: add timeout here ? */
R_API char *r2p_read(R2Pipe *r2p) {
	char buf[1024];
#if __WINDOWS__
	BOOL bSuccess = FALSE;
	DWORD dwRead = 0;
	memset (buf, 0, sizeof (buf));
	bSuccess = ReadFile (r2p->pipe, buf, sizeof (buf), &dwRead, NULL);
	if (!bSuccess || !buf[0]) {
		return NULL;
	}
	if (dwRead>0) {
		buf[dwRead] = 0;
	}
	buf[sizeof (buf)-1] = 0;
#else
	int i, rv;
	for (i=0; i<sizeof (buf)-1; i++) {
		rv = read (r2p->output[0], buf+i, 1);
		if (rv != 1 || !buf[i]) break;
	}
	buf[i] = 0;
#endif
	return strdup (buf);
}

R_API void r2p_free (R2Pipe *r2p) {
	r2p->magic = 0;
	r2p_close (r2p);
}
