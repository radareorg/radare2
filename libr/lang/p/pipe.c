/* radare2 - LGPL - Copyright 2015 pancake */

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"
#if __WINDOWS__
#include <windows.h>
#endif

static int lang_pipe_run(RLang *lang, const char *code, int len);
static int lang_pipe_file(RLang *lang, const char *file) {
	return lang_pipe_run (lang, file, -1);
}

#if __WINDOWS__
static HANDLE  myCreateChildProcess(const char * szCmdline) {
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE;
	ZeroMemory (&piProcInfo, sizeof (PROCESS_INFORMATION));
	ZeroMemory (&siStartInfo, sizeof (STARTUPINFO));
	siStartInfo.cb = sizeof (STARTUPINFO);
	LPTSTR szCmdLine2 = strdup (szCmdline);
	bSuccess = CreateProcess (NULL, szCmdLine2, NULL, NULL,
		TRUE, 0, NULL, NULL, &siStartInfo, &piProcInfo);
	free (szCmdLine2);
	//CloseHandle (piProcInfo.hProcess);
	//CloseHandle (piProcInfo.hThread);
	return bSuccess? piProcInfo.hProcess: NULL;
}
static BOOL bStopThread = FALSE;
static HANDLE hPipeInOut = NULL;
static HANDLE hproc = NULL;
#define PIPE_BUF_SIZE 4096
DWORD WINAPI ThreadFunction(LPVOID lpParam) {
	RLang * lang = lpParam;
	CHAR buf[PIPE_BUF_SIZE];
	BOOL bSuccess = FALSE;
	int i, res = 0;
	DWORD dwRead, dwWritten;
	r_cons_break (NULL, NULL);
	res = ConnectNamedPipe (hPipeInOut, NULL);
	if (!res) {
		eprintf ("ConnectNamedPipe failed\n");
		return FALSE;
	}
	do {
		if (r_cons_singleton ()->breaked) {
			TerminateProcess(hproc,0);
			break;
		}
		memset (buf, 0, PIPE_BUF_SIZE);
		bSuccess = ReadFile (hPipeInOut, buf, PIPE_BUF_SIZE, &dwRead, NULL);
                if (bStopThread)
			break;
		if (bSuccess && dwRead>0) {
			buf[sizeof (buf)-1] = 0;
			char *res = lang->cmd_str ((RCore*)lang->user, buf);
			if (res) {
				int res_len = strlen (res) + 1;
				for (i = 0; i < res_len; i++) {
					memset (buf, 0, PIPE_BUF_SIZE);
					dwWritten = 0;
					int writelen=res_len - i;
					int rc = WriteFile (hPipeInOut, res + i, writelen>PIPE_BUF_SIZE?PIPE_BUF_SIZE:writelen, &dwWritten, 0);
					if (bStopThread) {
						free (res);
						break;
					}
					if (!rc) {
						eprintf ("WriteFile: failed 0x%x\n", (int)GetLastError());
					}
					if (dwWritten > 0) {
						i += dwWritten - 1;
					} else {
						/* send null termination // chop */
						eprintf ("w32-lang-pipe: 0x%x\n", (ut32)GetLastError ());
						//WriteFile (hPipeInOut, "", 1, &dwWritten, NULL);
						//break;
					}
				}
				free (res);
			} else {
				WriteFile (hPipeInOut, "", 1, &dwWritten, NULL);
			}
		}
	} while(!bStopThread);
	r_cons_break_end ();
	return TRUE;
}
#else
static void env(const char *s, int f) {
	char *a = r_str_newf ("%d", f);
	r_sys_setenv (s, a);
//	eprintf ("%s %s\n", s, a);
	free (a);
}
#endif

static int lang_pipe_run(RLang *lang, const char *code, int len) {
#if __UNIX__
	int safe_in = dup (0);
	int child, ret;
	int input[2];
	int output[2];

	pipe (input);
	pipe (output);

	env ("R2PIPE_IN", input[0]);
	env ("R2PIPE_OUT", output[1]);

	child = r_sys_fork ();
	if (child == -1) {
		/* error */
	} else if (child == 0) {
		/* children */
		r_sandbox_system (code, 1);
		write (input[1], "", 1);
		close (input[0]);
		close (input[1]);
		close (output[0]);
		close (output[1]);
		exit (0);
		return false;
	} else {
		/* parent */
		char *res, buf[1024];

		/* Close pipe ends not required in the parent */
		close (output[1]);
		close (input[0]);

		r_cons_break (NULL, NULL);
		for (;;) {
			if (r_cons_singleton ()->breaked) {
				break;
			}
			memset (buf, 0, sizeof (buf));
			ret = read (output[0], buf, sizeof (buf)-1);
			if (ret <1 || !buf[0]) {
				break;
			}
			buf[sizeof (buf)-1] = 0;
			res = lang->cmd_str ((RCore*)lang->user, buf);
			//eprintf ("%d %s\n", ret, buf);
			if (res) {
				write (input[1], res, strlen (res)+1);
				free (res);
			} else {
				eprintf ("r_lang_pipe: NULL reply for (%s)\n", buf);
				write (input[1], "", 1); // NULL byte
			}
		}
		/* workaround to avoid stdin closed */
		if (safe_in != -1)
			close (safe_in);
		safe_in = open (ttyname(0), O_RDONLY);
		if (safe_in != -1) {
			dup2 (safe_in, 0);
		} else eprintf ("Cannot open ttyname(0) %s\n", ttyname(0));
		r_cons_break_end ();
	}

	close (input[0]);
	close (input[1]);
	close (output[0]);
	close (output[1]);
	if (safe_in != -1)
		close (safe_in);
	waitpid (child, NULL, 0);
	return true;
#else
#if __WINDOWS__
	HANDLE hThread = 0;
	char *r2pipe_var = r_str_newf ("R2PIPE_IN%x", _getpid ());
	char *r2pipe_paz = r_str_newf ("\\\\.\\pipe\\%s", r2pipe_var);
	SetEnvironmentVariable ("R2PIPE_PATH", r2pipe_var);
	hPipeInOut = CreateNamedPipe (r2pipe_paz,
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
			PIPE_BUF_SIZE,
			PIPE_BUF_SIZE,
			0, NULL);
	hproc = myCreateChildProcess (code);
	if (hproc) {
		bStopThread = FALSE;
		hThread = CreateThread (NULL, 0, ThreadFunction, lang, 0,0);
		WaitForSingleObject (hproc, INFINITE);
		bStopThread = TRUE;
		DeleteFile (r2pipe_paz);
		WaitForSingleObject (hThread, INFINITE);
		CloseHandle (hPipeInOut);
	}
	free (r2pipe_var);
	free (r2pipe_paz);
	return hproc != NULL;
#endif
#endif
}

static struct r_lang_plugin_t r_lang_plugin_pipe = {
	.name = "pipe",
	.ext = "pipe",
	.license = "LGPL",
	.desc = "Use #!pipe node script.js",
	.run = lang_pipe_run,
	.run_file = (void*)lang_pipe_file,
};
