/* radare2 - LGPL - Copyright 2015-2019 pancake */

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"
#if __WINDOWS__
#include <windows.h>
#endif
#ifdef _MSC_VER
#include <process.h>
#endif

static int lang_pipe_run(RLang *lang, const char *code, int len);
static int lang_pipe_file(RLang *lang, const char *file) {
	return lang_pipe_run (lang, file, -1);
}

#if __WINDOWS__
static HANDLE myCreateChildProcess(const char * szCmdline) {
	PROCESS_INFORMATION piProcInfo = {0};
	STARTUPINFO siStartInfo = {0};
	BOOL bSuccess = FALSE;
	siStartInfo.cb = sizeof (STARTUPINFO);
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
	siStartInfo.hStdInput = GetStdHandle (STD_INPUT_HANDLE);
	siStartInfo.hStdOutput = GetStdHandle (STD_OUTPUT_HANDLE);
	siStartInfo.hStdError = GetStdHandle (STD_ERROR_HANDLE);

	LPTSTR cmdline_ = r_sys_conv_utf8_to_win (szCmdline);
	bSuccess = CreateProcess (NULL, cmdline_, NULL, NULL,
		TRUE, 0, NULL, NULL, &siStartInfo, &piProcInfo);
	free (cmdline_);
	return bSuccess ? piProcInfo.hProcess : NULL;
}

static HANDLE hPipeInOut = NULL;
static HANDLE hproc = NULL;
#define PIPE_BUF_SIZE 8192

static void lang_pipe_run_win(RLang *lang) {
	CHAR buf[PIPE_BUF_SIZE];
	BOOL bSuccess = TRUE;
	int i, res = 0;
	DWORD dwRead = 0, dwWritten = 0, dwEvent;
	HANDLE hRead = CreateEvent (NULL, TRUE, FALSE, NULL);
	if (!hRead) {
		r_sys_perror ("lang_pipe_run_win/CreateEvent hRead");
		return;
	}
	HANDLE hWritten = CreateEvent (NULL, TRUE, FALSE, NULL);
	if (!hWritten) {
		r_sys_perror ("lang_pipe_run_win/CreateEvent hWritten");
		CloseHandle (hRead);
		return;
	}
	r_cons_break_push (NULL, NULL);
	do {
		if (r_cons_is_breaked ()) {
			TerminateProcess (hproc, 0);
			break;
		}
		OVERLAPPED oRead = { 0 };
		oRead.hEvent = hRead;
		memset (buf, 0, PIPE_BUF_SIZE);
		ReadFile (hPipeInOut, buf, PIPE_BUF_SIZE, NULL, &oRead);
		HANDLE hReadEvents[] = { hRead, hproc };
		dwEvent = WaitForMultipleObjects (R_ARRAY_SIZE (hReadEvents), hReadEvents,
		                                  FALSE, INFINITE);
		if (dwEvent == WAIT_OBJECT_0 + 1) { // hproc
			break;
		} else if (dwEvent == WAIT_FAILED) {
			r_sys_perror ("lang_pipe_run_win/WaitForMultipleObjects read");
			break;
		}
		bSuccess = GetOverlappedResult (hPipeInOut, &oRead, &dwRead, TRUE);
		if (!bSuccess) {
			break;
		}
		if (bSuccess && dwRead > 0) {
			buf[sizeof (buf) - 1] = 0;
			OVERLAPPED oWrite = { 0 };
			oWrite.hEvent = hWritten;
			char *res = lang->cmd_str ((RCore*)lang->user, buf);
			if (res) {
				int res_len = strlen (res) + 1;
				for (i = 0; i < res_len; i++) {
					memset (buf, 0, PIPE_BUF_SIZE);
					dwWritten = 0;
					int writelen = res_len - i;
					WriteFile (hPipeInOut, res + i,
					           writelen > PIPE_BUF_SIZE ? PIPE_BUF_SIZE : writelen,
					           NULL, &oWrite);
					HANDLE hWriteEvents[] = { hWritten, hproc };
					dwEvent = WaitForMultipleObjects (R_ARRAY_SIZE (hWriteEvents), hWriteEvents,
					                                  FALSE, INFINITE);
					if (dwEvent == WAIT_OBJECT_0 + 1) { // hproc
						break;
					} else if (dwEvent == WAIT_FAILED) {
						r_sys_perror ("lang_pipe_run_win/WaitForMultipleObjects write");
					}
					BOOL rc = GetOverlappedResult (hPipeInOut, &oWrite, &dwWritten, TRUE);
					if (!rc) {
						r_sys_perror ("lang_pipe_run_win/WriteFile res");
					}
					if (dwWritten > 0) {
						i += dwWritten - 1;
					} else {
						// send null termination // chop
						r_sys_perror ("lang_pipe_run_win/dwWritten");
						//WriteFile (hPipeInOut, "", 1, &dwWritten, NULL);
						//break;
					}
				}
				free (res);
			} else {
				WriteFile (hPipeInOut, "", 1, NULL, &oWrite);
				if (!GetOverlappedResult (hPipeInOut, &oWrite, &dwWritten, TRUE)) {
					r_sys_perror ("lang_pipe_run_win/WriteFile nul");
				}
			}
		}
	} while (true);
	r_cons_break_pop ();
	CloseHandle (hWritten);
	CloseHandle (hRead);
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

	if (pipe (input) != 0) {
		eprintf ("r_lang_pipe: pipe failed on input\n");
		if (safe_in != -1) {
			close (safe_in);
		}
		return false;
	}
	if (pipe (output) != 0) {
		eprintf ("r_lang_pipe: pipe failed on output\n");
		if (safe_in != -1) {
			close (safe_in);
		}
		return false;
	}
	
	env ("R2PIPE_IN", input[0]);
	env ("R2PIPE_OUT", output[1]);

	child = r_sys_fork ();
	if (child == -1) {
		/* error */
		perror ("pipe run");
	} else if (!child) {
		/* children */
		r_sandbox_system (code, 1);
		(void) write (input[1], "", 1);
		close (input[0]);
		close (input[1]);
		close (output[0]);
		close (output[1]);
		fflush (stdout);
		fflush (stderr);
		r_sys_exit (0, true);
		return false;
	} else {
		/* parent */
		char *res, buf[8192]; // TODO: use the heap?
		/* Close pipe ends not required in the parent */
		close (output[1]);
		close (input[0]);
		r_cons_break_push (NULL, NULL);
		for (;;) {
			if (r_cons_is_breaked ()) {
				break;
			}
			memset (buf, 0, sizeof (buf));
			void *bed = r_cons_sleep_begin ();
			ret = read (output[0], buf, sizeof (buf) - 1);
			r_cons_sleep_end (bed);
			if (ret < 1) {
				break;
			}
			if (!buf[0]) {
				continue;
			}
			buf[sizeof (buf) - 1] = 0;
			res = lang->cmd_str ((RCore*)lang->user, buf);
			//eprintf ("%d %s\n", ret, buf);
			if (res) {
				(void) write (input[1], res, strlen (res) + 1);
				free (res);
			} else {
				eprintf ("r_lang_pipe: NULL reply for (%s)\n", buf);
				(void) write (input[1], "", 1); // NULL byte
			}
		}
		r_cons_break_pop ();
		/* workaround to avoid stdin closed */
		if (safe_in != -1) {
			close (safe_in);
		}
		safe_in = -1;
		char *term_in = ttyname (0);
		if (term_in) {
			safe_in = open (term_in, O_RDONLY);
			if (safe_in != -1) {
				dup2 (safe_in, 0);
			} else {
				eprintf ("Cannot open ttyname(0) %s\n", term_in);
			}
		}
	}

	close (input[0]);
	close (input[1]);
	close (output[0]);
	close (output[1]);
	if (safe_in != -1) {
		close (safe_in);
	}
	waitpid (child, NULL, WNOHANG);
	return true;
#else
#if __WINDOWS__
	char *r2pipe_var = r_str_newf ("R2PIPE_IN%x", _getpid ());
	char *r2pipe_paz = r_str_newf ("\\\\.\\pipe\\%s", r2pipe_var);
	LPTSTR r2pipe_paz_ = r_sys_conv_utf8_to_win (r2pipe_paz);

	SetEnvironmentVariable (TEXT ("R2PIPE_PATH"), r2pipe_paz_);
	hPipeInOut = CreateNamedPipe (r2pipe_paz_,
			PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
			PIPE_BUF_SIZE,
			PIPE_BUF_SIZE,
			0, NULL);
	if (hPipeInOut == INVALID_HANDLE_VALUE) {
		r_sys_perror ("lang_pipe_run/CreateNamedPipe");
		goto beach;
	}
	HANDLE hConnected = CreateEvent (NULL, TRUE, FALSE, NULL);
	if (!hConnected) {
		r_sys_perror ("lang_pipe_run/CreateEvent hConnected");
		goto pipe_cleanup;
	}
	OVERLAPPED oConnect = { 0 };
	oConnect.hEvent = hConnected;
	hproc = myCreateChildProcess (code);
	BOOL connected = FALSE;
	if (hproc) {
		connected = ConnectNamedPipe (hPipeInOut, &oConnect);
		DWORD err = GetLastError ();
		if (!connected && err != ERROR_PIPE_CONNECTED) {
			if (err == ERROR_IO_PENDING) {
				HANDLE hEvents[] = { hConnected, hproc };
				DWORD dwEvent = WaitForMultipleObjects (R_ARRAY_SIZE (hEvents), hEvents,
				                                        FALSE, INFINITE);
				if (dwEvent == WAIT_OBJECT_0 + 1) { // hproc
					goto cleanup;
				} else if (dwEvent == WAIT_FAILED) {
					r_sys_perror ("lang_pipe_run/WaitForMultipleObjects connect");
					goto cleanup;
				}
				DWORD dummy;
				connected = GetOverlappedResult (hPipeInOut, &oConnect, &dummy, TRUE);
				err = GetLastError ();
			}
			if (!connected && err != ERROR_PIPE_CONNECTED) {
				r_sys_perror ("lang_pipe_run/ConnectNamedPipe");
				goto cleanup;
			}
		}
		lang_pipe_run_win (lang);
	}
cleanup:
	CloseHandle (hConnected);
pipe_cleanup:
	DeleteFile (r2pipe_paz_);
	CloseHandle (hPipeInOut);
beach:
	free (r2pipe_var);
	free (r2pipe_paz);
	free (r2pipe_paz_);
	return hproc != NULL;
#endif
#endif
}

static RLangPlugin r_lang_plugin_pipe = {
	.name = "pipe",
	.ext = "pipe",
	.license = "LGPL",
	.desc = "Use #!pipe node script.js",
	.run = lang_pipe_run,
	.run_file = (void*)lang_pipe_file,
};
