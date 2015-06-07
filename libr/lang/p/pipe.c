
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

static void env(const char *s, int f) {
	char *a = r_str_newf ("%d", f);
	r_sys_setenv (s, a);
//	eprintf ("%s %s\n", s, a);
	free (a);
}

#if __WINDOWS__
static HANDLE  myCreateChildProcess(const char * szCmdline) {
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE;
	DWORD dwWritten;
	ZeroMemory (&piProcInfo, sizeof (PROCESS_INFORMATION));
	ZeroMemory (&siStartInfo, sizeof (STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	bSuccess = CreateProcess (NULL, szCmdline, NULL, NULL,
		TRUE, 0, NULL, NULL, &siStartInfo, &piProcInfo);
	if (!bSuccess)
		return NULL;
	
	//CloseHandle (piProcInfo.hProcess);
	//CloseHandle (piProcInfo.hThread);
	return piProcInfo.hProcess;
}
#endif

static int lang_pipe_run(RLang *lang, const char *code, int len) {
	int safe_in = dup (0);
	int child, ret;
	int input[2];
	int output[2];

#if __UNIX__
	pipe (input);
	pipe (output);

	env ("R2PIPE_IN", input[0]);
	env ("R2PIPE_OUT", output[1]);

	child = r_sys_fork ();
	if (child == -1) {
		/* error */
	} else if (child == 0) {
		/* children */
#if 1
		r_sandbox_system (code, 1);
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
		write (input[1], "", 1);
		close (input[0]);
		close (input[1]);
		close (output[0]);
		close (output[1]);
		exit (0);
		return R_FALSE;
	} else {
		/* parent */
		char *res, buf[1024];

		/* Close pipe ends not required in the parent */
		close(output[1]);
		close(input[0]);

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
		dup2 (safe_in, 0);
		r_cons_break_end ();
	}

	close (input[0]);
	close (input[1]);
	close (output[0]);
	close (output[1]);
	close (safe_in);
	waitpid(child, NULL, 0);
	return R_TRUE;
#else
#if __WINDOWS__
	HANDLE hPipeInOut = NULL;
	HANDLE hproc=NULL;
	DWORD dwRead, dwWritten;
	CHAR buf[1024];
	BOOL bSuccess = FALSE;
	SECURITY_ATTRIBUTES saAttr;
	int res=0;
	sprintf(buf,"R2PIPE_IN%x",_getpid());
	SetEnvironmentVariable("R2PIPE_PATH",buf);
	sprintf(buf,"\\\\.\\pipe\\R2PIPE_IN%x",_getpid());
	hPipeInOut = CreateNamedPipe(buf,
		PIPE_ACCESS_DUPLEX,PIPE_TYPE_MESSAGE | \
		PIPE_READMODE_MESSAGE | \
		PIPE_NOWAIT,PIPE_UNLIMITED_INSTANCES,
		sizeof (buf), sizeof (buf), 0, NULL);
	hproc=myCreateChildProcess (code);
	if (hproc==NULL) {
		//eprintf("Error spawning process: %s\n",code);
		return R_TRUE;
	}
	r_cons_break (NULL, NULL);
	for (;;)
	{
		res = ConnectNamedPipe(hPipeInOut, NULL);
		if (GetLastError()==ERROR_PIPE_CONNECTED) {
			//eprintf("new client\n");
			break;
		}
		if (r_cons_singleton ()->breaked) {
			TerminateProcess(hproc,0);
			break;
		}

	}
	for (;;) {
		if (r_cons_singleton ()->breaked) {
			TerminateProcess(hproc,0);
			break;
		}
		memset (buf, 0, sizeof (buf));
		bSuccess = ReadFile( hPipeInOut, buf, sizeof (buf), &dwRead, NULL);
	  	if (dwRead!=0) {
			buf[sizeof(buf)-1] = 0;
			res = lang->cmd_str ((RCore*)lang->user, buf);
			if (res) {
				WriteFile(hPipeInOut, res, strlen (res)+1, &dwWritten, NULL);
				free (res);
			} else {
				WriteFile(hPipeInOut, "", 1, &dwWritten, NULL);
			}
	  	}
	}
	CloseHandle(hPipeInOut);
	r_cons_break_end ();
	return R_TRUE;
#endif
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
