/* radare2 - LGPL - Copyright 2021 - pancake */

#include <r_types.h>
#include <r_util.h>

#if R2__WINDOWS__
#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#define BUFSIZE 1024
void r_sys_perror_str(const char *fun);

#define ErrorExit(x) { r_sys_perror(x); return false; }
char *ReadFromPipe(HANDLE fh, int *outlen);

// The input is fed from a worker thread while the main thread drains the
// output pipes: a synchronous write blocks as soon as the input fills the
// pipe and the child is not reading it (for example because the child is
// blocked writing to a full stdout pipe).
typedef struct {
	HANDLE handle;
	const char *input;
	DWORD len;
} StdinWriter;

static DWORD WINAPI stdin_writer_thread(LPVOID arg) {
	StdinWriter *w = (StdinWriter *)arg;
	DWORD written = 0;
	// a blocking anonymous pipe completes the requested write or fails if
	// the child closed its end; the thread owns and closes the handle
	const bool ok = WriteFile (w->handle, w->input, w->len, &written, NULL) && written == w->len;
	CloseHandle (w->handle);
	return ok? 0: 1;
}

R_API bool r_sys_cmd_str_full_w32(const char *cmd, const char *input, int ilen, char **output, int *outlen, char **sterr) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_EXEC)) {
		return false;
	}
	HANDLE in = NULL;
	HANDLE out = NULL;
	HANDLE err = NULL;
	SECURITY_ATTRIBUTES saAttr;

	// Set the bInheritPlugin flag so pipe handles are inherited.
	saAttr.nLength = sizeof (SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;
	HANDLE fi = NULL;
	HANDLE fo = NULL;
	HANDLE fe = NULL;

	// Create a pipe for the child process's STDOUT and STDERR.
	// Ensure the read handle to the pipe for STDOUT and SRDERR and write handle of STDIN is not inherited.
	if (output) {
		if (!CreatePipe (&fo, &out, &saAttr, 0)) {
			ErrorExit ("StdOutRd CreatePipe");
		}
		if (!SetHandleInformation (fo, HANDLE_FLAG_INHERIT, 0)) {
			ErrorExit ("StdOut SetHandleInformation");
		}
	}
	if (sterr) {
		if (!CreatePipe (&fe, &err, &saAttr, 0)) {
			ErrorExit ("StdErrRd CreatePipe");
		}
		if (!SetHandleInformation (fe, HANDLE_FLAG_INHERIT, 0)) {
			ErrorExit ("StdErr SetHandleInformation");
		}
	}
	if (input) {
		if (!CreatePipe (&fi, &in, &saAttr, 0)) {
			ErrorExit ("StdInRd CreatePipe");
		}
		// The parent write end must not be inherited, otherwise the child
		// would hold its own stdin pipe open and never see EOF.
		if (!SetHandleInformation (in, HANDLE_FLAG_INHERIT, 0)) {
			ErrorExit ("StdIn SetHandleInformation");
		}
	}

	if (!r_sys_create_child_proc_w32 (cmd, fi, out, err)) {
		if (fi) {
			CloseHandle (fi);
		}
		if (in) {
			CloseHandle (in);
		}
		if (fo) {
			CloseHandle (fo);
		}
		if (out) {
			CloseHandle (out);
		}
		if (fe) {
			CloseHandle (fe);
		}
		if (err) {
			CloseHandle (err);
		}
		return false;
	}

	// The child owns its ends of the pipes now; close the parent copies before
	// feeding stdin so a child that exits early breaks the pipe instead of
	// leaving the writer blocked with the read end still open.
	if (fi && !CloseHandle (fi)) {
		ErrorExit ("PipeIn CloseHandle");
	}
	fi = NULL;
	if (out && !CloseHandle (out)) {
		ErrorExit ("StdOutWr CloseHandle");
	}
	out = NULL;
	if (err && !CloseHandle (err)) {
		ErrorExit ("StdErrWr CloseHandle");
	}
	err = NULL;

	const int inlen = input? (ilen >= 0? ilen: (int)strlen (input) + 1): 0;
	StdinWriter w = { in, input, (DWORD)inlen };
	HANDLE writer = NULL;
	if (input) {
		writer = CreateThread (NULL, 0, stdin_writer_thread, &w, 0, NULL);
		if (!writer) {
			r_sys_perror ("CreateThread");
			// do not run the command without feeding its input
			if (in) {
				CloseHandle (in);
			}
			if (fo) {
				CloseHandle (fo);
			}
			if (fe) {
				CloseHandle (fe);
			}
			return false;
		}
		in = NULL; // the writer thread owns and closes the handle
	}

	if (output) {
		*output = ReadFromPipe (fo, outlen);
	}

	if (sterr) {
		*sterr = ReadFromPipe (fe, NULL);
	}
	if (writer) {
		WaitForSingleObject (writer, INFINITE);
		DWORD wret = 0;
		if (GetExitCodeThread (writer, &wret) && wret) {
			R_LOG_DEBUG ("Failed to feed the whole input to the child");
		}
		CloseHandle (writer);
	}
	if (fo && !CloseHandle (fo)) {
		ErrorExit ("PipeOut CloseHandle");
	}
	if (fe && !CloseHandle (fe)) {
		ErrorExit ("PipeErr CloseHandle");
	}

	return true;
}

R_API bool r_sys_create_child_proc_w32(const char *cmdline, HANDLE in, HANDLE out, HANDLE err) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_EXEC)) {
		return false;
	}
	PROCESS_INFORMATION pi = {0};
	STARTUPINFO si = {0};
	LPTSTR cmdline_;
	bool ret = false;
	const size_t max_length = 32768 * sizeof (TCHAR);
	LPTSTR _cmdline_ = malloc (max_length);

	if (!_cmdline_) {
		return false;
	}

	// Set up members of the STARTUPINFO structure.
	// This structure specifies the STDIN and STDOUT handles for redirection.
	si.cb = sizeof (STARTUPINFO);
	si.hStdError = err;
	si.hStdOutput = out;
	si.hStdInput = in;
	si.dwFlags |= STARTF_USESTDHANDLES;
	cmdline_ = r_sys_conv_utf8_to_win (cmdline);
	ExpandEnvironmentStrings (cmdline_, _cmdline_, max_length - 1);
	if ((ret = CreateProcess (NULL,
			_cmdline_,     // command line
			NULL,          // process security attributes
			NULL,          // primary thread security attributes
			TRUE,          // handles are inherited
			0,             // creation flags
			NULL,          // use parent's environment
			NULL,          // use parent's current directory
			&si,           // STARTUPINFO pointer
			&pi))) {  // receives PROCESS_INFORMATION
		ret = true;
		CloseHandle (pi.hProcess);
		CloseHandle (pi.hThread);
	} else {
		r_sys_perror ("CreateProcess");
	}
	free (cmdline_);
	free (_cmdline_);
	return ret;
}

char *ReadFromPipe(HANDLE fh, int *outlen) {
	DWORD dwRead;
	CHAR chBuf[BUFSIZE];
	BOOL bSuccess = FALSE;
	int strl = 0;
	int strsz = BUFSIZE + 1;

	if (outlen) {
		*outlen = 0;
	}
	char *str = malloc (strsz);
	if (!str) {
		return NULL;
	}
	while (true) {
		bSuccess = ReadFile (fh, chBuf, BUFSIZE, &dwRead, NULL);
		if (!bSuccess || dwRead == 0) {
			break;
		}
		if (strl+dwRead>strsz) {
			char *str_tmp = str;
			strsz += 4096;
			str = realloc (str, strsz);
			if (!str) {
				free (str_tmp);
				return NULL;
			}
		}
		memcpy (str+strl, chBuf, dwRead);
		strl += dwRead;
	}
	str[strl] = 0;
	if (outlen) {
		*outlen = strl;
	}
	return str;
}
#endif
