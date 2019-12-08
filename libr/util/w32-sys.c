#include <r_types.h>
#include <r_util.h>

#if __WINDOWS__
#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#define BUFSIZE 1024
void r_sys_perror_str(const char *fun);

#define ErrorExit(x) { r_sys_perror(x); return false; }
char *ReadFromPipe(HANDLE fh, int *outlen);

R_API char *r_sys_get_src_dir_w32() {
	TCHAR fullpath[MAX_PATH + 1];
	TCHAR shortpath[MAX_PATH + 1];

	if (!GetModuleFileName (NULL, fullpath, MAX_PATH + 1) ||
		!GetShortPathName (fullpath, shortpath, MAX_PATH + 1)) {
		return NULL;
	}
	char *path = r_sys_conv_win_to_utf8 (shortpath);
	char *dir = r_file_dirname (path);
	if (!r_sys_getenv_asbool ("R_ALT_SRC_DIR")) {
		char *tmp = dir;
		dir = r_file_dirname (tmp);
		free (tmp);
	}
	return dir;
}

R_API bool r_sys_cmd_str_full_w32(const char *cmd, const char *input, char **output, int *outlen, char **sterr) {
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
		DWORD nBytesWritten;
		WriteFile (in, input, strlen (input) + 1, &nBytesWritten, NULL);
		if (!SetHandleInformation (in, HANDLE_FLAG_INHERIT, 0)) {
			ErrorExit ("StdIn SetHandleInformation");
		}
	}

	if (!r_sys_create_child_proc_w32 (cmd, fi, out, err)) {
		return false;
	}

	// Close the write end of the pipe before reading from the
	// read end of the pipe, to control child process execution.
	// The pipe is assumed to have enough buffer space to hold the
	// data the child process has already written to it.
	if (in && !CloseHandle (in)) {
		ErrorExit ("StdInWr CloseHandle");
	}
	if (out && !CloseHandle (out)) {
		ErrorExit ("StdOutWr CloseHandle");
	}
	if (err && !CloseHandle (err)) {
		ErrorExit ("StdErrWr CloseHandle");
	}

	if (output) {
		*output = ReadFromPipe (fo, outlen);
	}

	if (sterr) {
		*sterr = ReadFromPipe (fe, NULL);
	}

	if (fi && !CloseHandle (fi)) {
		ErrorExit ("PipeIn CloseHandle");
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
	PROCESS_INFORMATION pi = {0};
	STARTUPINFO si = {0};
	LPTSTR cmdline_;
	bool ret = false;
	const size_t max_length = 32768 * sizeof (TCHAR);
	LPTSTR _cmdline_ = malloc (max_length);

	if (!_cmdline_) {
		R_LOG_ERROR ("Failed to allocate memory\n");
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
	char *str;
	int strl = 0;
	int strsz = BUFSIZE+1;

	if (outlen) {
		*outlen = 0;
	}
	str = malloc (strsz);
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
