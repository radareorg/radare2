#include <r_types.h>
#include <r_util.h>

#if __WINDOWS__
#include <windows.h> 
#include <stdio.h> 
#ifndef __CYGWIN__
#include <tchar.h>
#endif

#define BUFSIZE 1024
void r_sys_perror(const char *fun);

#define ErrorExit(x) { r_sys_perror(x); return NULL; }
static int CreateChildProcess(const char *szCmdline, HANDLE out);
char *ReadFromPipe(HANDLE fh); 

// HACKY
static char *getexe(const char *str) {
	char *ptr, *argv0 = strdup (str);
	ptr = strchr (argv0, ' ');
	if (ptr) *ptr = '\0';
	argv0 = realloc (argv0, strlen (argv0)+8);
	strcat (argv0, ".exe");
	return argv0;
}

R_API char *r_sys_cmd_str_w32(const char *cmd) { 
	char *ret = NULL;
	HANDLE out = NULL;
	HANDLE in = NULL;
	SECURITY_ATTRIBUTES saAttr; 
	char *argv0 = getexe (cmd);

	// Set the bInheritPlugin flag so pipe handles are inherited. 
	saAttr.nLength = sizeof (SECURITY_ATTRIBUTES); 
	saAttr.bInheritHandle = TRUE; 
	saAttr.lpSecurityDescriptor = NULL; 
	HANDLE fh;

	// Create a pipe for the child process's STDOUT. 
	if (!CreatePipe (&fh, &out, &saAttr, 0)) 
		ErrorExit ("StdoutRd CreatePipe"); 

	// Ensure the read handle to the pipe for STDOUT is not inherited.
	if (!SetHandleInformation (fh, HANDLE_FLAG_INHERIT, 0) )
		ErrorExit ("Stdout SetHandleInformation"); 

	CreateChildProcess (cmd, out);

	in = CreateFile (argv0,
			GENERIC_READ, 
			FILE_SHARE_READ, 
			NULL, 
			OPEN_EXISTING, 
			FILE_ATTRIBUTE_READONLY, 
			NULL); 

	if (in == INVALID_HANDLE_VALUE) {
		eprintf ("CreateFile (%s)\n", argv0);
		ErrorExit ("CreateFile"); 
	}

	// Close the write end of the pipe before reading from the 
	// read end of the pipe, to control child process execution.
	// The pipe is assumed to have enough buffer space to hold the
	// data the child process has already written to it.
	if (!CloseHandle (out))
		ErrorExit ("StdOutWr CloseHandle"); 
	ret = ReadFromPipe (fh);
	free (argv0);

	return ret; 
} 

static int CreateChildProcess(const char *szCmdline, HANDLE out) { 
	PROCESS_INFORMATION piProcInfo; 
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE; 

	ZeroMemory (&piProcInfo, sizeof (PROCESS_INFORMATION) );

	// Set up members of the STARTUPINFO structure. 
	// This structure specifies the STDIN and STDOUT handles for redirection.
	ZeroMemory (&siStartInfo, sizeof (STARTUPINFO) );
	siStartInfo.cb = sizeof(STARTUPINFO); 
	siStartInfo.hStdError = out;
	siStartInfo.hStdOutput = out;
	siStartInfo.hStdInput = NULL;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	bSuccess = CreateProcess (NULL, 
			(LPSTR)szCmdline,// command line 
			NULL,          // process security attributes 
			NULL,          // primary thread security attributes 
			TRUE,          // handles are inherited 
			0,             // creation flags 
			NULL,          // use parent's environment 
			NULL,          // use parent's current directory 
			&siStartInfo,  // STARTUPINFO pointer 
			&piProcInfo);  // receives PROCESS_INFORMATION 

	if (bSuccess) {
		CloseHandle (piProcInfo.hProcess);
		CloseHandle (piProcInfo.hThread);
	} else r_sys_perror ("CreateProcess");
	return bSuccess;
}

char *ReadFromPipe(HANDLE fh) {
	DWORD dwRead;
	CHAR chBuf[BUFSIZE]; 
	BOOL bSuccess = FALSE;
	char *str;
	int strl = 0;
	int strsz = BUFSIZE+1;

	str = malloc (strsz);
	for (;;) { 
		bSuccess = ReadFile (fh, chBuf, BUFSIZE, &dwRead, NULL);
		if (! bSuccess || dwRead == 0) break; 
		chBuf[dwRead] = '\0';
		if (strl+dwRead>strsz) {
			strsz += 4096;
			str = realloc (str, strsz);
			if (!str)
				return NULL;
		}
		memcpy (str+strl, chBuf, dwRead);
		strl += dwRead;
	} 
	str[strl] = 0;
	return str;
} 
#endif
