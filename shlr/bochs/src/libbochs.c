/* libbochs - radare2 - LGPL - Copyright 2016-2023 - SkUaTeR, pancake */

#include "libbochs.h"

static R_TH_LOCAL char *lpTmpBuffer = NULL;

#define SIZE_BUF 0x5800 * 2

#if R2__WINDOWS__
#ifdef _MSC_VER
#pragma comment(lib, "user32.lib")
#endif
static int RunRemoteThread_(libbochs_t* b, const ut8 *lpBuffer, ut32 dwSize, int a4, ut32 *lpExitCode) {
	int result = 0;
	SIZE_T NumberOfBytesWritten;

	LPVOID pProcessMemory = VirtualAllocEx (b->processInfo.hProcess, 0, dwSize, 0x1000u, 0x40u);
	if (pProcessMemory) {
		if (WriteProcessMemory (b->processInfo.hProcess, pProcessMemory, lpBuffer, dwSize, &NumberOfBytesWritten)) {
			HANDLE hInjectThread = CreateRemoteThread (b->processInfo.hProcess, 0, 0, pProcessMemory, 0, 0, 0);
			if (hInjectThread) {
				if (!WaitForSingleObject (hInjectThread, 0xFFFFFFFF)
					&& (!a4 || ReadProcessMemory (b->processInfo.hProcess,
					pProcessMemory, (PVOID)lpBuffer, dwSize, &NumberOfBytesWritten)))
				{
					if (lpExitCode) {
						GetExitCodeThread (hInjectThread, (PDWORD)lpExitCode);
					}
					result = 1;
				}
				CloseHandle (hInjectThread);
			}
		}
		VirtualFreeEx (b->processInfo.hProcess, pProcessMemory, 0, 0x8000u);
	}
	return result;
}
#endif

void bochs_reset_buffer(libbochs_t* b) {
	memset (b->data, 0, SIZE_BUF);
	b->punteroBuffer = 0;
}

bool bochs_cmd_stop(libbochs_t * b) {
#if R2__WINDOWS__
	HMODULE hKernel;
	unsigned int ExitCode;
	ut8 buffer[] = {
		0x68, 0x00, 0x00, 0x00, 0x00,	//push    0
		0x68, 0x00, 0x00, 0x00, 0x00,	//push    0
		0xE8, 0x00, 0x00, 0x00, 0x00,	//call    $
		0x83, 0x04, 0x24, 0x0A,		//add     [esp], 0A
		0x68, 0x30, 0x30, 0x30, 0x30,	//push    GenerateConsoleCtrlEvent
		0xC3,                           //retn
		0xC2, 0x04, 0x00,		//retn 4
		0xeb, 0xfe			//jmp $
	};
	hKernel = GetModuleHandle (TEXT ("kernel32"));
	FARPROC apiOffset = (FARPROC)GetProcAddress (hKernel, "GenerateConsoleCtrlEvent");
#if _WIN64
#pragma message("warning this bochs shellcode is 32bit only")
	*((DWORD *)&buffer[20]) = 0;
#else
	*((DWORD *)&buffer[20]) = (DWORD)(size_t)apiOffset;
#endif
	ExitCode = RunRemoteThread_ (b, (const ut8*)&buffer, 0x1Eu, 0, &ExitCode) && ExitCode;
	return ExitCode;
#else
	return 0;
#endif
}

bool bochs_wait(libbochs_t *b) {
#if __wasi__
	return false;
#elif R2__WINDOWS__
	int times = 100;
	DWORD dwRead, aval, leftm;
	bochs_reset_buffer(b);
	do {
		while (PeekNamedPipe (b->hReadPipeIn, NULL, 0, NULL, &aval, &leftm)) {
			if (aval < 0) {
				break;
			}
			if (!ReadFile (b->hReadPipeIn, &b->data[b->punteroBuffer], SIZE_BUF, &dwRead, 0)) {
				R_LOG_ERROR ("bochs_wait: ERROR reading from pipe");
				return false;
			}
			if (dwRead) {
				b->punteroBuffer +=dwRead;
			}
		}
		if (strstr (b->data, "<bochs:")) {
			break;
		}
		Sleep (5);
	} while (--times);
	return true;
#else
	int flags,n;
	bochs_reset_buffer (b);
	flags = fcntl (b->hReadPipeIn, F_GETFL, 0);
	(void) fcntl (b->hReadPipeIn, (flags | O_NONBLOCK));
	for (;;) {
		n = read (b->hReadPipeIn, lpTmpBuffer, SIZE_BUF - 1);
		if (n > 0) {
			lpTmpBuffer[n] = 0;
			if (b->punteroBuffer + n >= SIZE_BUF - 1) {
				bochs_reset_buffer(b);
			}
			// XXX overflow here
			memcpy (b->data + b->punteroBuffer, lpTmpBuffer, n + 1);
			b->punteroBuffer += n;
			if (strstr (&b->data[0], "<bochs:")) {
				break;
			}
		}
	}
	(void) fcntl (b->hReadPipeIn, (flags | ~O_NONBLOCK));
	return true;
#endif
}

void bochs_send_cmd(libbochs_t* b, const char *cmd, bool bWait) {
	char *cmdbuff = r_str_newf ("%s\n", cmd);
	bochs_reset_buffer (b);
	size_t cmdlen = strlen (cmdbuff);
#if R2__WINDOWS__
	DWORD dwWritten;
	if (!WriteFile (b->hWritePipeOut, cmdbuff, cmdlen, &dwWritten, NULL)) {
#else
	if (write (b->hWritePipeOut, cmdbuff, cmdlen) != cmdlen) {
#endif
		R_LOG_ERROR ("boch_send_cmd failed");
		goto beach;
	}
	if (bWait)
		bochs_wait (b);
beach:
	free (cmdbuff);
}

int bochs_read(libbochs_t* b, ut64 addr, int count, ut8 * buf) {
	char buff[128];
	char * data;
	int i = 0, ini = 0, fin = 0, pbuf = 0, totalread = 0;
	totalread = (count >SIZE_BUF / 3)?  SIZE_BUF / 3: count;
	snprintf (buff, sizeof (buff), "xp /%imb 0x%016"PFMT64x"", totalread, addr);
	bochs_send_cmd (b, buff, true);
	data = strstr (&b->data[0], "[bochs]:");
	if (!data) {
		R_LOG_ERROR ("bochs_read: Can't find bochs prompt");
		return false;
	}
	size_t lenRec = strlen (data);
	if (!strncmp (data, "[bochs]:", 8)) {
		i += 10; // seek to next line
		do {
			while (data[i] != 0 && data[i] != ':' && i < lenRec) // find :
				i++;
			ini = ++i;
			while (data[i] != 0 &&  data[i] !='\n' && data[i]!=0xd && i < lenRec) // find newline
				i++;
			fin = i++;
			data[fin] = 0;
			if (data[i] == '<')
				break;
			pbuf += r_hex_str2bin (&data[ini], &buf[pbuf]);
			i++; // next line
		} while (data[i] != '<' && i < lenRec);
	}
	return 0;
}

void bochs_close(libbochs_t* b) {
	b->isRunning = false;
#if __wasi__
#elif R2__WINDOWS__
	CloseHandle (b->hReadPipeIn);
	CloseHandle (b->hReadPipeOut);
	CloseHandle (b->hWritePipeIn);
	CloseHandle (b->hWritePipeOut);
	CloseHandle (b->ghWriteEvent);
	TerminateProcess (b->processInfo.hProcess,0);
	free (b->data);
	free (lpTmpBuffer);
#else
	close (b->hReadPipeIn);
	close (b->hWritePipeOut);
	kill (b->pid, SIGKILL);
	R_FREE (b->data);
	R_FREE (lpTmpBuffer);
#endif
}

bool bochs_open(libbochs_t* b, const char * pathBochs, const char * pathConfig) {
	bool result = false;

	b->data = malloc (SIZE_BUF);
	if (!b->data) {
		return false;
	}
	lpTmpBuffer = malloc (SIZE_BUF);
	if (!lpTmpBuffer) {
		R_FREE (b->data);
		return false;
	}
#if R2__WINDOWS__
	struct _SECURITY_ATTRIBUTES PipeAttributes;
	char commandline[1024];
	PipeAttributes.nLength = 12;
	PipeAttributes.bInheritHandle = 1;
	PipeAttributes.lpSecurityDescriptor = 0;
	//
	if (CreatePipe (&b->hReadPipeIn, &b->hReadPipeOut, &PipeAttributes, SIZE_BUF) &&
	    CreatePipe (&b->hWritePipeIn, &b->hWritePipeOut, &PipeAttributes, SIZE_BUF)
	   ) {
		LPTSTR commandline_;

		memset (&b->info, 0, sizeof (STARTUPINFOA));
		memset (&b->processInfo, 0, sizeof (PROCESS_INFORMATION));
		b->info.cb = sizeof (STARTUPINFOA);
		b->info.hStdError = b->hReadPipeOut;
		b->info.hStdOutput = b->hReadPipeOut;
		b->info.hStdInput = b->hWritePipeIn;
		b->info.dwFlags |=  STARTF_USESTDHANDLES;
		snprintf (commandline, sizeof (commandline), "\"%s\" -f \"%s\" -q ", pathBochs, pathConfig);
		R_LOG_DEBUG ("*** Creating process: %s", commandline);
		commandline_ = r_sys_conv_utf8_to_win (commandline);
		if (CreateProcess (NULL, commandline_, NULL, NULL, TRUE, CREATE_NEW_CONSOLE,
				NULL, NULL, &b->info, &b->processInfo)) {
			R_LOG_DEBUG ("Process created");
			WaitForInputIdle (b->processInfo.hProcess, INFINITE);
			R_LOG_DEBUG ("Initialized input");
			b->isRunning = true;
			bochs_reset_buffer (b);
			R_LOG_INFO ("Waiting for bochs");
			if (bochs_wait (b)) {
				R_LOG_INFO ("Ready");
				result = true;
			} else {
				bochs_close (b);
			}
		}
		free (commandline_);
	}
	return result;
#elif __wasi__
	// nothing
#else
	#define PIPE_READ 0
	#define PIPE_WRITE 1
	int aStdinPipe[2];
	int aStdoutPipe[2];
	int nChild;

	if (pipe (aStdinPipe) < 0) {
		R_LOG_ERROR ("allocating pipe for child input redirect");
		goto done;
	}
	if (pipe(aStdoutPipe) < 0) {
		close (aStdinPipe[PIPE_READ]);
		close (aStdinPipe[PIPE_WRITE]);
		R_LOG_ERROR ("allocating pipe for child output redirect");
		goto done;
	}

	nChild = fork ();
	if (0 == nChild) {
		// redirect stdin
		if (dup2 (aStdinPipe[PIPE_READ], STDIN_FILENO) == -1) {
			R_LOG_ERROR ("redirecting stdin");
			return false;
		}

		// redirect stdout
		if (dup2 (aStdoutPipe[PIPE_WRITE], STDOUT_FILENO) == -1) {
			R_LOG_ERROR ("redirecting stdout");
			return false;
		}

		// redirect stderr
		if (dup2 (aStdoutPipe[PIPE_WRITE], STDERR_FILENO) == -1) {
			R_LOG_ERROR ("redirecting stderr");
			return false;
		}

		close (aStdinPipe[PIPE_READ]);
		close (aStdinPipe[PIPE_WRITE]);
		close (aStdoutPipe[PIPE_READ]);
		close (aStdoutPipe[PIPE_WRITE]);
		(void) execl (pathBochs, pathBochs, "-q", "-f", pathConfig, NULL);
		perror ("execl");
		exit (1);
	} else if (nChild > 0) {
		close (aStdinPipe[PIPE_READ]);
		close (aStdoutPipe[PIPE_WRITE]);

		if (read (aStdoutPipe[PIPE_READ], lpTmpBuffer, 1) != 1) {
			R_LOG_ERROR ("boch_open failed");
			bochs_close (b);
		} else {
			b->hReadPipeIn  = aStdoutPipe[PIPE_READ];
			b->hWritePipeOut = aStdinPipe[PIPE_WRITE];
			b->isRunning = true;
			bochs_reset_buffer (b);
			R_LOG_INFO ("Waiting for bochs");
			if (bochs_wait (b)) {
				R_LOG_INFO ("Ready");
				b->pid = nChild;
				result = true;
			} else {
				bochs_close (b);
			}
		}
		return result;
	} else {
		perror ("pipe");
		// failed to create child
		close (aStdinPipe[PIPE_READ]);
		close (aStdinPipe[PIPE_WRITE]);
		close (aStdoutPipe[PIPE_READ]);
		close (aStdoutPipe[PIPE_WRITE]);
	}
#endif
done:
	R_FREE (b->data);
	R_FREE (lpTmpBuffer);
	return result;
}
