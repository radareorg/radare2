/* libbochs - radare2 - LGPL - Copyright 2016 - SkUaTeR */

#include "libbochs.h"

static char *lpTmpBuffer; //[0x2800u];
static char *cmdBuff;//[128];
int sizeSend = 0;


#define SIZE_BUF 0x5800 * 2

int RunRemoteThread_(libbochs_t* b, const ut8 *lpBuffer, ut32 dwSize, int a4, ut32 *lpExitCode) {
#if __WINDOWS__
	LPVOID pProcessMemory;
	HANDLE hInjectThread; 
	int result = 0; 
	signed int tmpResult;
	DWORD NumberOfBytesWritten; 

	tmpResult = 0;
	pProcessMemory = VirtualAllocEx(b->processInfo.hProcess, 0, dwSize, 0x1000u, 0x40u);
	if (pProcessMemory) {
		if (WriteProcessMemory(b->processInfo.hProcess, pProcessMemory, lpBuffer, dwSize, &NumberOfBytesWritten)) {
			hInjectThread = CreateRemoteThread(b->processInfo.hProcess, 0, 0, pProcessMemory, 0, 0, 0);
			if (hInjectThread) {
				if (!WaitForSingleObject(hInjectThread, 0xFFFFFFFF)
					&& (!a4 || ReadProcessMemory (b->processInfo.hProcess,
					pProcessMemory, lpBuffer, dwSize, &NumberOfBytesWritten)))
				{
					if (lpExitCode)
						GetExitCodeThread (hInjectThread, lpExitCode);
					tmpResult = 1;
				}
			}
		}
		VirtualFreeEx (b->processInfo.hProcess, pProcessMemory, 0, 0x8000u);
		if (hInjectThread)
			CloseHandle (hInjectThread);
		result = tmpResult;
	}
	return result;
#else
	return 0;
#endif
}

void ResetBuffer_(libbochs_t* b) {
	memset (b->data, 0, SIZE_BUF);
	b->punteroBuffer = 0;
}

bool CommandStop_(libbochs_t * b) {
#if __WINDOWS__
	HMODULE hKernel;
	DWORD ExitCode;
	DWORD apiOffset = 0;
	char buffer[] = { 
		0x68, 0x00, 0x00, 0x00, 0x00,	//push    0
		0x68, 0x00, 0x00, 0x00, 0x00,	//push    0
		0xE8, 0x00, 0x00, 0x00, 0x00,	//call    $
		0x83, 0x04, 0x24, 0x0A,		//add     [esp], 0A
		0x68, 0x30, 0x30, 0x30, 0x30,	//push    GenerateConsoleCtrlEvent
		0xC3,                           //retn 
		0xC2, 0x04, 0x00,		//retn 4
		0xeb, 0xfe			//jmp $
	};
	hKernel = GetModuleHandleA("kernel32");
	apiOffset = (DWORD)GetProcAddress(hKernel, "GenerateConsoleCtrlEvent");
	*((DWORD *)&buffer[20]) = apiOffset;
	ExitCode = RunRemoteThread_(b, &buffer, 0x1Eu, 0, &ExitCode) && ExitCode;
	return ExitCode;
#else
	return 0;
#endif
}

bool WaitForReply_(libbochs_t *b) {
#if __WINDOWS__
	int times = 0;
	DWORD dwRead,aval,leftm;
	times = 100; // reintenta durante 10 segundos
	ResetBuffer_(b);	
	do {
		while (PeekNamedPipe (b->hReadPipeIn, NULL, 0, NULL, &aval, &leftm)) {
			if (aval < 0) break;
			if (!ReadFile(b->hReadPipeIn, &b->data[b->punteroBuffer], SIZE_BUF, &dwRead, 0)) {
				lprintf("WaitForReply_: !!ERROR Leyendo datos del pipe.\n\n");
				return false;
			}
			//lprintf("mythreadlector: %x %x\n",NumberOfBytesRead,punteroBuffer);
			if (dwRead)
				b->punteroBuffer +=dwRead; 
		}
		if (strstr (b->data, "<bochs:")) {
			break;
		}
		Sleep (10);
	} while (--times);
	return true;
#else
	return false;
#endif
}

void bochs_send_cmd(libbochs_t* b, const char * comando, bool bWait) {
#if __WINDOWS__
	//lprintf("Enviando comando: %s\n",comando);
	DWORD dwWritten;
	ResetBuffer_(b);
	ZeroMemory(cmdBuff,128);
	sizeSend=sprintf(cmdBuff,"%s\n",comando);
	WriteFile(b->hWritePipeOut, cmdBuff, strlen(cmdBuff), &dwWritten, NULL);
	if (bWait)
		WaitForReply_(b);
#else
#warning TODO
#endif
}

int bochs_read_(libbochs_t* b, ut64 addr, int count, ut8 * buf) {
	char buff[128];
	int lenRec = 0,i = 0,ini = 0, fin = 0, pbuf = 0, totalread = 0;
	totalread = (count >SIZE_BUF / 3)?  SIZE_BUF / 3: count;

	snprintf(buff, sizeof (buff), "xp /%imb 0x%016"PFMT64x"",totalread,addr);
	bochs_send_cmd (b, buff, true);

	lprintf ("%s\n", b->data);

	lenRec = strlen (b->data);
	if (!strncmp (b->data, "[bochs]:", 8)) {
		i += 10; // nos sitiamos en la siguiente linea.
		do {
			while (b->data[i] != 0 && b->data[i] != ':' && i < lenRec) // buscamos los :
				i++;
			ini = ++i;
			while (b->data[i] != 0 && b->data[i] != 0x0d && i < lenRec) // buscamos los el retorno
				i++;
			fin = i++;
			b->data[fin] = 0;
			pbuf+=r_hex_str2bin(&b->data[ini],&buf[pbuf]);
			//lprintf("%s\n", &lpBuffer[ini]);
			i++; // siguiente linea
		} while (b->data[i] != '<' && i < lenRec);
	}
	return 0;
}
	
void bochs_close_(libbochs_t* b) {
	b->isRunning = false;
#if __WINDOWS__
	CloseHandle (b->hReadPipeIn);
	CloseHandle (b->hReadPipeOut);
	CloseHandle (b->hWritePipeIn);
	CloseHandle (b->hWritePipeOut);
	CloseHandle (b->ghWriteEvent);
	TerminateProcess (b->processInfo.hProcess,0);
#endif
	free(b->data);
	free (lpTmpBuffer);
	free (cmdBuff);
}

bool bochs_open_(libbochs_t* b, const char * rutaBochs, const char * rutaConfig) {
	bool result = false;
#if __WINDOWS__
	struct _SECURITY_ATTRIBUTES PipeAttributes;
	char commandline[1024];
	// alojamos el buffer de datos
	b->data = malloc(SIZE_BUF);
	lpTmpBuffer = malloc(SIZE_BUF);
	cmdBuff = malloc(128);
	lprintf("bochs_open: invocado\n"); 
	// creamos los pipes
	PipeAttributes.nLength = 12;
	PipeAttributes.bInheritHandle = 1;
	PipeAttributes.lpSecurityDescriptor = 0;
	//
	result = FALSE;
	if (CreatePipe(&b->hReadPipeIn, &b->hReadPipeOut, &PipeAttributes, SIZE_BUF) && 
	    CreatePipe(&b->hWritePipeIn, &b->hWritePipeOut, &PipeAttributes, SIZE_BUF)
	   ) {
		//  Inicializamos las estructuras
		ZeroMemory(&b->info, sizeof(STARTUPINFO));
		ZeroMemory(&b->processInfo, sizeof(PROCESS_INFORMATION));
		b->info.cb = sizeof(STARTUPINFO);
		// Asignamos los pipes
		b->info.hStdError = b->hReadPipeOut;
		b->info.hStdOutput = b->hReadPipeOut;
		b->info.hStdInput = b->hWritePipeIn;
		b->info.dwFlags |=  STARTF_USESTDHANDLES;
		// Creamos el proceso
		sprintf(commandline, "\"%s\" -f \"%s\" -q ",rutaBochs,rutaConfig);
		lprintf("*** Creando proces: %s\n",commandline);
		if (CreateProcessA(NULL, commandline, NULL, NULL,TRUE, CREATE_NEW_CONSOLE , NULL, NULL, &b->info, &b->processInfo)) {
			lprintf ("Proceso spawneado\n");
			WaitForInputIdle (b->processInfo.hProcess, INFINITE);
			lprintf ("Entrada inicializada\n");

			b->isRunning = true;
			//CreateThread(NULL, 0, MyThLector_, b, 0, 0);
			//b->ghWriteEvent = CreateEvent(NULL, TRUE, FALSE, TEXT("WriteEvent"));
			//CreateThread(NULL, 0, MyThEscritor_, b, 0, 0);
			ResetBuffer_(b);
			lprintf("Esperando inicializacion de bochs.\n");
			if (WaitForReply_(b)) {
				lprintf("Inicializacion completa.\n");
				result = true;
			} else {
				bochs_close_(b);
			}
		}
	}
#endif
	return result;
}
