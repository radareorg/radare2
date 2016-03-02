
/* libgdbr - LGPL - Copyright 2014 - defragger */

#include "libbochs.h"
static char * lpTmpBuffer; //[0x2800u];
static char * cmdBuff;//[128];
int sizeSend=0;
#define SIZE_BUF 0x5600 * 2
/*DWORD WINAPI MyThLector_(LPVOID lpParam)
{
	libbochs_t * a = lpParam;
	DWORD NumberOfBytesRead;
	do
	{
		ZeroMemory(lpTmpBuffer, SIZE_BUF);
		if (!ReadFile(a->hReadPipeIn, lpTmpBuffer, SIZE_BUF, &NumberOfBytesRead, 0))
		{
			printf("\n\n!!ERROR Leyendo datos del pipe\n\n");
			break;
		}
		//eprintf("mythreadlector: %x %x\n",NumberOfBytesRead,punteroBuffer);
		if (NumberOfBytesRead)
		{
			memcpy(&a->data[a->punteroBuffer], lpTmpBuffer, NumberOfBytesRead);
			a->punteroBuffer += NumberOfBytesRead;
		}
	} while (a->bEjecuta);

	return 0;

}

  DWORD WINAPI MyThEscritor_(LPVOID lpParam)
{
	libbochs_t * a = lpParam;
	DWORD dwWritten;
	do
	{
		WaitForSingleObject(a->ghWriteEvent, INFINITE);
		ResetEvent(a->ghWriteEvent);
		//eprintf("ThreadEscritor: MYBOCHSCMD: %s\n", cmdBuff
		WriteFile(a->hWritePipeOut, cmdBuff, strlen(cmdBuff), &dwWritten, NULL);
	} while (a->bEjecuta);
	return 0;

}
*/
int EjecutaThreadRemoto_(libbochs_t* b, LPVOID lpBuffer, DWORD dwSize, int a4, LPDWORD lpExitCode)
{
	LPVOID pProcessMemory;
	HANDLE hInjectThread; 
	int result = 0; 
	signed int tmpResult;
	DWORD NumberOfBytesWritten; 

	tmpResult = 0;
	pProcessMemory = VirtualAllocEx(b->processInfo.hProcess, 0, dwSize, 0x1000u, 0x40u);
	if (pProcessMemory)
	{
		if (WriteProcessMemory(b->processInfo.hProcess, pProcessMemory, lpBuffer, dwSize, &NumberOfBytesWritten))
		{
			hInjectThread = CreateRemoteThread(b->processInfo.hProcess, 0, 0, pProcessMemory, 0, 0, 0);
			if (hInjectThread)
			{
				if (!WaitForSingleObject(hInjectThread, 0xFFFFFFFF)
						&& (!a4 || ReadProcessMemory(b->processInfo.hProcess, pProcessMemory, lpBuffer, dwSize, &NumberOfBytesWritten)))
				{
					if (lpExitCode)
						GetExitCodeThread(hInjectThread, lpExitCode);
					tmpResult = 1;
				}
			}
		}
		VirtualFreeEx(b->processInfo.hProcess, pProcessMemory, 0, 0x8000u);
		if (hInjectThread)
			CloseHandle(hInjectThread);
		result = tmpResult;
	}
	return result;
}
void ResetBuffer_(libbochs_t* b)
{
	ZeroMemory(b->data, SIZE_BUF);
	b->punteroBuffer = 0;
}
BOOL CommandStop_(libbochs_t * b) {
	HMODULE hKernel;
	DWORD ExitCode;
	DWORD apiOffset = 0;
	DWORD dwRead,aval,leftm;
	int veces = 100;
	char buffer[] = { 0x68, 0x00, 0x00, 0x00, 0x00,	//		push    0
		0x68, 0x00, 0x00, 0x00, 0x00,	//      push    0
		0xE8, 0x00, 0x00, 0x00, 0x00,	//      call    $ + 5
		0x83, 0x04, 0x24, 0x0A,			//      add     dword ptr[esp], 0Ah
		0x68, 0x30, 0x30, 0x30, 0x30,	//      push    offset kernel32_GenerateConsoleCtrlEvent
		0xC3,                           //      retn 
		0xC2, 0x04, 0x00,					//      retn 4
		0xeb, 0xfe						//      jmp $
	};
	hKernel = GetModuleHandleA("kernel32");
	apiOffset = (DWORD)GetProcAddress(hKernel, "GenerateConsoleCtrlEvent");
	*((DWORD *)&buffer[20]) = apiOffset;
	ExitCode = EjecutaThreadRemoto_(b, &buffer, 0x1Eu, 0, &ExitCode) && ExitCode;
	ResetBuffer_(b);	
	eprintf("Esperando parada.\n");
	veces=100; // reintenta durante 10 segundos
	do {
		while(PeekNamedPipe(b->hReadPipeIn,NULL,NULL,NULL,&aval,&leftm)) {
			if (aval>0) {
				if (!ReadFile(b->hReadPipeIn, &b->data[b->punteroBuffer], SIZE_BUF, &dwRead, 0))
				{
					printf("\n\n!!ERROR Leyendo datos del pipe\n\n");
					break;
				}
				//eprintf("mythreadlector: %x %x\n",NumberOfBytesRead,punteroBuffer);
				if (dwRead)
					b->punteroBuffer +=dwRead; 
			}
			else
				break;
		}
		if (strstr(b->data, "<bochs:")) {
			break;
		}
		Sleep(100);
	} while(--veces);
	return ExitCode;
}

/*VOID EnviaComando_(libbochs_t* b, char * comando) {
	//eprintf("Enviando comando: %s\n",comando);
	ResetBuffer_(b);
	ZeroMemory(cmdBuff,128);
	sizeSend=sprintf(cmdBuff,"%s\n",comando);
	SetEvent(b->ghWriteEvent);
	Sleep(10);
}*/
VOID EnviaComando_(libbochs_t* b, char * comando) {
	//eprintf("Enviando comando: %s\n",comando);
	DWORD aval,leftm,dwWritten,dwRead;
	int veces = 100;
	ResetBuffer_(b);
	ZeroMemory(cmdBuff,128);
	sizeSend=sprintf(cmdBuff,"%s\n",comando);
	WriteFile(b->hWritePipeOut, cmdBuff, strlen(cmdBuff), &dwWritten, NULL);
	Sleep(10);
	do {
		while(PeekNamedPipe(b->hReadPipeIn,NULL,NULL,NULL,&aval,&leftm)) {
			if (aval>0) {
				if (!ReadFile(b->hReadPipeIn, &b->data[b->punteroBuffer], SIZE_BUF, &dwRead, 0))
				{
					printf("\n\n!!ERROR Leyendo datos del pipe\n\n");
					break;
				}
				//eprintf("mythreadlector: %x %x\n",NumberOfBytesRead,punteroBuffer);
				if (dwRead)
					b->punteroBuffer +=dwRead; 
			}
			else
				break;
		}
		if (strstr(b->data, "<bochs:")) {
			break;
		}
		Sleep(100);
	} while(--veces);
}
int bochs_read_(libbochs_t* b,ut64 addr,int count,ut8 * buf) {
	char buff[128];
	int lenRec = 0,i = 0,ini = 0, fin = 0, pbuf = 0;
	sprintf(buff,"xp /%imb 0x%016"PFMT64x"",count,addr);
	EnviaComando_(b,buff);
	lenRec=strlen(b->data);
	if (!strncmp(b->data, "[bochs]:", 8)) {
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
			//eprintf("%s\n", &lpBuffer[ini]);
			i++; // siguiente linea
		} while (b->data[i] != '<' && i < lenRec);
	}
	return 0;
}
	
void bochs_close_(libbochs_t* b) {
	b->bEjecuta=FALSE;
	CloseHandle(b->hReadPipeIn);
	CloseHandle(b->hReadPipeOut);
	CloseHandle(b->hWritePipeIn);
	CloseHandle(b->hWritePipeOut);
	CloseHandle(b->ghWriteEvent);
	TerminateProcess(b->processInfo.hProcess,0);
	free(b->data);
	free(lpTmpBuffer);
	free(cmdBuff);

}


BOOL bochs_open_(libbochs_t* b ,char * rutaBochs, char * rutaConfig) {
	struct _SECURITY_ATTRIBUTES PipeAttributes;
	BOOL result;
	char commandline[1024];
	int veces;
	DWORD aval,dwRead,leftm;
	// alojamos el buffer de datos
	b->data = malloc(SIZE_BUF);
	lpTmpBuffer = malloc(SIZE_BUF);
	cmdBuff = malloc(128);
	eprintf("bochs_open: invocado\n"); 
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
		eprintf("*** Creando proces: %s\n",commandline);
		if (CreateProcessA(NULL, commandline, NULL, NULL,TRUE, CREATE_NEW_CONSOLE , NULL, NULL, &b->info, &b->processInfo)) {
			eprintf("Proceso spawneado\n");
			WaitForInputIdle(b->processInfo.hProcess, INFINITE);
			eprintf("Entrada inicializada\n");

			b->bEjecuta=TRUE;
			//CreateThread(NULL, 0, MyThLector_, b, 0, 0);
			//b->ghWriteEvent = CreateEvent(NULL, TRUE, FALSE, TEXT("WriteEvent"));
			//CreateThread(NULL, 0, MyThEscritor_, b, 0, 0);
			ResetBuffer_(b);
			eprintf("Esperando inicializacion de bochs.\n");
			veces=100; // reintenta durante 10 segundos
			do {
				while(PeekNamedPipe(b->hReadPipeIn,NULL,NULL,NULL,&aval,&leftm)) {
					if (aval>0) {
						if (!ReadFile(b->hReadPipeIn, &b->data[b->punteroBuffer], SIZE_BUF, &dwRead, 0))
						{
							printf("\n\n!!ERROR Leyendo datos del pipe\n\n");
							break;
						}
						//eprintf("mythreadlector: %x %x\n",NumberOfBytesRead,punteroBuffer);
						if (dwRead)
							b->punteroBuffer +=dwRead; 
					}
					else
						break;
				}

				eprintf(" leido = %s\n",b->data);

				if (strstr(b->data, "<bochs:1>")) {
					eprintf("Inicializacion completada.\n%s\n",b->data);
					break;
				}
				Sleep(100);
			} while(--veces);
			if (veces>0)	
				result = TRUE;
			else
				bochs_close_(b);
		}
	}
	return result;
}

