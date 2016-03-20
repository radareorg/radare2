
/* libgdbr - LGPL - Copyright 2014 - defragger */

#include "libbochs.h"
static char * lpTmpBuffer; //[0x2800u];
static char * cmdBuff;//[128];
int sizeSend=0;
#define SIZE_BUF 0x5800 * 2
#define eprintf(x,y...) \ 
{ FILE * myfile;  myfile=fopen("logio.txt","a"); fprintf(myfile,x,##y);fflush(myfile);fclose(myfile); }
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
	ExitCode = EjecutaThreadRemoto_(b, &buffer, 0x1Eu, 0, &ExitCode) && ExitCode;
	return ExitCode;
}
BOOL EsperaRespuesta_(libbochs_t *b) {
	int veces = 0;
	DWORD dwRead,aval,leftm;
	veces = 100; // reintenta durante 10 segundos
	ResetBuffer_(b);	
	do {
		while(PeekNamedPipe(b->hReadPipeIn,NULL,0,NULL,&aval,&leftm)) {
			if (aval>0) {
				if (!ReadFile(b->hReadPipeIn, &b->data[b->punteroBuffer], SIZE_BUF, &dwRead, 0))
				{
					eprintf("EsperaRespuesta_: !!ERROR Leyendo datos del pipe.\n\n");
					return FALSE;
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
		Sleep(10);
	} while(--veces);
	return TRUE;
}
VOID EnviaComando_(libbochs_t* b, char * comando, BOOL bWait) {
	//eprintf("Enviando comando: %s\n",comando);
	DWORD dwWritten;
	ResetBuffer_(b);
	ZeroMemory(cmdBuff,128);
	sizeSend=sprintf(cmdBuff,"%s\n",comando);
	WriteFile(b->hWritePipeOut, cmdBuff, strlen(cmdBuff), &dwWritten, NULL);
	if (bWait)
		EsperaRespuesta_(b);
}
int bochs_read_(libbochs_t* b,ut64 addr,int count,ut8 * buf) {
	char buff[128];
	int lenRec = 0,i = 0,ini = 0, fin = 0, pbuf = 0, totalread = 0;
	if (count >SIZE_BUF / 3)
		totalread=SIZE_BUF / 3;
	else
		totalread=count;
	sprintf(buff,"xp /%imb 0x%016"PFMT64x"",totalread,addr);
	EnviaComando_(b,buff,TRUE);
	eprintf("%s\n",b->data);
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
			if (EsperaRespuesta_(b)) {
				eprintf("Inicializacion completa.\n");
				result = TRUE;
			}
			else
				bochs_close_(b);
		}
	}
	return result;
}

