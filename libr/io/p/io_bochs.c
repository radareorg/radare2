// 
// Copyright (c) 2014, The Lemon Man, All rights reserved.

// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this library.

#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>
typedef struct libbochs_t {
	char * data;
	int punteroBuffer;
	int sizeSend;
	HANDLE hReadPipeIn;
	HANDLE hReadPipeOut;
	HANDLE hWritePipeIn;
	HANDLE hWritePipeOut;
	HANDLE ghWriteEvent;
	PROCESS_INFORMATION processInfo;
	STARTUPINFO info;
	BOOL bEjecuta;
} libbochs_t;


typedef struct {
	libbochs_t desc;        //libgdbr_t desc;
} RIOBochs;

static libbochs_t *desc = NULL; //static libgdbr_t *desc = NULL;
static RIODesc *riobochs = NULL;

static char * lpTmpBuffer; //[0x2800u];
static char * cmdBuff;//[128];
int sizeSend=0;
/*
static char lpBuffer[0x2800u];
int punteroBuffer=0, sizeSend=0;
HANDLE hReadPipeIn = NULL, hReadPipeOut = NULL;
HANDLE hWritePipeIn = NULL, hWritePipeOut = NULL;
HANDLE ghWriteEvent;
PROCESS_INFORMATION processInfo;
BOOL bEjecuta = FALSE;


DWORD WINAPI MyThLector(LPVOID lpParam)
{
	DWORD NumberOfBytesRead;
	do
	{
		ZeroMemory(lpTmpBuffer, 0x2800u);
		if (!ReadFile(hReadPipeIn, lpTmpBuffer, 0x2800u, &NumberOfBytesRead, 0))
		{
			printf("\n\n!!ERROR Leyendo datos del pipe\n\n");
			break;
		}
		//eprintf("mythreadlector: %x %x\n",NumberOfBytesRead,punteroBuffer);
		if (NumberOfBytesRead)
		{
			memcpy(&lpBuffer[punteroBuffer], lpTmpBuffer, NumberOfBytesRead);
			punteroBuffer += NumberOfBytesRead;
		}
	} while (bEjecuta);

	return 0;

}

DWORD WINAPI MyThEscritor(LPVOID lpParam)
{
	DWORD dwWritten;
	do
	{
		WaitForSingleObject(ghWriteEvent, INFINITE);
		ResetEvent(ghWriteEvent);
		//eprintf("ThreadEscritor: MYBOCHSCMD: %s\n", cmdBuff
		WriteFile(hWritePipeOut, cmdBuff, strlen(cmdBuff), &dwWritten, NULL);
	} while (bEjecuta);
	return 0;

}

int EjecutaThreadRemoto(HANDLE hProcess, LPVOID lpBuffer, DWORD dwSize, int a4, LPDWORD lpExitCode)
{
	LPVOID pProcessMemory;
	HANDLE hInjectThread; 
	int result = 0; 
	signed int tmpResult;
	DWORD NumberOfBytesWritten; 

	tmpResult = 0;
	pProcessMemory = VirtualAllocEx(hProcess, 0, dwSize, 0x1000u, 0x40u);
	if (pProcessMemory)
	{
		if (WriteProcessMemory(hProcess, pProcessMemory, lpBuffer, dwSize, &NumberOfBytesWritten))
		{
			hInjectThread = CreateRemoteThread(hProcess, 0, 0, pProcessMemory, 0, 0, 0);
			if (hInjectThread)
			{
				if (!WaitForSingleObject(hInjectThread, 0xFFFFFFFF)
						&& (!a4 || ReadProcessMemory(hProcess, pProcessMemory, lpBuffer, dwSize, &NumberOfBytesWritten)))
				{
					if (lpExitCode)
						GetExitCodeThread(hInjectThread, lpExitCode);
					tmpResult = 1;
				}
			}
		}
		VirtualFreeEx(hProcess, pProcessMemory, 0, 0x8000u);
		if (hInjectThread)
			CloseHandle(hInjectThread);
		result = tmpResult;
	}
	return result;
}

static void ResetBuffer()
{
	ZeroMemory(lpBuffer, 0x2800u);
	punteroBuffer = 0;
}

static BOOL CommandStop(HANDLE hProcess) {
	HMODULE hKernel;
	DWORD ExitCode;
	DWORD apiOffset = 0;
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
	ExitCode = EjecutaThreadRemoto(hProcess, &buffer, 0x1Eu, 0, &ExitCode) && ExitCode;
	ResetBuffer();	
	return ExitCode;
}

static VOID EnviaComando(char * comando) {
	//eprintf("Enviando comando: %s\n",comando);
	ResetBuffer();
	ZeroMemory(cmdBuff,128);
	sizeSend=sprintf(cmdBuff,"%s\n",comando);
	SetEvent(ghWriteEvent);
	Sleep(200);
}

static BOOL bochs_open(libbochs_t* b ,char * rutaBochs, char * rutaConfig) {
	STARTUPINFO info;
	struct _SECURITY_ATTRIBUTES PipeAttributes;
	BOOL result;
	char commandline[1024];
	int veces;
	// creamos los pipes
	PipeAttributes.nLength = 12;
	PipeAttributes.bInheritHandle = 1;
	PipeAttributes.lpSecurityDescriptor = 0;
	//
	result = FALSE;
	if (CreatePipe(&hReadPipeIn, &hReadPipeOut, &PipeAttributes, 0) && 
	    CreatePipe(&hWritePipeIn, &hWritePipeOut, &PipeAttributes, 0)
	   ) {
		//  Inicializamos las estructuras
		ZeroMemory(&info, sizeof(STARTUPINFO));
		ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
		info.cb = sizeof(STARTUPINFO);
		// Asignamos los pipes
		info.hStdError = hReadPipeOut;
		info.hStdOutput = hReadPipeOut;
		info.hStdInput = hWritePipeIn;
		info.dwFlags |=  STARTF_USESTDHANDLES;
		// Creamos el proceso
		sprintf(commandline, "\"%s\" -f \"%s\" -q ",rutaBochs,rutaConfig);
		printf("*** Creando proces: %s\n",commandline);
		if (CreateProcessA(NULL, commandline, NULL, NULL,TRUE, CREATE_NEW_CONSOLE , NULL, NULL, &info, &processInfo)) {
			printf("Proceso spawneado\n");
			WaitForInputIdle(processInfo.hProcess, INFINITE);
			printf("Entrada inicializada\n");

			bEjecuta=TRUE;
			CreateThread(NULL, 0, MyThLector, &info, 0, 0);
			ghWriteEvent = CreateEvent(NULL, TRUE, FALSE, TEXT("WriteEvent"));
			CreateThread(NULL, 0, MyThEscritor, &info, 0, 0);
			eprintf("Esperando inicializacion de bochs.\n");
			ResetBuffer();
			veces=100; // reintenta durante 10 segundos
			do {
				if (strstr(lpBuffer, "<bochs:1>")) {
					eprintf("Inicializacion completada.\n%s\n",lpBuffer);
					break;
				}
				Sleep(100);
			} while(--veces);
			if (veces>0)	
				result = TRUE;
		}
	}
	return result;
}
static int bochs_read(ut64 addr,int count,ut8 * buf) {
	char buff[128];
	int lenRec = 0,i = 0,ini = 0, fin = 0, pbuf = 0;
	sprintf(buff,"xp /%imb 0x%016"PFMT64x"",count,addr);
	EnviaComando(buff);
	lenRec=strlen(lpBuffer);
	if (!strncmp(lpBuffer, "[bochs]:", 8)) {
		i += 10; // nos sitiamos en la siguiente linea.
		do {
			while (lpBuffer[i] != 0 && lpBuffer[i] != ':' && i < lenRec) // buscamos los :
				i++;
			ini = ++i;
			while (lpBuffer[i] != 0 && lpBuffer[i] != 0x0d && i < lenRec) // buscamos los el retorno
				i++;
			fin = i++;
			lpBuffer[fin] = 0;
			pbuf+=r_hex_str2bin(&lpBuffer[ini],&buf[pbuf]);
			//eprintf("%s\n", &lpBuffer[ini]);
			i++; // siguiente linea
		} while (lpBuffer[i] != '<' && i < lenRec);
	}
	return 0;
}
	
static void bochs_close() {
	bEjecuta=FALSE;
	CloseHandle(hReadPipeIn);
	CloseHandle(hReadPipeOut);
	CloseHandle(hWritePipeIn);
	CloseHandle(hWritePipeOut);
	CloseHandle(ghWriteEvent);
	TerminateProcess(processInfo.hProcess,0);
}
*/


DWORD WINAPI MyThLector_(LPVOID lpParam)
{
	libbochs_t * a = lpParam;
	DWORD NumberOfBytesRead;
	do
	{
		ZeroMemory(lpTmpBuffer, 0x2800u);
		if (!ReadFile(a->hReadPipeIn, lpTmpBuffer, 0x2800u, &NumberOfBytesRead, 0))
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
static void ResetBuffer_(libbochs_t* b)
{
	ZeroMemory(b->data, 0x2800u);
	b->punteroBuffer = 0;
}
static BOOL CommandStop_(libbochs_t * b) {
	HMODULE hKernel;
	DWORD ExitCode;
	DWORD apiOffset = 0;
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
	return ExitCode;
}

static VOID EnviaComando_(libbochs_t* b, char * comando) {
	//eprintf("Enviando comando: %s\n",comando);
	ResetBuffer_(b);
	ZeroMemory(cmdBuff,128);
	sizeSend=sprintf(cmdBuff,"%s\n",comando);
	SetEvent(b->ghWriteEvent);
	Sleep(100);
}
static int bochs_read_(libbochs_t* b,ut64 addr,int count,ut8 * buf) {
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
	
static void bochs_close_(libbochs_t* b) {
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


static BOOL bochs_open_(libbochs_t* b ,char * rutaBochs, char * rutaConfig) {
	struct _SECURITY_ATTRIBUTES PipeAttributes;
	BOOL result;
	char commandline[1024];
	int veces;
	// alojamos el buffer de datos
	b->data = malloc(2800u);
	lpTmpBuffer = malloc(0x2800u);
	cmdBuff = malloc(128);
	eprintf("bochs_open: invocado\n"); 
	// creamos los pipes
	PipeAttributes.nLength = 12;
	PipeAttributes.bInheritHandle = 1;
	PipeAttributes.lpSecurityDescriptor = 0;
	//
	result = FALSE;
	if (CreatePipe(&b->hReadPipeIn, &b->hReadPipeOut, &PipeAttributes, 0) && 
	    CreatePipe(&b->hWritePipeIn, &b->hWritePipeOut, &PipeAttributes, 0)
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
		printf("*** Creando proces: %s\n",commandline);
		if (CreateProcessA(NULL, commandline, NULL, NULL,TRUE, CREATE_NEW_CONSOLE , NULL, NULL, &b->info, &b->processInfo)) {
			printf("Proceso spawneado\n");
			WaitForInputIdle(b->processInfo.hProcess, INFINITE);
			printf("Entrada inicializada\n");

			b->bEjecuta=TRUE;
			CreateThread(NULL, 0, MyThLector_, b, 0, 0);
			b->ghWriteEvent = CreateEvent(NULL, TRUE, FALSE, TEXT("WriteEvent"));
			CreateThread(NULL, 0, MyThEscritor_, b, 0, 0);
			eprintf("Esperando inicializacion de bochs.\n");
			ResetBuffer_(b);
			veces=100; // reintenta durante 10 segundos
			do {
				if (strstr(b->data, "<bochs:1>")) {
					eprintf("Inicializacion completada.\n%s\n",b->data);
					break;
				}
				Sleep(100);
			} while(--veces);
			if (veces>0)	
				result = TRUE;
		}
	}
	return result;
}

static int __plugin_open(RIO *io, const char *file, ut8 many) {
	return !strncmp (file, "bochs://", strlen ("bochs://"));
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	RIOBochs  *riob;
	eprintf("io_open\n");
	if (!__plugin_open (io, file, 0))
		return NULL;
	if (riobochs) {
		// FIX: Don't allocate more than one gdb RIODesc
		return riobochs;
	}
	riob = R_NEW0 (RIOBochs);
	// Inicializamos
	//gdbr_init (&riog->desc);
	//if (gdbr_connect (&riog->desc, host, i_port) == 0) {
	//if (bochs_open(&riob->desc,"f:\\VMs\\vmware\\cidox\\bochs\\bochsdbg.exe", "f:\\VMs\\vmware\\cidox\\bochs\\cidoxx32.bxrc") == FALSE)
	if (bochs_open_(&riob->desc,"f:\\VMs\\vmware\\cidox\\bochs\\bochsdbg.exe", "f:\\VMs\\vmware\\cidox\\bochs\\cidoxx32.bxrc") == TRUE)
	{
		desc = &riob->desc;
		riobochs = r_io_desc_new (&r_io_plugin_bochs, -1, file, rw, mode, riob);
		//riogdb = r_io_desc_new (&r_io_plugin_gdb, riog->desc.sock->fd, file, rw, mode, riog);
		return riobochs;
	}
	eprintf ("bochsio.open: Cannot connect to bochs.\n");
	free (riob);
//	return r_io_desc_new (&r_io_plugin_bochs, -1, file, true, mode, 0);
	return NULL;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	eprintf("io_write\n");
	return -1;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	// eprintf("io_seek %016"PFMT64x" \n",offset);
	return offset;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	memset (buf, 0xff, count);
	ut64 addr = io->off;
	if (!desc || !desc->data) return -1;
	// eprintf("io_read ofs= %016"PFMT64x" count= %x\n",io->off,count);
	//bochs_read(addr,count,buf);
	bochs_read_(desc,addr,count,buf);
	return count;
}

static int __close(RIODesc *fd) {
	// eprintf("io_close\n");
	//bochs_close();
	bochs_close_(desc);
	return true;
}
	
static int __system(RIO *io, RIODesc *fd, const char *cmd) {
        printf("system command (%s)\n", cmd);
        if (!strcmp (cmd, "help")) {
                eprintf ("Usage: =!cmd args\n"
                        " =!:<bochscmd>      - Send a bochs command.\n"
                        " =!dobreak          - pause bochs.\n");
			
	} else if (!strncmp (cmd, ":", 1)) {
		eprintf("Enviando comando bochs\n");
		//EnviaComando_(&cmd[1]);
		//io->cb_printf ("%s\n", lpBuffer);
		EnviaComando_(desc,&cmd[1]);
		io->cb_printf ("%s\n", desc->data);
		return 1;
	} else if (!strncmp (cmd, "dobreak", 7)) {

		//CommandStop(processInfo.hProcess);
		//io->cb_printf ("%s\n", lpBuffer);
		CommandStop_(desc);
		io->cb_printf ("%s\n", desc->data);
		return 1;
	}         
        return true;
}

RIOPlugin r_io_plugin_bochs  = {
	.name = "bochs",
	.desc = "Attach to a BOCHS debugger",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.write = __write,
	.plugin_open = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.isdbg = true
};
