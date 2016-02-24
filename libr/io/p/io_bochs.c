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

static char lpTmpBuffer[0x2800u];
static char lpBuffer[0x2800u];
int punteroBuffer=0, sizeSend=0;
HANDLE hReadPipeIn = NULL, hReadPipeOut = NULL;
HANDLE hWritePipeIn = NULL, hWritePipeOut = NULL;
HANDLE ghWriteEvent;
PROCESS_INFORMATION processInfo;

static char cmdBuff[128];


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
	} while (1);

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
	} while (1);
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
BOOL  CommandStop(HANDLE hProcess)
{
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

	apiOffset = GetProcAddress(hKernel, "GenerateConsoleCtrlEvent");

	*((DWORD *)&buffer[20]) = apiOffset;

	ExitCode = EjecutaThreadRemoto(hProcess, &buffer, 0x1Eu, 0, &ExitCode) && ExitCode;
	ZeroMemory(lpBuffer, 0x2800u);
	punteroBuffer = 0;
	return ExitCode;
}
static void ResetBuffer()
{
	ZeroMemory(lpBuffer, 0x2800u);
	punteroBuffer = 0;
}
VOID EnviaComando(char * comando)
{
	//eprintf("Enviando comando: %s\n",comando);
	ResetBuffer();
	ZeroMemory(cmdBuff,128);
	
	sizeSend=sprintf(cmdBuff,"%s\n",comando);
	SetEvent(ghWriteEvent);
	Sleep(200);	
}
static BOOL IniciaPipes(char * rutaBochs, char * rutaConfig)
{
	STARTUPINFO info;
	struct _SECURITY_ATTRIBUTES PipeAttributes; 
	char result; 
	char commandline[1024];
	char chBuff[128];
	DWORD NumberOfBytesRead, dwWritten;


	// creamos los pipes
	PipeAttributes.nLength = 12;
	PipeAttributes.bInheritHandle = 1;
	PipeAttributes.lpSecurityDescriptor = 0;
	// 				
	if (CreatePipe(&hReadPipeIn, &hReadPipeOut, &PipeAttributes, 0) && 	
	    CreatePipe(&hWritePipeIn, &hWritePipeOut, &PipeAttributes, 0)
	   )
	{
		result = 1;
	}
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
	sprintf(commandline, "\"%s\" -f \"%s\" -q ",rutaBochs,rutaConfig); //"f:\\VMs\\vmware\\cidox\\bochs\\bochsdbg.exe", "f:\\VMs\\vmware\\cidox\\bochs\\cidoxx32.bxrc");
	printf("*** Creando proces: %s\n",commandline);
	if (CreateProcessA(NULL, commandline, NULL, NULL,TRUE, CREATE_NEW_CONSOLE , NULL, NULL, &info, &processInfo))
	{
		printf("Proceso spawneado\n");
		WaitForInputIdle(processInfo.hProcess, INFINITE);
		printf("Entrada inicializada\n");

		CreateThread(NULL, 0, MyThLector, &info, 0, 0);

		ghWriteEvent = CreateEvent(NULL, TRUE, FALSE, TEXT("WriteEvent"));
		CreateThread(NULL, 0, MyThEscritor, &info, 0, 0);
	}
	
}
static int bochs_read(ut64 addr,int count,ut8 * buf) {
	char buff[128];
	int lenRec = 0,i = 0,ini = 0, fin = 0, pbuf = 0;
	sprintf(buff,"xp /%imb 0x%016"PFMT64x"",count,addr);
	EnviaComando(buff);
	lenRec=strlen(lpBuffer);
	if (!strncmp(lpBuffer, "[bochs]:", 8))
	{
		i += 10; // nos sitiamos en la siguiente linea.
		do
		{
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

		}while (lpBuffer[i] != '<' && i < lenRec);
	}
	return 0;
}
	

static int __plugin_open(RIO *io, const char *file, ut8 many) {
	return !strncmp (file, "bochs://", strlen ("bochs://"));
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	void *io_ctx;
	eprintf("io_open\n");
	if (!__plugin_open (io, file, 0))
		return NULL;
	IniciaPipes("f:\\VMs\\vmware\\cidox\\bochs\\bochsdbg.exe", "f:\\VMs\\vmware\\cidox\\bochs\\cidoxx32.bxrc");
	eprintf("Esperando inicializacion de bochs.\n");
	do
	{
		if (strstr(lpBuffer, "<bochs:1>")) {
			eprintf("Inicializacion completada.\n%s\n",lpBuffer);
			break;
		}
		Sleep(100);
	}while(1);
	return r_io_desc_new (&r_io_plugin_bochs, -1, file, true, mode, 0);
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	eprintf("io_write\n");
	return -1;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	//eprintf("io_seek %016"PFMT64x" \n",offset);
	return offset;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	memset (buf, 0xff, count);
	ut64 addr = io->off;
//	eprintf("io_read ofs= %016"PFMT64x" count= %x\n",io->off,count);
	bochs_read(addr,count,buf);
//	eprintf ("\nRecibido: %s\n", lpBuffer);
	//:hexstr2bin();
	return count;
}

static int __close(RIODesc *fd) {
	//eprintf("io_close\n");
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
		EnviaComando(&cmd[1]);
		io->cb_printf ("%s\n", lpBuffer);
		return 1;
	} else if (!strncmp (cmd, "dobreak", 7)) {

		CommandStop(processInfo.hProcess);
		io->cb_printf ("%s\n", lpBuffer);
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
