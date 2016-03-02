/*! \file */
#ifndef LIBBOCHS_H
#define LIBBOCHS_H
#include <r_util.h>
#include <windows.h>
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

//DWORD WINAPI MyThLector_(LPVOID lpParam)
//DWORD WINAPI MyThEscritor_(LPVOID lpParam)
BOOL EsperaRespuesta_(libbochs_t *b);
int EjecutaThreadRemoto_(libbochs_t* b, LPVOID lpBuffer, DWORD dwSize, int a4, LPDWORD lpExitCode);
void ResetBuffer_(libbochs_t* b);
BOOL CommandStop_(libbochs_t * b);
VOID EnviaComando_(libbochs_t* b, char * comando,BOOL bWait);
int bochs_read_(libbochs_t* b,ut64 addr,int count,ut8 * buf);
void bochs_close_(libbochs_t* b);
BOOL bochs_open_(libbochs_t* b ,char * rutaBochs, char * rutaConfig);


/*! 
int gdbr_remove_bp(libgdbr_t* g, ut64 address);
int gdbr_remove_hwbp(libgdbr_t* g, ut64 address);
*/
#endif
