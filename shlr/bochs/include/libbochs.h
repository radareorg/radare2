/*! \file */
#ifndef LIBBOCHS_H
#define LIBBOCHS_H

#include <r_util.h>

#if R2__WINDOWS__
#include <windows.h>
#endif

typedef struct libbochs_t {
	char *data;
	int punteroBuffer;
	int sizeSend;
#if R2__WINDOWS__
	HANDLE hReadPipeIn;
	HANDLE hReadPipeOut;
	HANDLE hWritePipeIn;
	HANDLE hWritePipeOut;
	HANDLE ghWriteEvent;
	PROCESS_INFORMATION processInfo;
	STARTUPINFO info;
#else
	int hReadPipeIn;
	int hReadPipeOut;
	int hWritePipeIn;
	int hWritePipeOut;
	int pid;
#endif
	bool isRunning;
} libbochs_t;

bool bochs_wait(libbochs_t *b);
void bochs_reset_buffer(libbochs_t* b);
bool bochs_cmd_stop(libbochs_t * b);
void bochs_send_cmd(libbochs_t* b, const char * comando, bool bWait);
int bochs_read(libbochs_t* b, ut64 addr, int count, ut8* buf);
void bochs_close(libbochs_t* b);
bool bochs_open(libbochs_t* b, const char *rutaBochs, const char *rutaConfig);

#endif
