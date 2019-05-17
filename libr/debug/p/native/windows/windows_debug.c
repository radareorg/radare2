#include <r_types.h>
#include <windows.h>
#include <processthreadsapi.h> // OpenProess
#include "windows_debug.h"

typedef struct {
	HANDLE processHandle;
} RIOW32;

int windows_attach (RDebug *dbg, int pid) {
	int ret;
	RIOW32 *rio = dbg->user;
	// TODO: move this code out
	if (!rio) {
		rio = dbg->user = R_NEW (RIOW32);
		rio->processHandle = (HANDLE)NULL;
	}
	else {
		rio = dbg->user;
	}
	if (!rio->processHandle) {
		HANDLE processHandle = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
		rio->processHandle = processHandle;
		if (processHandle) {
			// TODO: get main thread id
		} else {
			ret = -1;
		}
	}
	return ret;

	/*
	HANDLE process = w32_OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
	if (process != (HANDLE)NULL && DebugActiveProcess (pid)) {
		ret = w32_first_thread (pid);
	} else {
		ret = -1;
	}
	// XXX: What is this for?
	ret = w32_first_thread (pid);
	CloseHandle (process);
	return ret;
	*/
}
