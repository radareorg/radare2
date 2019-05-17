#include <r_types.h>
#include <windows.h>
#include <processthreadsapi.h> // OpenProess
#include "windows_debug.h"

typedef struct {
	bool dbgpriv;
	HANDLE processHandle;
} RIOW32;

static int w32_dbg_init() {
}

int windows_attach(RDebug *dbg, int pid) {
	int ret = -1;
	RIOW32 *rio = dbg->user;
	// TODO: move this code out
	if (!rio) {
		rio = dbg->user = R_NEW (RIOW32);
		rio->dbgpriv = false;
		rio->processHandle = (HANDLE)NULL;
	}
	else {
		rio = dbg->user;
	}
	if (!rio->dbgpriv) {
		rio->dbgpriv;
	}
	if (!rio->processHandle) {
		rio->processHandle = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
		if (rio->processHandle) {
			// TODO: get main thread id
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
