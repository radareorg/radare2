/* radare - LGPL - Copyright 2019-2021 - gustavo, pancake */

#include <r_types.h>

#if __WINDOWS__
#include <windows.h>
#include <r_util/r_w32dw.h>

static DWORD WINAPI __w32dbg_thread(LPVOID param) {
	W32DbgWInst *inst = param;
	W32DbgWParams *params = &inst->params;
	PROCESS_INFORMATION *pi = &inst->pi;
	for (;;) {
		WaitForSingleObject (inst->request_sem, INFINITE);
		switch (params->type) {
		case W32_CONTINUE:
			params->ret = ContinueDebugEvent (pi->dwProcessId, pi->dwThreadId, params->continue_status);
			break;
		case W32_WAIT:
			params->ret = WaitForDebugEvent (params->wait.de, params->wait.wait_time);
			if (params->ret) {
				pi->dwProcessId = params->wait.de->dwProcessId;
				pi->dwThreadId = params->wait.de->dwThreadId;
			}
			break;
		case W32_CALL_FUNC:
			params->ret = params->func.func (params->func.user);
			break;
		case W32_ATTACH:
			params->ret = DebugActiveProcess (pi->dwProcessId);
			break;
		case W32_DETACH:
		case W32_STOP:
			params->ret = DebugActiveProcessStop (pi->dwProcessId);
			break;
		default:
			break;
		}
		if (!params->ret) {
			params->err = GetLastError ();
		}
		ReleaseSemaphore (inst->result_sem, 1, NULL);
		if (params->type == W32_STOP) {
			break;
		}
	}
	return 0;
}

R_API W32DbgWInst *r_w32dw_new(void) {
	W32DbgWInst *inst = calloc (1, sizeof (W32DbgWInst));
	if (inst) {
		inst->request_sem = CreateSemaphore (NULL, 0, 1, NULL);
		inst->result_sem = CreateSemaphore (NULL, 0, 1, NULL);
		inst->debugThread = CreateThread (NULL, 0, __w32dbg_thread, inst, 0, NULL);
	}
	return inst;
}

R_API void r_w32dw_free(W32DbgWInst *inst) {
	inst->params.type = W32_STOP;
	ReleaseSemaphore (inst->request_sem, 1, NULL);
	CloseHandle (inst->request_sem);
	CloseHandle (inst->result_sem);
	free (inst);
}

R_API int r_w32dw_waitret(W32DbgWInst *inst) {
	ReleaseSemaphore (inst->request_sem, 1, NULL);
	WaitForSingleObject (inst->result_sem, INFINITE);
	return r_w32dw_ret (inst);
}
#endif
