#include <windows.h>
#include <w32dbg_wrap.h>

static DWORD WINAPI __w32dbg_thread(LPVOID param) {
	W32DbgWInst *inst = param;
	W32DbgWParams *params = &inst->params;
	PROCESS_INFORMATION *pi = &inst->pi;
	while (1) {
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

W32DbgWInst *w32dbg_wrap_new(void) {
	W32DbgWInst *inst = calloc (1, sizeof (W32DbgWInst));
	if (inst) {
		inst->request_sem = CreateSemaphore (NULL, 0, 1, NULL);
		inst->result_sem = CreateSemaphore (NULL, 0, 1, NULL);
		inst->debugThread = CreateThread (NULL, 0, __w32dbg_thread, inst, 0, NULL);
	}
	return inst;
}

void w32dbg_wrap_fini(W32DbgWInst *inst) {
	inst->params.type = W32_STOP;
	ReleaseSemaphore (inst->request_sem, 1, NULL);
	CloseHandle (inst->request_sem);
	CloseHandle (inst->result_sem);
	free (inst);
}

int w32dbg_wrap_wait_ret(W32DbgWInst *inst) {
	ReleaseSemaphore (inst->request_sem, 1, NULL);
	WaitForSingleObject (inst->result_sem, INFINITE);
	return w32dbgw_ret(inst);
}
