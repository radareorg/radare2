#include <windows.h>
#include <w32dbg_wrap.h>

static DWORD WINAPI __w32dbg_thread(LPVOID param) {
	w32dbg_wrap_instance *inst = param;
	w32dbg_wrap_params *params = inst->params;
	while (1) {
		WaitForSingleObject (inst->request_sem, INFINITE);
		switch (params->type) {
		case W32_CONTINUE:
			params->ret = ContinueDebugEvent (params->pid, params->tid, params->continue_status);
			break;
		case W32_WAIT:
			params->ret = WaitForDebugEvent (params->wait.de, params->wait.wait_time);
			break;
		case W32_CALL_FUNC:
			params->ret = params->func.func (params->func.user);
			break;
		case W32_ATTACH:
			params->ret = DebugActiveProcess (params->pid);
			break;
		case W32_DETTACH:
		case W32_STOP:
			params->ret = DebugActiveProcessStop (params->pid);
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

w32dbg_wrap_instance *w32dbg_wrap_new(void) {
	w32dbg_wrap_instance *inst = calloc (1, sizeof (w32dbg_wrap_instance));
	if (inst) {
		inst->params = calloc (1, sizeof (w32dbg_wrap_params));
		if (!inst->params) {
			return NULL;
		}
		inst->request_sem = CreateSemaphore (NULL, 0, 1, NULL);
		inst->result_sem = CreateSemaphore (NULL, 0, 1, NULL);
		inst->debugThread = CreateThread (NULL, 0, __w32dbg_thread, inst, 0, NULL);
	}
	return inst;
}

void w32dbg_wrap_fini(w32dbg_wrap_instance *inst) {
	inst->params->type = W32_STOP;
	ReleaseSemaphore (inst->request_sem, 1, NULL);
	CloseHandle (inst->request_sem);
	CloseHandle (inst->result_sem);
	free (inst->params);
	free (inst);
}

int w32dbg_wrap_wait_ret(w32dbg_wrap_instance *inst) {
	ReleaseSemaphore (inst->request_sem, 1, NULL);
	WaitForSingleObject (inst->result_sem, INFINITE);
	return w32dbgw_ret(inst);
}
