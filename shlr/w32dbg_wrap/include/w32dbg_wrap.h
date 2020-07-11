#ifndef W32DBG_WRAP
#define W32DBG_WRAP

typedef enum {
	W32_NONE,
	W32_CONTINUE,
	W32_ATTACH,
	W32_DETACH,
	W32_WAIT,
	W32_STOP,
	W32_CALL_FUNC
} w32dbg_wrap_req;

typedef struct {
	w32dbg_wrap_req type;
	union {
		DWORD continue_status;
		struct {
			DEBUG_EVENT *de;
			DWORD wait_time;
		} wait;
		struct {
			int (*func)(void *);
			void *user;
		} func;
	};
	int ret;
	DWORD err;
} W32DbgWParams;

typedef struct {
	HANDLE debugThread;
	W32DbgWParams params;
	HANDLE request_sem;
	HANDLE result_sem;
	ULONG_PTR winbase;
	PROCESS_INFORMATION pi;
	// Stores the TID of the thread DebugBreakProcess creates to ignore it's breakpoint
	DWORD break_tid;
} W32DbgWInst;

#define w32dbgw_ret(inst) inst->params.ret
#define w32dbgw_err(inst) (SetLastError (inst->params.err), inst->params.err)

W32DbgWInst *w32dbg_wrap_new(void);
int w32dbg_wrap_wait_ret(W32DbgWInst *inst);
void w32dbg_wrap_fini(W32DbgWInst *inst);

#endif
