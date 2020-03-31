#ifndef W32DBG_WRAP
#define W32DBG_WRAP

typedef enum {
	W32_NONE,
	W32_CONTINUE,
	W32_ATTACH,
	W32_DETTACH,
	W32_WAIT,
	W32_STOP,
	W32_CALL_FUNC
} w32dbg_wrap_req;

typedef struct {
	w32dbg_wrap_req type;
	DWORD pid;
	DWORD tid;
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
} w32dbg_wrap_params;

typedef struct w32dbg_wrap_instance_t {
	HANDLE debugThread;
	w32dbg_wrap_params *params;
	HANDLE request_sem;
	HANDLE result_sem;
} w32dbg_wrap_instance;

typedef struct {
	ULONG_PTR winbase;
	PROCESS_INFORMATION pi;
	w32dbg_wrap_instance *inst;
	// Stores the TID of the thread DebugBreakProcess creates to ignore it's breakpoint
	DWORD break_tid;
} RIOW32Dbg;

#define w32dbgw_ret(inst) inst->params->ret
#define w32dbgw_err(inst) (SetLastError (inst->params->err), inst->params->err)

w32dbg_wrap_instance *w32dbg_wrap_new(void);
int w32dbg_wrap_wait_ret(w32dbg_wrap_instance *inst);
void w32dbg_wrap_fini(w32dbg_wrap_instance *inst);

#endif
