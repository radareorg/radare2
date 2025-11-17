#ifndef W32DBG_WRAP
#define W32DBG_WRAP

#include <r_types.h>

#ifdef __cplusplus
extern "C" {
#endif
#if R2__WINDOWS__

typedef enum r_w32dw_request {
	W32_NONE,
	W32_CONTINUE,
	W32_ATTACH,
	W32_DETACH,
	W32_WAIT,
	W32_STOP,
	W32_CALL_FUNC
} RW32DwRequest;

typedef struct r_w32dw_params_t {
	RW32DwRequest type;
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
} RW32DwParams;

typedef struct r_w32dw_t {
	HANDLE debugThread;
	RW32DwParams params;
	HANDLE request_sem;
	HANDLE result_sem;
	ULONG_PTR winbase;
	PROCESS_INFORMATION pi;
	// Stores the TID of the thread DebugBreakProcess creates to ignore it's breakpoint
	DWORD break_tid;
} RW32Dw;

#define r_w32dw_ret(inst) inst->params.ret
#define r_w32dw_err(inst) SetLastError (inst->params.err)

R_API RW32Dw *r_w32dw_new(void);
R_API int r_w32dw_waitret(RW32Dw *inst);
R_API void r_w32dw_free(RW32Dw *inst);

#endif

#ifdef __cplusplus
}
#endif

#endif
