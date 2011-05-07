#ifndef _INCLUDE_R_DEBUG_H_
#define _INCLUDE_R_DEBUG_H_

#include <r_types.h>
#include <r_anal.h>
#include <r_util.h>
#include <r_reg.h>
#include <r_bp.h>
#include <r_io.h>
#include <r_syscall.h>
#include "list.h"

/* hack to fix compilation of debugger on BSD systems */
/* This needs some testing (netbsd, freebsd, openbsd, kfreebsd) */
#if __BSD__
#include <machine/reg.h>

#define PTRACE_PEEKTEXT PT_READ_I
#define PTRACE_POKETEXT PT_WRITE_I
#define PTRACE_PEEKDATA PT_READ_D
#define PTRACE_POKEDATA PT_WRITE_D
#define PTRACE_ATTACH PT_ATTACH
#define PTRACE_DETACH PT_DETACH
#define PTRACE_SINGLESTEP PT_STEP
#define PTRACE_CONT PT_CONTINUE
#define PTRACE_GETREGS PT_GETREGS
#define PTRACE_SETREGS PT_SETREGS
#define PTRACE_SYSCALL PT_STEP
#endif

enum {
	R_DBG_PROC_STOP = 's',
	R_DBG_PROC_RUN = 'r',
	R_DBG_PROC_SLEEP = 'S',
	R_DBG_PROC_ZOMBIE = 'z',
	R_DBG_PROC_DEAD = 'd',
	R_DBG_PROC_RAISED = 'R' // has produced a signal, breakpoint, etc..
};

// signal handling must support application and debugger level options
enum {
	R_DBG_SIGNAL_IGNORE, // ignore signal handler
	R_DBG_SIGNAL_BYPASS,
	R_DBG_SIGNAL_HANDLE, //
	R_DBG_SIGNAL_SETUP,
	//..
};

enum { // TODO: not yet used by r_debug
	R_DBG_REASON_UNKNOWN,
	R_DBG_REASON_NEW_PID,
	R_DBG_REASON_NEW_TID,
	R_DBG_REASON_NEW_LIB,
	R_DBG_REASON_EXIT_PID,
	R_DBG_REASON_EXIT_TID,
	R_DBG_REASON_EXIT_LIB,
	R_DBG_REASON_TRAP,
	R_DBG_REASON_ILL,
	R_DBG_REASON_INT,
	R_DBG_REASON_SIGNAL,
	R_DBG_REASON_FPU,
	R_DBG_REASON_BP,
	R_DBG_REASON_DEAD
};

/* TODO: move to r_anal */
typedef struct r_debug_frame_t {
	ut64 addr;
	int size;
} RDebugFrame;

typedef struct r_debug_map_t {
	char *name;
	ut64 addr;
	ut64 addr_end;
	ut64 size;
	char *file;
	int perm;
	int user;
} RDebugMap;

typedef struct r_debug_trace_t {
	RList *traces;
	int count;
	int enabled;
	//int changed;
	int tag;
	int dup;
	char *addresses;
	// TODO: add range here
} RDebugTrace;

typedef struct r_debug_tracepoint_t {
	ut64 addr;
	ut64 tags; // XXX
	int tag; // XXX
	int size;
	int count;
	int times;
	ut64 stamp;
} RDebugTracepoint;

typedef struct r_debug_t {
	int arch;
	int bits; /// XXX: MUST SET ///
	int pid;    /* selected process id */
	int tid;    /* selected thread id */
	int swstep; /* steps with software traps */
	int steps;  /* counter of steps done */
	int newstate;
	int reason; /* stop reason */
	RDebugTrace *trace;
	int stop_all_threads;
	struct r_reg_t *reg;
	RBreakpoint *bp;
	void *user;
	/* io */
	PrintfCallback printf;
	struct r_debug_plugin_t *h;
	struct list_head plugins;
	RAnal *anal;
	RIOBind iob;
	RList *maps; // <RDebugMap>
	RList *maps_user; // <RDebugMap>
	/* TODO
	- list of processes and their threads
	- list of mapped memory (from /proc/XX/maps)
	- list of managed memory (allocated in child...)
	*/
} RDebug;

typedef struct r_debug_desc_plugin_t {
	int (*open)(const char *path);
	int (*close)(int fd);
	int (*read)(int fd, ut64 addr, int len);
	int (*write)(int fd, ut64 addr, int len);
	int (*seek)(int fd, ut64 addr);
	int (*dup)(int fd, int newfd);
	RList* (*list)();
} RDebugDescPlugin;

/* TODO: pass dbg and user data pointer everywhere */
typedef struct r_debug_plugin_t {
	const char *name;
	//const char **archs; // MUST BE DEPREACTED!!!!
	ut32 bits;
	ut64 arch;
	/* life */
	int (*startv)(int argc, char **argv);
	int (*attach)(RDebug *dbg, int pid);
	int (*detach)(int pid);
	int (*select)(int pid, int tid);
	RList *(*threads)(int pid);
	RList *(*pids)(int pid);
	RList *(*tids)(int pid);
	RFList (*backtrace)(int count);
	/* flow */
	int (*step)(RDebug *dbg);
	int (*cont)(RDebug *dbg, int pid, int tid, int sig);
	int (*wait)(int pid);
	int (*kill)(RDebug *dbg, boolt thread, int sig);
	int (*contsc)(RDebug *dbg, int pid, int sc);
	RList* (*frames)(RDebug *dbg);
	RBreakpointCallback breakpoint;
// XXX: specify, pid, tid, or RDebug ?
	int (*reg_read)(struct r_debug_t *dbg, int type, ut8 *buf, int size);
	int (*reg_write)(int pid, int tid, int type, const ut8 *buf, int size); //XXX struct r_regset_t regs);
	char* (*reg_profile)(RDebug *dbg);
	/* memory */
	RList *(*map_get)(RDebug *dbg);
	ut64 (*map_alloc)(RDebug *dbg, RDebugMap *map);
	int (*map_dealloc)(RDebug *dbg, ut64 addr);
	int (*init)(RDebug *dbg);
	RDebugDescPlugin desc;
	// TODO: use RList here
	struct list_head list;
} RDebugPlugin;

// TODO: rename to r_debug_process_t ? maybe a thread too ?
typedef struct r_debug_pid_t {
	int pid;
	char status; /* stopped, running, zombie, sleeping ,... */
	int runnable; /* when using 'run', 'continue', .. this proc will be runnable */
	const char *path;
	ut64 pc;
} RDebugPid;

#ifdef R_API
R_API int r_debug_attach(struct r_debug_t *dbg, int pid);
R_API int r_debug_detach(struct r_debug_t *dbg, int pid);
R_API int r_debug_startv(struct r_debug_t *dbg, int argc, char **argv);
R_API int r_debug_start(struct r_debug_t *dbg, const char *cmd);
R_API int r_debug_stop_reason(struct r_debug_t *dbg);
R_API int r_debug_wait(struct r_debug_t *dbg);
R_API int r_debug_step_over(struct r_debug_t *dbg, int steps);
R_API int r_debug_continue_until(struct r_debug_t *dbg, ut64 addr);
R_API int r_debug_continue_until_optype(RDebug *dbg, int type, int over);
R_API int r_debug_continue_until_nontraced(RDebug *dbg);
R_API int r_debug_continue_syscall(struct r_debug_t *dbg, int sc);
//R_API int r_debug_pid_add(struct r_debug_t *dbg);
//R_API int r_debug_pid_add_thread(struct r_debug_t *dbg);
//R_API int r_debug_pid_del(struct r_debug_t *dbg);
//R_API int r_debug_pid_del_thread(struct r_debug_t *dbg);
R_API int r_debug_pid_list(RDebug *dbg, int pid);
R_API RDebugPid *r_debug_pid_new(const char *path, int pid, char status, ut64 pc);
R_API RDebugPid *r_debug_pid_free(RDebugPid *pid);
R_API RList *r_debug_pids(RDebug *dbg, int pid);

R_API int r_debug_set_arch(RDebug *dbg, int arch, int bits);
R_API int r_debug_use(struct r_debug_t *dbg, const char *str);
R_API int r_debug_plugin_add(struct r_debug_t *dbg, struct r_debug_plugin_t *foo);
R_API int r_debug_plugin_init(struct r_debug_t *dbg);
R_API int r_debug_plugin_list(struct r_debug_t *dbg);

R_API struct r_debug_t *r_debug_new(int hard);
R_API struct r_debug_t *r_debug_free(struct r_debug_t *dbg);

/* send signals */
R_API int r_debug_kill(struct r_debug_t *dbg, boolt thread, int sig);
// XXX: must be uint64 action
R_API int r_debug_kill_setup(struct r_debug_t *dbg, int sig, int action);
R_API int r_debug_step(struct r_debug_t *dbg, int steps);
R_API int r_debug_continue(struct r_debug_t *dbg);
R_API int r_debug_continue_kill(struct r_debug_t *dbg, int signal);
R_API int r_debug_select(struct r_debug_t *dbg, int pid, int tid);

/* handle.c */
R_API int r_debug_plugin_init(struct r_debug_t *dbg);
R_API int r_debug_plugin_set(struct r_debug_t *dbg, const char *str);
R_API int r_debug_plugin_list(struct r_debug_t *dbg);
R_API int r_debug_plugin_add(struct r_debug_t *dbg, struct r_debug_plugin_t *foo);

/* memory */
R_API int r_debug_map_alloc(RDebug *dbg, RDebugMap *map);
R_API int r_debug_map_dealloc(RDebug *dbg, RDebugMap *map);
R_API RList *r_debug_map_list_new();
R_API void r_debug_map_list_free(RList *maps);
R_API RDebugMap *r_debug_map_get(RDebug *dbg, ut64 addr);
R_API RDebugMap *r_debug_map_new (char *name, ut64 addr, ut64 addr_end, int perm, int user);
R_API void r_debug_map_free(RDebugMap *map);
R_API void r_debug_map_list(RDebug *dbg, ut64 addr);

/* descriptors */
R_API int r_debug_desc_open(RDebug *dbg, const char *path);
R_API int r_debug_desc_close(RDebug *dbg, int fd);
R_API int r_debug_desc_dup(RDebug *dbg, int fd, int newfd);
R_API int r_debug_desc_read(RDebug *dbg, int fd, ut64 addr, int len);
R_API int r_debug_desc_seek(RDebug *dbg, int fd, ut64 addr); // TODO: whence?
R_API int r_debug_desc_write(RDebug *dbg, int fd, ut64 addr, int len);
R_API int r_debug_desc_list(RDebug *dbg, int rad);

/* registers */
R_API int r_debug_reg_sync(RDebug *dbg, int type, int write);
R_API int r_debug_reg_list(RDebug *dbg, int type, int size, int rad);
R_API int r_debug_reg_set(RDebug *dbg, const char *name, ut64 num);
R_API ut64 r_debug_reg_get(RDebug *dbg, const char *name);

R_API void r_debug_io_bind(RDebug *dbg, RIO *io);
R_API ut64 r_debug_execute(struct r_debug_t *dbg, ut8 *buf, int len);
R_API int r_debug_map_sync(RDebug *dbg);

/* backtrace */
R_API RList *r_debug_frames (RDebug *dbg);

/* args XXX: weird food */
R_API ut64 r_debug_arg_get (RDebug *dbg, int fast, int num);
R_API int r_debug_arg_set (RDebug *dbg, int fast, int num, ut64 value);

/* pid */
R_API int r_debug_pid_list(struct r_debug_t *dbg, int pid);
R_API int r_debug_thread_list(struct r_debug_t *dbg, int pid);

R_API void r_debug_trace_reset (RDebug *dbg);
R_API int r_debug_trace_pc (RDebug *dbg);
R_API void r_debug_trace_at (RDebug *dbg, const char *str);
R_API RDebugTracepoint *r_debug_trace_get (RDebug *dbg, ut64 addr);
R_API void r_debug_trace_list (RDebug *dbg, int mode);
R_API RDebugTracepoint *r_debug_trace_add (RDebug *dbg, ut64 addr, int size);
R_API RDebugTrace *r_debug_trace_new ();
R_API void r_debug_trace_free (RDebug *dbg);
R_API int r_debug_trace_tag (RDebug *dbg, int tag);
R_API int r_debug_fork (RDebug *dbg);
R_API int r_debug_clone (RDebug *dbg);

#endif
#endif

/* regset */
//R_API struct r_regset_t* r_regset_diff(struct r_regset_t *a, struct r_regset_t *b);
//R_API int r_regset_set(struct r_regset_t *r, int idx, const char *name, ut64 value);
//R_API struct r_regset_t *r_regset_new(int size);
//R_API void r_regset_free(struct r_regset_t *r);

#if 0
Missing callbacks
=================
 - alloc
 - dealloc
 - list maps (memory regions)
 - change memory protections
 - touchtrace
 - filedescriptor set/get/mod..
 - get/set signals
 - get regs, set regs

#endif
