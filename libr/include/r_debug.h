#ifndef R2_DEBUG_H
#define R2_DEBUG_H

#include <r_types.h>
#include <r_anal.h>
#include <r_cons.h>
#include <r_util.h>
#include <r_reg.h>
#include <r_bp.h>
#include <r_db.h>
#include <r_io.h>
#include <r_syscall.h>
#include "list.h"

#include "r_bind.h"
#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_debug);

/* hack to fix compilation of debugger on BSD systems */
/* This needs some testing (netbsd, freebsd, openbsd, kfreebsd) */
#if __BSD__
#include <machine/reg.h>

/* hakish hack to hack the openbsd/sparc64 hack */
#undef reg
#undef fpreg
#undef fpstate
#undef trapframe
#undef rwindow

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
	R_DBG_SIGNAL_IGNORE=0, // ignore signal handler
	R_DBG_SIGNAL_CONT=1, // pass signal to chlidren and continue execution
	R_DBG_SIGNAL_SKIP=2, //
	//..
};

enum { // TODO: not yet used by r_debug
	R_DBG_REASON_DEAD = -1,
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

typedef struct r_debug_signal_t {
	int type;
	int num;
	ut64 handler;
} RDebugSignal;

typedef struct r_debug_desc_t {
	int fd;
	char *path;
	int perm;
	int type;
	ut64 off;
} RDebugDesc;

typedef struct r_debug_trace_t {
	RList *traces;
	int count;
	int enabled;
	//int changed;
	int tag;
	int dup;
	char *addresses;
	// TODO: add range here
	Sdb *db;
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
	int signum;
	RDebugTrace *trace;
	int stop_all_threads;
	RReg *reg;
	RBreakpoint *bp;
	int bpsize;
	void *user;
	/* io */
	PrintfCallback printf;
	struct r_debug_plugin_t *h;
	struct list_head plugins;
	RAnal *anal;
	RIOBind iob;
	RList *maps; // <RDebugMap>
	RList *maps_user; // <RDebugMap>
	RGraph *graph;
	Sdb *sgnls;
	RCoreBind corebind;
#if __WINDOWS__
	HANDLE process_handle;
#endif
	int trace_forks;
	int trace_execs;
	int trace_clone;
	// internal use only
	int _mode;
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
	RList* (*list)(int pid);
} RDebugDescPlugin;

typedef struct r_debug_info_t {
	int pid;
	int tid;
	int uid;
	int gid;
	char *exe;
	char *cmdline;
	char *cwd;
	int status; // zombie, running, sleeping, ...
	// retrieve mem/fd/core limits?
	// list of threads ? hasthreads? counter?
	// environment?
	// /proc/pid/stack ???
	// /proc/pid/syscall ???
	// 
} RDebugInfo;

/* TODO: pass dbg and user data pointer everywhere */
typedef struct r_debug_plugin_t {
	const char *name;
	const char *license;
	//const char **archs; // MUST BE DEPREACTED!!!!
	ut32 bits;
	ut64 arch;
	int canstep;
	/* life */
	RDebugInfo* (*info)(RDebug *dbg, const char *arg);
	int (*startv)(int argc, char **argv);
	int (*attach)(RDebug *dbg, int pid);
	int (*detach)(int pid);
	int (*select)(int pid, int tid);
	RList *(*threads)(RDebug *dbg, int pid);
	RList *(*pids)(int pid);
	RList *(*tids)(int pid);
	RFList (*backtrace)(int count);
	/* flow */
	int (*stop)(RDebug *dbg);
	int (*step)(RDebug *dbg);
	int (*step_over)(RDebug *dbg);
	int (*cont)(RDebug *dbg, int pid, int tid, int sig);
	int (*wait)(RDebug *dbg, int pid);
	int (*kill)(RDebug *dbg, int pid, int tid, int sig);
	RList* (*kill_list)(RDebug *dbg);
	int (*contsc)(RDebug *dbg, int pid, int sc);
	RList* (*frames)(RDebug *dbg, ut64 at);
	RBreakpointCallback breakpoint;
// XXX: specify, pid, tid, or RDebug ?
	int (*reg_read)(RDebug *dbg, int type, ut8 *buf, int size);
	int (*reg_write)(RDebug *dbg, int type, const ut8 *buf, int size); //XXX struct r_regset_t regs);
	char* (*reg_profile)(RDebug *dbg);
	/* memory */
	RList *(*map_get)(RDebug *dbg);
	RDebugMap* (*map_alloc)(RDebug *dbg, ut64 addr, int size);
	int (*map_dealloc)(RDebug *dbg, ut64 addr, int size);
	int (*map_protect)(RDebug *dbg, ut64 addr, int size, int perms);
	int (*init)(RDebug *dbg);
	int (*drx)(RDebug *dbg, int n, ut64 addr, int size, int rwx, int g);
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
R_API int r_debug_attach(RDebug *dbg, int pid);
R_API int r_debug_detach(RDebug *dbg, int pid);
R_API int r_debug_startv(RDebug *dbg, int argc, char **argv);
R_API int r_debug_start(RDebug *dbg, const char *cmd);
R_API int r_debug_stop_reason(RDebug *dbg);
R_API int r_debug_wait(RDebug *dbg);
R_API int r_debug_step_over(RDebug *dbg, int steps);
R_API int r_debug_continue_until(RDebug *dbg, ut64 addr);
R_API int r_debug_continue_until_optype(RDebug *dbg, int type, int over);
R_API int r_debug_continue_until_nontraced(RDebug *dbg);
R_API int r_debug_continue_syscall(RDebug *dbg, int sc);
R_API int r_debug_continue_syscalls(RDebug *dbg, int *sc, int n_sc);
//R_API int r_debug_pid_add(RDebug *dbg);
//R_API int r_debug_pid_add_thread(RDebug *dbg);
//R_API int r_debug_pid_del(RDebug *dbg);
//R_API int r_debug_pid_del_thread(RDebug *dbg);
R_API int r_debug_pid_list(RDebug *dbg, int pid, char fmt);
R_API RDebugPid *r_debug_pid_new(const char *path, int pid, char status, ut64 pc);
R_API RDebugPid *r_debug_pid_free(RDebugPid *pid);
R_API RList *r_debug_pids(RDebug *dbg, int pid);

R_API int r_debug_set_arch(RDebug *dbg, int arch, int bits);
R_API int r_debug_use(RDebug *dbg, const char *str);

R_API RDebugInfo *r_debug_info(RDebug *dbg, const char *arg);
R_API void r_debug_info_free (RDebugInfo *rdi);

R_API RDebug *r_debug_new(int hard);
R_API RDebug *r_debug_free(RDebug *dbg);

/* send signals */
R_API void r_debug_signal_init(RDebug *dbg);
R_API int r_debug_signal_send(RDebug *dbg, int num);
R_API int r_debug_signal_what(RDebug *dbg, int num);
R_API int r_debug_signal_resolve(RDebug *dbg, const char *signame);
R_API const char *r_debug_signal_resolve_i(RDebug *dbg, int signum);
R_API void r_debug_signal_setup(RDebug *dbg, int num, int opt);
R_API int r_debug_signal_set(RDebug *dbg, int num, ut64 addr);
R_API void r_debug_signal_list(RDebug *dbg, int mode);
R_API int r_debug_kill(RDebug *dbg, int pid, int tid, int sig);
R_API RList *r_debug_kill_list(RDebug *dbg);
// XXX: must be uint64 action
R_API int r_debug_kill_setup(RDebug *dbg, int sig, int action);
R_API int r_debug_step(RDebug *dbg, int steps);
R_API int r_debug_continue(RDebug *dbg);
R_API int r_debug_continue_kill(RDebug *dbg, int signal);
R_API int r_debug_select(RDebug *dbg, int pid, int tid);

/* handle.c */
R_API int r_debug_plugin_init(RDebug *dbg);
R_API int r_debug_plugin_set(RDebug *dbg, const char *str);
R_API int r_debug_plugin_list(RDebug *dbg);
R_API int r_debug_plugin_add(RDebug *dbg, RDebugPlugin *foo);

/* memory */
R_API RDebugMap *r_debug_map_alloc(RDebug *dbg, ut64 addr, int size);
R_API int r_debug_map_dealloc(RDebug *dbg, RDebugMap *map);
R_API RList *r_debug_map_list_new();
R_API void r_debug_map_list_free(RList *maps);
R_API RDebugMap *r_debug_map_get(RDebug *dbg, ut64 addr);
R_API RDebugMap *r_debug_map_new (char *name, ut64 addr, ut64 addr_end, int perm, int user);
R_API void r_debug_map_free(RDebugMap *map);
R_API void r_debug_map_list(RDebug *dbg, ut64 addr, int rad);

/* descriptors */
R_API RDebugDesc *r_debug_desc_new (int fd, char* path, int perm, int type, int off);
R_API void r_debug_desc_free (RDebugDesc *p);
R_API int r_debug_desc_open(RDebug *dbg, const char *path);
R_API int r_debug_desc_close(RDebug *dbg, int fd);
R_API int r_debug_desc_dup(RDebug *dbg, int fd, int newfd);
R_API int r_debug_desc_read(RDebug *dbg, int fd, ut64 addr, int len);
R_API int r_debug_desc_seek(RDebug *dbg, int fd, ut64 addr); // TODO: whence?
R_API int r_debug_desc_write(RDebug *dbg, int fd, ut64 addr, int len);
R_API int r_debug_desc_list(RDebug *dbg, int rad);

/* registers */
R_API int r_debug_reg_sync(RDebug *dbg, int type, int write);
R_API int r_debug_reg_list(RDebug *dbg, int type, int size, int rad, const char *use_color);
R_API int r_debug_reg_set(RDebug *dbg, const char *name, ut64 num);
R_API ut64 r_debug_reg_get(RDebug *dbg, const char *name);
R_API ut64 r_debug_reg_get_err(RDebug *dbg, const char *name, int *err);

R_API void r_debug_io_bind(RDebug *dbg, RIO *io);
R_API ut64 r_debug_execute(RDebug *dbg, const ut8 *buf, int len, int restore);
R_API int r_debug_map_sync(RDebug *dbg);

R_API int r_debug_stop(RDebug *dbg);

/* backtrace */
R_API RList *r_debug_frames (RDebug *dbg, ut64 at);

R_API int r_debug_is_dead (RDebug *dbg);
R_API int r_debug_map_protect (RDebug *dbg, ut64 addr, int size, int perms);
/* args XXX: weird food */
R_API ut64 r_debug_arg_get (RDebug *dbg, int fast, int num);
R_API int r_debug_arg_set (RDebug *dbg, int fast, int num, ut64 value);

/* pid */
R_API int r_debug_thread_list(RDebug *dbg, int pid);

R_API void r_debug_trace_reset (RDebug *dbg);
R_API int r_debug_trace_pc (RDebug *dbg);
R_API void r_debug_trace_at (RDebug *dbg, const char *str);
R_API RDebugTracepoint *r_debug_trace_get (RDebug *dbg, ut64 addr);
R_API void r_debug_trace_list (RDebug *dbg, int mode);
R_API RDebugTracepoint *r_debug_trace_add (RDebug *dbg, ut64 addr, int size);
R_API RDebugTrace *r_debug_trace_new ();
R_API void r_debug_trace_free (RDebug *dbg);
R_API int r_debug_trace_tag (RDebug *dbg, int tag);
R_API int r_debug_child_fork (RDebug *dbg);
R_API int r_debug_child_clone (RDebug *dbg);

R_API void r_debug_drx_list (RDebug *dbg);
R_API int r_debug_drx_set (RDebug *dbg, int idx, ut64 addr, int len, int rwx, int g);
R_API int r_debug_drx_unset (RDebug *dbg, int idx);

/* plugin pointers */
extern RDebugPlugin r_debug_plugin_native;
extern RDebugPlugin r_debug_plugin_esil;
extern RDebugPlugin r_debug_plugin_rap;
extern RDebugPlugin r_debug_plugin_gdb;
extern RDebugPlugin r_debug_plugin_bf;
extern RDebugPlugin r_debug_plugin_wind;

#endif

#ifdef __cplusplus
}
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
