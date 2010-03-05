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

// TODO Use chars!! 's' 'r' 'S' 'z' ??
enum {
	R_DBG_PROC_STOP,
	R_DBG_PROC_RUN,
	R_DBG_PROC_SLEEP,
	R_DBG_PROC_ZOMBIE,
};

// signal handling must support application and debugger level options
enum {
	R_DBG_SIGNAL_IGNORE, // ignore signal handler
	R_DBG_SIGNAL_BYPASS,
	R_DBG_SIGNAL_HANDLE, //
	R_DBG_SIGNAL_SETUP,
	//..
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

typedef struct r_debug_t {
	int pid;    /* selected process id */
	int tid;    /* selected thread id */
	int swstep; /* steps with software traps */
	int steps;  /* counter of steps done */
	int newstate;
	char *reg_profile;
	struct r_reg_t *reg;
	struct r_bp_t *bp;
	void *user;
	/* io */
	void (*printf)(const char *str, ...);
	struct r_debug_handle_t *h;
	struct list_head handlers;
	RIOBind iob;
	RList *maps; // <RDebugMap>
	RList *maps_user; // <RDebugMap>
	/* TODO
	- list of processes and their threads
	- list of mapped memory (from /proc/XX/maps)
	- list of managed memory (allocated in child...)
	*/
} RDebug;

/* TODO: pass dbg and user data pointer everywhere */
typedef struct r_debug_handle_t {
	const char *name;
	const char **archs; // MUST BE DEPREACTED!!!!
	ut32 bits;
	ut32 arch;
	/* life */
	int (*startv)(int argc, char **argv);
	int (*attach)(int pid);
	int (*detach)(int pid);
	int (*select)(int pid, int tid);
	RList *(*threads)(int pid);
	RList *(*pids)(int pid);
	RFList (*backtrace)(int count);
	/* flow */
	int (*step)(int pid); // if step() is NULL; reimplement it with traps
	int (*cont)(int pid, int sig);
	int (*wait)(int pid);
	int (*kill)(RDebug *dbg, int sig);
	int (*contsc)(int pid, int sc);
	RList* (*frames)(RDebug *dbg);
	/* registers */
	RBreakpointCallback breakpoint;
	int (*reg_read)(struct r_debug_t *dbg, int type, ut8 *buf, int size);
	char* (*reg_profile)();
	int (*reg_write)(int pid, int type, const ut8 *buf, int size); //XXX struct r_regset_t regs);
	/* memory */
	RList *(*map_get)(RDebug *dbg);
	ut64 (*map_alloc)(RDebug *dbg, RDebugMap *map);
	int (*map_dealloc)(RDebug *dbg, ut64 addr);
	int (*init)(RDebug *dbg);
	struct list_head list;
} RDebugHandle;

// TODO: rename to r_debug_process_t ? maybe a thread too ?
typedef struct r_debug_pid_t {
	int pid;
	char status; /* stopped, running, zombie, sleeping ,... */
	int runnable; /* when using 'run', 'continue', .. this proc will be runnable */
	const char *path;
	//struct list_head threads;
	//struct list_head childs;
	//struct r_debug_pid_t *parent;
	//struct list_head list;
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
R_API int r_debug_continue_syscall(struct r_debug_t *dbg, int sc);
R_API int r_debug_pid_add(struct r_debug_t *dbg);
R_API int r_debug_pid_add_thread(struct r_debug_t *dbg);
R_API int r_debug_pid_del(struct r_debug_t *dbg);
R_API int r_debug_pid_del_thread(struct r_debug_t *dbg);
R_API RDebugPid *r_debug_pid_free(RDebugPid *pid);
R_API int r_debug_pid_list(struct r_debug_t *dbg, int pid);
R_API RDebugPid *r_debug_pid_new(char *path, int pid, char status);

R_API int r_debug_use(struct r_debug_t *dbg, const char *str);
R_API int r_debug_handle_add(struct r_debug_t *dbg, struct r_debug_handle_t *foo);
R_API int r_debug_handle_init(struct r_debug_t *dbg);
R_API int r_debug_handle_list(struct r_debug_t *dbg);

R_API struct r_debug_t *r_debug_init(struct r_debug_t *dbg, int hard);
R_API struct r_debug_t *r_debug_new();
R_API struct r_debug_t *r_debug_free(struct r_debug_t *dbg);

/* send signals */
R_API int r_debug_kill(struct r_debug_t *dbg, int sig);
R_API int r_debug_kill_setup(struct r_debug_t *dbg, int sig, int action);
R_API int r_debug_step(struct r_debug_t *dbg, int steps);
R_API int r_debug_continue(struct r_debug_t *dbg);
R_API int r_debug_continue_kill(struct r_debug_t *dbg, int signal);
R_API int r_debug_select(struct r_debug_t *dbg, int pid, int tid);

/* handle.c */
R_API int r_debug_handle_init(struct r_debug_t *dbg);
R_API int r_debug_handle_set(struct r_debug_t *dbg, const char *str);
R_API int r_debug_handle_list(struct r_debug_t *dbg);
R_API int r_debug_handle_add(struct r_debug_t *dbg, struct r_debug_handle_t *foo);

/* memory */
R_API int r_debug_map_alloc(RDebug *dbg, RDebugMap *map);
R_API int r_debug_map_dealloc(RDebug *dbg, RDebugMap *map);
R_API RList *r_debug_map_list_new();
R_API void r_debug_map_list_free(RList *maps);
R_API RDebugMap *r_debug_map_get(RDebug *dbg, ut64 addr);
R_API RDebugMap *r_debug_map_new (char *name, ut64 addr, ut64 addr_end, int perm, int user);
R_API void r_debug_map_free(RDebugMap *map);
R_API int r_debug_map_dealloc(RDebug *dbg, RDebugMap *map);
R_API void r_debug_map_list(RDebug *dbg, ut64 addr);

/* registers */
R_API int r_debug_reg_sync(struct r_debug_t *dbg, int type, int write);
R_API int r_debug_reg_list(struct r_debug_t *dbg, int type, int size, int rad);
R_API int r_debug_reg_set(struct r_debug_t *dbg, const char *name, ut64 num);
R_API ut64 r_debug_reg_get(struct r_debug_t *dbg, const char *name);

R_API void r_debug_io_bind(RDebug *dbg, RIO *io);
R_API ut64 r_debug_execute(struct r_debug_t *dbg, ut8 *buf, int len);
R_API int r_debug_map_sync(RDebug *dbg);

/* backtrace */
R_API RList *r_debug_frames (RDebug *dbg);

/* args */
R_API ut64 r_debug_arg_get (RDebug *dbg, int fast, int num);
R_API int r_debug_arg_set (RDebug *dbg, int fast, int num, ut64 value);
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
