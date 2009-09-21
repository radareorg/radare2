#ifndef _INCLUDE_R_DEBUG_H_
#define _INCLUDE_R_DEBUG_H_

#include <r_types.h>
#include <r_util.h>
#include <r_reg.h>
#include <r_bp.h>
#include <r_io.h>
#include <r_syscall.h>
#include "list.h"


struct r_debug_t {
	int pid;    /* selected process id */
	int tid;    /* selected thread id */
	int swstep; /* steps with software traps */
	int steps;  /* counter of steps done */
	int newstate;
	struct r_reg_t *reg;
	struct r_regset_t *oregs;
	struct r_regset_t *regs;
	struct r_bp_t *bp;
	void *user;
	/* io */
	void (*printf)(const char *str, ...);
	struct r_debug_handle_t *h;
	struct list_head handlers;
	/* TODO
	- list of processes and their threads
	- list of mapped memory (from /proc/XX/maps)
	- list of managed memory (allocated in child...)
	*/
};

/* TODO: pass dbg and user data pointer everywhere */
struct r_debug_handle_t {
	const char *name;
	const char **archs;
	int (*get_arch)();
	/* life */
	int (*startv)(int argc, char **argv);
	int (*attach)(int pid);
	int (*detach)(int pid);
	/* flow */
	int (*step)(int pid); // if step() is NULL; reimplement it with traps
	int (*cont)(int pid);
	int (*wait)(int pid);
	int (*contsc)(int pid, int sc);
	/* registers */
	int (*reg_read)(struct r_debug_t *dbg, int type, ut8 *buf, int size);
	char* (*reg_profile)();
	int (*reg_write)(int pid, struct r_regset_t regs);
	/* memory */
	ut64 (*mmu_alloc)(void *user, ut64 size, ut64 addr);
	int (*mmu_free)(void *user, ut64 addr);

	struct list_head list;
};

enum {
	R_DBG_PROC_STOP,
	R_DBG_PROC_RUN,
	R_DBG_PROC_SLEEP,
	R_DBG_PROC_ZOMBIE,
};

struct r_debug_pid_t {
	int pid;
	int status; /* stopped, running, zombie, sleeping ,... */
	int runnable; /* when using 'run', 'continue', .. this proc will be runnable */
	struct list_head threads;
	struct list_head childs;
	struct r_debug_pid_t *parent;
	struct list_head list;
};

R_API int r_debug_use(struct r_debug_t *dbg, const char *str);
R_API int r_debug_handle_add(struct r_debug_t *dbg, struct r_debug_handle_t *foo);
R_API int r_debug_handle_init(struct r_debug_t *dbg);
R_API int r_debug_handle_list(struct r_debug_t *dbg)

R_API int r_debug_init(struct r_debug_t *dbg, int hard);
R_API struct r_debug_t *r_debug_new();
R_API struct r_debug_t *r_debug_free(struct r_debug_t *dbg);

/* send signals */
R_API int r_debug_kill(struct r_debug_t *dbg, int pid, int sig);
R_API int r_debug_step(struct r_debug_t *dbg, int steps);
R_API int r_debug_continue(struct r_debug_t *dbg);
R_API int r_debug_select(struct r_debug_t *dbg, int pid, int tid);

/* handle.c */
R_API int r_debug_handle_init(struct r_debug_t *dbg);
R_API int r_debug_handle_set(struct r_debug_t *dbg, const char *str);
R_API int r_debug_handle_list(struct r_debug_t *dbg);
R_API int r_debug_handle_add(struct r_debug_t *dbg, struct r_debug_handle_t *foo);

/* memory */
R_API ut64 r_debug_mmu_alloc(struct r_debug_t *dbg, ut64 size, ut64 addr);
R_API int r_debug_mmu_free(struct r_debug_t *dbg, ut64 addr);

/* registers */
R_API int r_debug_reg_sync(struct r_debug_t *dbg, int type, int write);
R_API ut64 r_debug_reg_get(struct r_debug_t *dbg, const char *name);
R_API int r_debug_reg_set(struct r_debug_t *dbg, const char *name, ut64 value);
R_API struct r_regset_t *r_debug_reg_diff(struct r_debug_t *dbg);
R_API int r_debug_reg_list(struct r_debug_t *dbg, int type, int size, int rad);

/* regset */
R_API struct r_regset_t* r_regset_diff(struct r_regset_t *a, struct r_regset_t *b);
R_API int r_regset_set(struct r_regset_t *r, int idx, const char *name, ut64 value);
R_API struct r_regset_t *r_regset_new(int size);
R_API void r_regset_free(struct r_regset_t *r);

#if 0
Missing callbacks
=================
 - alloc
 - dealloc
 - list maps
 - change memory protections
 - touchtrace
 - filedescriptor set/get/mod..
 - get/set signals
 - get regs, set regs

#endif

/* plugin pointers */
extern struct r_debug_handle_t r_debug_plugin_ptrace;
extern struct r_debug_handle_t r_debug_plugin_gdb;

#endif
