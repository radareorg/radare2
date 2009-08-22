#ifndef _INCLUDE_R_DEBUG_H_
#define _INCLUDE_R_DEBUG_H_

#include <r_types.h>
#include <r_util.h>
#include <r_reg.h>
#include <r_bp.h>
#include <r_syscall.h>
#include "list.h"

enum {
	R_DBG_ARCH_NULL = 0,
	R_DBG_ARCH_X86,
	R_DBG_ARCH_ARM,
	R_DBG_ARCH_PPC,
	R_DBG_ARCH_M68K,
	R_DBG_ARCH_JAVA,
	R_DBG_ARCH_MIPS,
	R_DBG_ARCH_SPARC,
	R_DBG_ARCH_CSR,
	R_DBG_ARCH_MSIL,
	R_DBG_ARCH_OBJD,
	R_DBG_ARCH_BF
};

#define R_DEBUG_REG_NAME_MAX 16
struct r_debug_reg_t {
	char name[R_DEBUG_REG_NAME_MAX];
	union {
		ut64 value;
		float fvalue;
		double dvalue;
	};
	int isfloat;
};

struct r_debug_regset_t {
	int nregs;
	struct r_debug_reg_t *regs;
};

/* TODO: pass dbg and user data pointer everywhere */
struct r_debug_handle_t {
	const char *name;
	const char **archs;
	int (*startv)(int argc, char **argv);
	int (*attach)(int pid);
	int (*detach)(int pid);
	int (*step)(int pid); // if step() is NULL; reimplement it with traps
	int (*cont)(int pid);
	int (*wait)(int pid);
	int (*contsc)(int pid, int sc);
	//int (*bp_write)(int pid, ut64 addr, int hw, int type);
	int (*bp_write)(int pid, ut64 addr, int size, int hw, int rwx);
	struct r_debug_regset_t * (*reg_read)(int pid);
	int (*reg_write)(int pid, struct r_debug_regset_t *regs);
	// XXX bad signature int (*bp_read)(int pid, ut64 addr, int hw, int type);
	struct list_head list;
};

struct r_debug_t {
	int pid;    /* selected process id */
	int tid;    /* selected thread id */
	int swstep; /* steps with software traps */
	int steps;  /* counter of steps done */
	int newstate;
	struct r_debug_regset_t *oregs;
	struct r_debug_regset_t *regs;
	struct r_bp_t bp;
	void *user;
	/* io */
	void (*printf)(const char *str, ...);
	int (*read)(void *user, int pid, ut64 addr, ut8 *buf, int len);
	int (*write)(void *user, int pid, ut64 addr, const ut8 *buf, int len);
	struct r_debug_handle_t *h;
	struct list_head handlers;
	/* TODO
	- list of processes and their threads
	- list of mapped memory (from /proc/XX/maps)
	- list of managed memory (allocated in child...)
	*/
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

R_API int r_debug_handle_add(struct r_debug_t *dbg, struct r_debug_handle_t *foo);
R_API int r_debug_handle_set(struct r_debug_t *dbg, const char *str);
R_API int r_debug_handle_init(struct r_debug_t *dbg);
R_API int r_debug_init(struct r_debug_t *dbg);
R_API struct r_debug_t *r_debug_new();
R_API struct r_debug_t *r_debug_free(struct r_debug_t *dbg);

#define CB_READ int (*_cb_read)(void *user, int pid, ut64 addr, ut8 *buf, int len)
#define CB_WRITE int (*_cb_write)(void *user, int pid, ut64 addr, const ut8 *buf, int len)

R_API int r_debug_set_io(struct r_debug_t *dbg, CB_READ, CB_WRITE, void *user);

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

/* breakpoints */
R_API int r_debug_bp_add(struct r_debug_t *dbg, ut64 addr, int size, int hw, int rwx);
R_API int r_debug_bp_del(struct r_debug_t *dbg, ut64 addr);
R_API int r_debug_bp_enable(struct r_debug_t *dbg, ut64 addr, int set);
R_API int r_debug_bp_disable(struct r_debug_t *dbg);
R_API int r_debug_bp_list(struct r_debug_t *dbg, int rad);

/* registers */
R_API int r_debug_reg_sync(struct r_debug_t *dbg, int write);
R_API ut64 r_debug_reg_get(struct r_debug_t *dbg, const char *name);
R_API int r_debug_reg_set(struct r_debug_t *dbg, const char *name, ut64 value);
R_API struct r_debug_regset_t *r_debug_reg_diff(struct r_debug_t *dbg);
R_API int r_debug_reg_list(struct r_debug_t *dbg, struct r_debug_regset_t *rs, int rad);

/* regset */
R_API struct r_debug_regset_t* r_debug_regset_diff(struct r_debug_regset_t *a, struct r_debug_regset_t *b);
R_API int r_debug_regset_set(struct r_debug_regset_t *r, int idx, const char *name, ut64 value);
R_API struct r_debug_regset_t *r_debug_regset_new(int size);
R_API void r_debug_regset_free(struct r_debug_regset_t *r);

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
