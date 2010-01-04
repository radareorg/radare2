#ifndef _INCLUDE_LIBR_BP_H_
#define _INCLUDE_LIBR_BP_H_

#include <r_types.h>
#include <r_io.h>
#include "list.h"

#define R_BP_MAXPIDS 10


#define R_BP_CONT_NORMAL 0
#define R_BP_CONT_NORMAL 0

typedef struct r_bp_arch_t {
	int length;
	int endian;
	const ut8 *bytes;
} rBreakpointArch;

enum {
	R_BP_TYPE_SW,
	R_BP_TYPE_HW,
	R_BP_TYPE_COND,
	R_BP_TYPE_FAULT,
};

typedef struct r_bp_handle_t {
	char *name;
	char *arch;
	int type; // R_BP_TYPE_SW
	int nbps;
	struct r_bp_arch_t *bps;
	struct list_head list;
} rBreakpointHandler;

typedef struct r_bp_item_t {
	ut64 addr;
	int size;
	int rwx;
	int hw;
	int trace;
	int enabled;
	int hits;
	ut8 *obytes; /* original bytes */
	ut8 *bbytes; /* breakpoint bytes */
	int pids[R_BP_MAXPIDS];
	struct list_head list;
} rBreakpointItem;

typedef struct r_bp_t {
	int trace_all;
	ut64 trace_bp;
	int nbps;
	int stepcont;
	struct r_io_bind_t iob; // compile time dependency
	struct r_bp_handle_t *cur;
	struct list_head plugins;
	struct list_head bps;
} rBreakpoint;

enum {
	R_BP_PROT_READ = 1,
	R_BP_PROT_WRITE = 2,
	R_BP_PROT_EXEC = 4,
};

#ifdef R_API
R_API int r_bp_init(struct r_bp_t *bp);
R_API struct r_bp_t *r_bp_new();
R_API struct r_bp_t *r_bp_free(struct r_bp_t *bp);

R_API int r_bp_del(struct r_bp_t *bp, ut64 addr);

R_API int r_bp_handle_add(struct r_bp_t *bp, struct r_bp_handle_t *foo);
R_API int r_bp_use(struct r_bp_t *bp, const char *name);
R_API int r_bp_handle_del(struct r_bp_t *bp, const char *name);
R_API void r_bp_handle_list(struct r_bp_t *bp);

R_API int r_bp_in(struct r_bp_t *bp, ut64 addr, int rwx);
R_API int r_bp_list(struct r_bp_t *bp, int rad);
R_API int r_bp_get_bytes(struct r_bp_t *bp, ut8 *buf, int len, int endian, int idx);
R_API int r_bp_set_trace(struct r_bp_t *bp, ut64 addr, int set);
R_API int r_bp_set_trace_bp(struct r_bp_t *bp, ut64 addr, int set);
R_API struct r_bp_item_t *r_bp_enable(struct r_bp_t *bp, ut64 addr, int set);

R_API int r_bp_add_cond(struct r_bp_t *bp, const char *cond);
R_API int r_bp_del_cond(struct r_bp_t *bp, int idx);
R_API int r_bp_add_fault(struct r_bp_t *bp, ut64 addr, int size, int rwx);

R_API struct r_bp_item_t *r_bp_add_sw(struct r_bp_t *bp, ut64 addr, int size, int rwx);
R_API struct r_bp_item_t *r_bp_add_hw(struct r_bp_t *bp, ut64 addr, int size, int rwx);
R_API int r_bp_at_addr(struct r_bp_t *bp, ut64 addr, int rwx);
#endif

/* plugin pointers */
extern struct r_bp_handle_t r_bp_plugin_x86;
extern struct r_bp_handle_t r_bp_plugin_arm;
#if 0
extern struct r_bp_handle_t r_bp_plugin_powerpc;
extern struct r_bp_handle_t r_bp_plugin_mips;
extern struct r_bp_handle_t r_bp_plugin_sparc;
#endif

#endif
