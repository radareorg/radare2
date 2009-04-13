#ifndef _INCLUDE_LIBR_BP_H_
#define _INCLUDE_LIBR_BP_H_

#include <r_types.h>
#include "list.h"

#define R_BP_MAXPIDS 10

struct r_bp_arch_t {
	int length;
	int endian;
	const u8 *bytes;
};

struct r_bp_handle_t {
	char *name;
	char *arch;
	int nbps;
	struct r_bp_arch_t *bps;
	struct list_head list;
};

struct r_bp_item_t {
	u64 addr;
	int size;
	int rwx;
	int hw;
	int trace;
	int enabled;
	u8 *obytes; /* original bytes */
	u8 *bbytes; /* breakpoint bytes */
	int pids[R_BP_MAXPIDS];
	struct list_head list;
};

struct r_bp_t {
	int trace_all;
	u64 trace_bp;
	int nbps;
	struct r_bp_handle_t *cur;
	struct list_head bps;
};

enum {
	R_BP_READ = 1,
	R_BP_WRITE = 2,
	R_BP_EXEC = 4,
};

R_API int r_bp_init(struct r_bp_t *bp);
R_API struct r_bp_t *r_bp_new();
R_API struct r_bp_t *r_bp_free(struct r_bp_t *bp);

R_API struct r_bp_item_t *r_bp_add(struct r_bp_t *bp, const u8 *obytes, u64 addr, int size, int hw, int rwx);
R_API int r_bp_del(struct r_bp_t *bp, u64 addr);

R_API int r_bp_handle_add(struct r_bp_t *bp, struct r_bp_handle_t *foo);
R_API int r_bp_handle_set(struct r_bp_t *bp, const char *name);
R_API int r_bp_handle_del(struct r_bp_t *bp, const char *name);

R_API int r_bp_in(struct r_bp_t *bp, u64 addr, int rwx);
R_API int r_bp_list(struct r_bp_t *bp, int rad);
R_API int r_bp_getbytes(struct r_bp_t *bp, u8 *buf, int len, int endian, int idx);
R_API int r_bp_set_trace(struct r_bp_t *bp, u64 addr, int set);
R_API int r_bp_set_trace_bp(struct r_bp_t *bp, u64 addr, int set);

/* plugin pointers */
extern struct r_bp_handle_t r_bp_plugin_x86;
extern struct r_bp_handle_t r_bp_plugin_arm;
extern struct r_bp_handle_t r_bp_plugin_powerpc;
extern struct r_bp_handle_t r_bp_plugin_mips;
extern struct r_bp_handle_t r_bp_plugin_sparc;

#endif
