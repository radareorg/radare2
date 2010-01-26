/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */

#ifndef _INCLUDE_R_TRACE_H_
#define _INCLUDE_R_TRACE_H_

#include <r_types.h>
#include <list.h>

typedef struct r_trace_t {
	struct list_head traces;
	int num;
	int changed;
	int tag;
	int dup;
	int (*printf)(const char *str,...);
} RTrace;

typedef struct r_trace_item_t {
	ut64 addr;
	ut64 tags;
	int opsize;
	int times;
	int count;
	struct timeval tm;
	struct list_head list;
} RTraceItem;

#ifdef R_API
R_API int r_trace_init(struct r_trace_t *t);
R_API struct r_trace_t *r_trace_new();
R_API int r_trace_tag_get(struct r_trace_t *t);
R_API int r_trace_tag_set(struct r_trace_t *t, int id);
R_API int r_trace_sort(struct r_trace_t *t);
R_API struct r_trace_item_t *r_trace_get(struct r_trace_t *t, ut64 addr, int tag);
R_API int r_trace_times(struct r_trace_t *tr, ut64 addr);
R_API int r_trace_count(struct r_trace_t *tr, ut64 addr);
R_API int r_trace_index(struct r_trace_t *tr, ut64 addr);
R_API int r_trace_set_times(struct r_trace_t *tr, ut64 addr, int times);
R_API int r_trace_add(struct r_trace_t *tr, ut64 addr, int opsize);
R_API ut64 r_trace_range(struct r_trace_t *t, ut64 from, int tag);
R_API ut64 r_trace_next(struct r_trace_t *tr, ut64 from, int tag);
R_API void r_trace_show(struct r_trace_t *tr, int plain, int tag);
R_API void r_trace_reset(struct r_trace_t *tr);
R_API int r_trace_get_between(struct r_trace_t *tr, ut64 from, ut64 to);
#endif
#endif
