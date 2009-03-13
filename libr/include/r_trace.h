/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */

#ifndef _INCLUDE_R_ASM_H_
#define _INCLUDE_R_ASM_H_

#include <r_types.h>
#include <list.h>

struct r_trace_t {
	struct list_head traces;
	int num;
	int changed;
	int tag;
	int dup;
	int (*printf)(const char *str,...);
};

struct r_trace_item_t {
	u64 addr;
	u64 tags;
	int opsize;
	int times;
	int count;
	struct timeval tm;
	struct list_head list;
};

int r_trace_init(struct r_trace_t *t);
struct r_trace_t *r_trace_new();
int r_trace_tag_get(struct r_trace_t *t);
int r_trace_tag_set(struct r_trace_t *t, int id);
int r_trace_sort(struct r_trace_t *t);
struct r_trace_item_t *r_trace_get(struct r_trace_t *t, u64 addr, int tag);
int r_trace_times(struct r_trace_t *tr, u64 addr);
int r_trace_count(struct r_trace_t *tr, u64 addr);
int r_trace_index(struct r_trace_t *tr, u64 addr);
int r_trace_set_times(struct r_trace_t *tr, u64 addr, int times);
int r_trace_add(struct r_trace_t *tr, u64 addr, int opsize);
u64 r_trace_range(struct r_trace_t *t, u64 from, int tag);
u64 r_trace_next(struct r_trace_t *tr, u64 from, int tag);
void r_trace_show(struct r_trace_t *tr, int plain, int tag);
void r_trace_reset(struct r_trace_t *tr);
int r_trace_get_between(struct r_trace_t *tr, u64 from, u64 to);
#endif
