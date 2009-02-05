#ifndef _INCLUDE_R_RANGE_H_
#define _INCLUDE_R_RANGE_H_

#include "r_types.h"
#include "r_util.h"
#include "list.h"

struct r_range_item_t {
	u64 from;
	u64 to;
	u8 *data;
	int datalen;
	struct list_head list;
};

struct r_range_t {
	int count;
	int changed;
	struct list_head ranges;
};

int r_range_init(struct r_range_t *r);
struct r_range_t *r_range_new();
struct r_range_t *r_range_new_from_string(const char *string);
struct r_range_t *r_range_free(struct r_range_t *r);

struct r_range_item_t *r_range_item_get(struct r_range_t *r, u64 addr);
u64 r_range_size(struct r_range_t *r);
int r_range_add_from_string(struct r_range_t *rgs, const char *string);
struct r_range_item_t *r_range_add(struct r_range_t *rgs, u64 from, u64 to, int rw);
int r_range_sub(struct r_range_t *rgs, u64 from, u64 to);
int r_range_merge(struct r_range_t *rgs, struct r_range_t *r);
int r_range_contains(struct r_range_t *rgs, u64 addr);
int r_range_sort(struct r_range_t *rgs);
int r_range_percent(struct r_range_t *rgs);
int r_range_list(struct r_range_t *rgs, int rad);
int r_range_get_n(struct r_range_t *rgs, int n, u64 *from, u64 *to);
struct r_range_t *r_range_inverse(struct r_range_t *rgs, u64 from, u64 to, int flags);

#endif
