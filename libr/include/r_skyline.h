#ifndef R_SKYLINE_H
#define R_SKYLINE_H

#include "r_vector.h"
#include "r_util/r_itv.h"

typedef struct r_skyline_item_t {
	RInterval itv;
	void *user;
} RSkylineItem;

typedef struct r_skyline_t {
	RVector v;
} RSkyline;

R_API bool r_skyline_add(RSkyline *skyline, RInterval itv, void *user);
R_API const RSkylineItem *r_skyline_get_item_intersect(RSkyline *skyline, ut64 addr, ut64 len);

static inline void r_skyline_init(RSkyline *skyline) {
	r_return_if_fail (skyline);
	r_vector_init (&skyline->v, sizeof (RSkylineItem), NULL, NULL);
}

static inline void r_skyline_fini(RSkyline *skyline) {
	r_return_if_fail (skyline);
	r_vector_fini (&skyline->v);
}

static inline void r_skyline_clear(RSkyline *skyline) {
	r_return_if_fail (skyline);
	r_vector_clear (&skyline->v);
}

static inline const RSkylineItem *r_skyline_get_item(RSkyline *skyline, ut64 addr) {
	r_return_val_if_fail (skyline, NULL);
	return r_skyline_get_item_intersect (skyline, addr, 0);
}

static inline void *r_skyline_get(RSkyline *skyline, ut64 addr) {
	r_return_val_if_fail (skyline, NULL);
	const RSkylineItem *item = r_skyline_get_item (skyline, addr);
	return item ? item->user : NULL;
}

static inline void *r_skyline_get_intersect(RSkyline *skyline, ut64 addr, ut64 len) {
	r_return_val_if_fail (skyline, NULL);
	const RSkylineItem *item = r_skyline_get_item_intersect (skyline, addr, len);
	return item ? item->user : NULL;
}

static inline bool r_skyline_contains(RSkyline *skyline, ut64 addr) {
	r_return_val_if_fail (skyline, false);
	return (bool)r_skyline_get_item (skyline, addr);
}

#endif
