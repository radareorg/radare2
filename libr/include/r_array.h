/* radare - LGPL - Copyright 2010 nibble <.ds@gmail.com> */

#ifndef _INCLUDE_R_ARRAY_H_
#define _INCLUDE_R_ARRAY_H_

#include <stdlib.h>
#include <string.h>

#define r_array_t void**
#define RArray void**
#define r_array_rewind(it) for (; it!=*it; it--); it++
#define r_array_next(it) *it!=0
#define r_array_get(it) *(it++)
#define r_array_iterator(x) x
#define r_array_unref(x) x

static inline void **r_array_init(void **it, int n) {
	*it = it;
	memset (++it, 0, (n+1) * sizeof (void*));
	return it;
}

static inline void **r_array_new(int n) {
	void **it;
	if (!(it = (void **)malloc ((n+2) * sizeof (void*))))
		return NULL;
	return r_array_init (it, n);
}

static inline void **r_array_prev(void **it) {
	void **p = it;
	return (--it==*it)?p:it;
}

static inline void r_array_set(void **it, int idx, void *data) {
	r_array_rewind (it);
	it[idx] = data;
}

static inline void r_array_delete(void **it, int idx) {
	r_array_rewind (it);
	free (it[idx]);
	for(it += idx; *it; it++) *it = *(it+1);
}

#define r_array_foreach(it, pos) \
	r_array_rewind(it); \
	while (r_array_next (it) && (pos = r_array_get (it)))

static inline void r_array_free(void **it) {
	void *pos;
	r_array_foreach (it, pos)
		free (pos);
	r_array_rewind (it);
	free (--it);
}

#endif
