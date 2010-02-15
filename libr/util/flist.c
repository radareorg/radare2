/* radare - LGPL - Copyright 2010 pancake <@nopcode.org> */

#include <r_types.h>
//#include <r_flist.h>
// NOTE: reimplemnetation of r_flist in C (if no R_API defined)

#if 1
#define r_flist_t void**
#define RFList void**
#define r_flist_rewind(it) for (; it!=*it; it--); it++
#define r_flist_next(it) *it!=0
#define r_flist_get(it) *(it++)
#define r_flist_iterator(x) x
#define r_flist_unref(x) x
#endif

R_API void **r_flist_init(void **it, int n) {
	*it = it;
	memset (++it, 0, (n+1) * sizeof (void*));
	return it;
}

R_API void **r_flist_new(int n) {
	void **it;
	if (!(it = (void **)malloc ((n+2) * sizeof (void*))))
		return NULL;
	return r_flist_init (it, n);
}

R_API void **r_flist_prev(void **it) {
	void **p = it--;
	return (it==*it)?p:it;
}

R_API void r_flist_set(void **it, int idx, void *data) {
	r_flist_rewind (it);
	it[idx] = data;
}

R_API void r_flist_delete(void **it, int idx) {
	r_flist_rewind (it);
	free (it[idx]);
	for(it += idx; *it; it++) *it = *(it+1);
}

#define r_flist_foreach(it, pos) \
	r_flist_rewind(it); \
	while (r_flist_next (it) && (pos = r_flist_get (it)))

R_API void r_flist_free(void **it) {
	void *pos;
	r_flist_foreach (it, pos)
		free (pos);
	r_flist_rewind (it);
	free (--it);
}
