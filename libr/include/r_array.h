#ifndef _INCLUDE_R_ARRAY_H_
#define _INCLUDE_R_ARRAY_H_

#define r_array_t void**
#define RArray void**
#define r_array_rewind(it) for (; it!=*it; it--); it++
#define r_array_next(it) *it!=0
#define r_array_get(it) *(it++)
#define r_array_iterator(x) x
#define r_array_unref(x) x

R_API void **r_array_init(void **it, int n);
R_API void **r_array_new(int n);
R_API void **r_array_prev(void **it);
R_API void r_array_set(void **it, int idx, void *data);
R_API void r_array_delete(void **it, int idx);
R_API void r_array_free(void **it);

#define r_array_foreach(it, pos) \
	r_array_rewind(it); \
	while (r_array_next (it) && (pos = r_array_get (it)))

#endif
