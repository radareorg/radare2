/* radare - LGPL - Copyright 2010 nibble <.ds@gmail.com> */

#include <r_util.h>

R_API void **r_array_init(void **it, int n) {
	*it = it;
	memset (++it, 0, (n+1) * sizeof (void*));
	return it;
}

R_API void **r_array_new(int n) {
	void **it;
	if (!(it = (void **)malloc ((n+2) * sizeof (void*))))
		return NULL;
	return r_array_init (it, n);
}

R_API void **r_array_prev(void **it) {
	void **p = it;
	return (--it==*it)?p:it;
}

R_API void r_array_set(void **it, int idx, void *data) {
	r_array_rewind (it);
	it[idx] = data;
}

R_API void r_array_delete(void **it, int idx) {
	r_array_rewind (it);
	free (it[idx]);
	for(it += idx; *it; it++) *it = *(it+1);
}

R_API void r_array_free(void **it) {
	void *pos;
	r_array_foreach (it, pos)
		free (pos);
	r_array_rewind (it);
	free (--it);
}

/* TODO: r_array_iterator */
