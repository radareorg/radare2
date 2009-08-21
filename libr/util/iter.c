/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include "r_util.h"

R_API void **r_iter_new(int n)
{
	void **ptr = (void **)calloc(n+1, sizeof(void*));
	*ptr = ptr;
	return (ptr+1);
}

R_API void r_iter_set(void **ptr, int idx, void *data)
{
	ptr[idx] = data;
}

R_API void *r_iter_get(void **ptr)
{
	return *ptr;
}

R_API void **r_iter_next(void **it)
{
	return it+1;
}

R_API void **r_iter_next_n(void **ptr, int idx)
{
	return ptr+idx;
}

R_API void **r_iter_prev(void **it)
{
	return --it, (it==*it)?NULL:it;
}

R_API void r_iter_delete(void **it)
{
	for(; *it; it++)
		*it = *(it+1);
}

R_API int r_iter_last(void **it)
{
	return (*it != NULL);
}

R_API void **r_iter_first(void **it)
{
	void **p = it;
	// TODO: better code
	while (1) {
		it = r_iter_prev(p);
		if (!it) break;
		p = it;
	}
	return p;
}

R_API void r_iter_foreach(void **it, int (*callback)(void *, void *), void *user)
{
	for(; r_iter_get(it); it = r_iter_next(it))
		callback (r_iter_get(it), user);
}

R_API void **r_iter_free(void *ptr)
{
	void **p = r_iter_first(ptr);
	if (p) free (p-1);
	return NULL;
}

#if TEST
int main()
{
	int i = 0;
	void **it = r_iter_new(3);
	void **iter = NULL;

	r_iter_set(it, 0, "foo");
	r_iter_set(it, 1, "bar");
	r_iter_set(it, 2, "cow");

	r_iter_delete(r_iter_get(it, 1));
	it = r_iter_first(r_iter_next(it));

	for(iter = it; r_iter_get(iter); iter = r_iter_next(iter)) {
		printf("%d %s\n", i++, (char *)r_iter_get(iter));
	}

	r_iter_free(it);

	return 0;
}
#endif
