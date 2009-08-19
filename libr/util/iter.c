/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */
#include "r_util.h"

// TODO: reimplement in cpp macros

R_API void **r_iter_new(int size)
{
	void **ptr = (void **)malloc(sizeof(void *) * (size+1));
	*ptr = ptr;
	memset(ptr+1, 0, size);
	return (ptr+1);
}

R_API void r_iter_set(void **ptr, int idx, void *data)
{
	ptr[idx] = data;
}

R_API void **r_iter_get(void **ptr, int idx)
{
	return ptr+idx;
}

R_API void *r_iter_current(void **ptr)
{
	return *ptr;
}

R_API void **r_iter_next(void **it)
{
	//return r_iter_get(it, 1);
	return it+1;
}

R_API void **r_iter_prev(void **it)
{
	it--;
	return (*it==it)?NULL:it;
}

R_API void r_iter_delete(void **it)
{
	void **iter, **p;
	/* XXX ugly code */
	while (1) {
		if (!*iter) break;
		p = iter+1;
		if (!*p) break;
		*iter = *p;
		iter = p;
	}
	*iter = 0;
}

R_API int r_iter_last(void **it)
{
	return (*it != NULL);
}

R_API void **r_iter_first(void **it)
{
	void *p = it;
	while (1) {
		it = r_iter_prev(p);
		if (!it) break;
		p = it;
	}
	return p;
}

R_API void *r_iter_foreach(void *it, int (*callback)(void *, void *), void *user)
{
	//void *ptr = 
}

R_API void *r_iter_free(void *ptr)
{
	void **p = r_iter_first(ptr);
	if (p) free (p-1);
}

#if TEST
main()
{
	void **iter;
	int i = 0;
	void **it = r_iter_new(3);

	r_iter_set(it, 0, "foo");
	r_iter_set(it, 1, "bar");
	r_iter_set(it, 2, "cow");

	r_iter_delete(r_iter_get(it, 1));

	for(iter = it; r_iter_current(iter); iter = r_iter_next(iter)) {
		printf("%d %s\n", i++, (char *)r_iter_current(iter));
	}

	r_iter_free(it);
}
#endif
