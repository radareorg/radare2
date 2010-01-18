/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include "r_util.h"

R_API void **r_array_init(void **ptr, int n)
{
	*ptr = ptr;
	memset (++ptr, 0, n * sizeof(void*));
	return ptr;
}

R_API void **r_array_new(int n)
{
	void **ptr = (void **)malloc((n+1) * sizeof(void*));
	return r_array_init (ptr, n);
}

R_API void r_array_set(void **ptr, int idx, void *data)
{
	ptr[idx] = data;
}

// previously named r_array_get
#if 0
R_API void *r_array_cur(void **ptr)
{
	return *ptr;
}

// previously named r_array_next
R_API void **r_array_get(void **it)
{
	return it+1;
}
#endif

R_API void **r_array_get_n(void **ptr, int idx)
{
	return ptr+idx;
}

R_API void **r_array_prev(void **it)
{
	return --it, (it==*it)?NULL:it;
}

R_API void r_array_delete(void **it)
{
	for(; *it; it++)
		*it = *(it+1);
}

#if 0
/* previously named _last */
R_API int r_array_next(void **it)
{
	return (*it == NULL);
}
#endif

R_API void **r_array_first(void **it)
{
	void **p = it;
	// TODO: better code
	while (1) {
		it = r_array_prev(p);
		if (!it) break;
		p = it;
	}
	return p;
}

R_API void r_array_foreach(void **it, int (*callback)(void *, void *), void *user)
{
	r_array_t i = r_array_iterator (it);
	while (r_array_next (i))
		callback (r_array_get (i), user);
}

#if 0
R_API void **r_array_free(void *ptr)
{
	void **p = r_array_first(ptr);
	if (p) free (p-1);
	return NULL;
}
#endif

#if TEST
int main()
{
	int i = 0;
	void **it = r_array_new(3);
	void **iter = NULL;

	r_array_set(it, 0, "foo");
	r_array_set(it, 1, "bar");
	r_array_set(it, 2, "cow");

	r_array_delete(r_array_get(it, 1));
	it = r_array_first(r_array_next(it));

	for(iter = it; r_array_get(iter); iter = r_array_next(iter)) {
		printf("%d %s\n", i++, (char *)r_array_get(iter));
	}

	r_array_free(it);

	return 0;
}
#endif
