/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */
#include "r_util.h"

int main()
{
	int i = 0;
	void **iter, **it = r_iter_new(3);

	r_iter_set(it, 0, "foo");
	r_iter_set(it, 1, "bar");
	r_iter_set(it, 2, "cow");

	r_iter_delete(r_iter_next_n(it, 1));
	/* NOOP test */
	it = r_iter_first(r_iter_next(it));

	for(iter = it; r_iter_get(iter); iter = r_iter_next(iter)) {
		printf("%d %s\n", i++, (char *)r_iter_get(iter));
	}

	r_iter_free(it);

	return 0;
}
