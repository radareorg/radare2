/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */
#include "r_util.h"

void test_iter_new () {
	int i = 0;
	void **iter, **it = r_iter_new (3);

	r_iter_set (it, 0, "foo");
	r_iter_set (it, 1, "bar");
	r_iter_set (it, 2, "cow");

	r_iter_delete (r_iter_get_n (it, 1));
	/* NOOP test */
	it = r_iter_first (r_iter_get (it));

	for(iter = it; r_iter_cur (iter); iter = r_iter_get (iter)) {
		printf ("%d %s\n", i++, (char *)r_iter_cur (iter));
	}

	r_iter_free(it);
}

void test_iter_static () {
	int i = 0;
	void *data[10];
	r_iter_t it = (r_iter_t) &data;
	r_iter_t iter;

	it = (r_iter_t) r_iter_init (it, 9);

	r_iter_set (it, 0, "foo");
	r_iter_set (it, 1, "bar");
	r_iter_set (it, 2, "cow");

	r_iter_delete (r_iter_get_n (it, 1));
	/* NOOP test */
	it = r_iter_first (r_iter_get (it));

	for(iter = it; r_iter_cur (iter); iter = r_iter_get (iter)) {
		printf ("%d %s\n", i++, (char *)r_iter_cur (iter));
	}
}

int main()
{

	test_iter_new ();
	test_iter_static ();

	return 0;
}
