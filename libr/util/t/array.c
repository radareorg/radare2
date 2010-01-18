/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */
#include "r_util.h"

void test_array_new () {
	int i = 0;
	void **iter, **it = r_array_new (3);

	r_array_set (it, 0, "foo");
	r_array_set (it, 1, "bar");
	r_array_set (it, 2, "cow");

	r_array_delete (r_array_get_n (it, 1));
	/* NOOP test */
	//it = r_array_first (r_array_get (it));
	//iter = r_array_iterator (it);
	r_array_rewind (it);

	for(iter = it; r_array_next (iter); ) {
		char *str = r_array_get (iter);
		printf ("%d %s\n", i++, str);
	}

	r_array_free(it);
}

void test_array_static () {
	int i = 0;
	void *data[10];
	rArray iter;
	rArray it = (rArray) &data;

	it = (rArray) r_array_init (it, 9);

	r_array_set (it, 0, "foo");
	r_array_set (it, 1, "bar");
	r_array_set (it, 2, "cow");

	r_array_delete (r_array_get_n (it, 1));
	r_array_rewind (it);

	for(iter = it; r_array_next (iter); ) {
		char *str = r_array_get (iter);
		printf ("%d %s\n", i++, str);
	}
}

int main()
{
	test_array_new ();
	test_array_static ();

	return 0;
}
