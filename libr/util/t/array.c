/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */
#include "r_util.h"

void test_flist () {
	int i;
	void **it = r_flist_new (3);
	char *pos = NULL;

	for (i=0;i<9999;i++) {
		r_flist_set (it, i, "foo");
	}

	r_flist_delete (it, 1);

	r_flist_foreach (it, pos) {
		printf("%s\n", pos);
	}

	r_flist_free(it);

	return 0;
}

int main() {
	test_flist();
}

