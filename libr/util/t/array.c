/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */
#include "r_util.h"

int main() {
	void **it = r_flist_new (3);
	char *pos = NULL;

	r_flist_set(it, 0, strdup ("foo"));
	r_flist_set(it, 1, strdup ("bar"));
	r_flist_set(it, 2, strdup ("cow"));

	r_flist_delete (it, 1);

	r_flist_foreach(it, pos) {
		printf("%s\n", pos);
	}

	r_flist_free(it);

	return 0;
}
