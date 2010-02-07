/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */
#include "r_util.h"

int main() {
	void **it = r_array_new (3);
	char *pos = NULL;

	r_array_set(it, 0, strdup ("foo"));
	r_array_set(it, 1, strdup ("bar"));
	r_array_set(it, 2, strdup ("cow"));

	r_array_delete (it, 1);

	r_array_foreach(it, pos) {
		printf("%s\n", pos);
	}

	r_array_free(it);

	return 0;
}
