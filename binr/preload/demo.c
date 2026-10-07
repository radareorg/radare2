#include <stdio.h>
#include <dlfcn.h>

int main(int argc, char **argv) {
	void *a = dlopen(NULL, RTLD_LAZY);
	void *m = dlsym (a, "r_main_radare2");
	if (m) {
		int (*r2main)(void *cons, int argc, char **argv) = m;
		return r2main (NULL, argc, argv);
	}
	return 0;
}
