/* radare - LGPL - Copyright 2007-2010 pancake<nopcode.org> */

/* simple example testing the r_alloca api */
#include <r_util.h>
#include <stdio.h>

#define TIMES 299999

int afun(const char *str, int iters) {
	int ret;
	char *ptr;
	if (iters == 0) return 0;
	ret = strlen(str)+1;
 	ptr = alloca(ret);
	memcpy(ptr, str, ret);
	return afun(str, iters-1);
}

int fun(const char *str, int iters) {
	int ret;
	char *ptr;
	if (iters == 0) return 0;
 	ptr = (char *)r_alloca_str(str);
	ret = fun(str, iters-1);
	return r_alloca_ret_i( ret );
}

/* malloc */
int mfun(const char *str, int iters) {
	int ret;
	char *ptr;
	if (iters == 0) return 0;
	ptr = strdup(str);
	ret = mfun(ptr, iters-1);
	free(ptr);
	return ret;
}

/* main */
int main() {
	int i;
	printf("Running r_alloca performance test...\n");
	fflush(stdout);

	system("date");
	r_alloca_init();
	for (i=0;i<TIMES;i++)
		fun("food for the heap", 128);
	system("date");

	printf("\n--\nRunning malloc performance test...\n");
	system("date");
	r_alloca_init();
	for (i=0;i<TIMES;i++)
		mfun("food for the heap", 128);
	system("date");

	printf("\n--\nRunning alloc performance test...\n");
	system("date");
	r_alloca_init();
	for (i=0;i<TIMES;i++)
		afun("food for the stack", 128);
	system("date");

	fflush(stdout);
	return 0;
}
