typedef int (*fp)(int a, int b);

struct foo {
	int x;
	// note that this fp is tied to foo
	int (*fp)(int a , int b );
	char *b;
	// this one must use the global typedef instead
	fp fp2;
};
