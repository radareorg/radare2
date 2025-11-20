#include <stdio.h>
int main() {
	char foo[8];
	snprintf (foo, sizeof(foo), "🔥🚀📎🏎️😔");
	printf ("%s\n", foo);
	return 0;
}
