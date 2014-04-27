#include <r_util.h>

void test(const char *s) {
	int n;
	printf("STR: %s\n", s);
	n = r_str_word_count(s);
	printf("NUM: %d\n", n);
}

int main() {
	test("1");
	test("");
	test("1 2 3");
	test("1,2,3");
	test("1, 2, 3");
	test(" 1, 2, 3 ");
	return 0;
}
