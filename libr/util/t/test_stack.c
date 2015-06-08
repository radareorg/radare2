#include <r_util.h>

void check (int n, int exp) {
	if (n == exp) {
		printf("[+] test passed (actual: %d; expected: %d)\n", n, exp);
	} else {
		printf("[-] test failed (actual: %d; expected: %d)\n", n, exp);
	}
}

void check_empty(RStack *s, int exp) {
	if (r_stack_is_empty(s) == exp) {
		printf("[+] test passed (stack empty status)\n");
	} else {
		printf("[-] test failed (stack empty status)\n");
	}
}

int main(int argc, char **argv) {
	RStack *s = r_stack_new(5);
	int n;

	r_stack_push(s, (void *)10);
	r_stack_push(s, (void *)1);
	r_stack_push(s, (void *)2);
	r_stack_push(s, (void *)3);
	r_stack_push(s, (void *)4);
	r_stack_push(s, (void *)5);
	r_stack_push(s, (void *)6);
	r_stack_push(s, (void *)8);
	r_stack_push(s, (void *)9);
	r_stack_push(s, (void *)6);
	n = (int)r_stack_pop(s);
	check(n, 6);
	n = (int)r_stack_pop(s);
	check(n, 9);
	n = (int)r_stack_pop(s);
	check(n, 8);
	n = (int)r_stack_pop(s);
	check(n, 6);
	n = (int)r_stack_pop(s);
	check(n, 5);
	n = (int)r_stack_pop(s);
	check(n, 4);
	n = (int)r_stack_pop(s);
	check(n, 3);
	n = (int)r_stack_pop(s);
	check(n, 2);
	n = (int)r_stack_pop(s);
	check(n, 1);
	check_empty(s, R_FALSE);
	n = (int)r_stack_pop(s);
	check(n, 10);

	check_empty(s, R_TRUE);
	n = (int)r_stack_pop(s);
	check(n, 0);
	n = (int)r_stack_pop(s);
	check(n, 0);
	check_empty(s, R_TRUE);

	r_stack_push(s, (void *)10);
	r_stack_push(s, (void *)1);
	check_empty(s, R_FALSE);

	r_stack_free(s);
	return 0;
}
