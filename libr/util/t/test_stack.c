#include <r_util.h>

void check (int n, int exp, char *descr) {
	descr = descr == NULL ? "" : descr;
	if (n == exp) {
		printf("[+][%s] test passed (actual: %d; expected: %d)\n", descr, n, exp);
	} else {
		printf("[-][%s] test failed (actual: %d; expected: %d)\n", descr, n, exp);
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

	check(r_stack_size(s), 0, "stack.0");
	r_stack_push(s, (void *)10);
	r_stack_push(s, (void *)1);
	r_stack_push(s, (void *)2);
	check(r_stack_size(s), 3, "stack.3");
	r_stack_push(s, (void *)3);
	r_stack_push(s, (void *)4);
	r_stack_push(s, (void *)5);
	r_stack_push(s, (void *)6);
	r_stack_push(s, (void *)8);
	r_stack_push(s, (void *)9);
	r_stack_push(s, (void *)6);
	n = (int)r_stack_pop(s);
	check(n, 6, NULL);
	n = (int)r_stack_pop(s);
	check(n, 9, NULL);
	n = (int)r_stack_pop(s);
	check(n, 8, NULL);
	n = (int)r_stack_pop(s);
	check(n, 6, NULL);
	n = (int)r_stack_pop(s);
	check(n, 5, NULL);
	n = (int)r_stack_pop(s);
	check(n, 4, NULL);
	n = (int)r_stack_pop(s);
	check(n, 3, NULL);
	n = (int)r_stack_pop(s);
	check(n, 2, NULL);

	check(r_stack_size(s), 2, "stack.2");
	n = (int)r_stack_pop(s);
	check(n, 1, NULL);
	check_empty(s, false);
	check(r_stack_size(s), 1, "stack.1");
	n = (int)r_stack_pop(s);
	check(n, 10, NULL);

	check(r_stack_size(s), 0, "stack.0.2");
	check_empty(s, true);
	n = (int)r_stack_pop(s);
	check(n, 0, NULL);
	n = (int)r_stack_pop(s);
	check(n, 0, NULL);
	check_empty(s, true);

	r_stack_push(s, (void *)10);
	r_stack_push(s, (void *)1);
	check_empty(s, false);

	r_stack_free(s);
	return 0;
}
