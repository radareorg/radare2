#include <r_util.h>

void check (int n, int exp) {
	if (n == exp) {
		printf("[+] test passed (actual: %d; expected: %d)\n", n, exp);
	} else {
		printf("[-] test failed (actual: %d; expected: %d)\n", n, exp);
	}
}

void check_empty(RQueue *q, int exp) {
	if (r_queue_is_empty(q) == exp) {
		printf("[+] test passed (stack empty status)\n");
	} else {
		printf("[-] test failed (stack empty status)\n");
	}
}

int main(int argc, char **argv) {
	RQueue *q = r_queue_new(5);
	int n;

	check_empty(q, true);
	r_queue_enqueue(q, (void *)1);
	r_queue_enqueue(q, (void *)2);
	r_queue_enqueue(q, (void *)3);
	r_queue_enqueue(q, (void *)4);
	r_queue_enqueue(q, (void *)5);
	r_queue_enqueue(q, (void *)6);
	r_queue_enqueue(q, (void *)7);
	r_queue_enqueue(q, (void *)8);
	n = (int)r_queue_dequeue(q);
	check(n, 1);
	n = (int)r_queue_dequeue(q);
	check(n, 2);
	n = (int)r_queue_dequeue(q);
	check(n, 3);
	n = (int)r_queue_dequeue(q);
	check(n, 4);
	n = (int)r_queue_dequeue(q);
	check(n, 5);
	n = (int)r_queue_dequeue(q);
	check(n, 6);
	n = (int)r_queue_dequeue(q);
	check(n, 7);
	check_empty(q, false);
	n = (int)r_queue_dequeue(q);
	check(n, 8);
	n = (int)r_queue_dequeue(q);
	check(n, 0);
	check_empty(q, true);

	r_queue_enqueue(q, (void *)1);
	r_queue_enqueue(q, (void *)2);
	n = (int)r_queue_dequeue(q);
	r_queue_enqueue(q, (void *)3);
	n = (int)r_queue_dequeue(q);
	check(n, 2);

	check_empty(q, false);

	r_queue_free(q);
	return 0;
}
