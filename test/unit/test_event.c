
#include <r_util.h>
#include "minunit.h"

typedef struct {
	int count;
	int last_type;
	void *last_data;
} EventTestAcc;

static void callback_test(REvent *ev, int type, void *user, void *data) {
	EventTestAcc *acc = user;
	acc->count++;
	acc->last_type = type;
	acc->last_data = data;
}

bool test_r_event(void) {
	REvent *ev = r_event_new ((void *)0x1337);
	mu_assert_notnull (ev, "r_event_new ()");
	mu_assert_eq_fmt (ev->user, (void *)0x1337, "ev->user", "%p");

	EventTestAcc acc_all = { 0 };
	EventTestAcc acc_specific = { 0 };

	REventCallbackHandle handle_all = r_event_hook (ev, R_EVENT_ALL, callback_test, &acc_all);
	REventCallbackHandle handle_specific = r_event_hook (ev, R_EVENT_META_SET, callback_test, &acc_specific);

	r_event_send (ev, R_EVENT_META_DEL, (void *)0x4242);

	mu_assert_eq (acc_all.count, 1, "all count after event");
	mu_assert_eq (acc_all.last_type, R_EVENT_META_DEL, "all type after event");
	mu_assert_eq_fmt (acc_all.last_data, (void *)0x4242, "all type after event", "%p");
	mu_assert_eq (acc_specific.count, 0, "specific count after other event");

	r_event_send (ev, R_EVENT_META_SET, (void *)0xdeadbeef);

	mu_assert_eq (acc_all.count, 2, "all count after event");
	mu_assert_eq (acc_all.last_type, R_EVENT_META_SET, "all type after event");
	mu_assert_eq_fmt (acc_all.last_data, (void *)0xdeadbeef, "all type after event", "%p");

	mu_assert_eq (acc_specific.count, 1, "specific count after event");
	mu_assert_eq (acc_specific.last_type, R_EVENT_META_SET, "specific type after event");
	mu_assert_eq_fmt (acc_specific.last_data, (void *)0xdeadbeef, "specific type after event", "%p");

	r_event_unhook (ev, handle_all);
	r_event_send (ev, R_EVENT_META_SET, (void *)0xc0ffee);

	mu_assert_eq (acc_all.count, 2, "all count after event after being removed");
	mu_assert_eq (acc_all.last_type, R_EVENT_META_SET, "all type after event after being removed");
	mu_assert_eq_fmt (acc_all.last_data, (void *)0xdeadbeef, "all type after event after being removed", "%p");

	mu_assert_eq (acc_specific.count, 2, "specific count after event");
	mu_assert_eq (acc_specific.last_type, R_EVENT_META_SET, "specific type after event");
	mu_assert_eq_fmt (acc_specific.last_data, (void *)0xc0ffee, "specific type after event", "%p");

	r_event_unhook (ev, handle_specific);
	r_event_send (ev, R_EVENT_META_SET, (void *)0xc0ffee);

	mu_assert_eq (acc_specific.count, 2, "specific count after event after being removed");
	mu_assert_eq (acc_specific.last_type, R_EVENT_META_SET, "specific type after event after being removed");
	mu_assert_eq_fmt (acc_specific.last_data, (void *)0xc0ffee, "specific type after event after being removed", "%p");

	r_event_free (ev);

	mu_end;
}

int all_tests() {
	mu_run_test (test_r_event);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
