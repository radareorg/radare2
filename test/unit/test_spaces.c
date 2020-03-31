#include <r_util.h>
#include "minunit.h"

bool test_space_basic(void) {
	RSpaces *sps = r_spaces_new ("spacename");
	mu_assert_streq (sps->name, "spacename", "spacename should be the name");

	RSpace *sp = r_spaces_get (sps, "notexisting");
	mu_assert_null (sp, "NULL should be returned if not existing");
	sp = r_spaces_current (sps);
	mu_assert_null (sp, "the current flagspace should not exist");

	sp = r_spaces_set (sps, "firstspace");
	mu_assert_notnull (sp, "a flagspace should be created");
	mu_assert_streq (sp->name, "firstspace", "right flag space name");

	sp = r_spaces_current (sps);
	mu_assert_notnull (sp, "the current flagspace should exist");
	mu_assert_streq (sp->name, "firstspace", "right flag space name");

	sp = r_spaces_get (sps, "firstspace");
	mu_assert_notnull (sp, "a flagspace should be created");
	mu_assert_streq (sp->name, "firstspace", "right flag space name");

	r_spaces_free (sps);
	mu_end;
}

bool test_space_stack(void) {
	RSpaces *sps = r_spaces_new ("spacename");

	RSpace *first = r_spaces_set (sps, "firstspace");
	r_spaces_set (sps, "secondspace");
	RSpace *third = r_spaces_set (sps, "thirdspace");
	r_spaces_set (sps, NULL);

	r_spaces_push (sps, "firstspace");
	r_spaces_push (sps, "*");
	r_spaces_push (sps, "thirdspace");

	RSpace *s = r_spaces_current (sps);
	mu_assert_ptreq (s, third, "third now set");
	r_spaces_pop (sps);
	s = r_spaces_current (sps);
	mu_assert_null (s, "all set");
	r_spaces_pop (sps);
	s = r_spaces_current (sps);
	mu_assert_ptreq (s, first, "first now set");
	r_spaces_pop (sps);
	s = r_spaces_current (sps);
	mu_assert_null (s, "nothing set");

	r_spaces_push (sps, "fourthspace");
	s = r_spaces_current (sps);
	mu_assert_streq (s->name, "fourthspace", "fourth created");

	s = r_spaces_get (sps, "fourthspace");
	mu_assert_notnull (s, "fourth should exist");

	r_spaces_free (sps);
	mu_end;
}

static void count_event(REvent *ev, int type, void *user, void *data) {
	RSpaceEvent *spev = (RSpaceEvent *)data;

	if (!strcmp (spev->data.count.space->name, "firstspace")) {
		spev->res = 1;
	} else if (!strcmp (spev->data.count.space->name, "secondspace")) {
		spev->res = 2;
	} else if (!strcmp (spev->data.count.space->name, "thirdspace")) {
		spev->res = 3;
	}
}

static bool test_event_called = false;

static void test_event(REvent *ev, int type, void *user, void *data) {
	test_event_called = true;
}

bool test_space_event(void) {
	RSpaces *sps = r_spaces_new ("spacename");
	r_spaces_add (sps, "firstspace");
	r_spaces_add (sps, "secondspace");
	RSpace *third = r_spaces_add (sps, "thirdspace");

	r_event_hook (sps->event, R_SPACE_EVENT_COUNT, count_event, NULL);
	r_event_hook (sps->event, R_SPACE_EVENT_UNSET, test_event, NULL);
	r_event_hook (sps->event, R_SPACE_EVENT_RENAME, test_event, NULL);

	int c = r_spaces_count (sps, "firstspace");
	mu_assert_eq (c, 1, "first contain 1");
	c = r_spaces_count (sps, "thirdspace");
	mu_assert_eq (c, 3, "third contain 3");

	test_event_called = false;
	r_spaces_rename (sps, "thirdspace", "mynewname");
	mu_assert ("rename_event has been called", test_event_called);

	RSpace *s = r_spaces_get (sps, "thirdspace");
	mu_assert_null (s, "thirdspace should not exist anymore");
	s = r_spaces_get (sps, "mynewname");
	mu_assert_notnull (s, "mynewname should exist now");
	mu_assert_ptreq (s, third, "and it should be equal to thirdspace ptr");

	test_event_called = false;
	r_spaces_unset (sps, "mynewname");
	mu_assert ("unset_event has been called", test_event_called);

	r_spaces_free (sps);
	mu_end;
}

int all_tests() {
	mu_run_test (test_space_basic);
	mu_run_test (test_space_stack);
	mu_run_test (test_space_event);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
