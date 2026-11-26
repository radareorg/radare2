#include <r_search.h>
#include "minunit.h"

typedef struct {
	int reads;
	int begins;
	int ends;
	bool cancel_after_read;
	bool fail_read;
	bool fail_begin;
} SearchBreakState;

static bool begin_search(void *user) {
	SearchBreakState *state = user;
	state->begins++;
	return !state->fail_begin;
}

static bool check_search(void *user) {
	SearchBreakState *state = user;
	return state->cancel_after_read && state->reads > 0;
}

static void end_search(void *user) {
	SearchBreakState *state = user;
	state->ends++;
}

static int read_search_data(RIO *io, ut64 addr, ut8 *buf, int len) {
	SearchBreakState *state = io->coreb.core;
	state->reads++;
	if (state->fail_read) {
		return -1;
	}
	memset (buf, 'a', len);
	return len;
}

static bool test_search_maps_with_break(void) {
	SearchBreakState state = { .cancel_after_read = true };
	const RBreakBind brk = { .user = &state, .begin = begin_search, .check = check_search, .end = end_search };
	RIO io = { .coreb.core = &state };
	RSearch *search = r_search_new (R_SEARCH_REGEXP);
	mu_assert_notnull (search, "create search");
	search->iob.io = &io;
	search->iob.read_at = read_search_data;
	mu_assert_true (r_search_kw_add (search, r_search_keyword_new_regexp ("/z/", NULL)), "add regexp");
	RIOMap first = { .itv = { .addr = 0, .size = 0x2000 } };
	RIOMap second = { .itv = { .addr = 0x4000, .size = 0x1000 } };
	RList *maps = r_list_new ();
	mu_assert_notnull (maps, "create map list");
	r_list_append (maps, &second);
	r_list_append (maps, &first);

	mu_assert_eq (r_search_maps_with_break (search, maps, &brk), 0, "cancel a standalone search");
	mu_assert_eq (state.reads, 1, "cancel before the next read");
	mu_assert_eq (state.begins, 1, "one scope for the full search");
	mu_assert_eq (state.ends, 1, "close the cancelled scope");

	state = (SearchBreakState) { .fail_read = true };
	mu_assert_eq (r_search_maps_with_break (search, maps, &brk), -1, "propagate a read error");
	mu_assert_eq (state.ends, 1, "close the scope on error");

	state = (SearchBreakState) { .fail_begin = true };
	mu_assert_eq (r_search_maps_with_break (search, maps, &brk), -1, "propagate a scope setup error");
	mu_assert_eq (state.ends, 0, "a failed begin opens no scope");
	mu_assert_eq (state.reads, 0, "no reads after scope setup fails");

	state = (SearchBreakState) {0};
	mu_assert_eq (r_search_maps_with_break (search, maps, NULL), 0, "search without a binding");
	mu_assert ("read beyond the first chunk", state.reads > 1);
	r_list_free (maps);
	r_search_free (search);
	mu_end;
}

int main(void) {
	mu_run_test (test_search_maps_with_break);
	return tests_passed != tests_run;
}
