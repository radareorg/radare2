#include <r_util.h>
#include <r_vec.h>
#include "minunit.h"

typedef struct {
	ut32 x;
	float *y;
} S;

void fini_S (S* s, void *user) {
	if (s) {
		free (s->y);
	}

	if (user) {
		ut32* x = user;
		(*x)++;
	}
}

R_GENERATE_VEC_IMPL_FOR(UT32, ut32);
R_GENERATE_VEC_IMPL_FOR(ST32, st32);
R_GENERATE_VEC_IMPL_FOR(S, S);


static bool test_vec_init(void) {
	RVecUT32 v;
	RVecUT32_init (&v);
	mu_assert_eq (R_VEC_START_ITER (&v), NULL, "init start");
	mu_assert_eq (R_VEC_END_ITER (&v), NULL, "init end");
	mu_assert_eq (R_VEC_CAPACITY (&v), 0, "init capacity");
	RVecUT32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_fini(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	ut32 x;
	for (x = 0; x < 8; x++) {
		RVecUT32_push_back (&v, &x);
	}

	RVecUT32_fini (&v, NULL, NULL);
	mu_assert_eq (R_VEC_START_ITER (&v), NULL, "fini start");
	mu_assert_eq (R_VEC_END_ITER (&v), NULL, "fini end");
	mu_assert_eq (R_VEC_CAPACITY (&v), 0, "fini capacity");

	RVecUT32_fini (&v, NULL, NULL);
	mu_assert_eq (R_VEC_START_ITER (&v), NULL, "fini start2");
	mu_assert_eq (R_VEC_END_ITER (&v), NULL, "fini end2");
	mu_assert_eq (R_VEC_CAPACITY (&v), 0, "fini capacity2");

	RVecS vS;
	RVecS_init (&vS);

	for (x = 0; x < 3; x++) {
		float *y = malloc (sizeof (float));
		*y = 3.14;
		S s = { .x = x, .y = y };
		RVecS_push_back (&vS, &s);
	}

	RVecS_fini (&vS, fini_S, NULL);

	mu_assert_eq (R_VEC_START_ITER (&vS), NULL, "fini start3");
	mu_assert_eq (R_VEC_END_ITER (&vS), NULL, "fini end3");
	mu_assert_eq (R_VEC_CAPACITY (&vS), 0, "fini capacity3");
	mu_end;
}

static bool test_vec_new(void) {
	RVecUT32 *v = RVecUT32_new ();
	mu_assert_eq (R_VEC_START_ITER (v), NULL, "new start");
	mu_assert_eq (R_VEC_END_ITER (v), NULL, "new end");
	mu_assert_eq (R_VEC_CAPACITY (v), 0, "new capacity");
	RVecUT32_free (v, NULL, NULL);
	mu_end;
}

static bool test_vec_free(void) {
	RVecUT32 *v = RVecUT32_new ();

	ut32 x;
	for (x = 0; x < 8; x++) {
		RVecUT32_push_back (v, &x);
	}

	RVecUT32_free (v, NULL, NULL);

	RVecS *vS = RVecS_new ();

	for (x = 0; x < 3; x++) {
		float *y = malloc (sizeof (float));
		*y = 3.14;
		S s = { .x = x, .y = y };
		RVecS_push_back (vS, &s);
	}

	RVecS_free (vS, fini_S, NULL);
	mu_end;
}

static bool test_vec_clone(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	ut32 x;
	for (x = 0; x < 3; x++) {
		RVecUT32_push_back (&v, &x);
	}

	RVecUT32 *v2 = RVecUT32_clone (&v);
	ut32 sum = 0;
	ut32 *y;
	R_VEC_FOREACH (v2, y) {
		sum += *y;
	}

	mu_assert_eq (RVecUT32_length (v2), 3, "clone length");
	mu_assert_eq (R_VEC_CAPACITY (v2), 8, "clone capacity");
	mu_assert_eq (sum, 3, "clone sum"); // 0 + 1 + 2

	RVecUT32_fini (&v, NULL, NULL);
	RVecUT32_free (v2, NULL, NULL);

	RVecS vS;
	RVecS_init (&vS);

	for (x = 0; x < 3; x++) {
		S s = { .x = x * 2, .y = NULL };
		RVecS_push_back (&vS, &s);
	}

	RVecS *vS2 = RVecS_clone (&vS);
	sum = 0;
	S *s;
	R_VEC_FOREACH (vS2, s) {
		sum += s->x;
	}

	mu_assert_eq (RVecS_length (vS2), 3, "clone length2");
	mu_assert_eq (R_VEC_CAPACITY (vS2), 8, "clone capacity2");
	mu_assert_eq (sum, 6, "clone sum2"); // 0 + 2 + 4

	RVecS_fini (&vS, fini_S, NULL);
	RVecS_free (vS2, fini_S, NULL);
	mu_end;
}

static bool test_vec_push_back(void) {
	RVecUT32 v;
	RVecUT32_init (&v);
	mu_assert_eq (R_VEC_START_ITER (&v), NULL, "push_back start");
	mu_assert_eq (R_VEC_END_ITER (&v), NULL, "push_back end");
	mu_assert_eq (R_VEC_CAPACITY (&v), 0, "push_back capacity");

	ut32 x;
	for (x = 0; x < 8; x++) {
		RVecUT32_push_back (&v, &x);
	}

	mu_assert_neq (R_VEC_START_ITER (&v), NULL, "push_back start2");
	mu_assert_neq (R_VEC_END_ITER (&v), NULL, "push_back end2");
	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "push_back capacity2");
	mu_assert_eq (RVecUT32_length (&v), 8, "push_back length2");

	RVecUT32_push_back (&v, &x);
	mu_assert_eq (R_VEC_CAPACITY (&v), 16, "push_back capacity3");
	mu_assert_eq (RVecUT32_length (&v), 9, "push_back length3");

	RVecUT32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_emplace_back(void) {
	RVecUT32 v;
	RVecUT32_init (&v);
	mu_assert_eq (R_VEC_START_ITER (&v), NULL, "emplace_back start");
	mu_assert_eq (R_VEC_END_ITER (&v), NULL, "emplace_back end");
	mu_assert_eq (R_VEC_CAPACITY (&v), 0, "emplace_back capacity");

	ut32 x;
	for (x = 0; x < 8; x++) {
		ut32 *ptr = RVecUT32_emplace_back (&v);
		*ptr = x;
	}

	mu_assert_neq (R_VEC_START_ITER (&v), NULL, "emplace_back start2");
	mu_assert_neq (R_VEC_END_ITER (&v), NULL, "emplace_back end2");
	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "emplace_back capacity2");
	mu_assert_eq (RVecUT32_length (&v), 8, "emplace_back length2");

	ut32 *ptr = RVecUT32_emplace_back (&v);
	*ptr = x;
	mu_assert_eq (R_VEC_CAPACITY (&v), 16, "emplace_back capacity3");
	mu_assert_eq (RVecUT32_length (&v), 9, "emplace_back length3");

	RVecUT32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_push_front(void) {
	RVecUT32 v;
	RVecUT32_init (&v);
	mu_assert_eq (R_VEC_START_ITER (&v), NULL, "push_front start");
	mu_assert_eq (R_VEC_END_ITER (&v), NULL, "push_front end");
	mu_assert_eq (R_VEC_CAPACITY (&v), 0, "push_front capacity");

	ut32 x;
	for (x = 0; x < 8; x++) {
		RVecUT32_push_front (&v, &x);
	}

	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "push_front capacity2");
	mu_assert_eq (RVecUT32_length (&v), 8, "push_front length2");

	mu_assert_eq (*RVecUT32_at (&v, 0), 7, "push_front at1");
	mu_assert_eq (*RVecUT32_at (&v, 1), 6, "push_front at2");
	mu_assert_eq (*RVecUT32_at (&v, 2), 5, "push_front at3");

	RVecUT32_push_front (&v, &x);
	mu_assert_eq (R_VEC_CAPACITY (&v), 16, "push_front capacity3");
	mu_assert_eq (RVecUT32_length (&v), 9, "push_front length3");

	RVecUT32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_emplace_front(void) {
	RVecUT32 v;
	RVecUT32_init (&v);
	mu_assert_eq (R_VEC_START_ITER (&v), NULL, "emplace_front start");
	mu_assert_eq (R_VEC_END_ITER (&v), NULL, "emplace_front end");
	mu_assert_eq (R_VEC_CAPACITY (&v), 0, "emplace_front capacity");

	ut32 x;
	for (x = 0; x < 8; x++) {
		ut32 *ptr = RVecUT32_emplace_front (&v);
		*ptr = x;
	}

	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "emplace_front capacity2");
	mu_assert_eq (RVecUT32_length (&v), 8, "emplace_front length2");

	mu_assert_eq (*RVecUT32_at (&v, 0), 7, "emplace_front at1");
	mu_assert_eq (*RVecUT32_at (&v, 1), 6, "emplace_front at2");
	mu_assert_eq (*RVecUT32_at (&v, 2), 5, "emplace_front at3");

	ut32 *ptr = RVecUT32_emplace_front (&v);
	*ptr = x;
	mu_assert_eq (R_VEC_CAPACITY (&v), 16, "emplace_front capacity3");
	mu_assert_eq (RVecUT32_length (&v), 9, "emplace_front length3");

	RVecUT32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_append(void) {
	RVecUT32 v1, v2;
	RVecUT32_init (&v1);
	RVecUT32_init (&v2);

	RVecUT32_append (&v1, &v2);
	mu_assert_eq (R_VEC_CAPACITY (&v1), 0, "append capacity1");
	mu_assert_eq (RVecUT32_length (&v1), 0, "append length1");
	mu_assert_eq (R_VEC_CAPACITY (&v2), 0, "append capacity2");
	mu_assert_eq (RVecUT32_length (&v2), 0, "append length2");

	ut32 x;
	for (x = 0; x < 8; x++) {
		RVecUT32_push_back (&v1, &x);
	}

	for (x = 0; x < 10; x++) {
		RVecUT32_push_back (&v2, &x);
	}

	RVecUT32_append (&v1, &v2);
	mu_assert_eq (R_VEC_CAPACITY (&v1), 32, "append capacity3");
	mu_assert_eq (RVecUT32_length (&v1), 18, "append length3");
	mu_assert_eq (R_VEC_CAPACITY (&v2), 16, "append capacity4");
	mu_assert_eq (RVecUT32_length (&v2), 10, "append length4");

	RVecUT32_fini (&v1, NULL, NULL);
	RVecUT32_fini (&v2, NULL, NULL);
	mu_end;
}

static bool test_vec_remove(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	ut32 x;
	for (x = 0; x < 8; x++) {
		RVecUT32_push_back (&v, &x);
	}

	RVecUT32_remove (&v, 0, NULL, NULL);
	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "remove capacity1");
	mu_assert_eq (RVecUT32_length (&v), 7, "remove length1");
	mu_assert_eq (*RVecUT32_at (&v, 0), 1, "remove at1");
	mu_assert_eq (*RVecUT32_at (&v, 1), 2, "remove at2");

	RVecUT32_remove (&v, 1, NULL, NULL);
	mu_assert_eq (*RVecUT32_at (&v, 0), 1, "remove at3");
	mu_assert_eq (*RVecUT32_at (&v, 1), 3, "remove at4");
	mu_assert_eq (*RVecUT32_at (&v, 2), 4, "remove at5");

	RVecUT32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_pop_front(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	ut32 x;
	for (x = 0; x < 8; x++) {
		RVecUT32_push_back (&v, &x);
	}

	RVecUT32_pop_front (&v, NULL, NULL);
	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "pop_front capacity1");
	mu_assert_eq (RVecUT32_length (&v), 7, "pop_front length1");
	mu_assert_eq (*RVecUT32_at (&v, 0), 1, "pop_front at1");
	mu_assert_eq (*RVecUT32_at (&v, 1), 2, "pop_front at2");

	RVecUT32_pop_front (&v, NULL, NULL);
	mu_assert_eq (RVecUT32_length (&v), 6, "pop_front length2");
	mu_assert_eq (*RVecUT32_at (&v, 0), 2, "pop_front at3");
	mu_assert_eq (*RVecUT32_at (&v, 1), 3, "pop_front at4");
	mu_assert_eq (*RVecUT32_at (&v, 2), 4, "pop_front at5");

	RVecUT32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_pop_back(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	ut32 x;
	for (x = 0; x < 8; x++) {
		RVecUT32_push_back (&v, &x);
	}

	RVecUT32_pop_back (&v, NULL, NULL);
	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "pop_back capacity1");
	mu_assert_eq (RVecUT32_length (&v), 7, "pop_back length1");
	mu_assert_eq (*RVecUT32_at (&v, 6), 6, "pop_back at1");
	mu_assert_eq (*RVecUT32_at (&v, 5), 5, "pop_back at2");

	RVecUT32_pop_back (&v, NULL, NULL);
	mu_assert_eq (RVecUT32_length (&v), 6, "pop_back length2");
	mu_assert_eq (*RVecUT32_at (&v, 5), 5, "pop_back at3");
	mu_assert_eq (*RVecUT32_at (&v, 4), 4, "pop_back at4");

	RVecUT32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_swap(void) {
	RVecUT32 v1, v2;
	RVecUT32_init (&v1);
	RVecUT32_init (&v2);

	RVecUT32_swap (&v1, &v2);
	mu_assert_eq (RVecUT32_length (&v1), 0, "swap length1");
	mu_assert_eq (RVecUT32_length (&v2), 0, "swap length2");

	ut32 x;
	for (x = 0; x < 3; x++) {
		RVecUT32_push_back (&v1, &x);
	}
	for (x = 0; x < 5; x++) {
		RVecUT32_push_back (&v2, &x);
	}

	mu_assert_eq (RVecUT32_length (&v1), 3, "swap length3");
	mu_assert_eq (RVecUT32_length (&v2), 5, "swap length4");

	RVecUT32_swap (&v1, &v2);

	mu_assert_eq (RVecUT32_length (&v1), 5, "swap length5");
	mu_assert_eq (RVecUT32_length (&v2), 3, "swap length6");

	for (x = 0; x < 5; x++) {
		mu_assert_eq (*RVecUT32_at (&v1, x), x, "at1");
	}
	for (x = 0; x < 3; x++) {
		mu_assert_eq (*RVecUT32_at (&v2, x), x, "at2");
	}

	RVecUT32_fini (&v1, NULL, NULL);
	RVecUT32_fini (&v2, NULL, NULL);
	mu_end;
}

static bool test_vec_clear(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	RVecUT32_clear (&v, NULL, NULL);
	mu_assert_eq (RVecUT32_length (&v), 0, "clear length1");
	mu_assert_eq (R_VEC_CAPACITY (&v), 0, "clear capacity1");

	ut32 x;
	for (x = 0; x < 3; x++) {
		RVecUT32_push_back (&v, &x);
	}

	mu_assert_eq (RVecUT32_length (&v), 3, "clear length2");
	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "clear capacity2");

	RVecUT32_clear (&v, NULL, NULL);

	mu_assert_eq (RVecUT32_length (&v), 0, "clear length3");
	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "clear capacity3");

	RVecUT32_clear (&v, NULL, NULL);
	mu_assert_eq (RVecUT32_length (&v), 0, "clear length4");
	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "clear capacity4");

	ut32 counter = 0;
	RVecS vS;
	RVecS_init (&vS);
	RVecS_clear (&vS, fini_S, &counter);
	mu_assert_eq (counter, 0, "clear counter1");

	for (x = 0; x < 3; x++) {
		float *y = malloc (sizeof (float));
		*y = 3.14;
		S s = { .x = x, .y = y };
		RVecS_push_back (&vS, &s);
	}

	RVecS_clear (&vS, fini_S, &counter);
	mu_assert_eq (counter, 3, "clear counter2");

	RVecUT32_fini (&v, NULL, NULL);
	RVecS_fini (&vS, fini_S, NULL);
	mu_end;
}

static bool test_vec_length(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	mu_assert_eq (RVecUT32_length (&v), 0, "length1");

	ut32 x;
	for (x = 0; x < 3; x++) {
		RVecUT32_push_back (&v, &x);
	}

	mu_assert_eq (RVecUT32_length (&v), 3, "length2");

	RVecUT32_clear (&v, NULL, NULL);

	mu_assert_eq (RVecUT32_length (&v), 0, "clear length3");

	RVecUT32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_capacity(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	mu_assert_eq (R_VEC_CAPACITY (&v), 0, "capacity1");

	ut32 x = 100;
	RVecUT32_push_back (&v, &x);

	for (x = 0; x < 3; x++) {
		RVecUT32_push_back (&v, &x);
	}

	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "capacity2");

	for (x = 0; x < 5; x++) {
		RVecUT32_push_back (&v, &x);
	}

	mu_assert_eq (R_VEC_CAPACITY (&v), 16, "capacity3");

	RVecUT32_push_back (&v, &x);
	mu_assert_eq (R_VEC_CAPACITY (&v), 16, "capacity4");

	RVecUT32_clear (&v, NULL, NULL);
	mu_assert_eq (R_VEC_CAPACITY (&v), 16, "clear capacity4");

	RVecUT32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_empty(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	mu_assert_eq (RVecUT32_empty (&v), true, "empty1");

	ut32 x = 100;
	RVecUT32_push_back (&v, &x);
	mu_assert_eq (RVecUT32_empty (&v), false, "empty2");

	for (x = 0; x < 3; x++) {
		RVecUT32_push_back (&v, &x);
	}

	mu_assert_eq (RVecUT32_empty (&v), false, "empty3");

	RVecUT32_clear (&v, NULL, NULL);
	mu_assert_eq (RVecUT32_empty (&v), true, "empty4");

	RVecUT32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_start_iter(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	mu_assert_eq (R_VEC_START_ITER (&v), NULL, "start iter1");

	ut32 x = 100;
	RVecUT32_push_back (&v, &x);
	mu_assert_neq (R_VEC_START_ITER (&v), NULL, "start iter2");

	for (x = 0; x < 3; x++) {
		RVecUT32_push_back (&v, &x);
	}

	mu_assert_neq (R_VEC_START_ITER (&v), NULL, "start iter3");

	RVecUT32_clear (&v, NULL, NULL);
	mu_assert_neq (R_VEC_START_ITER (&v), NULL, "start iter4");

	RVecUT32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_end_iter(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	mu_assert_eq (R_VEC_END_ITER (&v), NULL, "end iter1");

	ut32 x = 100;
	RVecUT32_push_back (&v, &x);
	mu_assert_neq (R_VEC_END_ITER (&v), NULL, "end iter2");

	for (x = 0; x < 3; x++) {
		RVecUT32_push_back (&v, &x);
	}

	mu_assert_neq (R_VEC_END_ITER (&v), NULL, "end iter3");

	RVecUT32_clear (&v, NULL, NULL);
	mu_assert_neq (R_VEC_END_ITER (&v), NULL, "end iter4");

	RVecUT32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_at(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	mu_assert_eq (RVecUT32_at (&v, 0), NULL, "at1");

	ut32 x;
	for (x = 0; x < 3; x++) {
		RVecUT32_push_back (&v, &x);
	}

	mu_assert_neq (RVecUT32_at (&v, 0), NULL, "at2");
	mu_assert_eq (RVecUT32_at (&v, 0), R_VEC_START_ITER (&v), "at3");
	mu_assert_eq (*RVecUT32_at (&v, 0), 0, "at4");

	*RVecUT32_at (&v, 0) = 10;
	mu_assert_eq (*RVecUT32_at (&v, 0), 10, "at5");

	RVecUT32_clear (&v, NULL, NULL);
	mu_assert_eq (RVecUT32_at (&v, 0), NULL, "at6");

	RVecUT32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_reserve(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	mu_assert_eq (RVecUT32_length (&v), 0, "reserve length1");
	mu_assert_eq (R_VEC_CAPACITY (&v), 0, "reserve capacity1");

	RVecUT32_reserve (&v, 12);
	mu_assert_eq (RVecUT32_length (&v), 0, "reserve length2");
	mu_assert_eq (R_VEC_CAPACITY (&v), 12, "reserve capacity2");

	ut32* start_iter = R_VEC_START_ITER (&v);

	ut32 x;
	for (x = 0; x < 9; x++) {
		RVecUT32_push_back (&v, &x);
	}

	mu_assert_eq (RVecUT32_length (&v), 9, "reserve length3");
	mu_assert_eq (R_VEC_CAPACITY (&v), 12, "reserve capacity3");
	mu_assert_eq (start_iter, R_VEC_START_ITER (&v), "reserve start iter3");

	RVecUT32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_shrink_to_fit(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	RVecUT32_reserve (&v, 12);
	RVecUT32_shrink_to_fit (&v);
	mu_assert_eq (RVecUT32_length (&v), 0, "shrink_to_fit length1");
	mu_assert_eq (R_VEC_CAPACITY (&v), 0, "shrink_to_fit capacity1");

	ut32 x;
	for (x = 0; x < 9; x++) {
		RVecUT32_push_back (&v, &x);
	}

	RVecUT32_shrink_to_fit (&v);
	mu_assert_eq (RVecUT32_length (&v), 9, "shrink_to_fit length2");
	mu_assert_eq (R_VEC_CAPACITY (&v), 9, "shrink_to_fit capacity2");

	RVecUT32_shrink_to_fit (&v);
	mu_assert_eq (RVecUT32_length (&v), 9, "shrink_to_fit length3");
	mu_assert_eq (R_VEC_CAPACITY (&v), 9, "shrink_to_fit capacity3");

	RVecUT32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_foreach(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	ut32 x;
	for (x = 0; x < 10; x++) {
		RVecUT32_push_back (&v, &x);
	}

	ut32 sum = 0;
	ut32 *y;
	R_VEC_FOREACH (&v, y) {
		sum += *y;
	}

	mu_assert_eq (sum, 45, "foreach sum1");

	RVecS vS;
	RVecS_init (&vS);

	for (x = 0; x < 10; x++) {
		S s = { .x = x + 1, .y = NULL };
		RVecS_push_back (&vS, &s);
	}

	sum = 0;
	S *s;
	R_VEC_FOREACH (&vS, s) {
		sum += s->x;
	}

	mu_assert_eq (sum, 55, "foreach sum2");

	RVecUT32_fini (&v, NULL, NULL);
	RVecS_fini (&vS, fini_S, NULL);
	mu_end;
}

static bool test_vec_foreach_prev(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	ut32 x;
	for (x = 0; x < 10; x++) {
		RVecUT32_push_back (&v, &x);
	}

	ut32 sum = 0;
	ut32 *y;
	R_VEC_FOREACH_PREV (&v, y) {
		sum += *y;
	}

	mu_assert_eq (sum, 45, "foreach prev sum1");

	RVecS vS;
	RVecS_init (&vS);

	for (x = 0; x < 10; x++) {
		S s = { .x = x + 1, .y = NULL };
		RVecS_push_back (&vS, &s);
	}

	sum = 0;
	S *s;
	R_VEC_FOREACH_PREV (&vS, s) {
		sum += s->x;
	}

	mu_assert_eq (sum, 55, "foreach prev sum2");

	RVecUT32_fini (&v, NULL, NULL);
	RVecS_fini (&vS, fini_S, NULL);
	mu_end;
}

static inline int compare_st32(st32 *a, st32 *b) {
	return *a - *b;
}

static bool test_vec_lower_bound(void) {
	RVecST32 v;
	RVecST32_init (&v);

	st32 x;
	for (x = 0; x < 5; x++) {
		st32 y = x * 2;
		RVecST32_push_back (&v, &y);
	}

	x = 3;
	size_t idx1 = RVecST32_lower_bound (&v, &x, compare_st32);
	mu_assert_eq (idx1, 2, "lower_bound1");

	x = -1;
	size_t idx2 = RVecST32_lower_bound (&v, &x, compare_st32);
	mu_assert_eq (idx2, 0, "lower_bound2");

	x = 0;
	size_t idx3 = RVecST32_lower_bound (&v, &x, compare_st32);
	mu_assert_eq (idx3, 0, "lower_bound3");

	x = 2;
	size_t idx4 = RVecST32_lower_bound (&v, &x, compare_st32);
	mu_assert_eq (idx4, 1, "lower_bound4");

	x = 42;
	size_t idx5 = RVecST32_lower_bound (&v, &x, compare_st32);
	mu_assert_eq (idx5, 5, "lower_bound5");

	RVecST32_fini (&v, NULL, NULL);
	mu_end;
}

static bool test_vec_upper_bound(void) {
	RVecST32 v;
	RVecST32_init (&v);

	st32 x;
	for (x = 0; x < 5; x++) {
		st32 y = x * 2;
		RVecST32_push_back (&v, &y);
	}

	x = 3;
	size_t idx1 = RVecST32_upper_bound (&v, &x, compare_st32);
	mu_assert_eq (idx1, 2, "upper_bound1");

	x = -1;
	size_t idx2 = RVecST32_upper_bound (&v, &x, compare_st32);
	mu_assert_eq (idx2, 0, "upper_bound2");

	x = 0;
	size_t idx3 = RVecST32_upper_bound (&v, &x, compare_st32);
	mu_assert_eq (idx3, 1, "upper_bound3");

	x = 2;
	size_t idx4 = RVecST32_upper_bound (&v, &x, compare_st32);
	mu_assert_eq (idx4, 2, "upper_bound4");

	x = 42;
	size_t idx5 = RVecST32_upper_bound (&v, &x, compare_st32);
	mu_assert_eq (idx5, 5, "upper_bound5");

	RVecST32_fini (&v, NULL, NULL);
	mu_end;
}

static int all_tests(void) {
	mu_run_test (test_vec_init);
	mu_run_test (test_vec_fini);
	mu_run_test (test_vec_new);
	mu_run_test (test_vec_free);
	mu_run_test (test_vec_clone);
	mu_run_test (test_vec_push_back);
	mu_run_test (test_vec_emplace_back);
	mu_run_test (test_vec_push_front);
	mu_run_test (test_vec_emplace_front);
	mu_run_test (test_vec_append);
	mu_run_test (test_vec_remove);
	mu_run_test (test_vec_pop_front);
	mu_run_test (test_vec_pop_back);
	mu_run_test (test_vec_swap);
	mu_run_test (test_vec_clear);
	mu_run_test (test_vec_length);
	mu_run_test (test_vec_capacity);
	mu_run_test (test_vec_empty);
	mu_run_test (test_vec_start_iter);
	mu_run_test (test_vec_end_iter);
	mu_run_test (test_vec_at);
	mu_run_test (test_vec_reserve);
	mu_run_test (test_vec_shrink_to_fit);
	mu_run_test (test_vec_foreach);
	mu_run_test (test_vec_foreach_prev);
	mu_run_test (test_vec_lower_bound);
	mu_run_test (test_vec_upper_bound);

	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
