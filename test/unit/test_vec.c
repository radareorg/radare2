#include <r_util.h>
#include <r_vec.h>
#include "minunit.h"

typedef struct {
	ut32 x;
	float *y;
} S;

static ut32 count_S = 0;

static inline void fini_S(S* s) {
	if (s) {
		free (s->y);
	}

	count_S++;
}

static inline int compare_st32(const st32 *a, const st32 *b) {
	return *a - *b;
}

static inline int find_compare_st32(const st32 *a, const void *b) {
	return compare_st32 (a, (st32*) b);
}

R_VEC_TYPE (RVecUT32, ut32);
R_VEC_TYPE (RVecST32, st32);
R_VEC_TYPE_WITH_FINI (RVecS, S, fini_S);


static bool test_vec_init(void) {
	RVecUT32 v;
	RVecUT32_init (&v);
	mu_assert_eq (R_VEC_START_ITER (&v), NULL, "init start");
	mu_assert_eq (R_VEC_END_ITER (&v), NULL, "init end");
	mu_assert_eq (R_VEC_START_ITER (&v), R_VEC_END_ITER (&v), "init start == end");
	mu_assert_eq (R_VEC_CAPACITY (&v), 0, "init capacity");
	RVecUT32_fini (&v);
	mu_end;
}

static bool test_vec_fini(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	ut32 x;
	for (x = 0; x < 8; x++) {
		RVecUT32_push_back (&v, &x);
	}

	RVecUT32_fini (&v);
	mu_assert_eq (R_VEC_START_ITER (&v), NULL, "fini start");
	mu_assert_eq (R_VEC_END_ITER (&v), NULL, "fini end");

	RVecS vS;
	RVecS_init (&vS);

	for (x = 0; x < 3; x++) {
		float *y = malloc (sizeof (float));
		*y = (float)3.14;
		S s = { .x = x, .y = y };
		RVecS_push_back (&vS, &s);
	}

	RVecS_fini (&vS);

	mu_assert_eq (R_VEC_START_ITER (&vS), NULL, "fini start2");
	mu_assert_eq (R_VEC_END_ITER (&vS), NULL, "fini end2");
	mu_end;
}

static bool test_vec_new(void) {
	RVecUT32 *v = RVecUT32_new ();
	mu_assert_eq (R_VEC_START_ITER (v), NULL, "new start");
	mu_assert_eq (R_VEC_END_ITER (v), NULL, "new end");
	mu_assert_eq (R_VEC_START_ITER (v), R_VEC_END_ITER (v), "new start == end");
	mu_assert_eq (R_VEC_CAPACITY (v), 0, "new capacity");
	RVecUT32_free (v);
	mu_end;
}

static bool test_vec_free(void) {
	RVecUT32 *v = RVecUT32_new ();

	ut32 x;
	for (x = 0; x < 8; x++) {
		RVecUT32_push_back (v, &x);
	}

	RVecUT32_free (v);

	RVecS *vS = RVecS_new ();

	for (x = 0; x < 3; x++) {
		float *y = malloc (sizeof (float));
		*y = (float)3.14;
		S s = { .x = x, .y = y };
		RVecS_push_back (vS, &s);
	}

	RVecS_free (vS);
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

	RVecUT32_fini (&v);
	RVecUT32_free (v2);

	RVecS vS;
	RVecS_init (&vS);

	for (x = 0; x < 10; x++) {
		S s = { .x = x * 2, .y = NULL };
		RVecS_push_back (&vS, &s);
	}

	RVecS *vS2 = RVecS_clone (&vS);
	sum = 0;
	S *s;
	R_VEC_FOREACH (vS2, s) {
		sum += s->x;
	}

	mu_assert_eq (RVecS_length (vS2), 10, "clone length2");
	mu_assert_eq (R_VEC_CAPACITY (vS2), 16, "clone capacity2");
	mu_assert_eq (sum, 90, "clone sum2"); // 0 + 2 + 4 + ...

	RVecS_fini (&vS);
	RVecS_free (vS2);
	mu_end;
}

static bool test_vec_push_back(void) {
	RVecUT32 v;
	RVecUT32_init (&v);
	mu_assert_eq (R_VEC_START_ITER (&v), NULL, "push_back start");
	mu_assert_eq (R_VEC_END_ITER (&v), NULL, "push_back end");
	mu_assert_eq (R_VEC_START_ITER (&v), R_VEC_END_ITER (&v), "push_back start == end");
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

	RVecUT32_fini (&v);
	mu_end;
}

static bool test_vec_emplace_back(void) {
	RVecUT32 v;
	RVecUT32_init (&v);
	mu_assert_eq (R_VEC_START_ITER (&v), NULL, "emplace_back start");
	mu_assert_eq (R_VEC_END_ITER (&v), NULL, "emplace_back end");
	mu_assert_eq (R_VEC_START_ITER (&v), R_VEC_END_ITER (&v), "emplace_back start == end");
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

	RVecUT32_fini (&v);
	mu_end;
}

static bool test_vec_push_front(void) {
	RVecUT32 v;
	RVecUT32_init (&v);
	mu_assert_eq (R_VEC_START_ITER (&v), NULL, "push_front start");
	mu_assert_eq (R_VEC_END_ITER (&v), NULL, "push_front end");
	mu_assert_eq (R_VEC_START_ITER (&v), R_VEC_END_ITER (&v), "push_front start == end");
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

	RVecUT32_fini (&v);
	mu_end;
}

static bool test_vec_emplace_front(void) {
	RVecUT32 v;
	RVecUT32_init (&v);
	mu_assert_eq (R_VEC_START_ITER (&v), NULL, "emplace_front start");
	mu_assert_eq (R_VEC_END_ITER (&v), NULL, "emplace_front end");
	mu_assert_eq (R_VEC_START_ITER (&v), R_VEC_END_ITER (&v), "emplace_front start == end");
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

	RVecUT32_fini (&v);
	mu_end;
}

void copy_S(S *dst, const S *src) {
	dst->x = src->x;
	dst->y = malloc (sizeof (float));
	*dst->y = *src->y;
}

static bool test_vec_append(void) {
	RVecUT32 v1, v2;
	RVecUT32_init (&v1);
	RVecUT32_init (&v2);

	RVecUT32_append (&v1, &v2, NULL);
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

	RVecUT32_append (&v1, &v2, NULL);
	mu_assert_eq (R_VEC_CAPACITY (&v1), 18, "append capacity3");
	mu_assert_eq (RVecUT32_length (&v1), 18, "append length3");
	mu_assert_eq (R_VEC_CAPACITY (&v2), 16, "append capacity4");
	mu_assert_eq (RVecUT32_length (&v2), 10, "append length4");

	RVecUT32_fini (&v1);
	RVecUT32_fini (&v2);

	RVecS v3, v4;
	RVecS_init (&v3);
	RVecS_init (&v4);

	S s = { .x = 0, .y = malloc (sizeof (float)) };
	*s.y = 1.23f;
	RVecS_push_back (&v3, &s);

	for (x = 0; x < 10; x++) {
		S s = { .x = 0, .y = malloc (sizeof (float)) };
		*s.y = 4.56f;
		RVecS_push_back (&v4, &s);
	}

	RVecS_append (&v3, &v4, copy_S);
	mu_assert_neq (RVecS_at (&v3, 2)->y, RVecS_at (&v4, 0)->y, "append copy1");
	mu_assert_neq (RVecS_at (&v3, 3)->y, RVecS_at (&v4, 1)->y, "append copy1");

	RVecS_fini (&v3);
	RVecS_fini (&v4);
	mu_end;
}

static bool test_vec_remove(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	ut32 x;
	for (x = 0; x < 8; x++) {
		RVecUT32_push_back (&v, &x);
	}

	RVecUT32_remove (&v, 0);
	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "remove capacity1");
	mu_assert_eq (RVecUT32_length (&v), 7, "remove length1");
	mu_assert_eq (*RVecUT32_at (&v, 0), 1, "remove at1");
	mu_assert_eq (*RVecUT32_at (&v, 1), 2, "remove at2");

	RVecUT32_remove (&v, 1);
	mu_assert_eq (*RVecUT32_at (&v, 0), 1, "remove at3");
	mu_assert_eq (*RVecUT32_at (&v, 1), 3, "remove at4");
	mu_assert_eq (*RVecUT32_at (&v, 2), 4, "remove at5");

	RVecUT32_fini (&v);
	mu_end;
}

static bool test_vec_pop_front(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	ut32 x;
	for (x = 0; x < 8; x++) {
		RVecUT32_push_back (&v, &x);
	}

	RVecUT32_pop_front (&v);
	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "pop_front capacity1");
	mu_assert_eq (RVecUT32_length (&v), 7, "pop_front length1");
	mu_assert_eq (*RVecUT32_at (&v, 0), 1, "pop_front at1");
	mu_assert_eq (*RVecUT32_at (&v, 1), 2, "pop_front at2");

	RVecUT32_pop_front (&v);
	mu_assert_eq (RVecUT32_length (&v), 6, "pop_front length2");
	mu_assert_eq (*RVecUT32_at (&v, 0), 2, "pop_front at3");
	mu_assert_eq (*RVecUT32_at (&v, 1), 3, "pop_front at4");
	mu_assert_eq (*RVecUT32_at (&v, 2), 4, "pop_front at5");

	RVecUT32_fini (&v);
	mu_end;
}

static bool test_vec_pop_back(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	ut32 x;
	for (x = 0; x < 8; x++) {
		RVecUT32_push_back (&v, &x);
	}

	RVecUT32_pop_back (&v);
	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "pop_back capacity1");
	mu_assert_eq (RVecUT32_length (&v), 7, "pop_back length1");
	mu_assert_eq (*RVecUT32_at (&v, 6), 6, "pop_back at1");
	mu_assert_eq (*RVecUT32_at (&v, 5), 5, "pop_back at2");

	RVecUT32_pop_back (&v);
	mu_assert_eq (RVecUT32_length (&v), 6, "pop_back length2");
	mu_assert_eq (*RVecUT32_at (&v, 5), 5, "pop_back at3");
	mu_assert_eq (*RVecUT32_at (&v, 4), 4, "pop_back at4");

	RVecUT32_fini (&v);
	mu_end;
}


static bool test_vec_erase_back(void) {
	count_S = 0;
	RVecS v;
	RVecS_init (&v);

	// on empty vector
	RVecS_erase_back (&v, v._end);
	mu_assert_eq (R_VEC_CAPACITY (&v), 0, "erase_back capacity1");
	mu_assert_eq (RVecS_length (&v), 0, "erase_back length1");

	ut32 x;
	for (x = 0; x < 8; x++) {
		S s = { .x = x, .y = NULL};
		RVecS_push_back (&v, &s);
	}

	// try removing nothing on non-empty vector
	RVecS_erase_back (&v, v._end);
	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "erase_back capacity2");
	mu_assert_eq (RVecS_length (&v), 8, "erase_back length2");
	mu_assert_eq (RVecS_at (&v, 7)->x, 7, "erase_back at1");
	mu_assert_eq (RVecS_at (&v, 6)->x, 6, "erase_back at2");

	// remove last elems of non-empty vector
	count_S = 0;
	RVecS_erase_back (&v, RVecS_at (&v, 4));
	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "erase_back capacity3");
	mu_assert_eq (RVecS_length (&v), 4, "erase_back length3");
	mu_assert_eq (RVecS_at (&v, 4), NULL, "erase_back at3");
	mu_assert_eq (RVecS_at (&v, 3)->x, 3, "erase_back at4");
	mu_assert_eq (count_S, 4, "erase count");

	RVecS_fini (&v);
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

	RVecUT32_fini (&v1);
	RVecUT32_fini (&v2);
	mu_end;
}

static bool test_vec_clear(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	RVecUT32_clear (&v);
	mu_assert_eq (RVecUT32_length (&v), 0, "clear length1");
	mu_assert_eq (R_VEC_CAPACITY (&v), 0, "clear capacity1");

	ut32 x;
	for (x = 0; x < 3; x++) {
		RVecUT32_push_back (&v, &x);
	}

	mu_assert_eq (RVecUT32_length (&v), 3, "clear length2");
	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "clear capacity2");

	RVecUT32_clear (&v);

	mu_assert_eq (RVecUT32_length (&v), 0, "clear length3");
	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "clear capacity3");

	RVecUT32_clear (&v);
	mu_assert_eq (RVecUT32_length (&v), 0, "clear length4");
	mu_assert_eq (R_VEC_CAPACITY (&v), 8, "clear capacity4");

	count_S = 0;
	RVecS vS;
	RVecS_init (&vS);
	RVecS_clear (&vS);
	mu_assert_eq (count_S, 0, "clear counter1");

	for (x = 0; x < 3; x++) {
		float *y = malloc (sizeof (float));
		*y = (float)3.14;
		S s = { .x = x, .y = y };
		RVecS_push_back (&vS, &s);
	}

	RVecS_clear (&vS);
	mu_assert_eq (count_S, 3, "clear counter2");

	RVecUT32_fini (&v);
	RVecS_fini (&vS);
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

	RVecUT32_clear (&v);

	mu_assert_eq (RVecUT32_length (&v), 0, "clear length3");

	RVecUT32_fini (&v);
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

	RVecUT32_clear (&v);
	mu_assert_eq (R_VEC_CAPACITY (&v), 16, "clear capacity4");

	RVecUT32_fini (&v);
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

	RVecUT32_clear (&v);
	mu_assert_eq (RVecUT32_empty (&v), true, "empty4");

	RVecUT32_fini (&v);
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

	RVecUT32_clear (&v);
	mu_assert_neq (R_VEC_START_ITER (&v), NULL, "start iter4");

	RVecUT32_fini (&v);
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

	RVecUT32_clear (&v);
	mu_assert_neq (R_VEC_END_ITER (&v), NULL, "end iter4");

	RVecUT32_fini (&v);
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

	RVecUT32_clear (&v);
	mu_assert_eq (RVecUT32_at (&v, 0), NULL, "at6");

	RVecUT32_fini (&v);
	mu_end;
}

static bool test_vec_last(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	mu_assert_eq (RVecUT32_last (&v), NULL, "last1");

	ut32 x;
	for (x = 0; x < 3; x++) {
		RVecUT32_push_back (&v, &x);
	}

	mu_assert_neq (RVecUT32_last (&v), NULL, "last2");
	mu_assert_eq (*RVecUT32_last (&v), 2, "last4");

	*RVecUT32_last (&v) = 10;
	mu_assert_eq (*RVecUT32_last (&v), 10, "last5");

	RVecUT32_clear (&v);
	mu_assert_eq (RVecUT32_last (&v), NULL, "last6");

	RVecUT32_fini (&v);
	mu_end;
}

static bool test_vec_find(void) {
	RVecST32 v;
	RVecST32_init (&v);

	st32 x = 0;
	mu_assert_eq (RVecST32_find (&v, &x, find_compare_st32), NULL, "find1");

	for (x = 0; x < 3; x++) {
		RVecST32_push_back (&v, &x);
	}

	x = 0;
	mu_assert_eq (*RVecST32_find (&v, &x, find_compare_st32), 0, "find2");
	x = 1;
	mu_assert_eq (*RVecST32_find (&v, &x, find_compare_st32), 1, "find3");
	x = 2;
	mu_assert_eq (*RVecST32_find (&v, &x, find_compare_st32), 2, "find4");
	x = 3;
	mu_assert_eq (RVecST32_find (&v, &x, find_compare_st32), NULL, "find5");

	RVecST32_clear (&v);
	x = 0;
	mu_assert_eq (RVecST32_find (&v, &x, find_compare_st32), NULL, "find6");

	RVecST32_fini (&v);
	mu_end;
}

static inline int greater_than_ut32(const st32 *a, const void *b_) {
	const ut32 *b = b_;
	return *a > *b;
}

static bool test_vec_find_if_not(void) {
	RVecST32 v;
	RVecST32_init (&v);

	st32 x = 0;
	mu_assert_eq (RVecST32_find_if_not (&v, &x, greater_than_ut32), NULL, "find_if_not1");

	for (x = 0; x < 3; x++) {
		RVecST32_push_back (&v, &x);
	}

	x = 0;
	mu_assert_eq (*RVecST32_find_if_not (&v, &x, greater_than_ut32), 1, "find_if_not2");
	x = 1;
	mu_assert_eq (*RVecST32_find_if_not (&v, &x, greater_than_ut32), 2, "find_if_not3");
	x = 2;
	mu_assert_eq (RVecST32_find_if_not (&v, &x, greater_than_ut32), NULL, "find_if_not4");

	RVecST32_clear (&v);
	x = 0;
	mu_assert_eq (RVecST32_find_if_not (&v, &x, greater_than_ut32), NULL, "find_if_not6");

	RVecST32_fini (&v);
	mu_end;
}

static bool test_vec_find_index(void) {
	RVecST32 v;
	RVecST32_init (&v);

	st32 x = 0;
	mu_assert_eq (RVecST32_find_index (&v, &x, find_compare_st32), UT64_MAX, "find_index1");

	for (x = 0; x < 3; x++) {
		RVecST32_push_back (&v, &x);
	}

	x = 0;
	mu_assert_eq (RVecST32_find_index (&v, &x, find_compare_st32), 0, "find_index2");
	x = 1;
	mu_assert_eq (RVecST32_find_index (&v, &x, find_compare_st32), 1, "find_index3");
	x = 2;
	mu_assert_eq (RVecST32_find_index (&v, &x, find_compare_st32), 2, "find_index4");
	x = 3;
	mu_assert_eq (RVecST32_find_index (&v, &x, find_compare_st32), UT64_MAX, "find_index5");

	RVecST32_clear (&v);
	x = 0;
	mu_assert_eq (RVecST32_find_index (&v, &x, find_compare_st32), UT64_MAX, "find_index6");

	RVecST32_fini (&v);
	mu_end;
}

static bool test_vec_reserve(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	mu_assert_eq (RVecUT32_length (&v), 0, "reserve length1");
	mu_assert_eq (R_VEC_CAPACITY (&v), 0, "reserve capacity1");

	const bool success = RVecUT32_reserve (&v, 12);
	mu_assert_eq (success, true, "reserve success2");
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

	RVecUT32_fini (&v);
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

	RVecUT32_fini (&v);
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

	RVecUT32_fini (&v);
	RVecS_fini (&vS);
	mu_end;
}

static bool test_vec_foreach_prev(void) {
	RVecUT32 v;
	RVecUT32_init (&v);

	ut32 *y;
	ut32 sum = 0;

	// check for crash
	R_VEC_FOREACH_PREV (&v, y) {
		sum += *y;
	}
	ut32 x;
	for (x = 0; x < 10; x++) {
		RVecUT32_push_back (&v, &x);
	}

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

	RVecUT32_fini (&v);
	RVecS_fini (&vS);
	mu_end;
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

	RVecST32_fini (&v);
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

	RVecST32_fini (&v);
	mu_end;
}

static int compare_S(const S *a, const S *b) {
	if (*a->y < *b->y) {
		return -1;
	}
	if (*a->y > *b->y) {
		return 1;
	}
	return 0;
}

static inline int greater_than_st32(const st32 *a, const void *b_) {
	const st32 *b = b_;
	return *a > *b;
}

static bool test_vec_partition(void) {
	RVecST32 v;
	RVecST32_init (&v);

	st32 x = 123;
	RVecST32_push_back (&v, &x);
	x = 47;
	RVecST32_push_back (&v, &x);
	x = 59;
	RVecST32_push_back (&v, &x);
	x = 38;
	RVecST32_push_back (&v, &x);
	x = 250;
	RVecST32_push_back (&v, &x);

	x = 100;
	st32 *pivot = RVecST32_partition (&v, &x, greater_than_st32);
	mu_assert_eq (*RVecST32_at (&v, 0), 123, "partition1");
	mu_assert_eq (*RVecST32_at (&v, 1), 250, "partition2");
	mu_assert_eq (*RVecST32_at (&v, 2), 59, "partition3");
	mu_assert_eq (*RVecST32_at (&v, 3), 38, "partition4");
	mu_assert_eq (*RVecST32_at (&v, 4), 47, "partition5");
	mu_assert_eq (*pivot, 59, "partition6");

	x = 200;
	pivot = RVecST32_partition (&v, &x, greater_than_st32);
	mu_assert_eq (*RVecST32_at (&v, 0), 250, "partition7");
	mu_assert_eq (*RVecST32_at (&v, 1), 123, "partition8");
	mu_assert_eq (*RVecST32_at (&v, 2), 59, "partition9");
	mu_assert_eq (*RVecST32_at (&v, 3), 38, "partition10");
	mu_assert_eq (*RVecST32_at (&v, 4), 47, "partition11");
	mu_assert_eq (*pivot, 123, "partition12");

	x = 300;
	pivot = RVecST32_partition (&v, &x, greater_than_st32);
	mu_assert_eq (*RVecST32_at (&v, 0), 250, "partition13");
	mu_assert_eq (*RVecST32_at (&v, 1), 123, "partition14");
	mu_assert_eq (*RVecST32_at (&v, 2), 59, "partition15");
	mu_assert_eq (*RVecST32_at (&v, 3), 38, "partition16");
	mu_assert_eq (*RVecST32_at (&v, 4), 47, "partition17");
	mu_assert_eq (pivot, v._start, "partition18");

	RVecST32_fini (&v);
	mu_end;
}

static bool test_vec_sort(void) {
	RVecST32 v;
	RVecST32_init (&v);

	st32 x = 123;
	RVecST32_push_back (&v, &x);
	x = 47;
	RVecST32_push_back (&v, &x);
	x = 59;
	RVecST32_push_back (&v, &x);
	x = 38;
	RVecST32_push_back (&v, &x);
	x = 250;
	RVecST32_push_back (&v, &x);

	RVecST32_sort (&v, compare_st32);
	mu_assert_eq (*RVecST32_at (&v, 0), 38, "sort1");
	mu_assert_eq (*RVecST32_at (&v, 1), 47, "sort2");
	mu_assert_eq (*RVecST32_at (&v, 2), 59, "sort3");
	mu_assert_eq (*RVecST32_at (&v, 3), 123, "sort4");
	mu_assert_eq (*RVecST32_at (&v, 4), 250, "sort5");

	RVecST32_fini (&v);


	RVecS vS;
	RVecS_init (&vS);

	S s = { 0 };
	float *y;

	y = malloc (sizeof (float));
	*y = 3.14f;
	s.y = y;
	RVecS_push_back (&vS, &s);
	y = malloc (sizeof (float));
	*y = 1.42f;
	s.y = y;
	RVecS_push_back (&vS, &s);
	y = malloc (sizeof (float));
	*y = 9000.1f;
	s.y = y;
	RVecS_push_back (&vS, &s);
	y = malloc (sizeof (float));
	*y = 13.37f;
	s.y = y;
	RVecS_push_back (&vS, &s);

	RVecS_sort (&vS, compare_S);
	mu_assert_eq (*RVecS_at (&vS, 0)->y, 1.42, "sort6");
	mu_assert_eq (*RVecS_at (&vS, 1)->y, 3.14, "sort7");
	mu_assert_eq (*RVecS_at (&vS, 2)->y, 13.37, "sort8");
	mu_assert_eq (*RVecS_at (&vS, 3)->y, 9000.1, "sort9");

	RVecS_fini (&vS);
	mu_end;
}

static bool test_vec_uniq(void) {
	RVecST32 v;
	RVecST32_init (&v);

	mu_assert_eq (RVecST32_length (&v), 0, "uniq1");
	// Always need to sort before calling uniq
	RVecST32_sort (&v, compare_st32);
	RVecST32_uniq (&v, compare_st32);
	mu_assert_eq (RVecST32_length (&v), 0, "uniq2");

	st32 x = 123;
	RVecST32_push_back (&v, &x);
	x = 47;
	RVecST32_push_back (&v, &x);
	RVecST32_push_back (&v, &x);
	x = 38;
	RVecST32_push_back (&v, &x);
	x = 250;
	RVecST32_push_back (&v, &x);
	RVecST32_push_back (&v, &x);
	x = 47;
	RVecST32_push_back (&v, &x);

	mu_assert_eq (RVecST32_length (&v), 7, "uniq3");

	RVecST32_sort (&v, compare_st32);
	RVecST32_uniq (&v, compare_st32);
	mu_assert_eq (RVecST32_length (&v), 4, "uniq4");
	mu_assert_eq (*RVecST32_at (&v, 0), 38, "uniq5");
	mu_assert_eq (*RVecST32_at (&v, 1), 47, "uniq6");
	mu_assert_eq (*RVecST32_at (&v, 2), 123, "uniq7");
	mu_assert_eq (*RVecST32_at (&v, 3), 250, "uniq8");

	RVecST32_fini (&v);

	RVecS vS;
	RVecS_init (&vS);

	float data[] = { 3.14f, 1.42f, 9000.1f, 9000.1f, 3.14f, 13.37f, 13.37f, 13.37f };
	for (x = 0; x < 8; x++) {
		S s = { .x = 0, .y = malloc (sizeof (float)) };
		*s.y = data[x];
		RVecS_push_back (&vS, &s);
	}

	mu_assert_eq (RVecS_length (&vS), 8, "uniq9");
	RVecS_sort (&vS, compare_S);
	RVecS_uniq (&vS, compare_S);
	mu_assert_eq (RVecS_length (&vS), 4, "uniq10");
	mu_assert_eq (*RVecS_at (&vS, 0)->y, 1.42, "uniq11");
	mu_assert_eq (*RVecS_at (&vS, 1)->y, 3.14, "uniq12");
	mu_assert_eq (*RVecS_at (&vS, 2)->y, 13.37, "u niq13");
	mu_assert_eq (*RVecS_at (&vS, 3)->y, 9000.1, "uniq14");

	RVecS_fini (&vS);
	mu_end;
}

static inline void fini_buf(char** buf) {
	if (buf) {
		free (*buf);
	}
}

// This is mainly to test there are no warnings when generating code for a vec containing pointers.
R_VEC_TYPE_WITH_FINI(RVecBuf, char*, fini_buf);

static int find_compare_buf(char *const *const buf, void const *user) {
	char *const *const ptr = user;
	if (*buf == *ptr) {
		return 0;
	}
	return 1;
}

static bool test_vec_with_pointers(void) {
	RVecBuf buf;
	RVecBuf_init (&buf);

	char *ptr = NULL;
	mu_assert_eq (RVecBuf_find (&buf, &ptr, find_compare_buf), NULL, "pointer find1");

	ut32 x = 0;
	for (x = 0; x < 3; x++) {
		ptr = malloc (8);
		RVecBuf_push_back (&buf, &ptr);
	}

	ptr = malloc (8);
	RVecBuf_push_back (&buf, &ptr);

	char **ptr2 = RVecBuf_at (&buf, 3);
	mu_assert_eq (RVecBuf_find (&buf, &ptr, find_compare_buf), ptr2, "pointer find2");

	RVecBuf_fini (&buf);
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
	mu_run_test (test_vec_erase_back);
	mu_run_test (test_vec_swap);
	mu_run_test (test_vec_clear);
	mu_run_test (test_vec_length);
	mu_run_test (test_vec_capacity);
	mu_run_test (test_vec_empty);
	mu_run_test (test_vec_start_iter);
	mu_run_test (test_vec_end_iter);
	mu_run_test (test_vec_at);
	mu_run_test (test_vec_last);
	mu_run_test (test_vec_find);
	mu_run_test (test_vec_find_if_not);
	mu_run_test (test_vec_find_index);
	mu_run_test (test_vec_reserve);
	mu_run_test (test_vec_shrink_to_fit);
	mu_run_test (test_vec_foreach);
	mu_run_test (test_vec_foreach_prev);
	mu_run_test (test_vec_lower_bound);
	mu_run_test (test_vec_upper_bound);
	mu_run_test (test_vec_partition);
	mu_run_test (test_vec_sort);
	mu_run_test (test_vec_uniq);
	mu_run_test (test_vec_with_pointers);

	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
