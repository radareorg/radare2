#include <r_util.h>
#include <r_vector.h>
#include "minunit.h"

// allocates a vector of len ut32 values from 0 to len
// with capacity len + padding
static bool _init_test_vector(RVector *v, size_t len, size_t padding, RVectorFree free, void *free_user) {
	r_vector_init (v, sizeof (ut32), free, free_user);
	r_vector_reserve (v, len + padding);

	ut32 i;
	for (i = 0; i < len; i++) {
		r_vector_push (v, &i);
	}

	return v->len == len && v->capacity == len + padding;
}

#define init_test_vector(v, len, padding, free, free_user) { \
	bool _r = _init_test_vector((v), (len), (padding), (free), (free_user)); \
	mu_assert ("init_test_vector", _r); \
}

// allocates a pvector of len pointers to ut32 values from 0 to len
// with capacity len + padding
static bool _init_test_pvector(RPVector *v, size_t len, size_t padding) {
	r_pvector_init (v, free);
	r_pvector_reserve (v, len + padding);

	ut32 i;
	for (i = 0; i < len; i++) {
		ut32 *e = malloc (sizeof (ut32));
		*e = i;
		r_pvector_push (v, e);
	}

	return v->v.len == len && v->v.capacity == len + padding;
}

#define init_test_pvector(v, len, padding) { \
	bool _r = _init_test_pvector((v), (len), (padding)); \
	mu_assert ("init_test_pvector", _r); \
}

// allocates a pvector of len pointers with values from 0 to len
// with capacity len + padding
static bool _init_test_pvector2(RPVector *v, size_t len, size_t padding) {
	r_pvector_init (v, NULL);
	r_pvector_reserve (v, len + padding);

	int i;
	for (i = 0; (size_t)i < len; i++) {
		r_pvector_push (v, (void *)((size_t)i));
	}
	
	return v->v.len == len && v->v.capacity == len + padding;
}

#define init_test_pvector2(v, len, padding) { \
	bool _r = _init_test_pvector2((v), (len), (padding)); \
	mu_assert ("init_test_pvector2", _r); \
}

static bool test_vector_fini(void) {
	RVector v;
	r_vector_init (&v, sizeof (void *), NULL, free);
	r_vector_push (&v, &v);
	mu_assert_eq (v.elem_size, sizeof (void *), "init elem_size");
	mu_assert_eq (v.len, 1, "init len");
	mu_assert_notnull (v.a, "init a");
	mu_assert_null (v.free, "init free");
	mu_assert_eq (v.free_user, (void*)free, "init free_user");
	r_vector_clear (&v);
	mu_assert_eq (v.elem_size, sizeof (void *), "init elem_size");
	mu_assert_eq (v.len, 0, "init len");
	mu_assert_null (v.a, "init a");
	mu_assert_eq (v.capacity, 0, "init capacity");
	mu_assert_null (v.free, "init free");
	mu_assert_eq (v.free_user, (void*)free, "init free_user");
	r_vector_fini (&v);
	mu_assert_eq (v.elem_size, sizeof (void *), "init elem_size");
	mu_assert_eq (v.len, 0, "init len");
	mu_assert_null (v.a, "init a");
	mu_assert_eq (v.capacity, 0, "init capacity");
	mu_assert_null (v.free, "init free");
	mu_assert_null (v.free_user, "init free_user");
	mu_end;
}


static bool test_vector_init(void) {
	RVector v;
	r_vector_init (&v, 42, (void *)1337, (void *)42);
	mu_assert_eq (v.elem_size, 42UL, "init elem_size");
	mu_assert_eq (v.len, 0UL, "init len");
	mu_assert_null (v.a, "init a");
	mu_assert_eq (v.capacity, 0UL, "init capacity");
	mu_assert_eq (v.free, (void *)1337, "init free");
	mu_assert_eq (v.free_user, (void *)42, "init free_user");
	mu_end;
}

static bool test_vector_new(void) {
	RVector *v = r_vector_new (42, (void *)1337, (void *)42);
	mu_assert ("new", v);
	mu_assert_eq (v->elem_size, 42UL, "new elem_size");
	mu_assert_eq (v->len, 0UL, "new len");
	mu_assert_null (v->a, "new a");
	mu_assert_eq (v->capacity, 0UL, "new capacity");
	mu_assert_eq (v->free, (void *)1337, "init free");
	mu_assert_eq (v->free_user, (void *)42, "init free_user");
	free (v);
	mu_end;
}

#define FREE_TEST_COUNT 10

static void elem_free_test(void *e, void *user) {
	ut32 e_val = *((ut32 *)e);
	int *acc = (int *)user;
	if (e_val > FREE_TEST_COUNT) {
		e_val = FREE_TEST_COUNT;
	}
	acc[e_val]++;
}

static bool test_vector_clear(void) {
	RVector v;
	int acc[FREE_TEST_COUNT+1] = {0};
	init_test_vector (&v, FREE_TEST_COUNT, 0, elem_free_test, acc);
	r_vector_clear (&v);

	// see test_vector_free

	ut32 i;
	for (i = 0; i < FREE_TEST_COUNT; i++) {
		mu_assert_eq (acc[i], 1, "free individual elements");
	}

	mu_assert_eq (acc[FREE_TEST_COUNT], 0, "invalid free calls");
	mu_end;
}

static bool test_vector_free(void) {
	RVector *v = r_vector_new (4, NULL, NULL);
	int acc[FREE_TEST_COUNT+1] = {0};
	init_test_vector (v, FREE_TEST_COUNT, 0, elem_free_test, acc);

	r_vector_free (v);

	// elem_free_test does acc[i]++ for element value i
	// => acc[0] through acc[FREE_TEST_COUNT-1] == 1
	// acc[FREE_TEST_COUNT] is for potentially invalid calls of elem_free_test

	ut32 i;
	for (i=0; i<FREE_TEST_COUNT; i++) {
		mu_assert_eq (acc[i], 1, "free individual elements");
	}

	mu_assert_eq (acc[FREE_TEST_COUNT], 0, "invalid free calls");
	mu_end;
}


static bool test_vector_clone(void) {
	RVector v;
	init_test_vector (&v, 5, 0, NULL, NULL);
	RVector *v1 = r_vector_clone (&v);
	r_vector_clear (&v);
	mu_assert ("r_vector_clone", v1);
	mu_assert_eq (v1->len, 5UL, "r_vector_clone => len");
	mu_assert_eq (v1->capacity, 5UL, "r_vector_clone => capacity");
	ut32 i;
	for (i = 0; i < 5; i++) {
		mu_assert_eq (*((ut32 *)r_vector_index_ptr (v1, i)), i, "r_vector_clone => content");
	}
	r_vector_free (v1);


	init_test_vector (&v, 5, 5, NULL, NULL);
	v1 = r_vector_clone (&v);
	r_vector_clear (&v);
	mu_assert ("r_vector_clone (+capacity)", v1);
	mu_assert_eq (v1->len, 5UL, "r_vector_clone (+capacity) => len");
	mu_assert_eq (v1->capacity, 10UL, "r_vector_clone (+capacity) => capacity");
	for (i = 0; i < 5; i++) {
		mu_assert_eq (*((ut32 *)r_vector_index_ptr (v1, i)), i, "r_vector_clone => content");
	}
	// write over whole capacity to trigger potential errors with valgrind or asan
	for (i = 0; i < 10; i++) {
		*((ut32 *)r_vector_index_ptr (v1, i)) = 1337;
	}
	r_vector_free (v1);

	mu_end;
}

static bool test_vector_empty(void) {
	RVector v;
	r_vector_init (&v, 1, NULL, NULL);
	bool empty = r_vector_empty (&v);
	mu_assert_eq (empty, true, "r_vector_init => r_vector_empty");
	uint8_t e = 0;
	r_vector_push (&v, &e);
	empty = r_vector_empty (&v);
	mu_assert_eq (empty, false, "r_vector_push => !r_vector_empty");
	r_vector_pop (&v, &e);
	empty = r_vector_empty (&v);
	mu_assert_eq (empty, true, "r_vector_pop => r_vector_empty");
	r_vector_clear (&v);

	RVector *vp = r_vector_new (42, NULL, NULL);
	empty = r_vector_empty (&v);
	mu_assert_eq (empty, true, "r_vector_new => r_vector_empty");
	r_vector_free (vp);

	mu_end;
}

static bool test_vector_remove_at(void) {
	RVector v;
	init_test_vector (&v, 5, 0, NULL, NULL);

	ut32 e;
	r_vector_remove_at (&v, 2, &e);
	mu_assert_eq (e, 2, "r_vector_remove_at => into");
	mu_assert_eq (v.len, 4UL, "r_vector_remove_at => len");

	mu_assert_eq (((ut32 *)v.a)[0], 0, "r_vector_remove_at => remaining elements");
	mu_assert_eq (((ut32 *)v.a)[1], 1, "r_vector_remove_at => remaining elements");
	mu_assert_eq (((ut32 *)v.a)[2], 3, "r_vector_remove_at => remaining elements");
	mu_assert_eq (((ut32 *)v.a)[3], 4, "r_vector_remove_at => remaining elements");

	r_vector_remove_at (&v, 3, &e);
	mu_assert_eq (e, 4, "r_vector_remove_at (end) => into");
	mu_assert_eq (v.len, 3UL, "r_vector_remove_at (end) => len");

	mu_assert_eq (((ut32 *)v.a)[0], 0, "r_vector_remove_at (end) => remaining elements");
	mu_assert_eq (((ut32 *)v.a)[1], 1, "r_vector_remove_at (end) => remaining elements");
	mu_assert_eq (((ut32 *)v.a)[2], 3, "r_vector_remove_at (end) => remaining elements");

	r_vector_clear (&v);

	mu_end;
}

static bool test_vector_insert(void) {
	RVector v;

	init_test_vector (&v, 4, 2, NULL, NULL);
	ut32 e = 1337;
	e = *((ut32 *)r_vector_insert (&v, 1, &e));
	mu_assert_eq (v.len, 5UL, "r_vector_insert => len");
	mu_assert_eq (e, 1337, "r_vector_insert => content at returned ptr");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 0)), 0, "r_vector_insert => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 1)), 1337, "r_vector_insert => content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 2)), 1, "r_vector_insert => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 3)), 2, "r_vector_insert => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 4)), 3, "r_vector_insert => old content");
	r_vector_clear (&v);

	init_test_vector (&v, 4, 2, NULL, NULL);
	ut32 *p = r_vector_insert (&v, 1, NULL);
	*p = 1337;
	mu_assert_eq (v.len, 5UL, "r_vector_insert (null) => len");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 0)), 0, "r_vector_insert (null) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 1)), 1337, "r_vector_insert (null) => content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 2)), 1, "r_vector_insert (null) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 3)), 2, "r_vector_insert (null) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 4)), 3, "r_vector_insert (null) => old content");
	r_vector_clear (&v);

	init_test_vector (&v, 4, 0, NULL, NULL);
	e = 1337;
	e = *((ut32 *)r_vector_insert (&v, 1, &e));
	mu_assert ("r_vector_insert (resize) => capacity", v.capacity >= 5);
	mu_assert_eq (v.len, 5UL, "r_vector_insert => len");
	mu_assert_eq (e, 1337, "r_vector_insert => content at returned ptr");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 0)), 0, "r_vector_insert (resize) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 1)), 1337, "r_vector_insert (resize) => content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 2)), 1, "r_vector_insert (resize) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 3)), 2, "r_vector_insert (resize) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 4)), 3, "r_vector_insert (resize) => old content");
	r_vector_clear (&v);

	init_test_vector (&v, 4, 2, NULL, NULL);
	e = 1337;
	e = *((ut32 *)r_vector_insert (&v, 4, &e));
	mu_assert_eq (v.len, 5UL, "r_vector_insert (end) => len");
	mu_assert_eq (e, 1337, "r_vector_insert (end) => content at returned ptr");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 0)), 0, "r_vector_insert (end) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 1)), 1, "r_vector_insert (end) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 2)), 2, "r_vector_insert (end) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 3)), 3, "r_vector_insert (end) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 4)), 1337, "r_vector_insert (end) => content");
	r_vector_clear (&v);

	init_test_vector (&v, 4, 0, NULL, NULL);
	e = 1337;
	e = *((ut32 *)r_vector_insert (&v, 4, &e));
	mu_assert ("r_vector_insert (resize) => capacity", v.capacity >= 5);
	mu_assert_eq (v.len, 5UL, "r_vector_insert (end) => len");
	mu_assert_eq (e, 1337, "r_vector_insert (end) => content at returned ptr");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 0)), 0, "r_vector_insert (end, resize) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 1)), 1, "r_vector_insert (end, resize) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 2)), 2, "r_vector_insert (end, resize) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 3)), 3, "r_vector_insert (end, resize) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 4)), 1337, "r_vector_insert (end, resize) => content");
	r_vector_clear (&v);

	mu_end;
}

static bool test_vector_insert_range(void) {
	RVector v;
	ut32 range[] = { 0xC0, 0xFF, 0xEE };

	r_vector_init (&v, 4, NULL, NULL);
	ut32 *p = (ut32 *)r_vector_insert_range (&v, 0, range, 3);
	mu_assert_eq (p, r_vector_index_ptr (&v, 0), "r_vector_insert_range (empty) returned ptr");
	mu_assert_eq (v.len, 3UL, "r_vector_insert_range (empty) => len");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 0)), 0xC0, "r_vector_insert_range (empty) => new content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 1)), 0xFF, "r_vector_insert_range (empty) => new content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 2)), 0xEE, "r_vector_insert_range (empty) => new content");
	r_vector_clear (&v);

	init_test_vector (&v, 3, 3, NULL, NULL);
	p = (ut32 *)r_vector_insert_range (&v, 2, range, 3);
	mu_assert_eq (p, r_vector_index_ptr (&v, 2), "r_vector_insert_range returned ptr");
	mu_assert_eq (v.len, 6UL, "r_vector_insert_range => len");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 0)), 0, "r_vector_insert_range => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 1)), 1, "r_vector_insert_range => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 2)), 0xC0, "r_vector_insert_range => new content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 3)), 0xFF, "r_vector_insert_range => new content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 4)), 0xEE, "r_vector_insert_range => new content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 5)), 2, "r_vector_insert_range => old content");
	r_vector_clear (&v);

	init_test_vector (&v, 3, 3, NULL, NULL);
	p = (ut32 *)r_vector_insert_range (&v, 2, NULL, 3);
	mu_assert_eq (p, r_vector_index_ptr (&v, 2), "r_vector_insert_range (null) returned ptr");
	mu_assert_eq (v.len, 6UL, "r_vector_insert_range (null) => len");
	p[0] = 0xC0;
	p[1] = 0xFF;
	p[2] = 0xEE;
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 0)), 0, "r_vector_insert_range (null) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 1)), 1, "r_vector_insert_range (null) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 2)), 0xC0, "r_vector_insert_range (null) => new content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 3)), 0xFF, "r_vector_insert_range (null) => new content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 4)), 0xEE, "r_vector_insert_range (null) => new content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 5)), 2, "r_vector_insert_range (null) => old content");
	r_vector_clear (&v);

	init_test_vector (&v, 3, 3, NULL, NULL);
	p = (ut32 *)r_vector_insert_range (&v, 3, range, 3);
	mu_assert_eq (p, r_vector_index_ptr (&v, 3), "r_vector_insert_range (end) returned ptr");
	mu_assert_eq (v.len, 6UL, "r_vector_insert_range (end) => len");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 0)), 0, "r_vector_insert_range (end) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 1)), 1, "r_vector_insert_range (end) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 2)), 2, "r_vector_insert_range (end) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 3)), 0xC0, "r_vector_insert_range (end) => new content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 4)), 0xFF, "r_vector_insert_range (end) => new content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 5)), 0xEE, "r_vector_insert_range (end) => new content");
	r_vector_clear (&v);

	init_test_vector (&v, 3, 0, NULL, NULL);
	p = (ut32 *)r_vector_insert_range (&v, 2, range, 3);
	mu_assert_eq (p, r_vector_index_ptr (&v, 2), "r_vector_insert_range (resize) returned ptr");
	mu_assert_eq (v.len, 6UL, "r_vector_insert_range (resize) => len");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 0)), 0, "r_vector_insert_range (resize) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 1)), 1, "r_vector_insert_range (resize) => old content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 2)), 0xC0, "r_vector_insert_range (resize) => new content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 3)), 0xFF, "r_vector_insert_range (resize) => new content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 4)), 0xEE, "r_vector_insert_range (resize) => new content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 5)), 2, "r_vector_insert_range (resize) => old content");
	r_vector_clear (&v);

	mu_end;
}

static bool test_vector_pop(void) {
	RVector v;
	init_test_vector (&v, 3, 0, NULL, NULL);

	ut32 e;
	r_vector_pop (&v, &e);
	mu_assert_eq (e, 2, "r_vector_pop into");
	mu_assert_eq (v.len, 2UL, "r_vector_pop => len");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 0)), 0, "r_vector_pop => remaining content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 1)), 1, "r_vector_pop => remaining content");

	r_vector_pop (&v, &e);
	mu_assert_eq (e, 1, "r_vector_pop into");
	mu_assert_eq (v.len, 1UL, "r_vector_pop => len");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 0)), 0, "r_vector_pop => remaining content");

	r_vector_pop (&v, &e);
	mu_assert_eq (e, 0, "r_vector_pop (last) into");
	mu_assert_eq (v.len, 0UL, "r_vector_pop (last) => len");

	r_vector_clear (&v);

	mu_end;
}

static bool test_vector_pop_front(void) {
	RVector v;
	init_test_vector (&v, 3, 0, NULL, NULL);

	ut32 e;
	r_vector_pop_front (&v, &e);
	mu_assert_eq (e, 0, "r_vector_pop_front into");
	mu_assert_eq (v.len, 2UL, "r_vector_pop_front => len");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 0)), 1, "r_vector_pop_front => remaining content");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 1)), 2, "r_vector_pop_front => remaining content");

	r_vector_pop_front (&v, &e);
	mu_assert_eq (e, 1, "r_vector_pop_front into");
	mu_assert_eq (v.len, 1UL, "r_vector_pop_front => len");
	mu_assert_eq (*((ut32 *)r_vector_index_ptr (&v, 0)), 2, "r_vector_pop_front => remaining content");

	r_vector_pop_front (&v, &e);
	mu_assert_eq (e, 2, "r_vector_pop_front (last) into");
	mu_assert_eq (v.len, 0UL, "r_vector_pop_front (last) => len");

	r_vector_clear (&v);

	mu_end;
}

static bool test_vector_push(void) {
	RVector v;
	r_vector_init (&v, 4, NULL, NULL);

	ut32 *p = r_vector_push (&v, NULL);
	*p = 1337;
	mu_assert_eq (v.len, 1UL, "r_vector_push (null, empty, assign) => len == 1");
	ut32 e = *((ut32 *)r_vector_index_ptr (&v, 0));
	mu_assert_eq (e, 1337, "r_vector_push (null, empty, assign) => content");

	r_vector_clear (&v);


	r_vector_init (&v, 4, NULL, NULL);

	e = 1337;
	e = *((ut32 *)r_vector_push (&v, &e));
	mu_assert_eq (v.len, 1UL, "r_vector_push (empty) => len == 1");
	mu_assert_eq (e, 1337, "r_vector_push (empty) => content at returned ptr");
	e = *((ut32 *)r_vector_index_ptr (&v, 0));
	mu_assert_eq (e, 1337, "r_vector_push (empty) => content");

	e = 0xDEAD;
	e = *((ut32 *)r_vector_push (&v, &e));
	mu_assert_eq (v.len, 2UL, "r_vector_push => len == 2");
	mu_assert_eq (e, 0xDEAD, "r_vector_push (empty) => content at returned ptr");
	e = *((ut32 *)r_vector_index_ptr (&v, 0));
	mu_assert_eq (e, 1337, "r_vector_push => old content");
	e = *((ut32 *)r_vector_index_ptr (&v, 1));
	mu_assert_eq (e, 0xDEAD, "r_vector_push => content");

	e = 0xBEEF;
	e = *((ut32 *)r_vector_push (&v, &e));
	mu_assert_eq (v.len, 3UL, "r_vector_push => len == 3");
	mu_assert_eq (e, 0xBEEF, "r_vector_push (empty) => content at returned ptr");
	e = *((ut32 *)r_vector_index_ptr (&v, 0));
	mu_assert_eq (e, 1337, "r_vector_push => old content");
	e = *((ut32 *)r_vector_index_ptr (&v, 1));
	mu_assert_eq (e, 0xDEAD, "r_vector_push => old content");
	e = *((ut32 *)r_vector_index_ptr (&v, 2));
	mu_assert_eq (e, 0xBEEF, "r_vector_push => content");

	r_vector_clear (&v);


	init_test_vector (&v, 5, 0, NULL, NULL);
	e = 1337;
	e = *((ut32 *)r_vector_push (&v, &e));
	mu_assert ("r_vector_push (resize) => capacity", v.capacity >= 6);
	mu_assert_eq (v.len, 6UL, "r_vector_push (resize) => len");
	mu_assert_eq (e, 1337, "r_vector_push (empty) => content at returned ptr");

	size_t i;
	for (i = 0; i < v.len - 1; i++) {
		e = *((ut32 *)r_vector_index_ptr (&v, i));
		mu_assert_eq (e, (ut32)i, "r_vector_push (resize) => old content");
	}
	e = *((ut32 *)r_vector_index_ptr (&v, 5));
	mu_assert_eq (e, 1337, "r_vector_push (resize) => content");

	r_vector_clear (&v);

	mu_end;
}

static bool test_vector_push_front(void) {
	RVector v;
	r_vector_init (&v, 4, NULL, NULL);

	ut32 *p = r_vector_push_front (&v, NULL);
	*p = 1337;
	mu_assert_eq (v.len, 1UL, "r_vector_push_front (null, empty, assign) => len == 1");
	ut32 e = *((ut32 *)r_vector_index_ptr (&v, 0));
	mu_assert_eq (e, 1337, "r_vector_push_front (null, empty, assign) => content");

	r_vector_clear (&v);

	r_vector_init (&v, 4, NULL, NULL);

	e = 1337;
	e = *((ut32 *)r_vector_push_front (&v, &e));
	mu_assert_eq (v.len, 1UL, "r_vector_push_front (empty) => len == 1");
	mu_assert_eq (e, 1337, "r_vector_push_front (empty) => content at returned ptr");
	e = *((ut32 *)r_vector_index_ptr (&v, 0));
	mu_assert_eq (e, 1337, "r_vector_push (empty) => content");

	e = 0xDEAD;
	e = *((ut32 *)r_vector_push_front (&v, &e));
	mu_assert_eq (v.len, 2UL, "r_vector_push_front => len == 2");
	mu_assert_eq (e, 0xDEAD, "r_vector_push_front (empty) => content at returned ptr");
	e = *((ut32 *)r_vector_index_ptr (&v, 0));
	mu_assert_eq (e, 0xDEAD, "r_vector_push_front => content");
	e = *((ut32 *)r_vector_index_ptr (&v, 1));
	mu_assert_eq (e, 1337, "r_vector_push_front => old content");

	e = 0xBEEF;
	e = *((ut32 *)r_vector_push_front (&v, &e));
	mu_assert_eq (v.len, 3UL, "r_vector_push_front => len == 3");
	mu_assert_eq (e, 0xBEEF, "r_vector_push_front (empty) => content at returned ptr");
	e = *((ut32 *)r_vector_index_ptr (&v, 0));
	mu_assert_eq (e, 0xBEEF, "r_vector_push_front => content");
	e = *((ut32 *)r_vector_index_ptr (&v, 1));
	mu_assert_eq (e, 0xDEAD, "r_vector_push_front => old content");
	e = *((ut32 *)r_vector_index_ptr (&v, 2));
	mu_assert_eq (e, 1337, "r_vector_push_front => old content");

	r_vector_clear (&v);


	init_test_vector (&v, 5, 0, NULL, NULL);
	e = 1337;
	e = *((ut32 *)r_vector_push_front (&v, &e));
	mu_assert ("r_vector_push_front (resize) => capacity", v.capacity >= 6);
	mu_assert_eq (v.len, 6UL, "r_vector_push_front (resize) => len");
	mu_assert_eq (e, 1337, "r_vector_push_front (empty) => content at returned ptr");

	size_t i;
	for (i = 1; i < v.len; i++) {
		e = *((ut32 *)r_vector_index_ptr (&v, i));
		mu_assert_eq (e, (ut32)i - 1, "r_vector_push (resize) => old content");
	}
	e = *((ut32 *)r_vector_index_ptr (&v, 0));
	mu_assert_eq (e, 1337, "r_vector_push (resize) => content");

	r_vector_clear (&v);

	mu_end;
}

static bool test_vector_reserve(void) {
	RVector v;
	r_vector_init (&v, 4, NULL, NULL);

	r_vector_reserve (&v, 42);
	mu_assert_eq (v.capacity, 42UL, "r_vector_reserve (empty) => capacity");
	mu_assert ("r_vector_reserve (empty) => a", v.a);
	size_t i;
	for (i = 0; i < v.capacity; i++) {
		*((ut32 *)r_vector_index_ptr (&v, i)) = 1337;
	}
	v.len = 20;

	r_vector_reserve (&v, 100);
	mu_assert_eq (v.capacity, 100UL, "r_vector_reserve => capacity");
	mu_assert ("r_vector_reserve => a", v.a);
	for (i = 0; i < v.capacity; i++) {
		*((ut32 *)r_vector_index_ptr (&v, i)) = 1337;
	}

	r_vector_clear (&v);

	mu_end;
}

static bool test_vector_shrink(void) {
	RVector v;
	init_test_vector (&v, 5, 5, NULL, NULL);
	void *a = r_vector_shrink (&v);
	mu_assert_eq (a, v.a, "r_vector_shrink ret");
	mu_assert_eq (v.len, 5UL, "r_vector_shrink => len");
	mu_assert_eq (v.capacity, 5UL, "r_vector_shrink => capacity");
	r_vector_clear (&v);

	init_test_vector (&v, 5, 0, NULL, NULL);
	a = r_vector_shrink (&v);
	mu_assert_eq (a, v.a, "r_vector_shrink (already minimal) ret");
	mu_assert_eq (v.len, 5UL, "r_vector_shrink (already minimal) => len");
	mu_assert_eq (v.capacity, 5UL, "r_vector_shrink (already minimal) => capacity");
	r_vector_clear (&v);

	mu_end;
}

static bool test_vector_foreach(void) {
	RVector v;
	init_test_vector (&v, 5, 5, NULL, NULL);

	int i = 1;
	ut32 *it;
	int acc[5] = {0};
	r_vector_foreach (&v, it) {
		mu_assert_eq (acc[*it], 0, "unset acc element");
		acc[*it] = i++;
	}

	for (i = 0; i < 5; i++) {
		mu_assert_eq (acc[i], i + 1, "acc");
	}

	r_vector_clear (&v);

	mu_end;
}

static bool test_vector_lower_bound(void) {
	RVector v;
	r_vector_init (&v, sizeof (st64), NULL, NULL);
	st64 a[] = {0, 2, 4, 6, 8};
	r_vector_insert_range (&v, 0, a, 5);

	size_t l;
#define CMP(x, y) x - (*(st64 *)y)
	r_vector_lower_bound (&v, 3, l, CMP);
	mu_assert_eq (l, 2, "lower_bound");
	r_vector_lower_bound (&v, -1, l, CMP);
	mu_assert_eq (l, 0, "lower_bound");
	r_vector_lower_bound (&v, 0, l, CMP);
	mu_assert_eq (l, 0, "lower_bound");
	r_vector_lower_bound (&v, 2, l, CMP);
	mu_assert_eq (l, 1, "lower_bound");
	r_vector_lower_bound (&v, 42, l, CMP);
	mu_assert_eq (l, 5, "lower_bound");
#undef CMP
	r_vector_clear (&v);
	mu_end;
}

static bool test_pvector_init(void) {
	RPVector v;
	r_pvector_init (&v, (void *)1337);
	mu_assert_eq (v.v.elem_size, sizeof (void *), "elem_size");
	mu_assert_eq (v.v.len, 0UL, "len");
	mu_assert_null (v.v.a, "a");
	mu_assert_eq (v.v.capacity, 0UL, "capacity");
	mu_assert_eq (v.v.free_user, (void *)1337, "free");
	mu_end;
}

static bool test_pvector_new(void) {
	RPVector *v = r_pvector_new ((void *)1337);
	mu_assert_eq (v->v.elem_size, sizeof (void *), "elem_size");
	mu_assert_eq (v->v.len, 0UL, "len");
	mu_assert_null (v->v.a, "a");
	mu_assert_eq (v->v.capacity, 0UL, "capacity");
	mu_assert_eq (v->v.free_user, (void *)1337, "free");
	free (v);
	mu_end;
}

static bool test_pvector_clear(void) {
	// run with asan or valgrind
	RPVector v;
	init_test_pvector (&v, 5, 5);
	mu_assert_eq (v.v.len, 5UL, "initial len");
	mu_assert ("initial a", v.v.a);
	mu_assert_eq (v.v.capacity, 10UL, "initial capacity");
	r_pvector_clear (&v);
	mu_assert_eq (v.v.len, 0UL, "len");
	mu_assert_null (v.v.a, "a");
	mu_assert_eq (v.v.capacity, 0UL, "capacity");
	mu_end;
}

static bool test_pvector_free(void) {
	// run with asan or valgrind
	RPVector *v = R_NEW (RPVector);
	init_test_pvector (v, 5, 5);
	mu_assert_eq (v->v.len, 5UL, "initial len");
	mu_assert ("initial a", v->v.a);
	mu_assert_eq (v->v.capacity, 10UL, "initial capacity");
	r_pvector_free (v);
	mu_end;
}

static bool test_pvector_at(void) {
	RPVector v;
	init_test_pvector (&v, 5, 0);
	ut32 i;
	for (i = 0; i < 5; i++) {
		ut32 e = *((ut32 *)r_pvector_at (&v, i));
		mu_assert_eq (e, i, "at");
	}
	r_pvector_clear (&v);
	mu_end;
}

static bool test_pvector_set(void) {
	RPVector v;
	init_test_pvector (&v, 5, 0);
	free (((void **)v.v.a)[3]);
	r_pvector_set (&v, 3, (void *)1337);
	mu_assert_eq (((void **)v.v.a)[3], (void *)1337, "set");
	r_pvector_set (&v, 3, NULL);
	mu_assert_null (((void **)v.v.a)[3], "set");
	r_pvector_clear (&v);
	mu_end;
}

static bool test_pvector_contains(void) {
	RPVector v;
	init_test_pvector (&v, 5, 0);
	void *e = ((void **)v.v.a)[3];
	void **p = r_pvector_contains (&v, e);
	mu_assert_eq (p, (void **)v.v.a + 3, "contains");
	p = r_pvector_contains (&v, 0);
	mu_assert_null (p, "!contains");
	r_pvector_clear (&v);
	mu_end;
}

static bool test_pvector_remove_at(void) {
	RPVector v;
	init_test_pvector (&v, 5, 0);
	ut32 *e = r_pvector_remove_at (&v, 3);
	mu_assert_eq (*e, 3, "remove_at ret");
	free (e);
	mu_assert_eq (v.v.len, 4UL, "remove_at => len");
	mu_assert_eq (*((ut32 **)v.v.a)[0], 0, "remove_at => remaining content");
	mu_assert_eq (*((ut32 **)v.v.a)[1], 1, "remove_at => remaining content");
	mu_assert_eq (*((ut32 **)v.v.a)[2], 2, "remove_at => remaining content");
	mu_assert_eq (*((ut32 **)v.v.a)[3], 4, "remove_at => remaining content");
	r_pvector_clear (&v);
	mu_end;
}

static bool test_pvector_insert(void) {
	RPVector v;

	init_test_pvector2 (&v, 4, 2);
	void *e = (void *)1337;
	e = *r_pvector_insert (&v, 1, e);
	mu_assert_eq (v.v.len, 5UL, "insert => len");
	mu_assert_eq (e, (void *)1337, "insert => content at returned ptr");
	mu_assert_null (*((void **)r_vector_index_ptr (&v.v, 0)), "insert => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 1)), (void *)1337, "insert => content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 2)), (void *)1, "insert => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 3)), (void *)2, "insert => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 4)), (void *)3, "insert => old content");
	r_pvector_clear (&v);

	init_test_pvector2 (&v, 4, 0);
	e = (void *)1337;
	e = *r_pvector_insert (&v, 1, e);
	mu_assert ("insert (resize) => capacity", v.v.capacity >= 5);
	mu_assert_eq (v.v.len, 5UL, "insert (resize) => len");
	mu_assert_eq (e, (void *)1337, "insert (resize) => content at returned ptr");
	mu_assert_null (*((void **)r_vector_index_ptr (&v.v, 0)), "insert (resize) => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 1)), (void *)1337, "insert => content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 2)), (void *)1, "insert => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 3)), (void *)2, "insert => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 4)), (void *)3, "insert => old content");
	r_pvector_clear (&v);

	init_test_pvector2 (&v, 4, 2);
	e = (void *)1337;
	e = *r_pvector_insert (&v, 4, e);
	mu_assert_eq (v.v.len, 5UL, "insert (end) => len");
	mu_assert_eq (e, (void *)1337, "insert (end) => content at returned ptr");
	mu_assert_null (*((void **)r_vector_index_ptr (&v.v, 0)), "insert (end) => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 1)), (void *)1, "insert (end) => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 2)), (void *)2, "insert (end) => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 3)), (void *)3, "insert (end) => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 4)), (void *)1337, "insert (end) => content");
	r_pvector_clear (&v);

	init_test_pvector2 (&v, 4, 2);
	e = (void *)1337;
	e = *r_pvector_insert (&v, 4, e);
	mu_assert ("r_vector_insert (resize, resize) => capacity", v.v.capacity >= 5);
	mu_assert_eq (v.v.len, 5UL, "r_vector_insert (end, resize) => len");
	mu_assert_eq (e, (void *)1337, "r_vector_insert (end, resize) => content at returned ptr");
	mu_assert_null (*((void **)r_vector_index_ptr (&v.v, 0)), "r_vector_insert (end, resize) => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 1)), (void *)1, "r_vector_insert (end, resize) => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 2)), (void *)2, "r_vector_insert (end, resize) => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 3)), (void *)3, "r_vector_insert (end, resize) => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 4)), (void *)1337, "r_vector_insert (end, resize) => content");
	r_pvector_clear (&v);

	mu_end;
}

static bool test_pvector_insert_range(void) {
	RPVector v;
	void *range[] = { (void *)0xC0, (void *)0xFF, (void *)0xEE };

	r_pvector_init (&v, NULL);
	void **p = r_pvector_insert_range (&v, 0, range, 3);
	mu_assert_eq (p, r_vector_index_ptr (&v.v, 0), "insert_range (empty) returned ptr");
	mu_assert_eq (v.v.len, 3UL, "insert_range (empty) => len");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 0)), (void *)0xC0, "insert_range (empty) => new content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 1)), (void *)0xFF, "insert_range (empty) => new content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 2)), (void *)0xEE, "insert_range (empty) => new content");
	r_pvector_clear (&v);

	init_test_pvector2 (&v, 3, 3);
	p = r_pvector_insert_range (&v, 2, range, 3);
	mu_assert_eq (p, r_vector_index_ptr (&v.v, 2), "insert_range returned ptr");
	mu_assert_eq (v.v.len, 6UL, "insert_range => len");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 0)), (void *)0, "insert_range => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 1)), (void *)1, "insert_range => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 2)), (void *)0xC0, "insert_range => new content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 3)), (void *)0xFF, "insert_range => new content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 4)), (void *)0xEE, "insert_range => new content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 5)), (void *)2, "insert_range => old content");
	r_pvector_clear (&v);

	init_test_pvector2 (&v, 3, 3);
	p = r_pvector_insert_range (&v, 3, range, 3);
	mu_assert_eq (p, r_vector_index_ptr (&v.v, 3), "insert_range (end) returned ptr");
	mu_assert_eq (v.v.len, 6UL, "insert_range (end) => len");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 0)), (void *)0, "insert_range (end) => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 1)), (void *)1, "insert_range (end) => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 2)), (void *)2, "insert_range (end) => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 3)), (void *)0xC0, "insert_range (end) => new content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 4)), (void *)0xFF, "insert_range (end) => new content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 5)), (void *)0xEE, "insert_range (end) => new content");
	r_pvector_clear (&v);

	init_test_pvector2 (&v, 3, 0);
	p = r_pvector_insert_range (&v, 2, range, 3);
	mu_assert_eq (p, r_vector_index_ptr (&v.v, 2), "insert_range (resize) returned ptr");
	mu_assert_eq (v.v.len, 6UL, "insert_range (resize) => len");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 0)), (void *)0, "insert_range (resize) => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 1)), (void *)1, "insert_range (resize) => old content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 2)), (void *)0xC0, "insert_range (resize) => new content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 3)), (void *)0xFF, "insert_range (resize) => new content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 4)), (void *)0xEE, "insert_range (resize) => new content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 5)), (void *)2, "insert_range (resize) => old content");
	r_pvector_clear (&v);

	mu_end;
}

static bool test_pvector_pop(void) {
	RPVector v;
	init_test_pvector2 (&v, 3, 0);

	void *e = r_pvector_pop (&v);
	mu_assert_eq (e, (void *)2, "pop ret");
	mu_assert_eq (v.v.len, 2UL, "pop => len");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 0)), (void *)0, "pop => remaining content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 1)), (void *)1, "pop => remaining content");

	e = r_pvector_pop (&v);
	mu_assert_eq (e, (void *)1, "pop ret");
	mu_assert_eq (v.v.len, 1UL, "pop => len");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 0)), (void *)0, "pop => remaining content");

	e = r_pvector_pop (&v);
	mu_assert_eq (e, (void *)0, "pop (last) into");
	mu_assert_eq (v.v.len, 0UL, "pop (last) => len");

	r_pvector_clear (&v);

	mu_end;
}

static bool test_pvector_pop_front(void) {
	RPVector v;
	init_test_pvector2 (&v, 3, 0);

	void *e = r_pvector_pop_front (&v);
	mu_assert_null (e, "pop_front into");
	mu_assert_eq (v.v.len, 2UL, "pop_front => len");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 0)), (void *)1, "pop_front => remaining content");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 1)), (void *)2, "pop_front => remaining content");

	e = r_pvector_pop_front (&v);
	mu_assert_eq (e, (void *)1, "r_vector_pop_front into");
	mu_assert_eq (v.v.len, 1UL, "r_vector_pop_front => len");
	mu_assert_eq (*((void **)r_vector_index_ptr (&v.v, 0)), (void *)2, "pop_front => remaining content");

	e = r_pvector_pop_front (&v);
	mu_assert_eq (e, (void *)2, "pop_front (last) into");
	mu_assert_eq (v.v.len, 0UL, "pop_front (last) => len");

	r_pvector_clear (&v);

	mu_end;
}

static bool test_pvector_push(void) {
	RPVector v;
	r_pvector_init (&v, NULL);

	void *e = (void *)1337;
	e = *r_pvector_push (&v, e);
	mu_assert_eq (v.v.len, 1UL, "push (empty) => len == 1");
	mu_assert_eq (e, (void *)1337, "push (empty) => content at returned ptr");
	e = *((void **)r_vector_index_ptr (&v.v, 0));
	mu_assert_eq (e, (void *)1337, "r_vector_push (empty) => content");

	e = (void *)0xDEAD;
	e = *r_pvector_push (&v, e);
	mu_assert_eq (v.v.len, 2UL, "push => len == 2");
	mu_assert_eq (e, (void *)0xDEAD, "push => content at returned ptr");
	e = *((void **)r_vector_index_ptr (&v.v, 0));
	mu_assert_eq (e, (void *)1337, "push => old content");
	e = *((void **)r_vector_index_ptr (&v.v, 1));
	mu_assert_eq (e, (void *)0xDEAD, "push => content");

	e = (void *)0xBEEF;
	e = *r_pvector_push (&v, e);
	mu_assert_eq (v.v.len, 3UL, "push => len == 3");
	mu_assert_eq (e, (void *)0xBEEF, "push => content at returned ptr");
	e = *((void **)r_vector_index_ptr (&v.v, 0));
	mu_assert_eq (e, (void *)1337, "r_vector_push => old content");
	e = *((void **)r_vector_index_ptr (&v.v, 1));
	mu_assert_eq (e, (void *)0xDEAD, "r_vector_push => old content");
	e = *((void **)r_vector_index_ptr (&v.v, 2));
	mu_assert_eq (e, (void *)0xBEEF, "r_vector_push => content");

	r_vector_clear (&v.v);


	init_test_pvector2 (&v, 5, 0);
	e = (void *)1337;
	e = *r_pvector_push (&v, e);
	mu_assert ("push (resize) => capacity", v.v.capacity >= 6);
	mu_assert_eq (v.v.len, 6UL, "push (resize) => len");
	mu_assert_eq (e, (void *)1337, "push (empty) => content at returned ptr");

	size_t i;
	for (i = 0; i < v.v.len - 1; i++) {
		e = *((void **)r_vector_index_ptr (&v.v, i));
		mu_assert_eq (e, (void *)i, "push (resize) => old content");
	}
	e = *((void **)r_vector_index_ptr (&v.v, 5));
	mu_assert_eq (e, (void *)1337, "r_vector_push (resize) => content");

	r_vector_clear (&v.v);

	mu_end;
}

static bool test_pvector_push_front(void) {
	RPVector v;
	r_pvector_init (&v, NULL);

	void *e = (void *)1337;
	e = *r_pvector_push_front (&v, e);
	mu_assert_eq (v.v.len, 1UL, "push_front (empty) => len == 1");
	mu_assert_eq (e, (void *)1337, "push_front (empty) => content at returned ptr");
	e = *((void **)r_vector_index_ptr (&v.v, 0));
	mu_assert_eq (e, (void *)1337, "push_front (empty) => content");

	e = (void *)0xDEAD;
	e = *r_pvector_push_front (&v, e);
	mu_assert_eq (v.v.len, 2UL, "push_front => len == 2");
	mu_assert_eq (e, (void *)0xDEAD, "push_front (empty) => content at returned ptr");
	e = *((void **)r_vector_index_ptr (&v.v, 0));
	mu_assert_eq (e, (void *)0xDEAD, "push_front => content");
	e = *((void **)r_vector_index_ptr (&v.v, 1));
	mu_assert_eq (e, (void *)1337, "push_front => old content");

	e = (void *)0xBEEF;
	e = *r_pvector_push_front (&v, e);
	mu_assert_eq (v.v.len, 3UL, "push_front => len == 3");
	mu_assert_eq (e, (void *)0xBEEF, "push_front (empty) => content at returned ptr");
	e = *((void **)r_vector_index_ptr (&v.v, 0));
	mu_assert_eq (e, (void *)0xBEEF, "push_front => content");
	e = *((void **)r_vector_index_ptr (&v.v, 1));
	mu_assert_eq (e, (void *)0xDEAD, "push_front => old content");
	e = *((void **)r_vector_index_ptr (&v.v, 2));
	mu_assert_eq (e, (void *)1337, "push_front => old content");

	r_pvector_clear (&v);


	init_test_pvector2 (&v, 5, 0);
	e = (void *)1337;
	e = *r_pvector_push_front (&v, e);
	mu_assert ("push_front (resize) => capacity", v.v.capacity >= 6);
	mu_assert_eq (v.v.len, 6UL, "push_front (resize) => len");
	mu_assert_eq (e, (void *)1337, "push_front (empty) => content at returned ptr");

	size_t i;
	for (i = 1; i < v.v.len; i++) {
		e = *((void **)r_vector_index_ptr (&v.v, i));
		mu_assert_eq (e, (void *)(i - 1), "push_front (resize) => old content");
	}
	e = *((void **)r_vector_index_ptr (&v.v, 0));
	mu_assert_eq (e, (void *)1337, "push_front (resize) => content");

	r_pvector_clear (&v);

	mu_end;
}

static bool test_pvector_sort(void) {
	RPVector v;
	r_pvector_init (&v, free);
	r_pvector_push (&v, strdup ("Charmander"));
	r_pvector_push (&v, strdup ("Squirtle"));
	r_pvector_push (&v, strdup ("Bulbasaur"));
	r_pvector_push (&v, strdup ("Meowth"));
	r_pvector_push (&v, strdup ("Caterpie"));
	r_pvector_sort (&v, (RPVectorComparator) strcmp);

	mu_assert_eq (v.v.len, 5UL, "sort len");
	mu_assert_streq ((const char *)((void **)v.v.a)[0], "Bulbasaur", "sorted strings");
	mu_assert_streq ((const char *)((void **)v.v.a)[1], "Caterpie", "sorted strings");
	mu_assert_streq ((const char *)((void **)v.v.a)[2], "Charmander", "sorted strings");
	mu_assert_streq ((const char *)((void **)v.v.a)[3], "Meowth", "sorted strings");
	mu_assert_streq ((const char *)((void **)v.v.a)[4], "Squirtle", "sorted strings");
	r_pvector_clear (&v);

	mu_end;
}

static bool test_pvector_foreach(void) {
	RPVector v;
	init_test_pvector2 (&v, 5, 5);

	int i = 1;
	void **it;
	int acc[5] = {0};
	r_pvector_foreach (&v, it) {
		void *e = *it;
		int ev = (int)((size_t)e);
		mu_assert_eq (acc[ev], 0, "unset acc element");
		acc[ev] = i++;
	}

	for (i = 0; i < 5; i++) {
		mu_assert_eq (acc[i], i + 1, "acc");
	}

	r_pvector_clear (&v);

	mu_end;
}

static bool test_pvector_lower_bound(void) {
	void *a[] = {(void*)0, (void*)2, (void*)4, (void*)6, (void*)8};
	RPVector s;
	r_pvector_init (&s, NULL);
	s.v.a = malloc (sizeof (void *) * 5);
	s.v.capacity = 5;
	memcpy (s.v.a, a, sizeof (void *) * 5);
	s.v.len = 5;

	size_t l;
#define CMP(x, y) ((char *)(x) - (char *)(y))
	r_pvector_lower_bound (&s, 4, l, CMP);
	mu_assert_ptreq (r_pvector_at (&s, l), (void *)4, "lower_bound");
	r_pvector_lower_bound (&s, 5, l, CMP);
	mu_assert_ptreq (r_pvector_at (&s, l), (void *)6, "lower_bound 2");
	r_pvector_lower_bound (&s, 6, l, CMP);
	mu_assert_ptreq (r_pvector_at (&s, l), (void *)6, "lower_bound 3");
	r_pvector_lower_bound (&s, 9, l, CMP);
	mu_assert_eq (l, s.v.len, "lower_bound 3");
#undef CMP

	r_pvector_clear (&s);

	mu_end;
}

static int all_tests(void) {
	mu_run_test (test_vector_init);
	mu_run_test (test_vector_new);
	mu_run_test (test_vector_fini);
	mu_run_test (test_vector_clear);
	mu_run_test (test_vector_free);
	mu_run_test (test_vector_clone);
	mu_run_test (test_vector_empty);
	mu_run_test (test_vector_remove_at);
	mu_run_test (test_vector_insert);
	mu_run_test (test_vector_insert_range);
	mu_run_test (test_vector_pop);
	mu_run_test (test_vector_pop_front);
	mu_run_test (test_vector_push);
	mu_run_test (test_vector_push_front);
	mu_run_test (test_vector_reserve);
	mu_run_test (test_vector_shrink);
	mu_run_test (test_vector_foreach);
	mu_run_test (test_vector_lower_bound);

	mu_run_test (test_pvector_init);
	mu_run_test (test_pvector_new);
	mu_run_test (test_pvector_clear);
	mu_run_test (test_pvector_free);
	mu_run_test (test_pvector_at);
	mu_run_test (test_pvector_set);
	mu_run_test (test_pvector_contains);
	mu_run_test (test_pvector_remove_at);
	mu_run_test (test_pvector_insert);
	mu_run_test (test_pvector_insert_range);
	mu_run_test (test_pvector_pop);
	mu_run_test (test_pvector_pop_front);
	mu_run_test (test_pvector_push);
	mu_run_test (test_pvector_push_front);
	mu_run_test (test_pvector_sort);
	mu_run_test (test_pvector_foreach);
	mu_run_test (test_pvector_lower_bound);

	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
