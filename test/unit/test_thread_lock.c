#include <r_th.h>
#include "minunit.h"

// Shared data for testing
static int shared_counter = 0;
static RThreadLock *test_lock = NULL;

// Thread function that increments counter with lock protection
static RThreadFunctionRet increment_with_lock(RThread *th) {
	// Acquire the lock
	r_th_lock_enter(test_lock);

	// Critical section - increment counter
	shared_counter++;

	// Release the lock
	r_th_lock_leave(test_lock);

	return R_TH_STOP;
}

bool test_lock_basic(void) {
	// Initialize counter and create lock
	shared_counter = 0;
	test_lock = r_th_lock_new(false); // non-recursive lock
	mu_assert_notnull(test_lock, "Lock creation failed");

	// Create thread
	RThread *th = r_th_new(increment_with_lock, NULL, 0);
	mu_assert_notnull(th, "Thread creation failed");

	// Start thread
	r_th_start(th);

	// Wait for thread to complete
	r_th_wait(th);

	// Check that thread incremented counter
	mu_assert_eq(shared_counter, 1, "Thread didn't increment counter correctly");

	// Clean up
	r_th_free(th);
	r_th_lock_free(test_lock);

	mu_end;
}

// Thread function for testing recursion
static RThreadFunctionRet test_recursion(RThread *th) {
	bool first_enter = r_th_lock_enter(test_lock);
	mu_assert("First lock enter should succeed", first_enter);

	// In recursive mode, this should succeed
	// In non-recursive mode, this would deadlock, but we'll check tryenter instead
	bool second_enter = r_th_lock_tryenter(test_lock);

	if (second_enter) {
		// We were able to recursively lock, so increment and release inner lock
		shared_counter++;
		r_th_lock_leave(test_lock);
	}

	// Always release outer lock
	r_th_lock_leave(test_lock);

	return R_TH_STOP;
}

bool test_lock_recursive(void) {
	// Initialize counter
	shared_counter = 0;

	// Create recursive lock
	test_lock = r_th_lock_new(true); // recursive lock
	mu_assert_notnull(test_lock, "Recursive lock creation failed");

	// Create thread
	RThread *th = r_th_new(test_recursion, NULL, 0);
	mu_assert_notnull(th, "Thread creation failed");

	// Start thread
	r_th_start(th);

	// Wait for thread to complete
	r_th_wait(th);

	// Check that inner lock was acquired
	mu_assert_eq(shared_counter, 1, "Recursive lock didn't allow inner lock acquisition");

	// Clean up
	r_th_free(th);
	r_th_lock_free(test_lock);

	mu_end;
}

bool test_lock_non_recursive(void) {
	// Initialize counter
	shared_counter = 0;

	// Create non-recursive lock
	test_lock = r_th_lock_new(false); // non-recursive lock
	mu_assert_notnull(test_lock, "Non-recursive lock creation failed");

	// Create thread
	RThread *th = r_th_new(test_recursion, NULL, 0);
	mu_assert_notnull(th, "Thread creation failed");

	// Start thread
	r_th_start(th);

	// Wait for thread to complete
	r_th_wait(th);

	// Check that inner lock was NOT acquired (tryenter should have failed)
	mu_assert_eq(shared_counter, 0, "Non-recursive lock shouldn't allow inner lock acquisition");

	// Clean up
	r_th_free(th);
	r_th_lock_free(test_lock);

	mu_end;
}

// Multiple threads synchronizing with a lock
#define NUM_THREADS 5
static RThread *threads[NUM_THREADS];

static RThreadFunctionRet thread_increment_lock(RThread *th) {
	// Acquire lock
	r_th_lock_enter(test_lock);

	// Critical section
	shared_counter++;

	// Release lock
	r_th_lock_leave(test_lock);

	return R_TH_STOP;
}

bool test_lock_multiple_threads(void) {
	// Initialize counter and create lock
	shared_counter = 0;
	test_lock = r_th_lock_new(false); // non-recursive lock
	mu_assert_notnull(test_lock, "Lock creation failed");

	// Create and start threads
	int i;
	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = r_th_new(thread_increment_lock, NULL, 0);
		mu_assert_notnull(threads[i], "Thread creation failed");
		r_th_start(threads[i]);
	}

	// Wait for all threads to finish
	for (i = 0; i < NUM_THREADS; i++) {
		r_th_wait(threads[i]);
		r_th_free(threads[i]);
	}

	// Verify count
	mu_assert_eq(shared_counter, NUM_THREADS, "Thread synchronization failed");

	// Clean up
	r_th_lock_free(test_lock);

	mu_end;
}

bool test_lock_wait(void) {
	// Initialize counter
	shared_counter = 0;

	// Create lock
	test_lock = r_th_lock_new(false);
	mu_assert_notnull(test_lock, "Lock creation failed");

	// Acquire lock from main thread
	r_th_lock_enter(test_lock);

	// Create thread that will wait on lock
	RThread *th = r_th_new(increment_with_lock, NULL, 0);
	mu_assert_notnull(th, "Thread creation failed");

	// Start thread (it will block on lock)
	r_th_start(th);

	// Counter should still be 0 as thread is blocked
	r_sys_usleep(100000); // 100ms
	mu_assert_eq(shared_counter, 0, "Counter should still be 0 while thread is blocked");

	// Release lock to allow thread to proceed
	r_th_lock_leave(test_lock);

	// Wait for thread to complete
	r_th_wait(th);

	// Counter should now be 1
	mu_assert_eq(shared_counter, 1, "Counter should be 1 after thread completes");

	// Clean up
	r_th_free(th);
	r_th_lock_free(test_lock);

	mu_end;
}

bool test_atomic_operations(void) {
	// Test atomic exchange
	volatile R_ATOMIC_BOOL data = 0;

	bool prev = r_atomic_exchange(&data, true);
	mu_assert_eq(prev, false, "Initial value should be false");
	mu_assert("Atomic value should now be true", data);

	prev = r_atomic_exchange(&data, false);
	mu_assert_eq(prev, true, "Previous value should be true");
	mu_assert("Atomic value should now be false", !data);

	// Test atomic store
	r_atomic_store(&data, true);
	mu_assert("Atomic value should be true after store", data);

	r_atomic_store(&data, false);
	mu_assert("Atomic value should be false after store", !data);

	mu_end;
}

int all_tests(void) {
	mu_run_test(test_lock_basic);
	mu_run_test(test_lock_recursive);
	mu_run_test(test_lock_non_recursive);
	mu_run_test(test_lock_multiple_threads);
	mu_run_test(test_lock_wait);
	mu_run_test(test_atomic_operations);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
