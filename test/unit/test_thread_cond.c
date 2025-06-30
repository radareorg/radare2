#include <r_th.h>
#include "minunit.h"

// Shared data for testing
static int shared_counter = 0;
static RThreadLock *test_lock = NULL;
static RThreadCond *test_cond = NULL;
static bool condition_met = false;

// Thread function that waits for a condition
static RThreadFunctionRet wait_for_condition(RThread *th) {
	// Acquire lock
	r_th_lock_enter(test_lock);

	// Wait until condition is met
	while (!condition_met) {
		r_th_cond_wait(test_cond, test_lock);
	}

	// Condition is met, increment counter
	shared_counter++;

	// Release lock
	r_th_lock_leave(test_lock);

	return R_TH_STOP;
}

bool test_condition_basic(void) {
	// Initialize test data
	shared_counter = 0;
	condition_met = false;

	// Create lock and condition variable
	test_lock = r_th_lock_new(false);
	mu_assert_notnull(test_lock, "Lock creation failed");

	test_cond = r_th_cond_new();
	mu_assert_notnull(test_cond, "Condition variable creation failed");

	// Create thread that will wait on condition
	RThread *th = r_th_new(wait_for_condition, NULL, 0);
	mu_assert_notnull(th, "Thread creation failed");

	// Start thread
	r_th_start(th);

	// Give thread time to start and wait on condition
	r_sys_usleep(100000); // 100ms

	// Counter should still be 0 as condition is not met
	mu_assert_eq(shared_counter, 0, "Counter should be 0 while waiting for condition");

	// Acquire lock, set condition to true, signal condition, release lock
	r_th_lock_enter(test_lock);
	condition_met = true;
	r_th_cond_signal(test_cond);
	r_th_lock_leave(test_lock);

	// Wait for thread to complete
	r_th_wait(th);

	// Verify counter was incremented
	mu_assert_eq(shared_counter, 1, "Counter should be 1 after condition is met");

	// Clean up
	r_th_free(th);
	r_th_lock_free(test_lock);
	r_th_cond_free(test_cond);

	mu_end;
}

// Multiple threads waiting on a condition
#define NUM_WAITING_THREADS 5
static RThread *waiting_threads[NUM_WAITING_THREADS];

bool test_condition_multiple_threads(void) {
	// Initialize test data
	shared_counter = 0;
	condition_met = false;

	// Create lock and condition variable
	test_lock = r_th_lock_new(false);
	mu_assert_notnull(test_lock, "Lock creation failed");

	test_cond = r_th_cond_new();
	mu_assert_notnull(test_cond, "Condition variable creation failed");

	// Create and start multiple threads, all waiting on the same condition
	int i;
	for (i = 0; i < NUM_WAITING_THREADS; i++) {
		waiting_threads[i] = r_th_new(wait_for_condition, NULL, 0);
		mu_assert_notnull(waiting_threads[i], "Thread creation failed");
		r_th_start(waiting_threads[i]);
	}

	// Give threads time to start and wait on condition
	r_sys_usleep(200000); // 200ms

	// Counter should still be 0 as condition is not met
	mu_assert_eq(shared_counter, 0, "Counter should be 0 while waiting for condition");

	// Acquire lock, set condition to true, signal all threads, release lock
	r_th_lock_enter(test_lock);
	condition_met = true;
	r_th_cond_signal_all(test_cond);
	r_th_lock_leave(test_lock);

	// Wait for all threads to complete
	for (i = 0; i < NUM_WAITING_THREADS; i++) {
		r_th_wait(waiting_threads[i]);
		r_th_free(waiting_threads[i]);
	}

	// Verify all threads incremented the counter
	mu_assert_eq(shared_counter, NUM_WAITING_THREADS, "All threads should have incremented the counter");

	// Clean up
	r_th_lock_free(test_lock);
	r_th_cond_free(test_cond);

	mu_end;
}

// Test individual signal vs signal_all
static RThread *signal_threads[2];

bool test_condition_individual_signal(void) {
	// Initialize test data
	shared_counter = 0;
	condition_met = false;

	// Create lock and condition variable
	test_lock = r_th_lock_new(false);
	mu_assert_notnull(test_lock, "Lock creation failed");

	test_cond = r_th_cond_new();
	mu_assert_notnull(test_cond, "Condition variable creation failed");

	// Create and start two threads waiting on the same condition
	int i;
	for (i = 0; i < 2; i++) {
		signal_threads[i] = r_th_new(wait_for_condition, NULL, 0);
		mu_assert_notnull(signal_threads[i], "Thread creation failed");
		r_th_start(signal_threads[i]);
	}

	// Give threads time to start and wait on condition
	r_sys_usleep(100000); // 100ms

	// Counter should still be 0 as condition is not met
	mu_assert_eq(shared_counter, 0, "Counter should be 0 while waiting for condition");

	// Signal just one thread
	r_th_lock_enter(test_lock);
	condition_met = true;
	r_th_cond_signal(test_cond); // Signal one thread
	r_th_lock_leave(test_lock);

	// Give the signaled thread time to run
	r_sys_usleep(100000); // 100ms

	// Only one thread should have incremented the counter
	mu_assert_eq(shared_counter, 1, "Only one thread should have been signaled");

	// Now signal the other thread
	r_th_lock_enter(test_lock);
	r_th_cond_signal(test_cond); // Signal the remaining thread
	r_th_lock_leave(test_lock);

	// Wait for all threads to complete
	int i;
	for (i = 0; i < 2; i++) {
		r_th_wait(signal_threads[i]);
		r_th_free(signal_threads[i]);
	}

	// Verify both threads incremented the counter
	mu_assert_eq(shared_counter, 2, "Both threads should have incremented the counter");

	// Clean up
	r_th_lock_free(test_lock);
	r_th_cond_free(test_cond);

	mu_end;
}

int all_tests(void) {
	mu_run_test(test_condition_basic);
	mu_run_test(test_condition_multiple_threads);
	mu_run_test(test_condition_individual_signal);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
