#include <r_th.h>
#include "minunit.h"

// Shared data for testing
static int test_data = 0;

static RThreadFunctionRet test_thread_function(RThread *th) {
	// Simple increment of shared data
	test_data++;
	return R_TH_STOP;
}

static RThreadFunctionRet test_thread_repeat_function(RThread *th) {
	// Increment test_data and return REPEAT to be called again
	test_data++;
	if (test_data < 5) {
		return R_TH_REPEAT;
	}
	return R_TH_STOP;
}

static RThreadFunctionRet test_thread_delay_function(RThread *th) {
	// Just increment the counter after delay
	test_data++;
	return R_TH_STOP;
}

bool test_thread_basic(void) {
	// Reset test data
	test_data = 0;
	
	// Create a new thread
	RThread *th = r_th_new(test_thread_function, NULL, 0);
	mu_assert_notnull(th, "Thread creation failed");
	
	// Start the thread
	bool res = r_th_start(th);
	mu_assert_eq(res, true, "Thread start failed");
	
	// Wait for thread to finish
	r_th_wait(th);
	
	// Verify thread executed
	mu_assert_eq(test_data, 1, "Thread function didn't execute correctly");
	
	// Free thread
	r_th_free(th);
	
	mu_end;
}

bool test_thread_is_running(void) {
	// Create a new thread but don't start it yet
	RThread *th = r_th_new(test_thread_function, NULL, 0);
	mu_assert_notnull(th, "Thread creation failed");
	
	// Should be running (not started, but thread is alive)
	bool running = r_th_is_running(th);
	mu_assert_eq(running, true, "Thread should be marked as running after creation");
	
	// Explicitly set running to false
	r_th_set_running(th, false);
	running = r_th_is_running(th);
	mu_assert_eq(running, false, "Thread should not be running after setting to false");
	
	// Set it back to true
	r_th_set_running(th, true);
	running = r_th_is_running(th);
	mu_assert_eq(running, true, "Thread should be running after setting to true");
	
	// Free thread without starting
	r_th_free(th);
	
	mu_end;
}

bool test_thread_repeat(void) {
	// Reset test data
	test_data = 0;
	
	// Create thread with repeat function
	RThread *th = r_th_new(test_thread_repeat_function, NULL, 0);
	mu_assert_notnull(th, "Thread creation failed");
	
	// Start the thread
	bool res = r_th_start(th);
	mu_assert_eq(res, true, "Thread start failed");
	
	// Wait for thread to finish
	r_th_wait(th);
	
	// Verify thread repeated correctly
	mu_assert_eq(test_data, 5, "Thread function didn't repeat correctly");
	
	// Free thread
	r_th_free(th);
	
	mu_end;
}

bool test_thread_break(void) {
	// Reset test data
	test_data = 0;
	
	// Create thread with repeat function
	RThread *th = r_th_new(test_thread_repeat_function, NULL, 0);
	mu_assert_notnull(th, "Thread creation failed");
	
	// Start the thread
	bool res = r_th_start(th);
	mu_assert_eq(res, true, "Thread start failed");
	
	// Break the thread immediately
	r_th_break(th);
	
	// Wait for thread to finish
	r_th_wait(th);
	
	// Verify thread was broken before completing all repeats
	mu_assert_neq(test_data, 5, "Thread was not broken correctly");
	
	// Free thread
	r_th_free(th);
	
	mu_end;
}

bool test_thread_delay(void) {
	// Reset test data
	test_data = 0;
	
	// Create thread with 500ms delay
	RThread *th = r_th_new(test_thread_delay_function, NULL, 500);
	mu_assert_notnull(th, "Thread creation failed");
	
	// Start the thread
	bool res = r_th_start(th);
	mu_assert_eq(res, true, "Thread start failed");
	
	// Verify data hasn't changed yet
	mu_assert_eq(test_data, 0, "Thread executed before delay");
	
	// Wait for thread to finish
	r_th_wait(th);
	
	// Verify thread executed after delay
	mu_assert_eq(test_data, 1, "Thread didn't execute after delay");
	
	// Free thread
	r_th_free(th);
	
	mu_end;
}

bool test_thread_kill(void) {
	// Reset test data
	test_data = 0;
	
	// Create thread with long delay to ensure it's still running when we kill it
	RThread *th = r_th_new(test_thread_delay_function, NULL, 2000);
	mu_assert_notnull(th, "Thread creation failed");
	
	// Start the thread
	bool res = r_th_start(th);
	mu_assert_eq(res, true, "Thread start failed");
	
	// Kill the thread
	bool killed = r_th_kill(th, true);
	mu_assert_eq(killed, false, "Thread kill should return false");
	
	// Free thread
	r_th_free(th);
	
	// Verify thread didn't execute
	mu_assert_eq(test_data, 0, "Thread executed after being killed");
	
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_thread_basic);
	mu_run_test(test_thread_is_running);
	mu_run_test(test_thread_repeat);
	mu_run_test(test_thread_break);
	mu_run_test(test_thread_delay);
	mu_run_test(test_thread_kill);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}