#include <r_th.h>
#include "minunit.h"

// Shared data for testing
static int shared_counter = 0;
static RThreadSemaphore *test_sem = NULL;

// Thread function that increments counter with semaphore synchronization
static RThreadFunctionRet increment_with_sem(RThread *th) {
    // Wait on semaphore
    r_th_sem_wait(test_sem);
    
    // Critical section - increment counter
    shared_counter++;
    
    // Post semaphore to signal completion
    r_th_sem_post(test_sem);
    
    return R_TH_STOP;
}

bool test_semaphore_basic(void) {
    // Initialize counter and create semaphore with 1 permit
    shared_counter = 0;
    test_sem = r_th_sem_new(1);
    mu_assert_notnull(test_sem, "Semaphore creation failed");
    
    // Create thread
    RThread *th = r_th_new(increment_with_sem, NULL, 0);
    mu_assert_notnull(th, "Thread creation failed");
    
    // Start thread
    r_th_start(th);
    
    // Give the thread a chance to run
    r_sys_usleep(100000); // 100ms
    
    // Wait on semaphore to ensure synchronization
    r_th_sem_wait(test_sem);
    
    // Check that the thread incremented the counter
    mu_assert_eq(shared_counter, 1, "Thread didn't increment counter correctly");
    
    // Release semaphore
    r_th_sem_post(test_sem);
    
    // Wait for thread to complete
    r_th_wait(th);
    r_th_free(th);
    
    // Clean up
    r_th_sem_free(test_sem);
    
    mu_end;
}

// Thread function that uses semaphore as a counter
static RThreadFunctionRet wait_for_permits(RThread *th) {
    // Wait for 3 permits
    for (int i = 0; i < 3; i++) {
        r_th_sem_wait(test_sem);
        shared_counter++;
    }
    
    return R_TH_STOP;
}

bool test_semaphore_as_counter(void) {
    // Initialize counter and create semaphore with 0 permits
    shared_counter = 0;
    test_sem = r_th_sem_new(0);
    mu_assert_notnull(test_sem, "Semaphore creation failed");
    
    // Create thread
    RThread *th = r_th_new(wait_for_permits, NULL, 0);
    mu_assert_notnull(th, "Thread creation failed");
    
    // Start thread
    r_th_start(th);
    
    // Initially, counter should be 0 as no permits available
    r_sys_usleep(100000); // 100ms
    mu_assert_eq(shared_counter, 0, "Counter should be 0 as no permits available");
    
    // Post 2 permits
    r_th_sem_post(test_sem);
    r_th_sem_post(test_sem);
    
    // Give some time for thread to process
    r_sys_usleep(100000); // 100ms
    mu_assert_eq(shared_counter, 2, "Thread should have processed 2 permits");
    
    // Post final permit
    r_th_sem_post(test_sem);
    
    // Wait for thread completion
    r_th_wait(th);
    
    // Verify final count
    mu_assert_eq(shared_counter, 3, "Thread should have processed all 3 permits");
    
    // Clean up
    r_th_sem_free(test_sem);
    r_th_free(th);
    
    mu_end;
}

// Multiple threads synchronizing with a semaphore
#define NUM_THREADS 5
static RThread *threads[NUM_THREADS];

static RThreadFunctionRet thread_increment(RThread *th) {
    // Wait on semaphore
    r_th_sem_wait(test_sem);
    
    // Critical section
    shared_counter++;
    
    // Give up critical section
    r_th_sem_post(test_sem);
    
    return R_TH_STOP;
}

bool test_semaphore_multiple_threads(void) {
    // Initialize counter and create binary semaphore (mutex-like)
    shared_counter = 0;
    test_sem = r_th_sem_new(1);
    mu_assert_notnull(test_sem, "Semaphore creation failed");
    
    // Create and start threads
    for (int i = 0; i < NUM_THREADS; i++) {
        threads[i] = r_th_new(thread_increment, NULL, 0);
        mu_assert_notnull(threads[i], "Thread creation failed");
        r_th_start(threads[i]);
    }
    
    // Wait for all threads to finish
    for (int i = 0; i < NUM_THREADS; i++) {
        r_th_wait(threads[i]);
        r_th_free(threads[i]);
    }
    
    // Verify count
    mu_assert_eq(shared_counter, NUM_THREADS, "Thread synchronization failed");
    
    // Clean up
    r_th_sem_free(test_sem);
    
    mu_end;
}

int all_tests(void) {
    mu_run_test(test_semaphore_basic);
    mu_run_test(test_semaphore_as_counter);
    mu_run_test(test_semaphore_multiple_threads);
    return tests_passed != tests_run;
}

int main(int argc, char **argv) {
    return all_tests();
}