#include <r_th.h>
#include "minunit.h"

// Test data
static int consumer_count = 0;

// Consumer function for channel tests
static RThreadFunctionRet consumer_function(RThread *th) {
	RThreadChannel *tc = th->user;
	while (!th->breaked) {
		// Read message from channel
		RThreadChannelMessage *msg = r_th_channel_read(tc);
		if (!msg) {
			break;
		}
		
		// Increment counter based on received message
		consumer_count += *(int *)msg->msg;
		
		// Send response back (this is crucial for promise-based synchronization)
		r_th_channel_post(tc, msg);
	}
	return R_TH_STOP;
}

bool test_thread_channel_basic(void) {
	// Reset test data
	consumer_count = 0;
	
	// Create a channel with consumer thread
	RThreadChannel *tc = r_th_channel_new(consumer_function, NULL);
	mu_assert_notnull(tc, "Channel creation failed");
	
	// Set channel as thread user data
	tc->consumer->user = tc;
	
	// Create and send a message with value 5
	int value = 5;
	RThreadChannelMessage *msg = r_th_channel_message_new(tc, (const ut8*)&value, sizeof(int));
	mu_assert_notnull(msg, "Failed to create channel message");
	
	// Start the consumer thread
	r_th_start(tc->consumer);
	
	// Write message to channel
	r_th_channel_write(tc, msg);
	
	// Give some time for processing
	r_sys_usleep(100000);  // 100ms
	
	// Clean up
	r_th_channel_free(tc);
	
	// Verify consumer processed the message
	mu_assert_eq(consumer_count, 5, "Consumer didn't process message correctly");
	
	mu_end;
}

bool test_thread_channel_multiple_messages(void) {
	// Reset test data
	consumer_count = 0;
	
	// Create a channel with consumer thread
	RThreadChannel *tc = r_th_channel_new(consumer_function, NULL);
	mu_assert_notnull(tc, "Channel creation failed");
	
	// Set channel as thread user data
	tc->consumer->user = tc;
	
	// Start the consumer thread
	r_th_start(tc->consumer);
	
	// Send multiple messages and collect promises
	RThreadChannelPromise *promises[5];
	for (int i = 1; i <= 5; i++) {
		// Create message with value i
		RThreadChannelMessage *msg = r_th_channel_message_new(tc, (const ut8*)&i, sizeof(int));
		mu_assert_notnull(msg, "Failed to create channel message");
		
		// Use query to get a promise for the response
		promises[i-1] = r_th_channel_query(tc, msg);
		mu_assert_notnull(promises[i-1], "Failed to create channel promise");
	}
	
	// Wait for all promises to be fulfilled (ensures all messages are processed)
	for (int i = 0; i < 5; i++) {
		RThreadChannelMessage *response = r_th_channel_promise_wait(promises[i]);
		mu_assert_notnull(response, "Failed to get response from promise");
		r_th_channel_message_free(response);
		r_th_channel_promise_free(promises[i]);
	}
	
	// Clean up
	r_th_channel_free(tc);
	
	// Verify consumer processed all messages (1+2+3+4+5 = 15)
	mu_assert_eq(consumer_count, 15, "Consumer didn't process all messages correctly");
	
	mu_end;
}

bool test_thread_channel_query(void) {
	// Reset test data
	consumer_count = 0;
	
	// Create a channel with consumer thread
	RThreadChannel *tc = r_th_channel_new(consumer_function, NULL);
	mu_assert_notnull(tc, "Channel creation failed");
	
	// Set channel as thread user data
	tc->consumer->user = tc;
	
	// Start the consumer thread
	r_th_start(tc->consumer);
	
	// Create a message with value 10
	int value = 10;
	RThreadChannelMessage *msg = r_th_channel_message_new(tc, (const ut8*)&value, sizeof(int));
	mu_assert_notnull(msg, "Failed to create channel message");
	
	// Send query and get promise
	RThreadChannelPromise *promise = r_th_channel_query(tc, msg);
	mu_assert_notnull(promise, "Failed to create channel promise");
	
	// Wait for response
	RThreadChannelMessage *response = r_th_channel_promise_wait(promise);
	mu_assert_notnull(response, "Failed to get response from promise");
	
	// Verify response content
	mu_assert_eq(*(int*)response->msg, 10, "Incorrect response value");
	
	// Clean up
	r_th_channel_message_free(response);
	r_th_channel_promise_free(promise);
	r_th_channel_free(tc);
	
	// Verify consumer processed the message
	mu_assert_eq(consumer_count, 10, "Consumer didn't process message correctly");
	
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_thread_channel_basic);
	mu_run_test(test_thread_channel_multiple_messages);
	mu_run_test(test_thread_channel_query);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}