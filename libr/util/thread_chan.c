/* radare - LGPL - Copyright 2022-2025 - pancake */

#define R_LOG_DISABLE 1
#include <r_util.h>
#include <r_list.h>

R_API RThreadChannel *r_th_channel_new(RThreadFunction consumer, void *user) {
	R_LOG_DEBUG ("r_th_channel_new");
	RThreadChannel *tc = R_NEW0 (RThreadChannel);
	if (!tc) {
		return NULL;
	}
	// Initialize semaphore with 0 permits - consumers will initially block
	// until a message is pushed to the queue
	tc->sem = r_th_sem_new (0);
	if (!tc->sem) {
		free (tc);
		return NULL;
	}
	// Create recursive lock for thread safety
	tc->lock = r_th_lock_new (true);
	if (!tc->lock) {
		r_th_sem_free (tc->sem);
		free (tc);
		return NULL;
	}
	// Initialize message queues
	tc->stack = r_list_newf ((RListFree)r_th_channel_message_free);
	tc->responses = r_list_newf ((RListFree)r_th_channel_message_free);
	if (!tc->stack || !tc->responses) {
		r_list_free (tc->stack);
		r_list_free (tc->responses);
		r_th_lock_free (tc->lock);
		r_th_sem_free (tc->sem);
		free (tc);
		return NULL;
	}
	// Create and start the consumer thread
	tc->consumer = r_th_new (consumer, user, 0);
	if (!tc->consumer) {
		r_list_free (tc->stack);
		r_list_free (tc->responses);
		r_th_lock_free (tc->lock);
		r_th_sem_free (tc->sem);
		free (tc);
		return NULL;
	}
    // Launch consumer to begin processing
    r_th_start (tc->consumer);
    return tc;
}

R_API void r_th_channel_free(RThreadChannel *tc) {
	R_LOG_DEBUG ("r_th_channel_free");
	if (tc) {
		r_th_break (tc->consumer);
		r_th_sem_post (tc->sem);
		r_th_wait (tc->consumer);
		r_th_free (tc->consumer);
		//
		r_list_free (tc->stack);
		r_list_free (tc->responses);
		r_th_sem_free (tc->sem);
		r_th_lock_free (tc->lock);
		free (tc);
	}
}

R_API RThreadChannelMessage *r_th_channel_message_new(RThreadChannel *tc, const ut8 *msg, int len) {
	R_LOG_DEBUG ("r_th_channel_message_new");
	// lock struct
	RThreadChannelMessage *cm = R_NEW0 (RThreadChannelMessage);
	if (cm) {
		cm->id = tc->nextid;
		cm->msg = r_mem_dup (msg, len);
		cm->len = len;
		// Initialize message semaphore to 0 so readers block until posted
		cm->sem = r_th_sem_new (0);
		// r_th_sem_wait (cm->sem); // busy because stack is empty
		cm->lock = r_th_lock_new (false); // locked here
	}
	return cm;
}

R_API RThreadChannelMessage *r_th_channel_message_read(RThreadChannel *tc, RThreadChannelMessage *cm) {
	R_LOG_DEBUG ("r_th_channel_message_read");
	if (cm) {
		eprintf ("wait\n");
		r_th_sem_wait (cm->sem);
		eprintf ("waited\n");
	} else {
		eprintf ("not waited\n");
		// Don't create a dangling reference
	}
	return cm;
}

R_API RThreadChannelMessage *r_th_channel_promise_wait(RThreadChannelPromise *promise) {
	// wait for a message to be delivered, find one with the same promise id
	// RThreadChannelMessage *message = r_th_channel_message_new (promise->tc, "x", 0);
	// append message into the queue
	if (!promise || !promise->tc) {
		R_LOG_ERROR ("Invalid promise or thread channel in r_th_channel_promise_wait");
		return NULL;
	}

	while (true) {
		RListIter *iter;
		RThreadChannelMessage *res;
		if (!r_th_lock_enter (promise->tc->lock)) {
			R_LOG_ERROR ("Failed to acquire lock in r_th_channel_promise_wait");
			break;
		}
		if (promise->tc->responses) {
			r_list_foreach (promise->tc->responses, iter, res) {
				if (res && res->id == promise->id) {
					r_list_split_iter (promise->tc->responses, iter);
					r_th_lock_leave (promise->tc->lock);
					return res;
				}
			}
		}
		r_th_lock_leave (promise->tc->lock);
		// Sleep briefly to avoid CPU spinning
		r_sys_usleep (1000);  // 1ms sleep between checks
	}
	return NULL;
}

R_API RThreadChannelPromise *r_th_channel_promise_new(RThreadChannel *tc) {
	r_th_lock_enter (tc->lock);
	RThreadChannelPromise *promise = R_NEW0 (RThreadChannelPromise);
	if (!promise) {
		r_th_lock_leave (tc->lock);
		return NULL;
	}
	promise->tc = tc;
	promise->id = tc->nextid++;
	r_th_lock_leave (tc->lock);
	return promise;
}

// to be called only from the consumer thread
R_API void r_th_channel_post(RThreadChannel *tc, RThreadChannelMessage *cm) {
    // Post a response from the consumer thread
    r_th_lock_enter (tc->lock);
    r_list_append (tc->responses, cm);
    r_th_lock_leave (tc->lock);
    // Signal any reader waiting on this message
    r_th_sem_post (cm->sem);
}

R_API RThreadChannelPromise *r_th_channel_query(RThreadChannel *tc, RThreadChannelMessage *cm) {
	RThreadChannelPromise *promise = r_th_channel_promise_new (tc);
	if (!promise) {
		return NULL;
	}
	promise->id = cm->id;
	r_th_channel_write (tc, cm);
	return promise;
}

// push a message to the stack
R_API RThreadChannelMessage *r_th_channel_write(RThreadChannel *tc, RThreadChannelMessage *cm) {
	R_LOG_DEBUG ("r_th_channel_write");
	if (!tc || !cm) {
		return NULL;
	}
	// Use consistent lock ordering to prevent deadlocks:
	// Always acquire tc->lock first, then cm->lock if needed
	r_th_lock_enter (tc->lock);
	// Add message to the stack while holding the channel lock
	r_list_push (tc->stack, cm);
	// Release channel lock
	r_th_lock_leave (tc->lock);
	// Signal that a message is available
	// This unblocks any consumer thread waiting on r_th_sem_wait
	r_th_sem_post (tc->sem);
	return cm;
}

R_API void r_th_channel_promise_free(RThreadChannelPromise *cp) {
	// xxx
	free (cp);
}

R_API void r_th_channel_message_free(RThreadChannelMessage *cm) {
	R_LOG_DEBUG ("r_th_channel_message_free");
	if (cm) {
		r_th_sem_post (cm->sem);
		r_th_sem_free (cm->sem);
		free (cm->msg);
		r_th_lock_free (cm->lock);
		free (cm);
	}
}

// pick a message from the stack
R_API RThreadChannelMessage *r_th_channel_read(RThreadChannel *tc) {
	R_LOG_DEBUG ("r_th_channel_read");
	if (!tc) {
		return NULL;
	}
	// Wait for a message to be available
	// This blocks until r_th_channel_write posts to the semaphore
	r_th_sem_wait (tc->sem);
	// Now that a message should be available, acquire the lock
	// to safely access the message queue
	r_th_lock_enter (tc->lock);
	// Pop the message from the head of the queue
	RThreadChannelMessage *msg = r_list_pop_head (tc->stack);
	// Release the lock
	r_th_lock_leave (tc->lock);
	if (!msg) {
		// This should not happen - if we got past the semaphore wait,
		// there should be a message. If there isn't, it's a logic error.
		R_LOG_ERROR ("Thread channel read: semaphore signaled but no message found");
	}
	return msg;
}
