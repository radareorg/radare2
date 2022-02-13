/* radare - LGPL - Copyright 2022 - pancake */

#include <r_util.h>
#include <r_list.h>

R_API RThreadChannel *r_th_channel_new(void) {
	R_LOG_DEBUG ("r_th_channel_new");
	RThreadChannel *tc = R_NEW0 (RThreadChannel);
	if (tc) {
		tc->sem = r_th_sem_new (1);
		r_th_sem_wait (tc->sem); // busy because stack is empty
		tc->lock = r_th_lock_new (true);
		tc->stack = r_list_newf ((RListFree)r_th_channel_message_free);
		tc->responses = r_list_newf ((RListFree)r_th_channel_message_free);
	}
	return tc;
}

R_API void r_th_channel_free(RThreadChannel *tc) {
	R_LOG_DEBUG ("r_th_channel_free");
	if (tc) {
		r_list_free (tc->stack);
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
		cm->sem = r_th_sem_new (1);
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
		// r_ref (cm);
	}
	return cm;
}

R_API RThreadChannelMessage *r_th_channel_promise_wait(RThreadChannelPromise *promise) {
	// wait for a message to be delivered, find one with the same promise id
	// RThreadChannelMessage *message = r_th_channel_message_new (promise->tc, "x", 0);
	// append message into the queue
	while (true) {
		RListIter *iter;
		RThreadChannelMessage *res;
		r_th_lock_enter (promise->tc->lock);
		r_list_foreach (promise->tc->responses, iter, res) {
			if (res->id == promise->id) {
				r_list_split_iter (promise->tc->responses, iter);
				r_th_lock_leave (promise->tc->lock);
				return res;
			}
		}
		r_th_lock_leave (promise->tc->lock);
	}
	return NULL;
}

R_API RThreadChannelPromise *r_th_channel_promise_new(RThreadChannel *tc) {
	r_th_lock_enter (tc->lock);
	RThreadChannelPromise *promise = R_NEW0 (RThreadChannelPromise);
	promise->tc = tc;
	promise->id = tc->nextid;
	r_th_lock_leave (tc->lock);
	return promise;
}

// to be called only from the consumer thread
R_API void r_th_channel_post(RThreadChannel *tc, RThreadChannelMessage *cm) {
	r_th_lock_enter (tc->lock);
	// TODO: lock struct
	r_list_append (tc->responses, cm);
	r_th_sem_post (tc->sem);
	r_th_lock_leave (tc->lock);
}

R_API RThreadChannelPromise *r_th_channel_query(RThreadChannel *tc, RThreadChannelMessage *cm) {
	RThreadChannelPromise *promise = r_th_channel_promise_new (tc);
	promise->id = cm->id;
	r_th_channel_write (tc, cm);
	return promise;
}

// push a message to the stack
R_API RThreadChannelMessage *r_th_channel_write(RThreadChannel *tc, RThreadChannelMessage *cm) {
	R_LOG_DEBUG ("r_th_channel_write");
	r_return_val_if_fail (tc && cm, NULL);
	r_th_lock_enter (cm->lock);
		r_th_lock_enter (tc->lock);
		r_list_push (tc->stack, cm);
		r_th_lock_leave (tc->lock);
	//	r_th_lock_leave (cm->lock);
	r_th_lock_leave (cm->lock);
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
		//r_th_lock_leave (cm->lock);
		r_th_lock_free (cm->lock);
		free (cm);
	}
}

// pick a message from the stack
R_API RThreadChannelMessage *r_th_channel_read(RThreadChannel *tc) {
	R_LOG_DEBUG ("r_th_channel_read");
	r_th_lock_enter (tc->lock);
	RThreadChannelMessage *msg = r_list_pop_head (tc->stack);
	r_th_lock_leave (tc->lock);
	if (!msg) {
		return NULL;
	}
	// r_th_lock_enter (msg->lock);
	//r_th_sem_wait (msg->sem);
	//r_th_sem_post (tc->sem);
	return msg;
}
