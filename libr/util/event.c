/* radare2 - MIT - Copyright 2018 - pancake */

#include <r_util.h>
#include <r_vector.h>

typedef struct r_event_callback_hook_t {
	REventCallback cb;
	void *user;
	int handle;
} REventCallbackHook;

static void ht_callback_free(HtUPKv *kv) {
	r_vector_free ((RVector *)kv->value);
}

R_API REvent *r_event_new(void *user) {
	REvent *ev = R_NEW0 (REvent);
	if (!ev) {
		return NULL;
	}

	ev->user = user;
	ev->next_handle = 0;
	ev->callbacks = ht_up_new (NULL, ht_callback_free, NULL);
	if (!ev->callbacks) {
		goto err;
	}
	r_vector_init (&ev->all_callbacks, sizeof (REventCallbackHook), NULL, NULL);
	return ev;
err:
	r_event_free (ev);
	return NULL;
}

R_API void r_event_free(REvent *ev) {
	if (!ev) {
		return;
	}
	ht_up_free (ev->callbacks);
	r_vector_clear (&ev->all_callbacks);
	free (ev);
}

static RVector *get_cbs(REvent *ev, int type) {
	RVector *cbs = ht_up_find (ev->callbacks, (ut64)type, NULL);
	if (!cbs) {
		cbs = r_vector_new (sizeof (REventCallbackHook), NULL, NULL);
		if (cbs) {
			ht_up_insert (ev->callbacks, (ut64)type, cbs);
		}
	}
	return cbs;
}

R_API REventCallbackHandle r_event_hook(REvent *ev, int type, REventCallback cb, void *user) {
	REventCallbackHandle handle = { 0 };
	REventCallbackHook hook;

	r_return_val_if_fail (ev, handle);
	hook.cb = cb;
	hook.user = user;
	hook.handle = ev->next_handle++;
	if (type == R_EVENT_ALL) {
		r_vector_push (&ev->all_callbacks, &hook);
	} else {
		RVector *cbs = get_cbs (ev, type);
		if (!cbs) {
			return handle;
		}
		r_vector_push (cbs, &hook);
	}
	handle.handle = hook.handle;
	handle.type = type;
	return handle;
}

static bool del_hook(void *user, const ut64 k, const void *v) {
	int handle = *(int *)user;
	RVector *cbs = (RVector *)v;
	REventCallbackHook *hook;
	size_t i;
	r_return_val_if_fail (cbs, false);
	r_vector_enumerate (cbs, hook, i) {
		if (hook->handle == handle) {
			r_vector_remove_at (cbs, i, NULL);
			break;
		}
	}
	return true;
}

R_API void r_event_unhook(REvent *ev, REventCallbackHandle handle) {
	r_return_if_fail (ev);
	if (handle.type == R_EVENT_ALL) {
		// try to delete it both from each list of callbacks and from
		// the "all_callbacks" vector
		ht_up_foreach (ev->callbacks, del_hook, &handle.handle);
		del_hook (&handle.handle, 0, &ev->all_callbacks);
	} else {
		RVector *cbs = ht_up_find (ev->callbacks, (ut64)handle.type, NULL);
		r_return_if_fail (cbs);
		del_hook (&handle.handle, 0, cbs);
	}
}

R_API void r_event_send(REvent *ev, int type, void *data) {
	REventCallbackHook *hook;
	r_return_if_fail (ev && !ev->incall);

	// send to both the per-type callbacks and to the all_callbacks
	ev->incall = true;
	r_vector_foreach (&ev->all_callbacks, hook) {
		hook->cb (ev, type, hook->user, data);
	}
	ev->incall = false;

	RVector *cbs = ht_up_find (ev->callbacks, (ut64)type, NULL);
	if (!cbs) {
		return;
	}
	ev->incall = true;
	r_vector_foreach (cbs, hook) {
		hook->cb (ev, type, hook->user, data);
	}
	ev->incall = false;
}
