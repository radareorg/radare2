/* radare2 - MIT - Copyright 2018 - pancake */

#include <r_util.h>
#include <r_vector.h>

R_API REvent *r_event_new(void *user) {
	REvent *ev = R_NEW0 (REvent);
	if (!ev) {
		return NULL;
	}

	ev->callbacks = ht_up_new0 ();

	// skip R_EVENT_ALL and R_EVENT_MAX, so that they don't have a mapping
	// and if used in hook/unhook/send APIs will raise a warning
	ut64 i;
	for (i = 1; i < R_EVENT_MAX; ++i) {
		ht_up_insert (ev->callbacks, (ut64)i, r_vector_new (sizeof (REventCallbackHook), NULL, NULL));
	}
	ev->user = user;

	ev->hook_handle_next = 0;

	return ev;
}

R_API void r_event_free(REvent *ev) {
	if (!ev) {
		return;
	}
	ut64 i;
	for (i = 1; i < R_EVENT_MAX; ++i) {
		RVector *entry = ht_up_find (ev->callbacks, i, NULL);
		r_vector_free (entry);
	}
	ht_up_free (ev->callbacks);
	free (ev);
}

static bool add_hook(void *hook, const ut64 k, const void *v) {
	RVector *cbs = (RVector *)v;
	r_return_val_if_fail (cbs, false);
	r_vector_push (cbs, hook);
	return true;
}

R_API int r_event_hook(REvent *ev, int type, REventCallback cb, void *user) {
	r_return_val_if_fail (ev, -1);
	REventCallbackHook hook;
	hook.cb = cb;
	hook.user = user;
	hook.handle = ev->hook_handle_next++;
	if (type == R_EVENT_ALL) {
		ht_up_foreach (ev->callbacks, add_hook, &hook);
	} else {
		RPVector *cbs = ht_up_find (ev->callbacks, (ut64)type, NULL);
		add_hook (&hook, 0, cbs);
	}
	return hook.handle;
}

static bool del_hook(void *user, const ut64 k, const void *v) {
	int handle = (int)(intptr_t)user;
	RVector *cbs = (RVector *)v;
	r_return_val_if_fail (cbs, false);
	for (size_t i=0; i<cbs->len; i++) {
		REventCallbackHook *hook = r_vector_index_ptr (cbs, i);
		if (hook->handle == handle) {
			r_vector_remove_at (cbs, i, NULL);
			break;
		}
	}
	return true;
}

R_API void r_event_unhook(REvent *ev, int type, int handle) {
	r_return_if_fail (ev);
	if (type == R_EVENT_ALL) {
		ht_up_foreach (ev->callbacks, del_hook, (void *)(intptr_t )handle);
	} else {
		RPVector *cbs = ht_up_find (ev->callbacks, (ut64)type, NULL);
		del_hook ((void *)(intptr_t )handle, 0, cbs);
	}
}

R_API void r_event_send(REvent *ev, int type, void *data) {
	r_return_if_fail (ev && !ev->incall);
	RVector *cbs = ht_up_find (ev->callbacks, (ut64)type, NULL);
	r_return_if_fail (cbs);
	ev->incall = true;
	REventCallbackHook *hook;
	r_vector_foreach (cbs, hook) {
		hook->cb (ev, type, hook->user, data);
	}
	ev->incall = false;
}
