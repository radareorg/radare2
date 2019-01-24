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
		ht_up_insert (ev->callbacks, (ut64)i, r_pvector_new (NULL));
	}
	ev->user = user;
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

static bool add_hook(void *cb, const ut64 k, const void *v) {
	RPVector *cbs = (RPVector *)v;
	r_return_val_if_fail (cbs, false);
	r_pvector_push (cbs, cb);
	return true;
}

R_API void r_event_hook(REvent *ev, int type, REventCallback cb) {
	r_return_if_fail (ev);
	if (type == R_EVENT_ALL) {
		ht_up_foreach (ev->callbacks, add_hook, cb);
	} else {
		RPVector *cbs = ht_up_find (ev->callbacks, type, NULL);
		add_hook (cb, 0, cbs);
	}
}

static bool del_hook(void *cb, const ut64 k, const void *v) {
	RPVector *cbs = (RPVector *)v;
	r_return_val_if_fail (cbs, false);
	r_pvector_remove_data (cbs, cb);
	return true;
}

R_API void r_event_unhook(REvent *ev, int type, REventCallback cb) {
	r_return_if_fail (ev);
	if (type == R_EVENT_ALL) {
		ht_up_foreach (ev->callbacks, del_hook, cb);
	} else {
		RPVector *cbs = ht_up_find (ev->callbacks, type, NULL);
		del_hook (cb, 0, cbs);
	}
}

R_API void r_event_send(REvent *ev, int type, void *data) {
	r_return_if_fail (ev && !ev->incall);

	void **it;
	RPVector *cbs = ht_up_find (ev->callbacks, type, NULL);
	r_return_if_fail (cbs);
	ev->incall = true;
	r_pvector_foreach (cbs, it) {
		REventCallback cb = *it;
		cb (ev, type, ev->user, data);
	}
	ev->incall = false;
}
