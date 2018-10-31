/* radare2 - MIT - Copyright 2018 - pancake */

#include <r_util.h>
#include <r_vector.h>

R_API REvent *r_event_new(void *user) {
	REvent *ev = R_NEW0 (REvent);
	if (!ev) {
		return NULL;
	}

	ev->callbacks = ht_new_size (R_EVENT_MAX, NULL, NULL, NULL);
	ev->callbacks->cmp = NULL;
	ev->callbacks->hashfn = NULL;
	ev->callbacks->dupkey = NULL;
	ev->callbacks->calcsizeK = NULL;
	// skip R_EVENT_ALL and R_EVENT_MAX, so that they don't have a mapping
	// and if used in hook/unhook/send APIs will raise a warning
	ut32 i;
	for (i = 1; i < R_EVENT_MAX; ++i) {
		ht_insert (ev->callbacks, (char *)(size_t)i, r_pvector_new (NULL));
	}
	ev->user = user;
	return ev;
}

R_API void r_event_free(REvent *ev) {
	if (!ev) {
		return;
	}
	ht_free (ev->callbacks);
	free (ev);
}

static bool add_hook(void *cb, const char *k, void *v) {
	RPVector *cbs = (RPVector *)v;
	r_return_val_if_fail (cbs, false);
	r_pvector_push (cbs, cb);
	return true;
}

R_API void r_event_hook(REvent *ev, REventType type, REventCallback cb) {
	r_return_if_fail (ev);
	if (type == R_EVENT_ALL) {
		ht_foreach (ev->callbacks, add_hook, cb);
	} else {
		RPVector *cbs = ht_find (ev->callbacks, (char *)(size_t)type, NULL);
		add_hook (cb, NULL, cbs);
	}
}

static bool del_hook(void *cb, const char *k, void *v) {
	RPVector *cbs = (RPVector *)v;
	r_return_val_if_fail (cbs, false);
	r_pvector_remove_data (cbs, cb);
	return true;
}

R_API void r_event_unhook(REvent *ev, REventType type, REventCallback cb) {
	r_return_if_fail (ev);
	if (type == R_EVENT_ALL) {
		ht_foreach (ev->callbacks, del_hook, cb);
	} else {
		RPVector *cbs = ht_find (ev->callbacks, (char *)(size_t)type, NULL);
		del_hook (cb, NULL, cbs);
	}
}

R_API void r_event_send(REvent *ev, REventType type, void *data) {
	r_return_if_fail (ev && !ev->incall);

	void **it;
	RPVector *cbs = ht_find (ev->callbacks, (char *)(size_t)type, NULL);
	r_return_if_fail (cbs);
	ev->incall = true;
	r_pvector_foreach (cbs, it) {
		REventCallback cb = *it;
		cb (ev, type, data);
	}
	ev->incall = false;
}
