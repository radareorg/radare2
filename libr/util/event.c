/* radare2 - MIT - Copyright 2018-2024 - pancake */

#include <r_util.h>

static void ht_callback_free(HtUPKv *kv) {
	RVecREventHook_fini (kv->value);
}

R_API REvent *r_event_new(void *user) {
	REvent *ev = R_NEW0 (REvent);
	if (!ev) {
		return NULL;
	}
	ev->user = user;
	ut32 i;
	for (i = 0; i < R_EVENT_LAST; i++) {
		RVecREventHook_init (&ev->known_events[i]);
	}
	ev->lock = r_th_lock_new (false);
	ev->other_events = ht_up_new (NULL, ht_callback_free, NULL);
	if (R_UNLIKELY (!ev->other_events)) {
		r_event_free (ev);
		ev = NULL;
	}
	return ev;
}

R_API void r_event_free(REvent *ev) {
	if (!ev) {
		return;
	}
	r_th_lock_enter (ev->lock);
	ht_up_free (ev->other_events);
	RVecREventHook_fini (&ev->all_events);
	ut32 i;
	for (i = 0; i < R_EVENT_LAST; i++) {
		RVecREventHook_fini (&ev->known_events[i]);
	}
	r_th_lock_leave (ev->lock);
	r_th_lock_free (ev->lock);
	free (ev);
}

static RVecREventHook *get_cbs(REvent *ev, int type) {
	RVecREventHook *cbs = ht_up_find (ev->other_events, (ut64)type, NULL);
	if (!cbs) {
		cbs = R_NEW0 (RVecREventHook);
		RVecREventHook_init (cbs);
		if (R_LIKELY (cbs)) {
			ht_up_insert (ev->other_events, (ut64)type, cbs);
		}
	}
	return cbs;
}

R_API bool r_event_hook(REvent * R_NULLABLE ev, ut32 type, REventCallback cb, void *user) {
	if (!ev) {
		return false;
	}
	r_th_lock_enter (ev->lock);
	REventHook hook = { type, cb, user };

	if (type == R_EVENT_ALL) {
		RVecREventHook_push_back (&ev->all_events, &hook);
	} else {
		if (type < R_EVENT_LAST) {
			RVecREventHook_push_back (&ev->known_events[type], &hook);
		} else {
			RVecREventHook *cbs = get_cbs (ev, type);
			if (R_LIKELY (cbs)) {
				RVecREventHook_push_back (cbs, &hook);
			}
		}
	}
	r_th_lock_leave (ev->lock);
	return true;
}

static inline bool del_hook(RVecREventHook *hooks, const ut64 k, REventCallback cb) {
	REventHook *hook;
	size_t n = 0;
	R_VEC_FOREACH (hooks, hook) {
		if (hook->cb == cb) {
			RVecREventHook_remove (hooks, n);
			return true;
		}
		n++;
	}
	return false;
}

R_API bool r_event_unhook(REvent * R_NULLABLE ev, ut32 event_type, REventCallback cb) {
	bool res = false;
	if (!ev) {
		return res;
	}
	r_th_lock_enter (ev->lock);
	if (event_type == R_EVENT_ALL) {
		res = del_hook (&ev->all_events, 0, cb);
	} else if (event_type < R_EVENT_LAST) {
		res = del_hook (&ev->known_events[event_type], 0, cb);
	} else {
		RVecREventHook *hooks = ht_up_find (ev->other_events, (ut64)event_type, NULL);
		if (hooks != NULL) {
			res = del_hook (hooks, 0, cb);
		}
	}
	r_th_lock_leave (ev->lock);
	return res;
}

// r_event_send (core->ev, R_EVENT_ANALYSIS_START, "");
R_API void r_event_send(REvent * R_NULLABLE ev, ut32 event_type, void *data) {
	if (!ev || event_type == R_EVENT_ALL) {
		return;
	}
	REventHook *hook;
	r_th_lock_enter (ev->lock);

	R_VEC_FOREACH (&ev->all_events, hook) {
		hook->cb (ev, event_type, hook->user, data);
	}
	RVecREventHook *eh = NULL;
	if (R_LIKELY (event_type < R_EVENT_LAST)) {
		eh = &ev->known_events[event_type];
	} else {
		eh = ht_up_find (ev->other_events, (ut64)event_type, NULL);
	}
	if (R_LIKELY (eh)) {
		R_VEC_FOREACH (eh, hook) {
			hook->cb (ev, event_type, hook->user, data);
		}
	}
	r_th_lock_leave (ev->lock);
}
