/* radare2 - MIT - Copyright 2018 - pancake */

#include <r_util.h>

R_API REvent *r_event_new(void *user) {
	REvent *ev = R_NEW0 (REvent);
	if (ev) {
		ev->callbacks = r_list_newf (NULL);
		ev->user = user;
	}
	return ev;
}

R_API void r_event_free(REvent *ev) {
	r_return_if_fail (ev);
	r_list_free (ev->callbacks);
	free (ev);
}

R_API void r_event_hook(REvent *ev, REventCallback cb) {
	r_return_if_fail (ev);
	r_list_append (ev->callbacks, cb);
}

R_API void r_event_unhook(REvent *ev, REventCallback cb) {
	r_return_if_fail (ev);
	r_list_delete_data (ev->callbacks, cb);
}

R_API void r_event_send(REvent *ev, int type, void *data) {
	r_return_if_fail (ev && !ev->incall);
	ev->incall = true;
	RListIter *iter;
	REventCallback cb;
	r_list_foreach (ev->callbacks, iter, cb) {
		cb (ev, type, data);
	}
	ev->incall = false;
}
