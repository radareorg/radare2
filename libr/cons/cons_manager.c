// Minimal synchronous Console Manager stub (Phase 3 scaffolding)
#include <r_cons.h>
#include "cons_manager.h"

R_API RConsManager *r_cons_manager_new(RCons *cons) {
	R_RETURN_VAL_IF_FAIL (cons, NULL);
	RConsManager *mgr = R_NEW0 (RConsManager);
	if (!mgr) {
		return NULL;
	}
	mgr->term_lock = r_th_lock_new (false);
	mgr->cons = cons;
	return mgr;
}

R_API void r_cons_manager_free(RConsManager *mgr) {
	if (!mgr) {
		return;
	}
	r_th_lock_free (mgr->term_lock);
	free (mgr);
}

R_API void r_cons_manager_enqueue_flush(RConsManager *mgr, RConsBuffer *buf, int flags, bool wait) {
	R_RETURN_IF_FAIL (mgr && mgr->cons && buf && buf->data);
	(void)flags;
	(void)wait;
	// Synchronous: lock terminal and flush using legacy r_cons_flush
	r_th_lock_enter (mgr->term_lock);
	RConsContext tmp = {0};
	tmp.buffer = buf->data;
	tmp.buffer_len = buf->len;
	tmp.buffer_sz = buf->len;
	tmp.pageable = false;
	RConsContext *saved = mgr->cons->context;
	r_cons_context_load (&tmp);
	r_cons_flush (mgr->cons);
	r_cons_context_load (saved);
	// After flush, reset frees responsibility: free the buffer memory
	free (buf->data);
	buf->data = NULL;
	buf->len = 0;
	r_th_lock_leave (mgr->term_lock);
}
