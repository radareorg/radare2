/* radare - LGPL - Copyright 2022-2024 - pancake */

#include <r_anal.h>

R_API bool r_anal_tid_kill(RAnal *anal, int tid) {
	R_RETURN_VAL_IF_FAIL (anal, false);
	RListIter *iter;
	RAnalThread *th;
	r_list_foreach (anal->threads, iter, th) {
		if (th->id == tid) {
			if (tid == anal->thread) {
				RAnalThread *first = r_list_first (anal->threads);
				if (first) {
					r_anal_tid_select (anal, first->id);
				}
			}
			r_list_delete (anal->threads, iter);
			return true;
		}
	}
	return false;
}

// XXX deprecate R2_600. its unused and does nothing
R_API int r_anal_tid_usemap(RAnal *anal, int map) {
	// TODO
	return 0;
}

R_API int r_anal_tid_add(RAnal *anal, int map) {
	R_RETURN_VAL_IF_FAIL (anal, -1);
	if (map < 1) {
		// return -1;
	}
	RListIter *iter;
	RAnalThread *th;
	RAnalThread *at = R_NEW0 (RAnalThread);
	if (!at) {
		return -1;
	}
	at->map = map;
	int tid = 0;
	r_list_foreach (anal->threads, iter, th) {
		if (th->id > tid) {
			tid = th->id;
		}
	}
	tid++;
	at->reg = r_reg_clone (anal->reg);
	at->id = tid;
	at->birth = r_time_now ();
	r_list_append (anal->threads, at);
	return tid;
}

R_API RAnalThread *r_anal_tid_get(RAnal *anal, int tid) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	if (tid < 1) {
		return NULL;
	}
	RListIter *iter;
	RAnalThread *th;
	r_list_foreach (anal->threads, iter, th) {
		if (th->id == tid) {
			return th;
		}
	}
	return NULL;
}

R_API void r_anal_thread_free(RAnalThread *t) {
	free (t);
}

R_API bool r_anal_tid_select(RAnal *anal, int tid) {
	R_RETURN_VAL_IF_FAIL (anal, false);
	if (tid < 1) {
		return false;
	}
	RListIter *iter;
	RAnalThread *th;
	r_list_foreach (anal->threads, iter, th) {
		if (th->id == tid) {
			anal->thread = tid;
			RReg *or = anal->reg;
			if (th->reg) {
				r_ref (th->reg);
				anal->reg = th->reg;
			}
			r_unref (or);
			return true;
		}
	}
	return false;
}
