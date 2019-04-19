/* radare2 - LGPL - Copyright 2018-2019 - pancake */

#include <r_core.h>

#if 0

TODO:

- add more methods to "undo according to some conditions"
- undo all comments in current offfset
#endif

R_API RCoreUndo *r_core_undo_new(ut64 offset, const char *action, const char *revert) {
	RCoreUndo *cu = R_NEW (RCoreUndo);
	if (cu) {
		cu->action = strdup (action);
		cu->revert = strdup (revert);
		cu->tstamp = r_sys_now ();
		cu->offset = offset;
	}
	return cu;
}

R_API void r_core_undo_free(RCoreUndo *cu) {
	if (cu) {
		free (cu->action);
		free (cu->revert);
	}
	free (cu);
}

R_API void r_core_undo_push(RCore *core, RCoreUndo *cu) {
	r_list_append (core->undos, cu);
}

R_API void r_core_undo_pop(RCore *core) {
	RCoreUndo *undo = r_list_pop (core->undos);
	if (undo) {
		r_core_cmd0 (core, undo->revert);
		r_core_undo_free (undo);
	}
}

R_API bool r_core_undo_condition(RCoreUndo *cu, RCoreUndoCondition *cond) {
	if (!cond) {
		return true;
	}
	bool mustPrint = false;
	if (cond->addr != UT64_MAX) {
		mustPrint = (cu->offset == cond->addr);
	}
	if (cond->minstamp) {
		mustPrint = (cu->tstamp >= cond->minstamp);
	}
	if (cond->glob) {
		mustPrint = r_str_glob (cu->action, cond->glob);
	}
	return mustPrint;
}

R_API void r_core_undo_print(RCore *core, int mode, RCoreUndoCondition *cond) {
	RCoreUndo *cu;
	RListIter *iter;
	if (mode) {
		r_list_foreach (core->undos, iter, cu) {
			if (r_core_undo_condition (cu, cond)) {
				r_cons_printf ("%s @ 0x%"PFMT64x"\n", cu->revert, cu->offset);
			}
		}
	} else {
		r_list_foreach (core->undos, iter, cu) {
			r_cons_printf ("0x%08"PFMT64x" %"PFMT64d"  %s (revert: %s)\n",
				cu->offset, cu->tstamp, cu->action, cu->revert);
		}
	}
}
