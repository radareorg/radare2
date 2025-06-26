/* radare2 - LGPL - Copyright 2018-2025 - pancake */

#include <r_core.h>

#if 0
TODO:

- add more methods to "undo according to some conditions"
- undo all comments in current offfset
#endif

R_API RCoreUndo *r_core_undo_new(ut64 addr, const char *action, const char *revert) {
	RCoreUndo *cu = R_NEW (RCoreUndo);
	if (cu) {
		cu->action = strdup (action);
		cu->revert = strdup (revert);
		cu->tstamp = r_time_now ();
		cu->addr = addr;
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
	R_RETURN_IF_FAIL (core && cu);
	r_list_append (core->undos, cu);
	core->undoindex ++;
}

R_API void r_core_undo_pop(RCore *core) {
	R_RETURN_IF_FAIL (core);
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
		mustPrint = (cu->addr == cond->addr);
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
				r_cons_printf (core->cons, "%s @ 0x%"PFMT64x"\n", cu->revert, cu->addr);
			}
		}
	} else {
		ut64 now = r_time_now ();
		int i = 0;
		r_list_foreach (core->undos, iter, cu) {
			const char * arrow = (i == core->undoindex - 1)? "*": "-";
			r_cons_printf (core->cons, "%s 0x%08"PFMT64x" old:% ds cmd: %s (revert: %s)\n",
				arrow, cu->addr, (int)((now - cu->tstamp) / 1000000), cu->action, cu->revert);
			i++;
		}
	}
}

R_API void r_core_undo_down(RCore *core) {
	// undo
	int undos = r_list_length (core->undos);
	if (core->undoindex >= undos) {
		return;
	}
	core->undoindex++;
	RCoreUndo *undo = r_list_get_n (core->undos, core->undoindex - 1);
	if (undo) {
		r_core_cmd0 (core, undo->action);
	}
}

R_API void r_core_undo_up(RCore *core) {
	// redo
	const bool cmd_undo = r_config_get_b (core->config, "cmd.undo");
	r_config_set_b (core->config, "cmd.undo", false);
	core->undoindex--;
	if (core->undoindex < 0) {
		core->undoindex = 0;
		return;
	}
	RCoreUndo *undo = r_list_get_n (core->undos, core->undoindex);
	if (undo) {
		r_core_cmd0 (core, undo->revert);
	}
	r_config_set_b (core->config, "cmd.undo", cmd_undo);
}
