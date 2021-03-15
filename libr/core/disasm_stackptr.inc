/* radare - LGPL - Copyright 2019 - pancake */

#define USE_BB_STACKPTR 0
#define USE_BB_LINEAR 1

static void ds_update_stackptr(RDisasmState *ds, RAnalOp *op) {
	if (!ds->show_stackptr) {
		return;
	}
	ds->ostackptr = ds->stackptr;
	switch (op->stackop) {
	
	case R_ANAL_STACK_RESET:
		ds->stackptr = 0;
		break;
	case R_ANAL_STACK_INC:
		ds->stackptr += op->stackptr;
		break;
	default:
		/* nothing to do here */
		break;
	}
	/* XXX if we reset the stackptr 'ret 0x4' has not effect.
	 * Use RAnalFunction->RAnalOp->stackptr? */
	if (op->type == R_ANAL_OP_TYPE_RET) {
		ds->stackptr = 0;
	}
}

static int _stackptr_range(RDisasmState *ds, ut64 addr, ut64 addr_end, int stackptr, int *ostackptr) {
	ut64 at = addr;
	ut64 end = addr_end;
	while (at < end) {
		int sz = 1;
		RAnalOp* op = r_core_anal_op (ds->core, at, 0);
		if (op) {
			*ostackptr = stackptr;
			switch (op->stackop) {
			case R_ANAL_STACK_RESET:
				stackptr = 0;
				break;
			case R_ANAL_STACK_INC:
				stackptr += op->stackptr;
				break;
			default:
				/* nothing to do here */
				break;
			}
			if (op->size > 0) {
				sz = op->size;
			}
			r_anal_op_free (op);
		}
		at += sz;
	} 
	return stackptr;
}

static int ds_ostackptr_atfcn(RDisasmState *ds, int *ostackptr) {
	if (!ds->show_stackptr) {
		return 0;
	}
#if USE_BB_LINEAR
	if (ds->at >= ds->fcn->addr) {
		return _stackptr_range (ds, ds->fcn->addr, ds->at, 0, ostackptr);
	}
	return ds->stackptr;
#else
	int stackptr = 0;
	// SLOW, recursive emulation is more correct, but slow to find paths
	// return stackptr;
	ut64 addr = ds->at;
	RList *paths = r_core_anal_graph_to (ds->core, addr, 2);
	if (paths) {
		RAnalBlock *bb;
		RList *path;
		RListIter *pathi;
		RListIter *bbi;
		r_list_foreach (paths, pathi, path) {
			r_list_foreach (path, bbi, bb) {
				ut64 end = bb->addr + bb->size;
				if (addr >= bb->addr && addr < bb->addr + bb->size) {
					end = addr;
				}
				stackptr = _stackptr_range (ds, bb->addr, end, stackptr, ostackptr);
			}
		}
		r_list_free (paths);
	}
	return stackptr;
#endif
}

static int ds_ostackptr_at(RDisasmState *ds, int *ostackptr) {
#if USE_BB_STACKPTR
	// XXX doesnt works because bb->stackptr returns the maximum increment of the bb instead of the initial stackptr value
	*ostackptr = ds->ostackptr;
	RAnalFunction *fcn = r_anal_get_fcn_in (ds->core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
	if (fcn) {
		RAnalBlock *bb = r_anal_fcn_bbget_in (ds->core->anal, fcn, ds->at);
		if (bb) {
			return bb->stackptr;
		} else {
			r_warn_if_reached ();
		}
	}
	return 0;
#else
	if (ds->fcn) {
		return ds_ostackptr_atfcn (ds, ostackptr);
	}
	*ostackptr = ds->ostackptr;
	return ds->stackptr;
#endif
}

static void ds_print_stackptr(RDisasmState *ds) {
	int ostackptr = 0;
	int stackptr = ds_ostackptr_at (ds, &ostackptr);
	if (ds->show_stackptr) {
		r_cons_printf ("%5d%s", stackptr,
			ds->analop.type == R_ANAL_OP_TYPE_CALL?">":
			ds->analop.stackop == R_ANAL_STACK_ALIGN? "=":
			stackptr > ostackptr? "+":
			stackptr < ostackptr? "-": " ");
		ds_update_stackptr (ds, &ds->analop);
	}
}
