/* radare - LGPL - Copyright 2010-2014 - nibble, pancake */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

#define FCN_DEPTH 32
#define DB a->sdb_fcns
#define EXISTS(x,y...) snprintf (key, sizeof(key)-1,x,##y),sdb_exists(DB,key)
#define SETKEY(x,y...) snprintf (key, sizeof (key)-1, x,##y);

R_API const char *r_anal_fcn_type_tostring(int type) {
	switch (type) {
	case R_ANAL_FCN_TYPE_NULL: return "null";
	case R_ANAL_FCN_TYPE_FCN: return "fcn";
	case R_ANAL_FCN_TYPE_LOC: return "loc";
	case R_ANAL_FCN_TYPE_SYM: return "sym";
	case R_ANAL_FCN_TYPE_IMP: return "imp";
	case R_ANAL_FCN_TYPE_ROOT: return "root";
	}
	return "unk";
}

R_API RAnalFunction *r_anal_fcn_new() {
	RAnalFunction *fcn = R_NEW0 (RAnalFunction);
	if (!fcn) return NULL;
	fcn->name = NULL;
	fcn->dsc = NULL;
	/* Function return type */
	fcn->rets = 0;
	fcn->size = 0;
	/* Function qualifier: static/volatile/inline/naked/virtual */
	fcn->fmod = R_ANAL_FQUALIFIER_NONE;
	/* Function calling convention: cdecl/stdcall/fastcall/etc */
	fcn->call = R_ANAL_CC_TYPE_NONE;
	/* Function attributes: weak/noreturn/format/etc */
	fcn->attr = NULL;
	fcn->addr = -1;
	fcn->bits = 0;
	//fcn->vars = r_anal_var_list_new ();
	fcn->refs = r_anal_ref_list_new ();
	fcn->xrefs = r_anal_ref_list_new ();
	fcn->bbs = r_anal_bb_list_new ();
	fcn->fingerprint = NULL;
	fcn->diff = r_anal_diff_new ();
	fcn->args = NULL;
	fcn->locs = NULL;
	//fcn->locals = NULL;
	return fcn;
}

R_API RList *r_anal_fcn_list_new() {
	RList *list = r_list_new ();
	if (!list) return NULL;
	list->free = &r_anal_fcn_free;
	return list;
}

R_API void r_anal_fcn_free(void *_fcn) {
	RAnalFunction *fcn = _fcn;
	if (!_fcn) return;
	fcn->size = 0;
	free (fcn->name);
	free (fcn->attr);
	r_list_free (fcn->refs);
	r_list_free (fcn->xrefs);
	r_list_free (fcn->vars);
	r_list_free (fcn->locs);
#if 0
	// XXX: some shared basic blocks make it crash. 
	// TODO: fix it with sdb
	r_list_free (fcn->bbs);
	//r_list_free (fcn->locals);
#endif
	free (fcn->fingerprint);
	r_anal_diff_free (fcn->diff);
	free (fcn->args);
	free (fcn);
}

R_API int r_anal_fcn_xref_add (RAnal *a, RAnalFunction *fcn, ut64 at, ut64 addr, int type) {
	RAnalRef *ref;
	if (!fcn || !a|| !(ref = r_anal_ref_new ()))
		return R_FALSE;
	// set global reference
	r_anal_xrefs_set (a, type=='s'?"string":type=='d'?"data":"code", addr, at);
	// set per-function reference
#if FCN_OLD
	ref->at = at; // from
	ref->addr = addr; // to
	ref->type = type;
	// TODO: ensure we are not dupping xrefs
	r_list_append (fcn->refs, ref);
#endif
#if FCN_SDB
	char key[1024], val[1024];
	SETKEY ("fcn.0x%08"PFMT64x".xrefs", fcn->addr);
	sdb_array_add_num (DB, key, at, 0);
#endif
	return R_TRUE;
}

R_API int r_anal_fcn_xref_del (RAnal *a, RAnalFunction *fcn, ut64 at, ut64 addr, int type) {
#if FCN_OLD
	RAnalRef *ref;
	RListIter *iter;
	/* No need for _safe loop coz we return immediately after the delete. */
	r_list_foreach (fcn->xrefs, iter, ref) {
		if ((type != -1 || type == ref->type)  &&
			(at == 0LL || at == ref->at) &&
			(addr == 0LL || addr == ref->addr)) {
				r_list_delete (fcn->xrefs, iter);
				return R_TRUE;
		}
	}
#endif
#if FCN_SDB
	//sdb_array_delete_num (DB, key, at, 0);
#endif
	return R_FALSE;
}

static RAnalBlock *bbget(RAnalFunction *fcn, ut64 addr) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr == addr)
			return bb;
		if (addr >= bb->addr && (addr < bb->addr+bb->size))
			return bb;
	}
	return NULL;
}

#if 0
static int bbsum(RAnalFunction *fcn) {
	RListIter *iter;
	RAnalBlock *bb;
	ut32 size = 0;
	r_list_foreach (fcn->bbs, iter, bb) {
		size += bb->size;
	}
	return size;
}
#endif

#define FITFCNSZ() {st64 n=bb->addr+bb->size-fcn->addr; \
	if(n<0) { fcn->addr += n; fcn->size = -n; } else \
	if(fcn->size<n)fcn->size=n; }
static int fcn_recurse(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut8 *buf, ut64 len, int depth) {
	int ret = R_ANAL_RET_END;
	ut8 bbuf[8096];
	int overlapped = 0;
	char *varname;
	RAnalOp op = {0};
	int oplen, idx = 0;
// add basic block
	RAnalBlock *bb = NULL;
	RAnalBlock *bbg = NULL;
	if (depth<1)
		return R_ANAL_RET_ERROR; // MUST BE TOO DEEP
	if (bbget (fcn, addr)) 
		return R_ANAL_RET_ERROR; // MUST BE DUP
	bb = r_anal_bb_new();
	bb->addr = addr;
	bb->size = 0;
	bb->jump = UT64_MAX;
	bb->fail = UT64_MAX;
	bb->type = 0; // TODO
	r_list_append (fcn->bbs, bb);

	while (idx < len) {
		r_anal_op_fini (&op);
		if (buf[idx]==buf[idx+1] && buf[idx]==0xff && buf[idx+2]==0xff) {
			FITFCNSZ();
			return R_ANAL_RET_ERROR;
		}
// check if opcode is in another basic block
// in that case we break
		if ((oplen = r_anal_op (anal, &op, addr+idx, buf+idx, len-idx)) < 1) {
			if (idx == 0) {
				VERBOSE_ANAL eprintf ("Unknown opcode at 0x%08"PFMT64x"\n", addr+idx);
				r_anal_op_fini (&op);
				FITFCNSZ();
				return R_ANAL_RET_END;
			} else break; // unspecified behaviour
		}
		if (idx>0 && !overlapped) {
			bbg = bbget (fcn, addr+idx);
			if (bbg && bbg != bb) {
				bb->jump = addr+idx;
				overlapped = 1;
				//return R_ANAL_RET_END;
			}
		}
		idx += oplen;
		if (!overlapped) {
			bb->size += oplen;
			fcn->ninstr++;
			FITFCNSZ();
		//	fcn->size += oplen; /// XXX. must be the sum of all the bblocks
		}
		/* TODO: Parse fastargs (R_ANAL_VAR_ARGREG) */
		switch (op.stackop) {
		case R_ANAL_STACK_INC:
			fcn->stack += op.val;
			break;
		// TODO: use fcn->stack to know our stackframe
		case R_ANAL_STACK_SET:
			if (op.ptr > 0) {
				varname = r_str_newf ("arg_%x", op.ptr);
				r_anal_var_add (anal, fcn, op.addr, op.ptr,
						R_ANAL_VAR_SCOPE_ARG|R_ANAL_VAR_DIR_IN, NULL, varname, 1);
			} else {
				varname = r_str_newf ("local_%x", -op.ptr);
				r_anal_var_add (anal, fcn, op.addr, -op.ptr,
						R_ANAL_VAR_SCOPE_LOCAL|R_ANAL_VAR_DIR_NONE, NULL, varname, 1);
			}
			free (varname);
			break;
		// TODO: use fcn->stack to know our stackframe
		case R_ANAL_STACK_GET:
			if (op.ptr > 0) {
				varname = r_str_newf ("arg_%x", op.ptr);
				r_anal_var_add (anal, fcn, op.addr, op.ptr,
						R_ANAL_VAR_SCOPE_ARG|R_ANAL_VAR_DIR_IN, NULL, varname, 0);
			} else {
				varname = r_str_newf ("local_%x", -op.ptr);
				r_anal_var_add (anal, fcn, op.addr, -op.ptr,
						R_ANAL_VAR_SCOPE_LOCAL|R_ANAL_VAR_DIR_NONE, NULL, varname, 0);
			}
			free (varname);
			break;
		}
		if (op.ptr && op.ptr != UT64_MAX && op.ptr != UT32_MAX) {
			// swapped parameters wtf //
			//if (!r_anal_fcn_xref_add (anal, fcn, op.ptr, op.addr, 'd')) {
			if (!r_anal_fcn_xref_add (anal, fcn, op.addr, op.ptr, 'd')) {
				r_anal_op_fini (&op);
				FITFCNSZ ();
				return R_ANAL_RET_ERROR;
			}
		}
		switch (op.type) {
		case R_ANAL_OP_TYPE_NOP:
			if ((addr+idx-oplen) == fcn->addr) {
				fcn->addr = bb->addr = addr + idx;
				continue;
			}
			break;
		case R_ANAL_OP_TYPE_JMP:
#if 1
			if (!r_anal_fcn_xref_add (anal, fcn, op.addr, op.jump,
					R_ANAL_REF_TYPE_CODE)) {
				FITFCNSZ();
				r_anal_op_fini (&op);
				return R_ANAL_RET_ERROR;
			}
#endif
			if (!overlapped) {
				bb->jump = op.jump;
				bb->fail = UT64_MAX;
			}
			// hardcoded jmp size // must be checked at the end wtf?
			if (op.jump>fcn->addr && op.jump<(fcn->addr+fcn->size)) {
				/* jump inside the same function */
				FITFCNSZ();
				return R_ANAL_RET_END;
			} else {
				if (op.jump < addr-512 && op.jump<addr) {
					FITFCNSZ();
					return R_ANAL_RET_END;
				}
				if (op.jump > addr+512) {
					FITFCNSZ();
					return R_ANAL_RET_END;	
				}
			}
			break;
			//
			//FITFCNSZ();
			//return R_ANAL_RET_END;
/// DO not follow jmps.. this is probably a bug ... 
#if 0
			anal->iob.read_at (anal->iob.io, op.jump, bbuf, sizeof (bbuf));
			FITFCNSZ();
			return fcn_recurse (anal, fcn, op.jump, bbuf, sizeof (bbuf), depth-1);
#endif
		case R_ANAL_OP_TYPE_CJMP:
			if (!overlapped) {
				bb->jump = op.jump;
				bb->fail = op.fail;
			}
			anal->iob.read_at (anal->iob.io, op.jump, bbuf, sizeof (bbuf));
			FITFCNSZ();
			fcn_recurse (anal, fcn, op.jump, bbuf, sizeof (bbuf), depth-1);
			anal->iob.read_at (anal->iob.io, op.fail, bbuf, sizeof (bbuf));
			FITFCNSZ();
			return fcn_recurse (anal, fcn, op.fail, bbuf, sizeof (bbuf), depth-1);
#if 0
		// do not add xrefs for cjmps?
				r_anal_op_fini (&op);
#endif
			break;
		case R_ANAL_OP_TYPE_CALL:
			if (!r_anal_fcn_xref_add (anal, fcn, op.addr, op.jump,
					op.type == R_ANAL_OP_TYPE_CALL?
					R_ANAL_REF_TYPE_CALL : R_ANAL_REF_TYPE_CODE)) {
				r_anal_op_fini (&op);
				//fcn->size = bbsum (fcn);
				FITFCNSZ ();
				return R_ANAL_RET_ERROR;
			}
			break;
		//case R_ANAL_OP_TYPE_HLT:
		case R_ANAL_OP_TYPE_TRAP:
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_RET:
			FITFCNSZ();
			r_anal_op_fini (&op);
			//fcn->size = bbsum (fcn);
			return R_ANAL_RET_END;
		}
	}
	r_anal_op_fini (&op);
	FITFCNSZ ();
	return ret;
}

R_API int r_anal_fcn(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut8 *buf, ut64 len, int reftype) {
	fcn->size = 0;
	fcn->type = (reftype==R_ANAL_REF_TYPE_CODE)?
			R_ANAL_FCN_TYPE_LOC: R_ANAL_FCN_TYPE_FCN;
	
	if (fcn->addr == UT64_MAX) fcn->addr = addr;

	if (anal->cur && anal->cur->fcn){
		int result = anal->cur->fcn(anal, fcn, addr, buf, len, reftype);
		if (anal->cur->custom_fn_anal) return result;
	}
	
	//if (len>16)
	//	len -= 16; // XXX: hack to avoid buffer overflow by reading >64 bytes..
	return fcn_recurse (anal, fcn, addr, buf, len, FCN_DEPTH);
}

// TODO: need to implement r_anal_fcn_remove(RAnal *anal, RAnalFunction *fcn);
R_API int r_anal_fcn_insert(RAnal *anal, RAnalFunction *fcn) {
	RAnalFunction *f = r_anal_fcn_find (anal, fcn->addr,
		R_ANAL_FCN_TYPE_ROOT);
	if (f) return R_FALSE;
#if USE_NEW_FCN_STORE
	r_listrange_add (anal->fcnstore, fcn);
	// HUH? store it here .. for backweird compatibility
#endif
#if ANAL_FCN_SDB
#if 0
	// override bits, size, 
	fcn.<offset>=name,size,type
fcn.<offset>.bbs
	fcn.name.<name>=<offset>
#endif
	sdb_set (DB, "fcn.0x080", "", 0);
#endif
	r_list_append (anal->fcns, fcn);
	return R_TRUE;
}

R_API int r_anal_fcn_add(RAnal *a, ut64 addr, ut64 size, const char *name, int type, RAnalDiff *diff) {
	int append = 0;
	RAnalFunction *fcn = r_anal_fcn_find (a, addr, R_ANAL_FCN_TYPE_ROOT);
	if (fcn == NULL) {
		if (!(fcn = r_anal_fcn_new ()))
			return R_FALSE;
		append = 1;
	}
	fcn->addr = addr;
	fcn->size = size;
	free (fcn->name);
	fcn->name = strdup (name);
	fcn->type = type;
	if (diff) {
		fcn->diff->type = diff->type;
		fcn->diff->addr = diff->addr;
		R_FREE (fcn->diff->name);
		if (diff->name)
			fcn->diff->name = strdup (diff->name);
	}
#if FCN_SDB
	char key[128];
	SETKEY ("fcn.0x%08"PFMT64x, addr);
	sdb_set (DB, key, "TODO", 0); // TODO: add more info here
#endif
	return append? r_anal_fcn_insert (a, fcn): R_TRUE;
}

R_API int r_anal_fcn_del_locs(RAnal *anal, ut64 addr) {
	RListIter *iter, *iter2;
	RAnalFunction *fcn, *f = r_anal_fcn_find (anal, addr,
		R_ANAL_FCN_TYPE_ROOT);
#if USE_NEW_FCN_STORE
#warning TODO: r_anal_fcn_del_locs not implemented for newstore
#endif
	if (!f) return R_FALSE;
	r_list_foreach_safe (anal->fcns, iter, iter2, fcn) {
		if (fcn->type != R_ANAL_FCN_TYPE_LOC)
			continue;
		if (fcn->addr >= f->addr && fcn->addr < (f->addr+f->size))
			r_list_delete (anal->fcns, iter);
	}
	r_anal_fcn_del (anal, addr);
	return R_TRUE;
}

R_API int r_anal_fcn_del(RAnal *a, ut64 addr) {
	if (addr == UT64_MAX) {
#if USE_NEW_FCN_STORE
		r_listrange_free (a->fcnstore);
		a->fcnstore = r_listrange_new ();
#else
		r_list_free (a->fcns);
		if (!(a->fcns = r_anal_fcn_list_new ()))
			return R_FALSE;
#endif
	} else {
#if USE_NEW_FCN_STORE
		// XXX: must only get the function if starting at 0?
		RAnalFunction *f = r_listrange_find_in_range (a->fcnstore, addr);
		if (f) r_listrange_del (a->fcnstore, f);
#else
		RAnalFunction *fcni;
		RListIter *iter, *iter_tmp;
		r_list_foreach_safe (a->fcns, iter, iter_tmp, fcni) {
			if (addr >= fcni->addr && addr < fcni->addr+fcni->size) {
				r_list_delete (a->fcns, iter);
			}
		}
#endif
	}
	return R_TRUE;
}

R_API RAnalFunction *r_anal_fcn_find(RAnal *anal, ut64 addr, int type) {
#if USE_NEW_FCN_STORE
	// TODO: type is ignored here? wtf.. we need more work on fcnstore
	//if (root) return r_listrange_find_root (anal->fcnstore, addr);
	RAnalFunction *f = r_listrange_find_in_range (anal->fcnstore, addr);
	return (f->addr == addr)? f: NULL;
#else
	RAnalFunction *fcn, *ret = NULL;
	RListIter *iter;
	if (type == R_ANAL_FCN_TYPE_ROOT) {
		r_list_foreach (anal->fcns, iter, fcn) {
			if (addr == fcn->addr)
				return fcn;
		}
		return NULL;
	}
	r_list_foreach (anal->fcns, iter, fcn) {
		if (!type || (fcn->type & type)) {
			if (addr == fcn->addr || (ret == NULL && 
			   ((addr > fcn->addr) && (addr < fcn->addr+fcn->size))))
				ret = fcn;
		}
	}
	return ret;
#endif
}

R_API RAnalFunction *r_anal_fcn_find_name(RAnal *anal, const char *name) {
	RAnalFunction *fcn = NULL;
	RListIter *iter;
	r_list_foreach (anal->fcns, iter, fcn) {
		if (!strcmp (name, fcn->name))
			return fcn;
	}
	return NULL;
}

/* rename RAnalFunctionBB.add() */
R_API int r_anal_fcn_add_bb(RAnalFunction *fcn, ut64 addr, ut64 size, ut64 jump, ut64 fail, int type, RAnalDiff *diff) {
	RAnalBlock *bb = NULL, *bbi;
	RListIter *iter;
	int append = 0, mid = 0;

	r_list_foreach (fcn->bbs, iter, bbi) {
		if (addr == bbi->addr) {
			bb = bbi;
			mid = 0;
			break;
		} else
		if (addr > bbi->addr && addr < bbi->addr+bbi->size)
			mid = 1;
	}
	if (mid)
		return R_FALSE;
	if (bb == NULL) {
		if (!(bb = r_anal_bb_new ()))
			return R_FALSE;
		append = 1;
	}
	bb->addr = addr;
	bb->size = size;
	bb->jump = jump;
	bb->fail = fail;
	bb->type = type;
	if (diff) {
		bb->diff->type = diff->type;
		bb->diff->addr = diff->addr;
		R_FREE (bb->diff->name);
		if (diff->name)
			bb->diff->name = strdup (diff->name);
	}
	if (append) r_list_append (fcn->bbs, bb);
	return R_TRUE;
}

// TODO: rename fcn_bb_split()
R_API int r_anal_fcn_split_bb(RAnalFunction *fcn, RAnalBlock *bb, ut64 addr) {
	RAnalBlock *bbi;
#if R_ANAL_BB_HAS_OPS
	RAnalOp *opi;
#endif
	RListIter *iter;

	r_list_foreach (fcn->bbs, iter, bbi) {
		if (addr == bbi->addr)
			return R_ANAL_RET_DUP;
		if (addr > bbi->addr && addr < bbi->addr + bbi->size) {
			r_list_append (fcn->bbs, bb);
			bb->addr = addr+bbi->size;
			bb->size = bbi->addr + bbi->size - addr;
			bb->jump = bbi->jump;
			bb->fail = bbi->fail;
			bb->conditional = bbi->conditional;

			bbi->size = addr - bbi->addr;
			bbi->jump = addr;
			bbi->fail = -1;
			bbi->conditional = R_FALSE;
			if (bbi->type&R_ANAL_BB_TYPE_HEAD) {
				bb->type = bbi->type^R_ANAL_BB_TYPE_HEAD;
				bbi->type = R_ANAL_BB_TYPE_HEAD;
			} else {
				bb->type = bbi->type;
				bbi->type = R_ANAL_BB_TYPE_BODY;
			}
#if R_ANAL_BB_HAS_OPS
			if (bbi->ops) {
				r_list_foreach (bbi->ops, iter, opi) {
					if (opi->addr >= addr) {
						/* Remove opi from bbi->ops without free()ing it. */
						r_list_split (bbi->ops, opi);
						bbi->ninstr--;
						r_list_append (bb->ops, opi);
						bb->ninstr++;
					}
				}
			}
#endif
			return R_ANAL_RET_END;
		}
	}
	return R_ANAL_RET_NEW;
}

// TODO: rename fcn_bb_overlap()
R_API int r_anal_fcn_overlap_bb(RAnalFunction *fcn, RAnalBlock *bb) {
	RAnalBlock *bbi;
	RListIter *iter;
#if R_ANAL_BB_HAS_OPS
	RListIter *iter_tmp;
	RAnalOp *opi;
#endif

	r_list_foreach (fcn->bbs, iter, bbi)
		if (bb->addr+bb->size > bbi->addr && bb->addr+bb->size <= bbi->addr+bbi->size) {
			bb->size = bbi->addr - bb->addr;
			bb->jump = bbi->addr;
			bb->fail = -1;
			bb->conditional = R_FALSE;
			if (bbi->type & R_ANAL_BB_TYPE_HEAD) {
				bb->type = R_ANAL_BB_TYPE_HEAD;
				bbi->type = bbi->type^R_ANAL_BB_TYPE_HEAD;
			} else bb->type = R_ANAL_BB_TYPE_BODY;
#if R_ANAL_BB_HAS_OPS
			/* We can reuse iter because we return before the outer loop. */
			r_list_foreach_safe (bb->ops, iter, iter_tmp, opi) {
				if (opi->addr >= bbi->addr) {
			//		eprintf ("Must delete opi %p\n", iter);
					r_list_delete (bb->ops, iter);
				}
			}
#endif
			//r_list_unlink (bb->ops, opi);
			r_list_append (fcn->bbs, bb);
			return R_ANAL_RET_END;
		}
	return R_ANAL_RET_NEW;
}

R_API int r_anal_fcn_cc(RAnalFunction *fcn) {
	struct r_anal_bb_t *bbi;
	RListIter *iter;
	int ret = 0, retbb;

	r_list_foreach (fcn->bbs, iter, bbi) {
		retbb = ((bbi->type & R_ANAL_BB_TYPE_LAST))? 1: 0;
		ret += bbi->conditional + retbb;
	}
	return ret;
}

R_API RAnalVar *r_anal_fcn_get_var(RAnalFunction *fs, int num, int type) {
	RAnalVar *var;
	RListIter *iter;
	int count = 0;
	// vars are sorted by delta in r_anal_var_add()
	r_list_foreach (fs->vars, iter, var) {
		//if (type & var->type) /* What we need to use here? */
			if (count++ == num)
				return var;
	}
	return NULL;
}

R_API char *r_anal_fcn_to_string(RAnal *a, RAnalFunction* fs) {
	int i;
	char *sign;
	RAnalVar *arg, *ret;
	if (fs->type != R_ANAL_FCN_TYPE_FCN || fs->type != R_ANAL_FCN_TYPE_SYM)
		return NULL;
	ret = r_anal_fcn_get_var (fs, 0, R_ANAL_VAR_SCOPE_RET);
	sign = ret? r_str_newf ("%s %s (", ret->name, fs->name):
		r_str_newf ("void %s (", fs->name);
	/* FIXME: Use RAnalType instead */
	for (i=0; ; i++) {
		if (!(arg = r_anal_fcn_get_var (fs, i,
				R_ANAL_VAR_SCOPE_ARG|R_ANAL_VAR_SCOPE_ARGREG)))
			break;
#if 0
// TODO: implement array support using sdb
		if (arg->type->type == R_ANAL_TYPE_ARRAY)
			sign = r_str_concatf (sign, i?", %s %s:%02x[%d]":"%s %s:%02x[%d]",
				arg->type, arg->name, arg->delta, arg->type->custom.a->count);
		else 
#endif
		sign = r_str_concatf (sign, i?", %s %s:%02x":"%s %s:%02x",
			arg->type, arg->name, arg->delta);
	}
	return (sign = r_str_concatf (sign, ");"));
}

// TODO: This function is not fully implemented
/* set function signature from string */
R_API int r_anal_str_to_fcn(RAnal *a, RAnalFunction *f, const char *sig) {
	char *str; //*p, *q, *r

	if (!a || !f || !sig) {
		eprintf ("r_anal_str_to_fcn: No function received\n");
		return R_FALSE;
	}

	/* Add 'function' keyword */
	str = malloc(strlen(sig) + 10);
	strcpy(str, "function ");
	strcat(str, sig);

	/* TODO: Improve arguments parsing */
/*
	RAnalType *t;
	t = r_anal_str_to_type(a, str);
	str = strdup (sig);

	// TODO : implement parser
	//r_list_destroy (fs->vars);
	//set: fs->vars = r_list_new ();
	//set: fs->name
	eprintf ("ORIG=(%s)\n", sig);
	p = strchr (str, '(');
	if (!p) goto parsefail;
	*p = 0;
	q = strrchr (str, ' ');
	if (!q) goto parsefail;
	*q = 0;
	printf ("RET=(%s)\n", str);
	printf ("NAME=(%s)\n", q+1);
	// set function name
	free (f->name);
	f->name = strdup (q+1);
	// set return value
	// TODO: simplify this complex api usage
	r_anal_var_add (a, f, 0LL, 0,
			R_ANAL_VAR_SCOPE_RET|R_ANAL_VAR_DIR_OUT, t, "ret", 1);

	// parse arguments
	for (i=arg=0,p++;;p=q+1,i++) {
		q = strchr (p, ',');
		if (!q) {
			q = strchr (p, ')');
			if (!q) break;
		}
		*q = 0;
		p = r_str_chop (p);
		r = strrchr (p, ' ');
		if (!r) goto parsefail;
		*r = 0;
		r = r_str_chop (r+1);
		printf ("VAR %d=(%s)(%s)\n", arg, p, r);
		// TODO : increment arg by var size
		if ((var = r_anal_fcn_get_var (f, i, R_ANAL_VAR_SCOPE_ARG|R_ANAL_VAR_SCOPE_ARGREG))) {
			free (var->name); var->name = strdup(r);
			// FIXME: add cparse function
			free (var->type); var->type = r_anal_str_to_type(p);
		} else r_anal_var_add (a, f, 0LL, arg, R_ANAL_VAR_SCOPE_ARG|R_ANAL_VAR_DIR_IN, p, r, 0);
		arg++;
	}
	// r_anal_fcn_set_var (fs, 0, R_ANAL_VAR_DIR_OUT, );
	free (str);
*/
	return R_TRUE;

	//parsefail:
	//free (str);
	//eprintf ("Function string parse fail\n");
	//return R_FALSE;
}

R_API RAnalFunction *r_anal_get_fcn_at(RAnal *anal, ut64 addr) {
	RAnalFunction *fcni;
	RListIter *iter;
//eprintf ("DEPRECATED: get-at\n");
	r_list_foreach (anal->fcns, iter, fcni)
		//if (fcni->addr == addr)
		if (addr >= fcni->addr && addr < (fcni->addr+fcni->size))
			return fcni;
	return NULL;
}

/* getters */
R_API RList* r_anal_fcn_get_refs (RAnalFunction *anal) { return anal->refs; }
R_API RList* r_anal_fcn_get_xrefs (RAnalFunction *anal) { return anal->xrefs; }
R_API RList* r_anal_fcn_get_vars (RAnalFunction *anal) { return anal->vars; }
R_API RList* r_anal_fcn_get_bbs (RAnalFunction *anal) { return anal->bbs; }

R_API int r_anal_fcn_is_in_offset (RAnalFunction *fcn, ut64 addr) {
	return (addr >= fcn->addr &&  addr < (fcn->addr+fcn->size));
}

R_API int r_anal_fcn_count (RAnal *anal, ut64 from, ut64 to) {
	int n = 0;
	RAnalFunction *fcni;
	RListIter *iter;
	r_list_foreach (anal->fcns, iter, fcni)
		if (fcni->addr >= from && fcni->addr < to)
			return n++;
	return n;
}
