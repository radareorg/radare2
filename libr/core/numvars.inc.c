// R2R db/cmd/numvars

static ut64 getref(RCore *core, int n, char t, int type) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, 0);
	if (!fcn) {
		return UT64_MAX;
	}
	if (n < 0) {
		n = 0;
	}
	RVecAnalRef *anal_refs = (t == 'r')
		? r_anal_function_get_refs (fcn)
		: r_anal_function_get_xrefs (fcn);
	int i = 0;
	if (anal_refs) {
		RAnalRef *r;
		R_VEC_FOREACH (anal_refs, r) {
			if (r->type == type) {
				if (i == n) {
					ut64 addr = r->addr;
					RVecAnalRef_free (anal_refs);
					return addr;
				}
				i++;
			}
		}
	}
	RVecAnalRef_free (anal_refs);
	return UT64_MAX;
}

static ut64 invalid_numvar(RCore *core, const char *str) {
	core->num->nc.errors ++;
	core->num->nc.calc_err = str;
	return 0;
}

static ut64 numvar_instruction_prev(RCore *core, int n, bool *ok) {
	if (ok) {
		*ok = true;
	}
	// N forward instructions
	int i;
	if (n < 1) {
		R_LOG_ERROR ("Invalid negative value");
		n = 1;
	}
	int numinstr = n;
	// N previous instructions
	ut64 addr = core->addr;
	ut64 val = addr;
	if (r_core_prevop_addr (core, core->addr, numinstr, &addr)) {
		val = addr;
	} else {
		ut8 data[32];
		addr = core->addr;
		const int mininstrsize = r_anal_archinfo (core->anal, R_ARCH_INFO_MINOP_SIZE);
		for (i = 0; i < numinstr; i++) {
			ut64 prev_addr = r_core_prevop_addr_force (core, addr, 1);
			if (prev_addr == UT64_MAX) {
				prev_addr = addr - mininstrsize;
			}
			if (prev_addr == UT64_MAX || prev_addr >= core->addr) {
				break;
			}
			RAnalOp op = {0};
			r_anal_op (core->anal, &op, prev_addr, data,
				sizeof (data), R_ARCH_OP_MASK_BASIC);
			if (op.size < mininstrsize) {
				op.size = mininstrsize;
			}
			val -= op.size;
			r_anal_op_fini (&op);
			addr = prev_addr;
		}
	}
	return val;
}

static ut64 numvar_instruction_next(RCore *core, ut64 addr, int n, bool *ok) {
	RAnalOp op;
	// N forward instructions
	ut8 data[32];
	int i;
	ut64 val = addr;
	for (i = 0; i < n; i++) {
		r_io_read_at (core->io, val, data, sizeof (data));
		r_anal_op_init (&op);
		int ret = r_anal_op (core->anal, &op, val, data,
			sizeof (data), R_ARCH_OP_MASK_BASIC);
		if (ret < 1) {
			R_LOG_DEBUG ("cannot decode at 0x%08"PFMT64x, val);
		}
		val += op.size;
		r_anal_op_fini (&op);
	}
	if (ok) {
		*ok = true;
	}
	return val;

}

static ut64 numvar_instruction(RCore *core, const char *str, bool *ok) {
#if 0
* `$j` -> `$ij` jump destination
* `$f` -> `$if` fail destination
* `$i` -> `$in` next instruction (WIP)
* `$l` -> `$is` opcode length (RFC) why not use `s` instead?
* `$m` -> `$ir` memory opcode reference address
* `$v` -> `$iv` opcode immediate (RFC)
#endif
	const char ch0 = *str;
	int count = 1;
	if (ch0) {
		const char ch1 = str[1];
		if (ch1 == ':') {
			count = r_num_math (NULL, str + 2);
		} else if (ch1 == '{') {
			count = r_num_math (NULL, str + 2);
		} else if (isdigit (ch1)) {
			count = r_num_math (NULL, str + 1);
		} else if (ch1) {
			return invalid_numvar (core, "expected :,{ after $i?");
		}
	}
	if (ch0 == 'n') { // "$in"
		return numvar_instruction_next (core, core->addr, count, ok);
	}
	if (ch0 == 'p') { // "$ip"
		return numvar_instruction_prev (core, count, ok);
	}
	if (ch0 == 's') { // "$is"
		return numvar_instruction_next (core, 0, count, ok);
	}
	if (count != 1) {
		return invalid_numvar (core, "expected :,{ after $i?");
	}
	if (ok) {
		*ok = true;
	}
	RAnalOp op;
	r_anal_op_init (&op);
	r_anal_op (core->anal, &op, core->addr, core->block, core->blocksize, R_ARCH_OP_MASK_BASIC);
	r_anal_op_fini (&op); // we don't need strings or pointers, just values, which are not nullified in fini
	switch (ch0) {
	case 'j': // "$ij" instruction jump
		return op.jump;
	case 'f': // "$if" instruction fail
		return op.fail;
#if 0
	// already implemented above
	case 's': // "$is" instruction size
		return op.size;
#endif
	case 'r': // "$ir" instruction reference
		return op.ptr;
	case 'v': // "$iv" instruction value
		return op.val;
		break;
	case 'e':
		return r_anal_op_is_eob (&op);
	default:
		if (ok) {
			*ok = false;
		}
		break;
	}
	return invalid_numvar (core, "invalid $i?");
}

static ut64 numvar_k(RCore *core, const char *str, bool *ok) {
	if (!str[2]) {
		return invalid_numvar (core, "Usage: $k:key or $k{key}");
	}
	char *bptr = strdup (str + 3);
	if (str[2] == ':') {
		// do nothing
	} else if (str[2] == '{') {
		char *ptr = strchr (bptr, '}');
		if (!ptr) {
			free (bptr);
			return invalid_numvar (core, "missing closing brace");
		}
		*ptr = '\0';
	} else {
		free (bptr);
		return invalid_numvar (core, "Expected '{' or ':' after 'k'");
	}
	char *out = sdb_querys (core->sdb, NULL, 0, bptr);
	if (R_STR_ISNOTEMPTY (out)) {
		if (strstr (out, "$k{")) {
			free (bptr);
			free (out);
			return invalid_numvar (core, "Recursivity is not permitted here");
		}
		if (ok) {
			*ok = true;
		}
		// XXX RNum.math is not reentrant, so we hack this to fix breaking expression
		RNum nn = {0};
		memcpy (&nn, core->num, sizeof (RNum));
		free (bptr);
		ut64 r = r_num_math (&nn, out);
		free (out);
		return r;
	}
	free (bptr);
	free (out);
	return invalid_numvar (core, "unknown $k{key}");
}

static ut64 numvar_section(RCore *core, const char *str, bool *ok) {
	char ch0 = *str;
	char *name = NULL;
	if (ch0) {
		const char ch1 = str[1];
		if (ch0 == ':') {
			name = strdup (str + 1);
			ch0 = 0;
		} else if (ch1 == ':') {
			name = strdup (str + 2);
		} else if (ch0 == '{') {
			ch0 = 0;
			name = strdup (str + 1);
			char *ch = strchr (name, '}');
			if (ch) {
				*ch = 0;
			} else {
				free (name);
				return invalid_numvar (core, "missing } in $S");
			}
		} else if (ch1 == '{') {
			name = strdup (str + 2);
			char *ch = strchr (name, '}');
			if (ch) {
				*ch = 0;
			} else {
				free (name);
				return invalid_numvar (core, "missing } in $S");
			}
			// invalid
		}
	}
	RBinObject *bo = r_bin_cur_object (core->bin);
	if (!bo) {
		free (name);
		return invalid_numvar (core, "cant reference sections without a bin object");
	}
	RBinSection *s = NULL;
	if (name) {
		ut64 at = r_num_get (NULL, name);
		// TODO check numerrors
		if (at && at != UT64_MAX) {
			s = r_bin_get_section_at (bo, at, true);
		} else {
			// resolve section by name
			RListIter *it;
			RBinSection *sec;
			r_list_foreach (bo->sections, it, sec) {
				if (!strcmp (sec->name, name)) {
					s = sec;
					break;
				}
			}
			if (!s) {
				r_list_foreach (bo->sections, it, sec) {
					if (strstr (sec->name, name)) {
						s = sec;
						break;
					}
				}
			}
		}
		R_FREE (name);
	} else {
		s = r_bin_get_section_at (bo, core->addr, true);
	}
	if (!s) {
		return invalid_numvar (core, "cant find section");
	}
	if (ok) {
		*ok = true;
	}
	switch (ch0) {
	case 0: // "$S"
	case 'B': // "$SB"
		return s->vaddr;
	case 'S': // "$SS"
	case 's': // "$SS"
		return s->size;
	case 'D': // "$SD"
	case 'd': // "$SD"
		return core->addr - s->vaddr;
	case 'E': // "$SE"
	case 'e': // "$SE"
		return s->vaddr + s->size;
	}
	return invalid_numvar (core, "unknown $S subvar");
}

static ut64 numvar_bb(RCore *core, const char *str, bool *ok) {
	char ch0 = *str;
	char *name = NULL;
	if (ch0) {
		const char ch1 = str[1];
		if (ch0 == ':') {
			name = strdup (str + 1);
			ch0 = 0;
		} else if (ch1 == ':') {
			name = strdup (str + 2);
		} else if (ch0 == '{') {
			ch0 = 0;
			name = strdup (str + 1);
			char *ch = strchr (name, '}');
			if (ch) {
				*ch = 0;
			} else {
				free (name);
				return invalid_numvar (core, "missing } in $B");
			}
		} else if (ch1 == '{') {
			name = strdup (str + 2);
			char *ch = strchr (name, '}');
			if (ch) {
				*ch = 0;
			} else {
				free (name);
				return invalid_numvar (core, "missing } in $B");
			}
			// invalid
		}
	}
	int nth = -1;
	RAnalBlock *bb = NULL;
	if (name) {
		if (ch0 == 'C') {
			// index cases $BC:0 $BC:1 ...
			nth = atoi (name);
		} else {
			RNum nn = {0};
			memcpy (&nn, core->num, sizeof (RNum));
			ut64 at = r_num_get (&nn, name);
			R_FREE (name);
			// TODO check numerrors
			if (!at || at == UT64_MAX) {
				return invalid_numvar (core, "cant find basic block");
			}
			// bb = r_anal_get_block_at (core->anal, at); // only works at the bb addr
			bb = r_anal_bb_from_offset (core->anal, at);
		}
		R_FREE (name);
	} else {
		bb = r_anal_bb_from_offset (core->anal, core->addr);
		// bb = r_anal_get_block_at (core->anal, core->addr);
	}
	if (!bb) {
		return invalid_numvar (core, "cant find basic block");
	}
	if (ok) {
		*ok = true;
	}
	switch (ch0) {
	/* function bounds (uppercase) */
	case 0:
	case 'B': return bb->addr;
	case 'D': return core->addr - bb->addr;
	case 'E': return bb->addr + bb->size;
	case 'S': return bb->size;
	case 'I':
	case 'i': return bb->ninstr;
	case 'J':
	case 'j': return bb->jump;
	case 'F':
	case 'f': return bb->fail;
	case 'C': // cases
		  if (bb->switch_op) {
			  if (nth != -1) {
				  RAnalCaseOp *op = (RAnalCaseOp *)r_list_get_n (bb->switch_op->cases, nth);
				  if (op) {
					  return op->addr;
				  }
			  } else {
				  return r_list_length (bb->switch_op->cases);
			  }
		  }
		  return 0;
	//	  return invalid_numvar (core, "no switch case in this block");
	}
	return invalid_numvar (core, "unknown $B subvar");
}

static ut64 numvar_debug(RCore *core, const char *str, bool *ok) {
	char ch0 = *str;
	char *name = NULL;
	if (ch0) {
		if (ch0 == 'A') {
			return r_debug_get_baddr (core->dbg, NULL);
		}
		const char ch1 = str[1];
		if (ch0 == ':') {
			name = strdup (str + 1);
			ch0 = 0;
		} else if (ch1 == ':') {
			name = strdup (str + 2);
		} else if (ch0 == '{') {
			ch0 = 0;
			name = strdup (str + 1);
			char *ch = strchr (name, '}');
			if (ch) {
				*ch = 0;
			} else {
				free (name);
				return invalid_numvar (core, "missing } in $S");
			}
		} else if (ch1 == '{') {
			name = strdup (str + 2);
			char *ch = strchr (name, '}');
			if (ch) {
				*ch = 0;
			} else {
				free (name);
				return invalid_numvar (core, "missing } in $S");
			}
			// invalid
		}
	}
	RDebugMap *dmap = NULL;
	RDebugMap *map;
	RListIter *iter;
	r_debug_map_sync (core->dbg);
	if (name) {
		ut64 at = r_num_get (NULL, name);
		// TODO check numerrors
		if (at && at != UT64_MAX) {
			r_list_foreach (core->dbg->maps, iter, map) {
				if (at >= map->addr && at < map->addr_end) {
					dmap = map;
					break;
				}
			}
		} else {
			r_list_foreach (core->dbg->maps, iter, map) {
				if (at >= map->addr && at < map->addr_end) {
					dmap = map;
					break;
				}
			}
		}
		R_FREE (name);
	} else {
		const ut64 at = core->addr;
		r_list_foreach (core->dbg->maps, iter, map) {
			if (at >= map->addr && at < map->addr_end) {
				dmap = map;
				break;
			}
		}
	}
	if (!dmap) {
		return invalid_numvar (core, "cant find debug map");
	}
	if (ok) {
		*ok = true;
	}
	switch (ch0) {
	case 0: // "$S"
	case 'B': // "$SB"
		return dmap->addr;
	case 'S': // "$SS"
	case 's': // "$SS"
		return dmap->size;
	case 'D': // "$SD"
	case 'd': // "$SD"
		return core->addr - dmap->addr;
	case 'E': // "$SE"
	case 'e': // "$SE"
		return dmap->addr + dmap->size;
	}
	return invalid_numvar (core, "unknown $S subvar");
}

typedef struct {
	const char *name;
	RIOMap *map;
} MapLoopData;

static bool mapscb(void *user, void *data, ut32 id) {
	MapLoopData *mld = (void *)user;
	RIOMap *map = (RIOMap *)mld;
	if (map) {
		if (!strcmp (mld->name, map->name)) {
			mld->map = map;
			return false;
		}
	}
	return true;
}
static ut64 numvar_maps(RCore *core, const char *str, bool *ok) {
	char ch0 = *str;
	char *name = NULL;
	if (ch0) {
		const char ch1 = str[1];
		if (ch0 == ':') {
			name = strdup (str + 1);
			ch0 = 0;
		} else if (ch1 == ':') {
			name = strdup (str + 2);
		} else if (ch0 == '{') {
			ch0 = 0;
			name = strdup (str + 1);
			char *ch = strchr (name, '}');
			if (ch) {
				*ch = 0;
			} else {
				free (name);
				return invalid_numvar (core, "missing } in $M");
			}
		} else if (ch1 == '{') {
			name = strdup (str + 2);
			char *ch = strchr (name, '}');
			if (ch) {
				*ch = 0;
			} else {
				free (name);
				return invalid_numvar (core, "missing } in $M");
			}
			// invalid
		}
	}
	RIOMap *map = NULL;
	if (name) {
		ut64 at = r_num_get (NULL, name);
		// TODO check numerrors
		if (at && at != UT64_MAX) {
			map = r_io_map_get_at (core->io, at);
		} else {
			MapLoopData mld = { .name = name };
			r_id_storage_foreach (&core->io->maps, mapscb, &mld);
			map = mld.map;
		}
		R_FREE (name);
	} else {
		map = r_io_map_get_at (core->io, core->addr);
	}
	if (!map) {
		return invalid_numvar (core, "cant find a map");
	}
	if (ok) {
		*ok = true;
	}
	switch (ch0) {
	case 0:
	case 'b':
	case 'B': return r_io_map_begin (map);
	case 'd':
	case 'D': return core->addr - r_io_map_begin (map);
	case 'e':
	case 'E': return r_io_map_end (map);
	case 'S': return r_io_map_size (map);
	case 'M': // "MM"
		  {
			  ut64 lower = r_io_map_begin (map);
			  const int clear_bits = 16;
			  lower >>= clear_bits;
			  lower <<= clear_bits;
			  return lower;
		  }
	}
	return invalid_numvar (core, "unknown $M subvar");
}

static ut64 numvar_function(RCore *core, const char *str, bool *ok) {
	char ch0 = *str;
	char *name = NULL;
	int nth = -1;
	if (ch0) {
		const char ch1 = str[1];
		if (ch0 == ':') {
			name = strdup (str + 1);
			ch0 = 0;
		} else if (ch1 == ':') {
			name = strdup (str + 2);
		} else if (ch0 == '{') {
			ch0 = 0;
			name = strdup (str + 1);
			char *ch = strchr (name, '}');
			if (ch) {
				*ch = 0;
			} else {
				free (name);
				return invalid_numvar (core, "missing } in $F");
			}
		} else if (ch1 == '{') {
			name = strdup (str + 2);
			char *ch = strchr (name, '}');
			if (ch) {
				*ch = 0;
			} else {
				free (name);
				return invalid_numvar (core, "missing } in $F");
			}
			// invalid
		}
		if (name && isdigit (*name)) {
			nth = atoi (name);
			R_FREE (name);
		}
	}
	RAnalFunction *fcn = NULL;
	if (name) {
		ut64 at = r_num_get (NULL, name);
		// TODO check numerrors
		if (at && at != UT64_MAX) {
			RList *fcns = r_anal_get_functions_in (core->anal, at);
			if (fcns && r_list_length (fcns) > 0) {
				fcn = r_list_get_n (fcns, 0);
			}
			r_list_free (fcns);
//			fcn = r_anal_get_function_in (core->anal, at);
		} else {
			fcn = r_anal_get_function_byname (core->anal, name);
			R_FREE (name);
		}
		R_FREE (name);
	} else {
		RList *fcns = r_anal_get_functions_in (core->anal, core->addr);
		if (fcns && r_list_length (fcns) > 0) {
			fcn = r_list_get_n (fcns, 0);
		}
		r_list_free (fcns);
	}
	if (!fcn) {
		return invalid_numvar (core, "cant find function");
	}
	if (ok) {
		*ok = true;
	}
	switch (ch0) {
	case 0:
	case 'b':
	case 'B': return fcn->addr; // begin
	case 'd':
	case 'D': return core->addr - fcn->addr; // begin
	case 'e':
	case 'E': return r_anal_function_max_addr (fcn); // end
	case 's': return r_anal_function_linear_size (fcn);
	case 'S': return r_anal_function_realsize (fcn);
	case 'i': return fcn->ninstr;
	case 'I': return fcn->ninstr;
	// refs/xrefs
	case 'c':
	case 'C': // $FC nth call
		if (nth < 0) {
			return invalid_numvar (core, "missing or invalid nth index for $FC");
		}
		return getref (core, nth, 'r', R_ANAL_REF_TYPE_CALL);
	case 'r':
	case 'R':
		if (nth < 0) {
			return invalid_numvar (core, "missing or invalid nth index for $FR");
		}
		return getref (core, nth, 'r', R_ANAL_REF_TYPE_DATA);
	case 'j':
	case 'J': // $FJ nth jump
		if (nth < 0) {
			return invalid_numvar (core, "missing or invalid nth index for $FJ");
		}
		return getref (core, nth, 'r', R_ANAL_REF_TYPE_CODE);
	case 'x':
	case 'X': // $FX nth xref
		if (nth < 0) {
			return invalid_numvar (core, "missing or invalid nth index for $FX");
		}
		return getref (core, nth, 'x', R_ANAL_REF_TYPE_CALL);
	}
	return invalid_numvar (core, "unknown $F subvar");
}

static ut64 numvar_flag(RCore *core, const char *str, bool *ok) {
#if 0
* `$f` -> address of closest flag
  * `$fs` -> flag size
  * `$fd` -> distance to closest flag (delta offset)
  * `$fe` -> end of flag
* `$f{sym.main}` -> address of sym.main flag. same as `sym.main`
  * `$fs{sym.main}` -> size of sym.main
  * `$fd{sym.puts}` -> sym.puts-$$
  * `$fe{sym.main}` -> address where sym.main flag ends
#endif
	char ch0 = *str;
	char *name = NULL;
	if (ch0) {
		const char ch1 = str[1];
		if (ch0 == ':') {
			name = strdup (str + 1);
			ch0 = 0;
		} else if (ch1 == ':') {
			name = strdup (str + 2);
		} else if (ch0 == '{') {
			ch0 = 0;
			name = strdup (str + 1);
			char *ch = strchr (name, '}');
			if (ch) {
				*ch = 0;
			} else {
				free (name);
				return invalid_numvar (core, "missing } in $f");
			}
		} else if (ch1 == '{') {
			name = strdup (str + 2);
			char *ch = strchr (name, '}');
			if (ch) {
				*ch = 0;
			} else {
				free (name);
				return invalid_numvar (core, "missing } in $f");
			}
			// invalid
		}
	}
	RFlagItem *fi = NULL;
	ut64 addr = core->addr;
	if (name) {
		fi = r_flag_get (core->flags, name);
		if (!fi) {
			// XXX RNum.math is not reentrant, so we hack this to fix breaking expression
			RNum nn = {0};
			memcpy (&nn, core->num, sizeof (RNum));
			addr = r_num_math (&nn, name);
		}
		free (name);
	}
	if (!fi) {
		fi = r_flag_get_in (core->flags, addr);
		if (!fi) {
			fi = r_flag_get_at (core->flags, core->addr, true);
		}
	}
	if (!fi) {
		return invalid_numvar (core, "cant find flag");
	}
	switch (ch0) {
	case 0: // "$f"
	case 'b': // "$fb"
		return core->addr;
	case 's': // "$fs"
		return fi->size;
	case 'd': // "$fd"
		return core->addr - fi->addr;
	case 'e': // "$fe"
		return fi->addr + fi->size;
	}
	return invalid_numvar (core, "unknown $f subvar");
}

static ut64 numvar_dollar(RCore *core, const char *str, bool *ok) {
	if (!strcmp (str, "$$")) {
		return core->addr;
	}
	if (!strcmp (str, "$$c")) {
		if (core->print->cur_enabled) {
			return core->addr + core->print->cur;
		}
		return core->addr;
	}
	if (!strcmp (str, "$$$")) {
		return core->prompt_addr;
	}
	if (!strcmp (str, "$$$c")) {
		if (core->print->cur_enabled) {
			return core->prompt_addr + core->print->cur;
		}
		return core->prompt_addr;
	}
	return invalid_numvar (core, str);
}

static ut64 num_callback(RNum *userptr, const char *str, bool *ok) {
	RCore *core = (RCore *)userptr; // XXX ?
	char *ptr, *bptr, *out = NULL;
	RFlagItem *flag;
	ut64 ret = 0;

	RAnalOp op;
	r_anal_op_init (&op);

	if (ok) {
		*ok = false;
	}
	switch (*str) {
	case '.':
		if (str[1] == '.') {
			if (ok) {
				*ok = true;
			}
			return r_num_tail (core->num, core->addr, str + 2);
		}
		if (core->num->nc.curr_tok == '+') {
			ut64 off = core->num->nc.number_value.n;
			if (!off) {
				off = core->addr;
			}
			RAnalFunction *fcn = r_anal_get_function_at (core->anal, off);
			if (fcn) {
				if (ok) {
					*ok = true;
				}
				ut64 dst = r_anal_function_get_label (fcn, str + 1);
				if (dst == UT64_MAX) {
					dst = fcn->addr;
				}
				st64 delta = dst - off;
				if (delta < 0) {
					core->num->nc.curr_tok = '-';
					delta = off - dst;
				}
				return delta;
			}
		}
		break;
	case '[':
{
		ut64 n = 0LL;
		int refsz = core->rasm->config->bits / 8;
		const char *p = strchr (str, ':');
		if (p) {
			refsz = atoi (str + 1);
			str = p;
		}
		// push state
		if (!str[0] || !str[1]) {
			return 0;
		}
		const char *q;
		char *o = strdup (str + 1);
		if (o) {
			q = r_num_math_index (core->num, NULL);
			if (q) {
				if (r_str_replace_char (o, ']', 0)>0) {
					n = r_num_math (core->num, o);
					if (core->num->nc.errors) {
						return 0;
					}
					r_num_math_index (core->num, q);
				}
			}
			free (o);
		}
		// pop state
		if (ok) {
			*ok = true;
		}
		ut8 buf[sizeof (ut64)] = {0};
		(void)r_io_read_at (core->io, n, buf, R_MIN (sizeof (buf), refsz));
		const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->rasm->config);
		switch (refsz) {
		case 8:
			return r_read_ble64 (buf, be);
		case 4:
			return r_read_ble32 (buf, be);
		case 2:
			return r_read_ble16 (buf, be);
		case 1:
			return r_read_ble8 (buf);
		default:
			R_LOG_ERROR ("Invalid reference size: %d (%s)", refsz, str);
			return 0LL;
		}
}
		break;
	case '$':
		if (ok) {
			*ok = true;
		}
		switch (str[1]) {
		case 'i': // "$i"
			return numvar_instruction (core, str + 2, ok);
		case '.': // can use pc, sp, a0, a1, ...
			return r_debug_reg_get (core->dbg, str + 2);
		case 'k': // "$k{ey}" "$k:ey"
			return numvar_k (core, str, ok);
		case '{': // ${ev} eval var
			bptr = strdup (str + 2);
			ptr = strchr (bptr, '}');
			if (ptr) {
				ptr[0] = '\0';
				ut64 ret = r_config_get_i (core->config, bptr);
				free (bptr);
				return ret;
			} else {
				free (bptr);
				return invalid_numvar (core, "missing } in ${}");
			}
			break;
		case 'c': // $c console width
			return r_cons_get_size (core->cons, NULL);
		case 'd': // $d - same as 'op'
			if (core->io && core->io->desc) {
				return core->io->desc->fd;
			}
			return 0;
		case 'r': // $r
			if (str[2] == '{' || str[2] == ':') {
				bptr = strdup (str + 3);
				if (str[2] == '{') {
					ptr = strchr (bptr, '}');
					if (!ptr) {
						free (bptr);
						break;
					}
					*ptr = 0;
				}
				if (r_config_get_b (core->config, "cfg.debug")) {
					if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false)) {
						RRegItem *r = r_reg_get (core->dbg->reg, bptr, -1);
						if (r) {
							free (bptr);
							return r_reg_get_value (core->dbg->reg, r);
						}
					}
				} else {
					RRegItem *r = r_reg_get (core->anal->reg, bptr, -1);
					if (r) {
						free (bptr);
						return r_reg_get_value (core->anal->reg, r);
					}
				}
				free (bptr);
				return 0; // UT64_MAX;
			}
			int rows;
			(void)r_cons_get_size (core->cons, &rows);
			return rows;
		case 'p': // $p
			return r_sys_getpid ();
		case 'P': // $P
			return core->dbg->pid > 0 ? core->dbg->pid : 0;
		case 'f': // $f flags
			return numvar_flag (core, str + 2, ok);
		case 'M': // $M map address
			return numvar_maps (core, str + 2, ok);
		case 'b': // "$b" block size
			return core->blocksize;
		case 's': // $s file size
			if (str[2] == '{') { // $s{flag} flag size
				bptr = strdup (str + 3);
				ptr = strchr (bptr, '}');
				if (!ptr) {
					// invalid json
					free (bptr);
					break;
				}
				*ptr = '\0';
				RFlagItem *flag = r_flag_get (core->flags, bptr);
				ret = flag? flag->size: 0LL; // flag
				free (bptr);
				free (out);
				return ret;
			} else if (core->io->desc) {
				return r_io_fd_size (core->io, core->io->desc->fd);
			}
			return 0LL;
		case 'w': // $w word size
			return r_config_get_i (core->config, "asm.bits") / 8;
		case 'S': // $S section offset
			return numvar_section (core, str + 2, ok);
		case 'D': // $D
			return numvar_debug (core, str + 2, ok);
		case '?': // $?
			return core->num->value; // rc;
		case '$': // $$ offset
			return numvar_dollar (core, str, ok);
		case 'o': // $o
			{
				RBinSection *s = r_bin_get_section_at (r_bin_cur_object (core->bin), core->addr, true);
				return s ? core->addr - s->vaddr + s->paddr : core->addr;
			}
		case 'F': // $F function
			return numvar_function (core, str + 2, ok);
		case 'B': // $B basic blocks
			return numvar_bb (core, str + 2, ok);
		default:
			return invalid_numvar (core, str);
		}
		break;
	default:
		{
		const char str0 = *str;
		if (str0 >= 'A' || str0 == ':' || str0 == '_') {
			// NOTE: functions override flags
			RAnalFunction *fcn = r_anal_get_function_byname (core->anal, str);
			if (fcn) {
				if (ok) {
					*ok = true;
				}
				return fcn->addr;
			}
#if 0
			ut64 addr = r_anal_function_label_get (core->anal, core->addr, str);
			if (addr != 0) {
				ret = addr;
			} else {
				...
			}
#endif
			if ((flag = r_flag_get (core->flags, str))) {
				ret = flag->addr;
				if (ok) {
					*ok = true;
				}
				return ret;
			}

			// check for reg alias
			RRegItem *r = r_reg_get (core->dbg->reg, str, -1);
			if (r) {
				if (ok) {
					*ok = true;
				}
				ret = r_reg_get_value (core->dbg->reg, r);
				return ret;
			}
		}
		}
		break;
	}
	return ret;
}
