/* radare - MIT - Copyright 2024-2026 - pancake */

#define R_LOG_ORIGIN "prj"

#include "newprj.h"

static ut64 rprj_entry_remaining(RBuffer *b, ut64 next_entry) {
	const ut64 at = r_buf_at (b);
	return next_entry > at? next_entry - at: 0;
}

static bool rprj_entry_has(RBuffer *b, ut64 next_entry, ut64 len) {
	return rprj_entry_remaining (b, next_entry) >= len;
}

static void rprj_eval_load(RPrjCursor *cur, int mode, ut64 next_entry) {
	RBuffer *b = cur->b;
	RCore *core = cur->core;
	R2ProjectStringTable *st = cur->st;
	ut32 count = 0;
	if (!rprj_entry_has (b, next_entry, sizeof (count)) || !rprj_read_le32 (b, &count)) {
		R_LOG_WARN ("Truncated eval entry");
		return;
	}
	const ut64 bmax = rprj_entry_remaining (b, next_entry) / 8;
	if (count > bmax) {
		R_LOG_WARN ("Invalid eval record count %u", count);
		count = (ut32)bmax;
	}
	ut32 i;
	for (i = 0; i < count; i++) {
		ut32 k, v;
		if (!rprj_entry_has (b, next_entry, 8) || !rprj_read_le32 (b, &k) || !rprj_read_le32 (b, &v)) {
			R_LOG_WARN ("Truncated eval record %u/%u", i, count);
			break;
		}
		const char *name = rprj_st_get (st, k);
		const char *value = rprj_st_get (st, v);
		if (!name || !value) {
			R_LOG_WARN ("Invalid eval string index (%u,%u)", k, v);
			continue;
		}
		if (mode & R_CORE_NEWPRJ_MODE_LOG) {
			r_cons_printf (core->cons, "      %s = %s\n", name, value);
		}
		if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
			r_cons_printf (core->cons, "'e %s=%s\n", name, value);
		}
		if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
			const char *curval = r_config_get (core->config, name);
			if (curval && strcmp (curval, value)) {
				r_cons_printf (core->cons, "'e %s=%s\n", name, curval);
			}
		}
		if (mode & R_CORE_NEWPRJ_MODE_LOAD) {
			r_config_set (core->config, name, value);
		}
	}
}

static ut8 *rprj_find(RBuffer *b, ut32 type, ut32 *size) {
	r_buf_seek (b, sizeof (R2ProjectHeader), SEEK_SET);
	const ut64 last = r_buf_size (b);
	ut64 at = r_buf_at (b);
	*size = 0;
	while (r_buf_at (b) < last) {
		R2ProjectEntry entry = {0};
		if (!rprj_entry_read (b, &entry)) {
			R_LOG_ERROR ("find: Cannot read entry");
			break;
		}
		if (entry.size < sizeof (R2ProjectEntry) || entry.size > last - at) {
			R_LOG_ERROR ("invalid size");
			break;
		}
		if (entry.type == type) {
			const ut32 data_size = entry.size - sizeof (R2ProjectEntry);
			ut8 *buf = data_size? malloc (data_size): R_NEWS0 (ut8, 1);
			if (buf) {
				if (data_size && r_buf_read_at (b, at + sizeof (R2ProjectEntry), buf, data_size) != (st64)data_size) {
					free (buf);
					return NULL;
				}
				*size = data_size;
				return buf;
			}
			return NULL;
		}
		at += entry.size;
		r_buf_seek (b, at, SEEK_SET); // entry.size, SEEK_CUR);
	}
	return NULL;
}

static bool read_flag_extra_str(RPrjCursor *cur, ut64 next_entry, const char **out) {
	RBuffer *b = cur->b;
	ut32 idx;
	if (!rprj_entry_has (b, next_entry, sizeof (idx)) || !rprj_read_le32 (b, &idx)) {
		return false;
	}
	*out = rprj_st_get (cur->st, idx);
	return *out != NULL;
}

static bool read_flag_extras(RPrjCursor *cur, ut8 extras, ut64 next_entry, RPrjFlagExtras *fe) {
	if ((extras & RPRJ_FLAG_SPACE) && !read_flag_extra_str (cur, next_entry, &fe->space)) {
		return false;
	}
	if ((extras & RPRJ_FLAG_REALNAME) && !read_flag_extra_str (cur, next_entry, &fe->realname)) {
		return false;
	}
	if ((extras & RPRJ_FLAG_RAWNAME) && !read_flag_extra_str (cur, next_entry, &fe->rawname)) {
		return false;
	}
	if ((extras & RPRJ_FLAG_TYPE) && !read_flag_extra_str (cur, next_entry, &fe->type)) {
		return false;
	}
	if ((extras & RPRJ_FLAG_COLOR) && !read_flag_extra_str (cur, next_entry, &fe->color)) {
		return false;
	}
	if ((extras & RPRJ_FLAG_COMMENT) && !read_flag_extra_str (cur, next_entry, &fe->comment)) {
		return false;
	}
	if ((extras & RPRJ_FLAG_ALIAS) && !read_flag_extra_str (cur, next_entry, &fe->alias)) {
		return false;
	}
	return true;
}

static void rprj_diff_seen_addr(RList *seen, ut64 addr);
static void rprj_print_flag_script(RPrjCursor *cur, RFlagItem *fi);
static bool rprj_flag_differs(RFlag *flags, RFlagItem *fi, ut64 addr, ut64 size, RPrjFlagExtras *fe, ut8 extras);
static bool rprj_diff_flag_foreach_cb(RFlagItem *fi, void *user);

static void rprj_flag_load(RPrjCursor *cur, int mode, ut64 next_entry) {
	RCore *core = cur->core;
	RBuffer *b = cur->b;
	R2ProjectStringTable *st = cur->st;
	ut32 fcount = 0;
	if (!rprj_entry_has (b, next_entry, sizeof (fcount)) || !rprj_read_le32 (b, &fcount)) {
		R_LOG_WARN ("Truncated flag entry");
		return;
	}
	const ut64 bmax = rprj_entry_remaining (b, next_entry) / RPRJ_FLAG_SIZE;
	if (fcount > bmax) {
		R_LOG_WARN ("Invalid flag record count %u", fcount);
		fcount = (ut32)bmax;
	}
	RList *seen = (mode & R_CORE_NEWPRJ_MODE_DIFF)? r_list_newf (free): NULL;
	ut32 i;
	for (i = 0; i < fcount; i++) {
		if (!rprj_entry_has (b, next_entry, RPRJ_FLAG_SIZE)) {
			R_LOG_WARN ("Truncated flag record %u/%u", i, fcount);
			break;
		}
		R2ProjectFlag flag;
		if (!rprj_flag_read (b, &flag)) {
			R_LOG_WARN ("Truncated flag record %u/%u", i, fcount);
			break;
		}
		RPrjFlagExtras fe = {0};
		if (!read_flag_extras (cur, flag.extras, next_entry, &fe)) {
			R_LOG_WARN ("Truncated or invalid flag extras %u/%u", i, fcount);
			break;
		}
		const char *flag_name = rprj_st_get (st, flag.name);
		if (!flag_name) {
			R_LOG_WARN ("Invalid flag string index %u", flag.name);
			continue;
		}
		R2ProjectAddr addr = {
			.mod = flag.mod,
			.delta = flag.delta,
		};
		ut64 va = UT64_MAX;
		if (!rprj_project_addr_to_va (cur, &addr, &va)) {
			R_LOG_WARN ("Cannot resolve address for flag %s", flag_name);
			continue;
		}
		if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
			// flag names are sanitized by r_flag_set; meta fields may contain
			// arbitrary bytes and are intentionally skipped here until the
			// flag subcommands support a base64 form (like CCu).
			r_cons_printf (core->cons, fe.space? "'fs %s\n": "'fs *\n", fe.space);
			r_cons_printf (core->cons, "'f %s %u 0x%08"PFMT64x"\n",
				flag_name, flag.size, va);
		}
		if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
			RFlagItem *fi = r_flag_get (core->flags, flag_name);
			if (fi) {
				rprj_diff_seen_addr (seen, fi->id);
				if (rprj_flag_differs (core->flags, fi, va, flag.size, &fe, flag.extras)) {
					rprj_print_flag_script (cur, fi);
				}
			} else {
				r_cons_printf (core->cons, "'f- %s\n", flag_name);
			}
		}
		if (mode & R_CORE_NEWPRJ_MODE_LOAD) {
			RFlagItem *fi = fe.space
				? r_flag_set_inspace (core->flags, fe.space, flag_name, va, flag.size)
				: r_flag_set (core->flags, flag_name, va, flag.size);
			if (!fi) {
				continue;
			}
			// override autospace's prefix match with what the file encoded
			fi->space = fe.space? r_flag_space_get (core->flags, fe.space): NULL;
			fi->demangled = (flag.extras & RPRJ_FLAG_DEMANGLED);
			if (fe.realname) {
				r_flag_item_set_realname (core->flags, fi, fe.realname);
			}
			if (fe.rawname && strcmp (fe.rawname, flag_name)) {
				r_flag_item_set_rawname (core->flags, fi, fe.rawname);
			}
			if (fe.type) {
				r_flag_item_set_type (core->flags, fi, fe.type);
			}
			if (fe.color) {
				r_flag_item_set_color (core->flags, fi, fe.color);
			}
			if (fe.comment) {
				r_flag_item_set_comment (core->flags, fi, fe.comment);
			}
			if (R_STR_ISNOTEMPTY (fe.alias)) {
				r_flag_item_set_alias (core->flags, fi, fe.alias);
			}
		}
	}
	if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
		R2ProjectDiffCtx ctx = { cur, seen };
		r_flag_foreach (core->flags, rprj_diff_flag_foreach_cb, &ctx);
	}
	r_list_free (seen);
}

static bool rprj_function_is_registered(RAnal *anal, RAnalFunction *fcn) {
	if (!fcn) {
		return false;
	}
	RListIter *iter;
	RAnalFunction *it;
	RList *fcns = r_anal_get_fcns (anal);
	r_list_foreach (fcns, iter, it) {
		if (it == fcn) {
			return true;
		}
	}
	return false;
}

static RAnalFunction *rprj_function_get_registered(RAnal *anal, ut64 addr) {
	RAnalFunction *fcn = r_anal_get_function_at (anal, addr);
	if (rprj_function_is_registered (anal, fcn)) {
		return fcn;
	}
	if (fcn) {
		ht_up_delete (anal->ht_addr_fun, addr);
		if (fcn->name) {
			ht_pp_delete (anal->ht_name_fun, fcn->name);
		}
	}
	return NULL;
}

static void rprj_function_drop_stale_name(RAnal *anal, const char *name) {
	if (!name) {
		return;
	}
	bool found = false;
	RAnalFunction *fcn = ht_pp_find (anal->ht_name_fun, name, &found);
	if (found && !rprj_function_is_registered (anal, fcn)) {
		ht_pp_delete (anal->ht_name_fun, name);
		if (fcn) {
			ht_up_delete (anal->ht_addr_fun, fcn->addr);
		}
	}
}

static void rprj_block_load(RPrjCursor *cur, RAnalFunction *fcn, R2ProjectBlock *pbb, int mode, ut64 fcn_addr, RColor *colors, ut32 ncolors) {
	ut64 va = UT64_MAX;
	ut64 jump = UT64_MAX;
	ut64 fail = UT64_MAX;
	if (!rprj_project_addr_to_va (cur, &pbb->addr, &va)
			|| !rprj_project_addr_to_va (cur, &pbb->jump, &jump)
			|| !rprj_project_addr_to_va (cur, &pbb->fail, &fail)) {
		R_LOG_WARN ("Cannot resolve basic block for function %s", fcn? fcn->name: "?");
		return;
	}
	if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
		r_cons_printf (cur->core->cons, "'afb+ 0x%08"PFMT64x" 0x%08"PFMT64x" %"PFMT64u" 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
			fcn? fcn->addr: fcn_addr, va, pbb->size, jump, fail);
		if (pbb->color < ncolors) {
			RColor *color = colors + pbb->color;
			r_cons_printf (cur->core->cons, "'afbc rgb:%02x%02x%02x 0x%08"PFMT64x"\n",
				color->r, color->g, color->b, va);
		}
	}
	if (!(mode & R_CORE_NEWPRJ_MODE_LOAD) || !fcn || !pbb->size || pbb->size > ST32_MAX) {
		return;
	}
	RAnalBlock *bb = r_anal_function_bbget_at (cur->core->anal, fcn, va);
	if (!bb) {
		bb = r_anal_get_block_at (cur->core->anal, va);
		if (!bb) {
			bb = r_anal_create_block (cur->core->anal, va, pbb->size);
		}
		if (bb) {
			r_anal_function_add_block (fcn, bb);
		}
	}
	if (bb) {
		r_anal_block_set_size (bb, pbb->size);
		bb->jump = jump;
		bb->fail = fail;
		if (pbb->color < ncolors) {
			bb->color = colors[pbb->color];
		} else {
			memset (&bb->color, 0, sizeof (bb->color));
		}
	}
}

static void rprj_function_attr_load(RPrjCursor *cur, RAnalFunction *fcn, R2ProjectFunctionAttr *attr, const char *name, ut64 va, int mode) {
	if (!attr) {
		return;
	}
	const char *cc = attr->cc != UT32_MAX? rprj_st_get (cur->st, attr->cc): NULL;
	if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
		if (R_STR_ISNOTEMPTY (cc)) {
			r_cons_printf (cur->core->cons, "'afc %s @ 0x%08"PFMT64x"\n", cc, va);
		}
		if ((st64)attr->stack) {
			r_cons_printf (cur->core->cons, "'afS %"PFMT64d" @ 0x%08"PFMT64x"\n", (st64)attr->stack, va);
		}
		if (attr->flags & RPRJ_FUNC_ATTR_NORETURN) {
			r_cons_printf (cur->core->cons, "'tn 0x%08"PFMT64x"\n", va);
		}
	}
	if ((mode & R_CORE_NEWPRJ_MODE_LOAD) && fcn) {
		fcn->type = attr->type;
		fcn->bits = attr->bits;
		fcn->maxstack = (int)(st64)attr->stack;
		if (R_STR_ISNOTEMPTY (cc)) {
			fcn->callconv = r_str_constpool_get (&cur->core->anal->constpool, cc);
		}
		fcn->is_noreturn = attr->flags & RPRJ_FUNC_ATTR_NORETURN;
		if (fcn->is_noreturn) {
			r_anal_noreturn_add (cur->core->anal, name, va);
		}
	}
}

static void rprj_var_load(RPrjCursor *cur, RAnalFunction *fcn, R2ProjectVar *pvar, int mode, ut64 fcn_addr) {
	const char *name = rprj_st_get (cur->st, pvar->name);
	const char *type = rprj_st_get (cur->st, pvar->type);
	if (!name) {
		R_LOG_WARN ("Invalid function variable name index %u", pvar->name);
		return;
	}
	if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
		const char *typ = type? type: "";
		switch (pvar->kind) {
		case R_ANAL_VAR_KIND_REG:
			{
				RRegItem *reg = cur->core->anal->reg
					? r_reg_index_get (cur->core->anal->reg, R_ABS (pvar->delta))
					: NULL;
				if (reg) {
					r_cons_printf (cur->core->cons, "'afvr %s %s %s @ 0x%08"PFMT64x"\n",
						reg->name, name, typ, fcn_addr);
				}
			}
			break;
		case R_ANAL_VAR_KIND_BPV:
			r_cons_printf (cur->core->cons, "'afvb %d %s %s @ 0x%08"PFMT64x"\n",
				pvar->delta, name, typ, fcn_addr);
			break;
		case R_ANAL_VAR_KIND_SPV:
			r_cons_printf (cur->core->cons, "'afvs %d %s %s @ 0x%08"PFMT64x"\n",
				pvar->delta, name, typ, fcn_addr);
			break;
		default:
			break;
		}
	}
	if ((mode & R_CORE_NEWPRJ_MODE_LOAD) && fcn) {
		r_anal_function_set_var (fcn, pvar->delta, pvar->kind, type, -1, pvar->isarg, name);
	}
}

static void rprj_diff_var_free(R2ProjectDiffVar *var) {
	if (var) {
		free (var->name);
		free (var->type);
		free (var);
	}
}

static R2ProjectDiffVar *rprj_diff_var_find(RList *vars, ut8 kind, st32 delta) {
	RListIter *iter;
	R2ProjectDiffVar *var;
	r_list_foreach (vars, iter, var) {
		if (var->kind == kind && var->delta == delta) {
			return var;
		}
	}
	return NULL;
}

static bool rprj_diff_has_function(RList *fcns, ut64 addr) {
	RListIter *iter;
	R2ProjectDiffFunction *fcn;
	r_list_foreach (fcns, iter, fcn) {
		if (fcn->addr == addr) {
			return true;
		}
	}
	return false;
}

static bool rprj_diff_has_addr(RList *addrs, ut64 addr) {
	RListIter *iter;
	R2ProjectDiffAddr *a;
	r_list_foreach (addrs, iter, a) {
		if (a->addr == addr) {
			return true;
		}
	}
	return false;
}

static R2ProjectDiffBlock *rprj_diff_block_find(RList *bbs, ut64 addr) {
	RListIter *iter;
	R2ProjectDiffBlock *bb;
	r_list_foreach (bbs, iter, bb) {
		if (bb->addr == addr) {
			return bb;
		}
	}
	return NULL;
}

static R2ProjectDiffXref *rprj_diff_xref_find(RList *xrefs, ut64 from, ut64 to, ut32 type) {
	RListIter *iter;
	R2ProjectDiffXref *xref;
	r_list_foreach (xrefs, iter, xref) {
		if (xref->from == from && xref->to == to
				&& R_ANAL_REF_TYPE_MASK (xref->type) == R_ANAL_REF_TYPE_MASK (type)) {
			return xref;
		}
	}
	return NULL;
}

static void rprj_diff_seen_addr(RList *seen, ut64 addr) {
	R2ProjectDiffAddr *a = R_NEW (R2ProjectDiffAddr);
	a->addr = addr;
	r_list_append (seen, a);
}

static void rprj_print_comment_script(RPrjCursor *cur, ut64 addr, const char *comment) {
	if (R_STR_ISEMPTY (comment)) {
		r_cons_printf (cur->core->cons, "'CC- @ 0x%08"PFMT64x"\n", addr);
		return;
	}
	char *b64 = sdb_encode ((const ut8 *)comment, strlen (comment));
	if (b64) {
		r_cons_printf (cur->core->cons, "'@0x%08"PFMT64x"'CCu base64:%s\n", addr, b64);
		free (b64);
	}
}

static void rprj_print_flag_script(RPrjCursor *cur, RFlagItem *fi) {
	if (!fi || R_STR_ISEMPTY (fi->name)) {
		return;
	}
	const char *space = fi->space? fi->space->name: NULL;
	r_cons_printf (cur->core->cons, space? "'fs %s\n": "'fs *\n", space);
	r_cons_printf (cur->core->cons, "'f %s %"PFMT64u" 0x%08"PFMT64x"\n",
		fi->name, fi->size, fi->addr);
	if (fi->realname && strcmp (fi->realname, fi->name)) {
		char *rn = sdb_encode ((const ut8 *)fi->realname, strlen (fi->realname));
		const char *raw = R_STR_ISNOTEMPTY (fi->rawname)? fi->rawname: fi->name;
		char *rw = sdb_encode ((const ut8 *)raw, strlen (raw));
		if (rn && rw) {
			r_cons_printf (cur->core->cons, "'@0x%08"PFMT64x"'fu= 1 %s %s %s\n",
				fi->addr, fi->name, rw, rn);
		}
		free (rn);
		free (rw);
	}
	RFlagItemMeta *fim = r_flag_get_meta (cur->core->flags, fi->id);
	if (!fim) {
		return;
	}
	if (R_STR_ISNOTEMPTY (fim->color)) {
		r_cons_printf (cur->core->cons, "'fc %s=%s\n", fi->name, fim->color);
	}
	if (R_STR_ISNOTEMPTY (fim->comment)) {
		char *b64 = sdb_encode ((const ut8 *)fim->comment, strlen (fim->comment));
		if (b64) {
			r_cons_printf (cur->core->cons, "'fC %s base64:%s\n", fi->name, b64);
			free (b64);
		}
	}
	if (R_STR_ISNOTEMPTY (fim->alias)) {
		r_cons_printf (cur->core->cons, "'fa %s %s\n", fi->name, fim->alias);
	}
}

static bool rprj_flag_differs(RFlag *flags, RFlagItem *fi, ut64 addr, ut64 size, RPrjFlagExtras *fe, ut8 extras) {
	if (!fi || fi->addr != addr || fi->size != size) {
		return true;
	}
	const char *space = fi->space? fi->space->name: NULL;
	if (strcmp (r_str_get (space), r_str_get (fe->space))) {
		return true;
	}
	if ((fi->demangled? RPRJ_FLAG_DEMANGLED: 0) != (extras & RPRJ_FLAG_DEMANGLED)) {
		return true;
	}
	const char *realname = (fi->realname && strcmp (fi->realname, fi->name))? fi->realname: NULL;
	const char *rawname = (R_STR_ISNOTEMPTY (fi->rawname) && strcmp (fi->rawname, fi->name))? fi->rawname: NULL;
	if (strcmp (r_str_get (realname), r_str_get (fe->realname))) {
		return true;
	}
	if (strcmp (r_str_get (rawname), r_str_get (fe->rawname))) {
		return true;
	}
	RFlagItemMeta *fim = r_flag_get_meta (flags, fi->id);
	return strcmp (r_str_get (fim? fim->type: NULL), r_str_get (fe->type))
		|| strcmp (r_str_get (fim? fim->color: NULL), r_str_get (fe->color))
		|| strcmp (r_str_get (fim? fim->comment: NULL), r_str_get (fe->comment))
		|| strcmp (r_str_get (fim? fim->alias: NULL), r_str_get (fe->alias));
}

static void rprj_print_xref_script(RPrjCursor *cur, RAnalRef *ref) {
	r_cons_printf (cur->core->cons, "'ax%c 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
		(char)R_ANAL_REF_TYPE_MASK (ref->type), ref->addr, ref->at);
}

static bool rprj_diff_flag_foreach_cb(RFlagItem *fi, void *user) {
	R2ProjectDiffCtx *ctx = (R2ProjectDiffCtx *)user;
	if (fi && !rprj_diff_has_addr (ctx->seen, fi->id)) {
		rprj_print_flag_script (ctx->cur, fi);
	}
	return true;
}

static bool rprj_diff_hints_cb(ut64 addr, const RVecAnalAddrHintRecord *records, void *user) {
	R2ProjectDiffCtx *ctx = (R2ProjectDiffCtx *)user;
	const RAnalAddrHintRecord *record;
	R_VEC_FOREACH (records, record) {
		ut64 key = (addr << 8) | (ut64)record->type;
		if (rprj_diff_has_addr (ctx->seen, key)) {
			continue;
		}
		switch (record->type) {
		case R_ANAL_ADDR_HINT_TYPE_IMMBASE:
			r_cons_printf (ctx->cur->core->cons, "'ahi %d @ 0x%08"PFMT64x"\n", record->immbase, addr);
			break;
		case R_ANAL_ADDR_HINT_TYPE_NEW_BITS:
			r_cons_printf (ctx->cur->core->cons, "'ahb %d @ 0x%08"PFMT64x"\n", record->newbits, addr);
			break;
		default:
			break;
		}
	}
	return true;
}

static bool rprj_current_hint_value(RAnal *anal, ut64 addr, RAnalAddrHintType type, int *value) {
	const RVecAnalAddrHintRecord *records = r_anal_addr_hints_at (anal, addr);
	if (!records) {
		return false;
	}
	const RAnalAddrHintRecord *record;
	R_VEC_FOREACH (records, record) {
		if (record->type == type) {
			*value = type == R_ANAL_ADDR_HINT_TYPE_IMMBASE? record->immbase: record->newbits;
			return true;
		}
	}
	return false;
}

static void rprj_print_var_script(RPrjCursor *cur, RAnalVar *var, ut64 fcn_addr) {
	if (!var || R_STR_ISEMPTY (var->name)) {
		return;
	}
	const char *type = r_str_get (var->type);
	switch (var->kind) {
	case R_ANAL_VAR_KIND_REG:
		if (R_STR_ISNOTEMPTY (var->regname)) {
			r_cons_printf (cur->core->cons, "'afvr %s %s %s @ 0x%08"PFMT64x"\n",
				var->regname, var->name, type, fcn_addr);
		}
		break;
	case R_ANAL_VAR_KIND_BPV:
		r_cons_printf (cur->core->cons, "'afvb %d %s %s @ 0x%08"PFMT64x"\n",
			var->delta, var->name, type, fcn_addr);
		break;
	case R_ANAL_VAR_KIND_SPV:
		r_cons_printf (cur->core->cons, "'afvs %d %s %s @ 0x%08"PFMT64x"\n",
			var->delta, var->name, type, fcn_addr);
		break;
	default:
		break;
	}
}

static void rprj_print_function_attrs(RPrjCursor *cur, RAnalFunction *fcn) {
	if (R_STR_ISNOTEMPTY (fcn->callconv)) {
		r_cons_printf (cur->core->cons, "'afc %s @ 0x%08"PFMT64x"\n", fcn->callconv, fcn->addr);
	}
	if (fcn->maxstack) {
		r_cons_printf (cur->core->cons, "'afS %d @ 0x%08"PFMT64x"\n", fcn->maxstack, fcn->addr);
	}
	if (fcn->is_noreturn) {
		r_cons_printf (cur->core->cons, "'tn 0x%08"PFMT64x"\n", fcn->addr);
	}
}

static void rprj_print_function_script(RPrjCursor *cur, RAnalFunction *fcn) {
	if (!fcn || R_STR_ISEMPTY (fcn->name)) {
		return;
	}
	r_cons_printf (cur->core->cons, "'af+ 0x%08"PFMT64x" %s\n", fcn->addr, fcn->name);
	rprj_print_function_attrs (cur, fcn);
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		r_cons_printf (cur->core->cons, "'afb+ 0x%08"PFMT64x" 0x%08"PFMT64x" %"PFMT64u" 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
			fcn->addr, bb->addr, bb->size, bb->jump, bb->fail);
		if (rprj_color_is_set (&bb->color)) {
			r_cons_printf (cur->core->cons, "'afbc rgb:%02x%02x%02x 0x%08"PFMT64x"\n",
				bb->color.r, bb->color.g, bb->color.b, bb->addr);
		}
	}
	RAnalVar **var;
	R_VEC_FOREACH (&fcn->vars, var) {
		rprj_print_var_script (cur, *var, fcn->addr);
	}
}

static void rprj_diff_function_blocks(RPrjCursor *cur, RAnalFunction *fcn, RList *pbbs) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		R2ProjectDiffBlock *pbb = rprj_diff_block_find (pbbs, bb->addr);
		if (pbb) {
			pbb->seen = true;
		}
		const bool has_color = rprj_color_is_set (&bb->color);
		if (!pbb || pbb->size != bb->size || pbb->jump != bb->jump || pbb->fail != bb->fail) {
			r_cons_printf (cur->core->cons, "'afb+ 0x%08"PFMT64x" 0x%08"PFMT64x" %"PFMT64u" 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
				fcn->addr, bb->addr, bb->size, bb->jump, bb->fail);
		}
		if ((pbb && (pbb->has_color != has_color || (has_color && !rprj_color_eq (&pbb->color, &bb->color))))
				|| (!pbb && has_color)) {
			if (has_color) {
				r_cons_printf (cur->core->cons, "'afbc rgb:%02x%02x%02x 0x%08"PFMT64x"\n",
					bb->color.r, bb->color.g, bb->color.b, bb->addr);
			} else {
				r_cons_printf (cur->core->cons, "'afbc- 0x%08"PFMT64x"\n", bb->addr);
			}
		}
	}
	R2ProjectDiffBlock *pbb;
	r_list_foreach (pbbs, iter, pbb) {
		if (!pbb->seen) {
			r_cons_printf (cur->core->cons, "'afb- 0x%08"PFMT64x"\n", pbb->addr);
		}
	}
}

static void rprj_diff_function_attrs(RPrjCursor *cur, RAnalFunction *fcn, R2ProjectFunctionAttr *attr) {
	const char *cc = attr && attr->cc != UT32_MAX? rprj_st_get (cur->st, attr->cc): NULL;
	const bool noret = attr && (attr->flags & RPRJ_FUNC_ATTR_NORETURN);
	const st64 stack = attr? (st64)attr->stack: 0;
	if (strcmp (r_str_get (cc), r_str_get (fcn->callconv))) {
		if (R_STR_ISNOTEMPTY (fcn->callconv)) {
			r_cons_printf (cur->core->cons, "'afc %s @ 0x%08"PFMT64x"\n", fcn->callconv, fcn->addr);
		}
	}
	if (stack != fcn->maxstack) {
		r_cons_printf (cur->core->cons, "'afS %d @ 0x%08"PFMT64x"\n", fcn->maxstack, fcn->addr);
	}
	if (noret != fcn->is_noreturn) {
		r_cons_printf (cur->core->cons, fcn->is_noreturn
			? "'tn 0x%08"PFMT64x"\n"
			: "'tn- 0x%08"PFMT64x"\n", fcn->addr);
	}
}

static void rprj_diff_function_vars(RPrjCursor *cur, RAnalFunction *fcn, RList *pvars) {
	RAnalVar **varp;
	R_VEC_FOREACH (&fcn->vars, varp) {
		RAnalVar *var = *varp;
		R2ProjectDiffVar *pvar = rprj_diff_var_find (pvars, var->kind, var->delta);
		if (pvar) {
			pvar->seen = true;
		}
		if (!pvar || pvar->isarg != (var->isarg? 1: 0)
				|| strcmp (r_str_get (pvar->name), r_str_get (var->name))
				|| strcmp (r_str_get (pvar->type), r_str_get (var->type))) {
			rprj_print_var_script (cur, var, fcn->addr);
		}
	}
	RListIter *iter;
	R2ProjectDiffVar *pvar;
	r_list_foreach (pvars, iter, pvar) {
		if (!pvar->seen && R_STR_ISNOTEMPTY (pvar->name)) {
			r_cons_printf (cur->core->cons, "'afv- %s @ 0x%08"PFMT64x"\n", pvar->name, fcn->addr);
		}
	}
}

static void rprj_function_load(RPrjCursor *cur, int mode, ut64 next_entry) {
	RBuffer *b = cur->b;
	RCore *core = cur->core;
	R2ProjectStringTable *st = cur->st;
	ut32 count = 0;
	ut32 ncolors = 0;
	if (!rprj_entry_has (b, next_entry, sizeof (ncolors)) || !rprj_read_le32 (b, &ncolors)) {
		R_LOG_WARN ("Truncated function entry");
		return;
	}
	const ut64 remaining = next_entry > r_buf_at (b)? next_entry - r_buf_at (b): 0;
	if (remaining < 4 || ncolors > (remaining - 4) / RPRJ_COLOR_SIZE) {
		R_LOG_WARN ("Invalid function color table size %u", ncolors);
		return;
	}
	RColor *colors = NULL;
	if (ncolors > 0) {
		colors = R_NEWS0 (RColor, ncolors);
		if (!colors) {
			return;
		}
		ut32 i;
		for (i = 0; i < ncolors; i++) {
			if (!rprj_read_color (b, colors + i)) {
				R_LOG_WARN ("Truncated function color record %u/%u", i, ncolors);
				free (colors);
				return;
			}
		}
	}
	ut32 nattrs = 0;
	if (!rprj_entry_has (b, next_entry, sizeof (nattrs)) || !rprj_read_le32 (b, &nattrs)) {
		R_LOG_WARN ("Truncated function attribute table");
		free (colors);
		return;
	}
	R2ProjectFunctionAttr *attrs = NULL;
	const ut64 rem_attrs = next_entry > r_buf_at (b)? next_entry - r_buf_at (b): 0;
	if (rem_attrs < 4 || nattrs > (rem_attrs - 4) / RPRJ_FUNCTION_ATTR_SIZE) {
		R_LOG_WARN ("Invalid function attribute table size %u", nattrs);
		free (colors);
		return;
	}
	if (nattrs > 0) {
		attrs = R_NEWS0 (R2ProjectFunctionAttr, nattrs);
		if (!attrs) {
			free (colors);
			return;
		}
		ut32 i;
		for (i = 0; i < nattrs; i++) {
			if (!rprj_function_attr_read (b, attrs + i)) {
				R_LOG_WARN ("Truncated function attribute record %u/%u", i, nattrs);
				free (attrs);
				free (colors);
				return;
			}
		}
	}
	if (!rprj_entry_has (b, next_entry, sizeof (count)) || !rprj_read_le32 (b, &count)) {
		R_LOG_WARN ("Truncated function count");
		free (attrs);
		free (colors);
		return;
	}
	const ut64 fbmax = rprj_entry_remaining (b, next_entry) / RPRJ_FUNCTION_SIZE;
	if (count > fbmax) {
		R_LOG_WARN ("Invalid function record count %u", count);
		count = (ut32)fbmax;
	}
	RList *pfcns = (mode & R_CORE_NEWPRJ_MODE_DIFF)? r_list_newf (free): NULL;
	ut32 i;
	for (i = 0; i < count && r_buf_at (b) < next_entry; i++) {
		R2ProjectFunction pfcn;
		if (!rprj_entry_has (b, next_entry, RPRJ_FUNCTION_SIZE)) {
			R_LOG_WARN ("Truncated function record %u/%u", i, count);
			break;
		}
		if (!rprj_function_read (b, &pfcn)) {
			R_LOG_WARN ("Truncated function record %u/%u", i, count);
			break;
		}
		const char *name = rprj_st_get (st, pfcn.name);
		if (!name) {
			R_LOG_WARN ("Invalid function string index %u", pfcn.name);
		}
		ut64 va = UT64_MAX;
		RAnalFunction *fcn = NULL;
		const bool resolved = rprj_project_addr_to_va (cur, &pfcn.addr, &va);
		if (resolved) {
			if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
				R2ProjectDiffFunction *df = R_NEW (R2ProjectDiffFunction);
				df->addr = va;
				r_list_append (pfcns, df);
				fcn = rprj_function_get_registered (core->anal, va);
			}
			if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
				r_cons_printf (core->cons, "'af+ 0x%08"PFMT64x" %s\n", va, name? name: "");
			}
			if (mode & R_CORE_NEWPRJ_MODE_LOAD) {
				fcn = rprj_function_get_registered (core->anal, va);
				if (!fcn) {
					rprj_function_drop_stale_name (core->anal, name);
					R2ProjectFunctionAttr *attr = pfcn.attr < nattrs? attrs + pfcn.attr: NULL;
					fcn = r_anal_create_function (core->anal, name, va, attr? attr->type: 0, NULL);
				}
				if (fcn) {
					if (name) {
						r_anal_function_rename (fcn, name);
					}
				}
			}
			if (pfcn.attr < nattrs) {
				rprj_function_attr_load (cur, fcn, attrs + pfcn.attr, name, va, mode);
			}
		} else {
			R_LOG_WARN ("Cannot resolve function record %u/%u", i, count);
		}
		RList *pbbs = (mode & R_CORE_NEWPRJ_MODE_DIFF)? r_list_newf (free): NULL;
		RList *pvars = (mode & R_CORE_NEWPRJ_MODE_DIFF)? r_list_newf ((RListFree)rprj_diff_var_free): NULL;
		const ut64 bbmax = rprj_entry_remaining (b, next_entry) / RPRJ_BLOCK_SIZE;
		if (pfcn.nbbs > bbmax) {
			R_LOG_WARN ("Invalid basic block count %u in function %u/%u", pfcn.nbbs, i, count);
			pfcn.nbbs = (ut32)bbmax;
		}
		ut32 j;
		for (j = 0; j < pfcn.nbbs && r_buf_at (b) < next_entry; j++) {
			R2ProjectBlock pbb;
			if (!rprj_entry_has (b, next_entry, RPRJ_BLOCK_SIZE)) {
				R_LOG_WARN ("Truncated basic block record %u/%u in function %u/%u", j, pfcn.nbbs, i, count);
				r_list_free (pvars);
				r_list_free (pbbs);
				r_list_free (pfcns);
				free (attrs);
				free (colors);
				return;
			}
			if (!rprj_block_read (b, &pbb)) {
				R_LOG_WARN ("Truncated basic block record %u/%u in function %u/%u", j, pfcn.nbbs, i, count);
				r_list_free (pvars);
				r_list_free (pbbs);
				r_list_free (pfcns);
				free (attrs);
				free (colors);
				return;
			}
			if ((mode & R_CORE_NEWPRJ_MODE_DIFF) && resolved) {
				R2ProjectDiffBlock *dbb = R_NEW0 (R2ProjectDiffBlock);
				dbb->size = pbb.size;
				rprj_project_addr_to_va (cur, &pbb.addr, &dbb->addr);
				rprj_project_addr_to_va (cur, &pbb.jump, &dbb->jump);
				rprj_project_addr_to_va (cur, &pbb.fail, &dbb->fail);
				if (pbb.color < ncolors) {
					dbb->has_color = true;
					dbb->color = colors[pbb.color];
				}
				r_list_append (pbbs, dbb);
			}
			if (resolved) {
				rprj_block_load (cur, fcn, &pbb, mode, va, colors, ncolors);
			}
		}
		const ut64 vbmax = rprj_entry_remaining (b, next_entry) / RPRJ_VAR_SIZE;
		if (pfcn.nvars > vbmax) {
			R_LOG_WARN ("Invalid variable count %u in function %u/%u", pfcn.nvars, i, count);
			pfcn.nvars = (ut32)vbmax;
		}
		for (j = 0; j < pfcn.nvars && r_buf_at (b) < next_entry; j++) {
			R2ProjectVar pvar;
			if (!rprj_entry_has (b, next_entry, RPRJ_VAR_SIZE)) {
				R_LOG_WARN ("Truncated variable record %u/%u in function %u/%u", j, pfcn.nvars, i, count);
				r_list_free (pvars);
				r_list_free (pbbs);
				r_list_free (pfcns);
				free (attrs);
				free (colors);
				return;
			}
			if (!rprj_var_read (b, &pvar)) {
				R_LOG_WARN ("Truncated variable record %u/%u in function %u/%u", j, pfcn.nvars, i, count);
				r_list_free (pvars);
				r_list_free (pbbs);
				r_list_free (pfcns);
				free (attrs);
				free (colors);
				return;
			}
			if ((mode & R_CORE_NEWPRJ_MODE_DIFF) && resolved) {
				const char *vname = rprj_st_get (st, pvar.name);
				if (vname) {
					R2ProjectDiffVar *dvar = R_NEW0 (R2ProjectDiffVar);
					dvar->name = strdup (vname);
					dvar->type = strdup (r_str_get (rprj_st_get (st, pvar.type)));
					dvar->delta = pvar.delta;
					dvar->kind = pvar.kind;
					dvar->isarg = pvar.isarg;
					r_list_append (pvars, dvar);
				}
			}
			if (resolved) {
				rprj_var_load (cur, fcn, &pvar, mode, va);
			}
		}
		if ((mode & R_CORE_NEWPRJ_MODE_DIFF) && resolved) {
			if (!fcn) {
				r_cons_printf (core->cons, "'af- 0x%08"PFMT64x"\n", va);
			} else {
				if (name && strcmp (r_str_get (name), r_str_get (fcn->name))) {
					r_cons_printf (core->cons, "'afn %s 0x%08"PFMT64x"\n", fcn->name, va);
				}
				rprj_diff_function_attrs (cur, fcn, pfcn.attr < nattrs? attrs + pfcn.attr: NULL);
				rprj_diff_function_blocks (cur, fcn, pbbs);
				rprj_diff_function_vars (cur, fcn, pvars);
			}
		}
		r_list_free (pvars);
		r_list_free (pbbs);
	}
	if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
		RListIter *iter;
		RAnalFunction *fcn;
		RList *fcns = r_anal_get_fcns (core->anal);
		r_list_foreach (fcns, iter, fcn) {
			if (fcn && !rprj_diff_has_function (pfcns, fcn->addr)) {
				rprj_print_function_script (cur, fcn);
			}
		}
	}
	r_list_free (pfcns);
	free (attrs);
	free (colors);
}

static void r_core_newprj_load(RCore *core, const char *file, int mode) {
	RBuffer *b = r_buf_new_from_file (file);
	if (!b) {
		R_LOG_ERROR ("Cannot open file");
		return;
	}
	R2ProjectHeader hdr;
	if (!rprj_header_read (b, &hdr)) {
		R_LOG_ERROR ("Invalid file type");
		r_unref (b);
		return;
	}
	if (hdr.version != RPRJ_VERSION) {
		R_LOG_ERROR ("Unsupported project version %d (this build understands version %d)", hdr.version, RPRJ_VERSION);
		r_unref (b);
		return;
	}
	if (mode & R_CORE_NEWPRJ_MODE_LOG) {
		r_cons_printf (core->cons, "Project {\n");
		r_cons_printf (core->cons, "  Header {\n");
		r_cons_printf (core->cons, "    magic = 0x%08x OK\n", hdr.magic);
		r_cons_printf (core->cons, "    version = %d\n", hdr.version);
		r_cons_printf (core->cons, "  }\n");
	}
	R2ProjectStringTable st = {0};
	RPrjCursor cur = {
		.core = core,
		.st = &st,
		.b = b,
		.mods = r_list_newf (free),
	};
	st.data = rprj_find (b, RPRJ_STRS, &st.size);
	if (!st.data) {
		R_LOG_ERROR ("Missing string table (RPRJ_STRS) in project file");
		r_list_free (cur.mods);
		r_unref (b);
		return;
	}
	if (!rprj_st_is_valid (&st)) {
		R_LOG_ERROR ("Invalid string table (RPRJ_STRS) in project file");
		r_list_free (cur.mods);
		free (st.data);
		r_unref (b);
		return;
	}
	r_buf_seek (b, sizeof (R2ProjectHeader), SEEK_SET);

	ut32 modsize = 0;
	ut8 *modsbuf = rprj_find (b, RPRJ_MODS, &modsize);
	RBuffer *mods = modsbuf? r_buf_new_with_bytes (modsbuf, modsize): NULL;
	if (mods) {
		ut32 n = 0;
		while (n + sizeof (R2ProjectMod) <= modsize) {
			R2ProjectMod mod;
			if (!rprj_mods_read (mods, &mod)) {
				R_LOG_ERROR ("Cannot read mod");
				break;
			}
			R_LOG_DEBUG ("MOD: %s + 0x%08"PFMT64x, rprj_st_get (&st, mod.name), mod.vmin);
			r_list_append (cur.mods, r_mem_dup (&mod, sizeof (mod)));
			n += sizeof (mod);
		}
		RListIter *iter;
		R2ProjectMod *mod;
		r_list_foreach (cur.mods, iter, mod) {
			RIOMap *map = rprj_coremod (&cur, mod);
			if (map) {
				mod->vmin = r_io_map_from (map);
				mod->vmax = r_io_map_to (map);
			}
		}
	}

	R2ProjectEntry entry;
	r_buf_seek (b, sizeof (R2ProjectHeader), SEEK_SET);
	int n = 0;
	const ut64 bsz = r_buf_size (b);
	while (r_buf_at (b) < bsz) {
		const ut64 entry_at = r_buf_at (b);
		if (!rprj_entry_read (b, &entry)) {
			R_LOG_ERROR ("Cannot read entry");
			break;
		}
		if (entry.size < sizeof (R2ProjectEntry) || entry.size > bsz - entry_at) {
			R_LOG_ERROR ("Invalid entry size %u", entry.size);
			break;
		}
		if (mode & R_CORE_NEWPRJ_MODE_LOG) {
			r_cons_printf (core->cons, "  Entry<%s> {\n", rprj_entry_type_tostring (entry.type));
			r_cons_printf (core->cons, "    type = 0x%02x\n", entry.type);
			r_cons_printf (core->cons, "    size = %d\n", entry.size);
		}
		if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
			r_cons_printf (core->cons, "'f entry%d.%s=0x%08"PFMT64x"\n", n, rprj_entry_type_tostring (entry.type), r_buf_at (b));
		}
		const ut64 next_entry = entry_at + entry.size;
		switch (entry.type) {
		case RPRJ_STRS:
			{
				if (mode & R_CORE_NEWPRJ_MODE_LOG) {
					ut64 size;
					const ut8 *bdata = r_buf_data (b, &size);
					const ut64 at = r_buf_at (b);
					const ut32 data_size = entry.size - sizeof (R2ProjectEntry);
					if (bdata && at + data_size <= size) {
						const ut8 *data = bdata + at;
						ut32 i = 0;
						while (i < data_size) {
							const ut8 *nul = memchr (data + i, 0, data_size - i);
							if (!nul) {
								break;
							}
							const ut32 len = (ut32)(nul - (data + i));
							r_cons_printf (core->cons, "      => (%u) %s\n", len, (const char *)data + i);
							i += len + 1;
						}
					}
				}
				break;
			}
		case RPRJ_MODS: // modules
			if (mode & R_CORE_NEWPRJ_MODE_LOG) {
				// walk and print them
			}
			break;
		case RPRJ_MAPS:
			// rprj_maps_read (fd);
			break;
		case RPRJ_CMDS:
			if (mode & R_CORE_NEWPRJ_MODE_LOG) {
				r_cons_printf (core->cons, "    [\n");
			}
			while (r_buf_at (b) < next_entry) {
				// this entry requires disabled sandbox
				char *script;
				if (!rprj_string_read (b, next_entry, &script)) {
					R_LOG_ERROR ("Cannot read string");
					break;
				}
				if (mode & R_CORE_NEWPRJ_MODE_LOG) {
					r_cons_printf (core->cons, "      '%s'\n", script);
				}
				if (mode & R_CORE_NEWPRJ_MODE_CMD) {
					r_core_cmd0 (core, script);
				}
				free (script);
			}
			if (mode & R_CORE_NEWPRJ_MODE_LOG) {
				r_cons_printf (core->cons, "    ]\n");
			}
			break;
		case RPRJ_INFO:
			{
				R2ProjectInfo cmds = {0};
				if (!rprj_entry_has (b, next_entry, sizeof (R2ProjectInfo))) {
					R_LOG_WARN ("Truncated project info entry");
					break;
				}
				if (!rprj_info_read (b, &cmds)) {
					R_LOG_WARN ("Truncated project info entry");
					break;
				}
				const char *name = rprj_st_get (&st, cmds.name);
				const char *user = rprj_st_get (&st, cmds.user);
				if (!name || !user) {
					R_LOG_WARN ("Invalid project info string index (%u,%u)", cmds.name, cmds.user);
					break;
				}
				if (mode & R_CORE_NEWPRJ_MODE_LOG) {
					r_cons_printf (core->cons, "    ProjectInfo {\n");
					r_cons_printf (core->cons, "      Name: %s\n", name);
					r_cons_printf (core->cons, "      User: %s\n", user);
					//r_cons_printf (core->cons, "      Date: %s\n", r_time_usecs_tostring (cmds.time));
					r_cons_printf (core->cons, "    }\n");
				}
				if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
					const char *cur_name = r_config_get (core->config, "prj.name");
					const char *cur_user = r_config_get (core->config, "cfg.user");
					if (strcmp (r_str_get (cur_name), r_str_get (name))) {
						r_cons_printf (core->cons, "'e prj.name=%s\n", r_str_get (cur_name));
					}
					if (strcmp (r_str_get (cur_user), r_str_get (user))) {
						r_cons_printf (core->cons, "'e cfg.user=%s\n", r_str_get (cur_user));
					}
				}
			}
			break;
		case RPRJ_CMNT:
			{
				ut64 at = r_buf_at (b);
				ut64 last = at + entry.size - sizeof (R2ProjectEntry);
				RList *seen = (mode & R_CORE_NEWPRJ_MODE_DIFF)? r_list_newf (free): NULL;
				while (at < last && last - at >= sizeof (R2ProjectComment)) {
					R2ProjectComment cmnt;
					if (!rprj_cmnt_read (b, &cmnt)) {
						R_LOG_WARN ("Truncated comment record at 0x%08"PFMT64x, at);
						break;
					}
					const char *cmnt_text = rprj_st_get (&st, cmnt.text);
					if (!cmnt_text) {
						R_LOG_WARN ("Invalid comment string index %u", cmnt.text);
						at += sizeof (cmnt);
						continue;
					}
					R2ProjectAddr addr = {
						.mod = cmnt.mod,
						.delta = cmnt.delta,
					};
					ut64 va = UT64_MAX;
					if (rprj_project_addr_to_va (&cur, &addr, &va)) {
						char *b64 = sdb_encode ((const ut8 *)cmnt_text, strlen (cmnt_text));
						if (b64) {
							char *cmd = r_str_newf ("CCu base64:%s", b64);
							if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
								r_cons_printf (core->cons, "'@0x%08"PFMT64x"'%s\n", va, cmd);
							}
							if (mode & R_CORE_NEWPRJ_MODE_LOAD) {
								r_core_call_at (core, va, cmd);
							}
							free (cmd);
							free (b64);
						}
						if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
							rprj_diff_seen_addr (seen, va);
							const char *current = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, va);
							if (strcmp (r_str_get (current), cmnt_text)) {
								rprj_print_comment_script (&cur, va, current);
							}
						}
					} else {
						R_LOG_WARN ("Cannot resolve address for comment %s", cmnt_text);
					}
					at += sizeof (cmnt);
				}
				if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
					RIntervalTreeIter it;
					RAnalMetaItem *item;
					r_interval_tree_foreach (&core->anal->meta, it, item) {
						RIntervalNode *node = r_interval_tree_iter_get (&it);
						if (item->type == R_META_TYPE_COMMENT && !rprj_diff_has_addr (seen, node->start)) {
							rprj_print_comment_script (&cur, node->start, item->str);
						}
					}
				}
				r_list_free (seen);
			}
			break;
		case RPRJ_FLAG:
			rprj_flag_load (&cur, mode, next_entry);
			break;
		case RPRJ_EVAL:
			rprj_eval_load (&cur, mode, next_entry);
			break;
		case RPRJ_XREF:
			{
				ut32 count = 0;
				if (!rprj_entry_has (b, next_entry, sizeof (count)) || !rprj_read_le32 (b, &count)) {
					R_LOG_WARN ("Truncated xref entry");
					break;
				}
				const ut64 bmax = rprj_entry_remaining (b, next_entry) / RPRJ_XREF_SIZE;
				if (count > bmax) {
					R_LOG_WARN ("Invalid xref record count %u", count);
					count = (ut32)bmax;
				}
				RList *seen = (mode & R_CORE_NEWPRJ_MODE_DIFF)? r_list_newf (free): NULL;
				ut32 i;
				for (i = 0; i < count; i++) {
					R2ProjectXref xref;
					if (!rprj_entry_has (b, next_entry, RPRJ_XREF_SIZE) || !rprj_xref_read (b, &xref)) {
						R_LOG_WARN ("Truncated xref record %u/%u", i, count);
						break;
					}
					ut64 from = UT64_MAX;
					ut64 to = UT64_MAX;
					if (!rprj_project_addr_to_va (&cur, &xref.from, &from)
							|| !rprj_project_addr_to_va (&cur, &xref.to, &to)) {
						R_LOG_WARN ("Cannot resolve xref record %u/%u", i, count);
						continue;
					}
					if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
						r_cons_printf (core->cons, "'ax%c 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
							(char)R_ANAL_REF_TYPE_MASK (xref.type), to, from);
					}
					if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
						R2ProjectDiffXref *dx = R_NEW (R2ProjectDiffXref);
						dx->from = from;
						dx->to = to;
						dx->type = xref.type;
						r_list_append (seen, dx);
						RVecAnalRef *refs = r_anal_refs_get (core->anal, from);
						bool found = false;
						if (refs) {
							RAnalRef *ref;
							R_VEC_FOREACH (refs, ref) {
								if (ref->at == from && ref->addr == to
										&& R_ANAL_REF_TYPE_MASK (ref->type) == R_ANAL_REF_TYPE_MASK (xref.type)) {
									found = true;
									break;
								}
							}
							RVecAnalRef_free (refs);
						}
						if (!found) {
							r_cons_printf (core->cons, "'ax- 0x%08"PFMT64x" 0x%08"PFMT64x"\n", to, from);
						}
					}
					if (mode & R_CORE_NEWPRJ_MODE_LOAD) {
						r_anal_xrefs_set (core->anal, from, to, xref.type);
					}
				}
				if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
					RVecAnalRef *refs = r_anal_refs_get (core->anal, UT64_MAX);
					if (refs) {
						RAnalRef *ref;
						R_VEC_FOREACH (refs, ref) {
							R2ProjectDiffXref *dx = rprj_diff_xref_find (seen, ref->at, ref->addr, ref->type);
							if (!dx) {
								rprj_print_xref_script (&cur, ref);
							}
						}
						RVecAnalRef_free (refs);
					}
				}
				r_list_free (seen);
			}
			break;
		case RPRJ_FUNC:
			rprj_function_load (&cur, mode, next_entry);
			break;
		case RPRJ_HINT:
			{
				ut64 at = r_buf_at (b);
				ut64 last = at + entry.size - sizeof (R2ProjectEntry);
				RList *seen = (mode & R_CORE_NEWPRJ_MODE_DIFF)? r_list_newf (free): NULL;
				while (at < last && last - at >= sizeof (R2ProjectHint)) {
					R2ProjectHint hint;
					if (!rprj_hint_read (b, &hint)) {
						R_LOG_WARN ("Truncated hint record at 0x%08"PFMT64x, at);
						break;
					}
					R2ProjectAddr addr = {
						.mod = hint.mod,
						.delta = hint.delta,
					};
					ut64 va = UT64_MAX;
					if (!rprj_project_addr_to_va (&cur, &addr, &va) || va == UT64_MAX) {
						R_LOG_WARN ("Cannot resolve hint record at 0x%08"PFMT64x, at);
						at += sizeof (hint);
						continue;
					}
					if (hint.kind == 1) { // immbase
						int base = (int)hint.value;
						if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
							r_cons_printf (core->cons, "'ahi %d @ 0x%08"PFMT64x"\n", base, va);
						}
						if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
							rprj_diff_seen_addr (seen, (va << 8) | R_ANAL_ADDR_HINT_TYPE_IMMBASE);
							int curval = 0;
							if (!rprj_current_hint_value (core->anal, va, R_ANAL_ADDR_HINT_TYPE_IMMBASE, &curval)
									|| curval != base) {
								if (curval) {
									r_cons_printf (core->cons, "'ahi %d @ 0x%08"PFMT64x"\n", curval, va);
								} else {
									r_cons_printf (core->cons, "'ah- @ 0x%08"PFMT64x"\n", va);
								}
							}
						}
						if (mode & R_CORE_NEWPRJ_MODE_LOAD) {
							r_anal_hint_set_immbase (core->anal, va, base);
						}
					} else if (hint.kind == 2) { // newbits
						int nbits = (int)hint.value;
						if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
							r_cons_printf (core->cons, "'ahb %d @ 0x%08"PFMT64x"\n", nbits, va);
						}
						if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
							rprj_diff_seen_addr (seen, (va << 8) | R_ANAL_ADDR_HINT_TYPE_NEW_BITS);
							int curval = 0;
							if (!rprj_current_hint_value (core->anal, va, R_ANAL_ADDR_HINT_TYPE_NEW_BITS, &curval)
									|| curval != nbits) {
								if (curval) {
									r_cons_printf (core->cons, "'ahb %d @ 0x%08"PFMT64x"\n", curval, va);
								} else {
									r_cons_printf (core->cons, "'ah- @ 0x%08"PFMT64x"\n", va);
								}
							}
						}
						if (mode & R_CORE_NEWPRJ_MODE_LOAD) {
							r_anal_hint_set_newbits (core->anal, va, nbits);
						}
					}
					at += sizeof (hint);
				}
				if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
					R2ProjectDiffCtx ctx = { &cur, seen };
					r_anal_addr_hints_foreach (core->anal, rprj_diff_hints_cb, &ctx);
				}
				r_list_free (seen);
			}
			break;
		}
		if (mode & R_CORE_NEWPRJ_MODE_LOG) {
			r_cons_printf (core->cons, "  }\n");
		}
		// skip to the next entry
		r_buf_seek (b, next_entry, SEEK_SET);
		n++;
	}
	if (mode & R_CORE_NEWPRJ_MODE_LOG) {
		r_cons_printf (core->cons, "}\n");
	}
	r_unref (mods);
	free (modsbuf);
	r_list_free (cur.mods);
	free (st.data);
	r_unref (b);
}

// destructive: wipes the current session and loads the project into a clean
// environment. use r_core_newprj_load when you want to merge the project data into the
// existing session without losing current analysis.
static void r_core_newprj_open(RCore *core, const char *file) {
	if (!r_file_exists (file)) {
		R_LOG_ERROR ("Cannot find project file: %s", file);
		return;
	}
	const bool isint = r_config_get_b (core->config, "scr.interactive");
	if (isint && !r_cons_yesno (core->cons, 'n',
			"Opening a project discards the current session (files, flags, anal, config). Continue? (y/N)")) {
		R_LOG_INFO ("Aborted");
		return;
	}
	r_core_cmd0 (core, "o--");
	r_config_set (core->config, "prj.name", "");
	r_core_newprj_load (core, file, R_CORE_NEWPRJ_MODE_LOAD | R_CORE_NEWPRJ_MODE_CMD);
}
