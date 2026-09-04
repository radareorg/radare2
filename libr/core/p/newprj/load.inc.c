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
			r_strbuf_appendf (cur->out, "      %s = %s\n", name, value);
		}
		if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
			r_strbuf_appendf (cur->out, "'e %s=%s\n", name, value);
		}
		if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
			const char *curval = r_config_get (core->config, name);
			if (curval && strcmp (curval, value)) {
				r_strbuf_appendf (cur->out, "'e %s=%s\n", name, curval);
			}
		}
		if (mode & R_CORE_NEWPRJ_MODE_LOAD) {
			r_config_set (core->config, name, value);
		}
	}
}

static ut8 *rprj_find(RBuffer *b, ut32 type, ut32 *size) {
	r_buf_seek (b, RPRJ_HEADER_SIZE, SEEK_SET);
	const ut64 last = r_buf_size (b);
	ut64 at = r_buf_at (b);
	*size = 0;
	while (r_buf_at (b) < last) {
		R2ProjectEntry entry = {0};
		if (!rprj_entry_read (b, &entry)) {
			R_LOG_ERROR ("find: Cannot read entry");
			break;
		}
		if (entry.size < RPRJ_ENTRY_SIZE || entry.size > last - at) {
			R_LOG_ERROR ("invalid size");
			break;
		}
		if (entry.type == type) {
			const ut32 data_size = entry.size - RPRJ_ENTRY_SIZE;
			ut8 *buf = data_size? malloc (data_size): R_NEWS0 (ut8, 1);
			if (buf) {
				if (data_size && r_buf_read_at (b, at + RPRJ_ENTRY_SIZE, buf, data_size) != (st64)data_size) {
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
	static const struct { ut8 bit; size_t off; } tbl[] = {
		{ RPRJ_FLAG_SPACE,    r_offsetof (RPrjFlagExtras, space) },
		{ RPRJ_FLAG_REALNAME, r_offsetof (RPrjFlagExtras, realname) },
		{ RPRJ_FLAG_RAWNAME,  r_offsetof (RPrjFlagExtras, rawname) },
		{ RPRJ_FLAG_TYPE,     r_offsetof (RPrjFlagExtras, type) },
		{ RPRJ_FLAG_COLOR,    r_offsetof (RPrjFlagExtras, color) },
		{ RPRJ_FLAG_COMMENT,  r_offsetof (RPrjFlagExtras, comment) },
		{ RPRJ_FLAG_ALIAS,    r_offsetof (RPrjFlagExtras, alias) },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (tbl); i++) {
		if (extras & tbl[i].bit) {
			const char **slot = (const char **)((char *)fe + tbl[i].off);
			if (!read_flag_extra_str (cur, next_entry, slot)) {
				return false;
			}
		}
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
		if (!rprj_mod_va (cur, &addr, &va)) {
			R_LOG_WARN ("Cannot resolve address for flag %s", flag_name);
			continue;
		}
		if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
			// flag names are sanitized by r_flag_set; meta fields may contain
			// arbitrary bytes and are intentionally skipped here until the
			// flag subcommands support a base64 form (like CCu).
			r_strbuf_appendf (cur->out, fe.space? "'fs %s\n": "'fs *\n", fe.space);
			r_strbuf_appendf (cur->out, "'f %s %"PFMT64u" 0x%08"PFMT64x"\n",
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
				r_strbuf_appendf (cur->out, "'f- %s\n", flag_name);
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
	if (!rprj_mod_va (cur, &pbb->addr, &va)
			|| !rprj_mod_va (cur, &pbb->jump, &jump)
			|| !rprj_mod_va (cur, &pbb->fail, &fail)) {
		R_LOG_WARN ("Cannot resolve basic block for function %s", fcn? fcn->name: "?");
		return;
	}
	if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
		r_strbuf_appendf (cur->out, "'afb+ 0x%08"PFMT64x" 0x%08"PFMT64x" %"PFMT64u" 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
			fcn? fcn->addr: fcn_addr, va, pbb->size, jump, fail);
		if (pbb->color < ncolors) {
			RColor *color = colors + pbb->color;
			r_strbuf_appendf (cur->out, "'afbc rgb:%02x%02x%02x 0x%08"PFMT64x"\n",
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
			r_strbuf_appendf (cur->out, "'0x%08"PFMT64x"'afc %s\n", va, cc);
		}
		if (attr->flags & RPRJ_FUNC_ATTR_NORETURN) {
			r_strbuf_appendf (cur->out, "'tn 0x%08"PFMT64x"\n", va);
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

static void rprj_var_load(RPrjCursor *cur, RAnalFunction *fcn, R2ProjectVar *pvar, int mode, ut64 fcn_addr, st64 stack) {
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
					r_strbuf_appendf (cur->out, "'0x%08"PFMT64x"'afvr %s %s %s\n",
						fcn_addr, reg->name, name, typ);
				}
			}
			break;
		case R_ANAL_VAR_KIND_BPV:
			r_strbuf_appendf (cur->out, "'0x%08"PFMT64x"'afvb %d %s %s\n",
				fcn_addr, pvar->delta, name, typ);
			break;
		case R_ANAL_VAR_KIND_SPV:
			{
				const st64 delta = cur->core->anal->opt.var_newstack? pvar->delta: stack + pvar->delta;
				r_strbuf_appendf (cur->out, "'0x%08"PFMT64x"'afvs %"PFMT64d" %s %s\n",
					fcn_addr, delta, name, typ);
			}
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

static void rprj_print_meta_script(RPrjCursor *cur, RAnalMetaType type, ut64 addr, const char *text) {
	const bool vartype = type == R_META_TYPE_VARTYPE;
	if (R_STR_ISEMPTY (text)) {
		r_strbuf_appendf (cur->out, "'0x%08"PFMT64x"'%s-\n", addr, vartype? "Ct": "CC");
		return;
	}
	char *b64 = sdb_encode ((const ut8 *)text, strlen (text));
	if (b64) {
		r_strbuf_appendf (cur->out, "'@0x%08"PFMT64x"'%s base64:%s\n",
			addr, vartype? "Ct=": "CCu", b64);
		free (b64);
	}
}

static void rprj_print_flag_script(RPrjCursor *cur, RFlagItem *fi) {
	if (!fi || R_STR_ISEMPTY (fi->name)) {
		return;
	}
	const char *space = fi->space? fi->space->name: NULL;
	r_strbuf_appendf (cur->out, space? "'fs %s\n": "'fs *\n", space);
	r_strbuf_appendf (cur->out, "'f %s %"PFMT64u" 0x%08"PFMT64x"\n",
		fi->name, fi->size, fi->addr);
	if (fi->realname && strcmp (fi->realname, fi->name)) {
		char *rn = sdb_encode ((const ut8 *)fi->realname, strlen (fi->realname));
		const char *raw = R_STR_ISNOTEMPTY (fi->rawname)? fi->rawname: fi->name;
		char *rw = sdb_encode ((const ut8 *)raw, strlen (raw));
		if (rn && rw) {
			r_strbuf_appendf (cur->out, "'@0x%08"PFMT64x"'fu= 1 %s %s %s\n",
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
		r_strbuf_appendf (cur->out, "'fc %s=%s\n", fi->name, fim->color);
	}
	if (R_STR_ISNOTEMPTY (fim->comment)) {
		char *b64 = sdb_encode ((const ut8 *)fim->comment, strlen (fim->comment));
		if (b64) {
			r_strbuf_appendf (cur->out, "'fC %s base64:%s\n", fi->name, b64);
			free (b64);
		}
	}
	if (R_STR_ISNOTEMPTY (fim->alias)) {
		r_strbuf_appendf (cur->out, "'fa %s %s\n", fi->name, fim->alias);
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
	r_strbuf_appendf (cur->out, "'ax%c 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
		(char)R_ANAL_REF_TYPE_MASK (ref->type), ref->addr, ref->at);
}

static void rprj_print_hint_script(RPrjCursor *cur, ut64 addr, RAnalAddrHintType ht, int value) {
	const char *cmd = (ht == R_ANAL_ADDR_HINT_TYPE_IMMBASE)? "ahi": "ahb";
	r_strbuf_appendf (cur->out, "'0x%08"PFMT64x"'%s %d\n", addr, cmd, value);
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
			rprj_print_hint_script (ctx->cur, addr, record->type, record->immbase);
			break;
		case R_ANAL_ADDR_HINT_TYPE_NEW_BITS:
			rprj_print_hint_script (ctx->cur, addr, record->type, record->newbits);
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

static void rprj_print_var_script(RPrjCursor *cur, RAnalFunction *fcn, RAnalVar *var) {
	if (!var || R_STR_ISEMPTY (var->name)) {
		return;
	}
	const char *type = r_str_get (var->type);
	switch (var->kind) {
	case R_ANAL_VAR_KIND_REG:
		if (R_STR_ISNOTEMPTY (var->regname)) {
			r_strbuf_appendf (cur->out, "'0x%08"PFMT64x"'afvr %s %s %s\n",
				fcn->addr, var->regname, var->name, type);
		}
		break;
	case R_ANAL_VAR_KIND_BPV:
		// nothing restores bp_off on replay (af+ and the loader both leave it 0), so bp deltas stay raw
		r_strbuf_appendf (cur->out, "'0x%08"PFMT64x"'afvb %d %s %s\n",
			fcn->addr, var->delta, var->name, type);
		break;
	case R_ANAL_VAR_KIND_SPV:
		// the afS emitted above restores the frame these offsets are relative to
		r_strbuf_appendf (cur->out, "'0x%08"PFMT64x"'afvs %"PFMT64d" %s %s\n",
			fcn->addr,
			r_anal_var_frame_delta (cur->core->anal, fcn, var->kind, var->delta),
			var->name, type);
		break;
	default:
		break;
	}
}

static void rprj_print_function_attrs(RPrjCursor *cur, RAnalFunction *fcn) {
	if (R_STR_ISNOTEMPTY (fcn->callconv)) {
		r_strbuf_appendf (cur->out, "'0x%08"PFMT64x"'afc %s\n", fcn->addr, fcn->callconv);
	}
	// always emitted, even for an empty frame, because the afv[bs] offsets are relative to it
	r_strbuf_appendf (cur->out, "'0x%08"PFMT64x"'afS %d\n", fcn->addr, fcn->maxstack);
	if (fcn->is_noreturn) {
		r_strbuf_appendf (cur->out, "'tn 0x%08"PFMT64x"\n", fcn->addr);
	}
}

static void rprj_print_function_script(RPrjCursor *cur, RAnalFunction *fcn) {
	if (!fcn || R_STR_ISEMPTY (fcn->name)) {
		return;
	}
	r_strbuf_appendf (cur->out, "'af+ 0x%08"PFMT64x" %s\n", fcn->addr, fcn->name);
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		r_strbuf_appendf (cur->out, "'afb+ 0x%08"PFMT64x" 0x%08"PFMT64x" %"PFMT64u" 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
			fcn->addr, bb->addr, bb->size, bb->jump, bb->fail);
		if (rprj_color_is_set (&bb->color)) {
			r_strbuf_appendf (cur->out, "'afbc rgb:%02x%02x%02x 0x%08"PFMT64x"\n",
				bb->color.r, bb->color.g, bb->color.b, bb->addr);
		}
	}
	// after the blocks, before the vars: afS needs a resolvable function and sets the frame the afv[bs] offsets use
	rprj_print_function_attrs (cur, fcn);
	RAnalVar **var;
	R_VEC_FOREACH (&fcn->vars, var) {
		rprj_print_var_script (cur, fcn, *var);
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
			r_strbuf_appendf (cur->out, "'afb+ 0x%08"PFMT64x" 0x%08"PFMT64x" %"PFMT64u" 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
				fcn->addr, bb->addr, bb->size, bb->jump, bb->fail);
		}
		if ((pbb && (pbb->has_color != has_color || (has_color && !rprj_color_eq (&pbb->color, &bb->color))))
				|| (!pbb && has_color)) {
			if (has_color) {
				r_strbuf_appendf (cur->out, "'afbc rgb:%02x%02x%02x 0x%08"PFMT64x"\n",
					bb->color.r, bb->color.g, bb->color.b, bb->addr);
			} else {
				r_strbuf_appendf (cur->out, "'afbc- 0x%08"PFMT64x"\n", bb->addr);
			}
		}
	}
	R2ProjectDiffBlock *pbb;
	r_list_foreach (pbbs, iter, pbb) {
		if (!pbb->seen) {
			r_strbuf_appendf (cur->out, "'afb- 0x%08"PFMT64x"\n", pbb->addr);
		}
	}
}

static void rprj_diff_function_attrs(RPrjCursor *cur, RAnalFunction *fcn, R2ProjectFunctionAttr *attr) {
	const char *cc = attr && attr->cc != UT32_MAX? rprj_st_get (cur->st, attr->cc): NULL;
	const bool noret = attr && (attr->flags & RPRJ_FUNC_ATTR_NORETURN);
	const st64 stack = attr? (st64)attr->stack: 0;
	if (strcmp (r_str_get (cc), r_str_get (fcn->callconv))) {
		if (R_STR_ISNOTEMPTY (fcn->callconv)) {
			r_strbuf_appendf (cur->out, "'0x%08"PFMT64x"'afc %s\n", fcn->addr, fcn->callconv);
		}
	}
	if (stack != fcn->maxstack) {
		r_strbuf_appendf (cur->out, "'0x%08"PFMT64x"'afS %d\n", fcn->addr, fcn->maxstack);
	}
	if (noret != fcn->is_noreturn) {
		r_strbuf_appendf (cur->out, fcn->is_noreturn
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
			rprj_print_var_script (cur, fcn, var);
		}
	}
	RListIter *iter;
	R2ProjectDiffVar *pvar;
	r_list_foreach (pvars, iter, pvar) {
		if (!pvar->seen && R_STR_ISNOTEMPTY (pvar->name)) {
			r_strbuf_appendf (cur->out, "'0x%08"PFMT64x"'afv- %s\n", fcn->addr, pvar->name);
		}
	}
}

static bool rprj_function_resolve(RPrjCursor *cur, int mode, R2ProjectFunction *pfcn,
		R2ProjectFunctionAttr *attrs, ut32 nattrs, RList *pfcns, ut64 *out_va, RAnalFunction **out_fcn) {
	RCore *core = cur->core;
	const char *name = rprj_st_get (cur->st, pfcn->name);
	ut64 va = UT64_MAX;
	RAnalFunction *fcn = NULL;
	if (!rprj_mod_va (cur, &pfcn->addr, &va)) {
		*out_va = va;
		*out_fcn = NULL;
		return false;
	}
	if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
		R2ProjectDiffAddr *df = R_NEW (R2ProjectDiffAddr);
		df->addr = va;
		r_list_append (pfcns, df);
		fcn = rprj_function_get_registered (core->anal, va);
	}
	if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
		r_strbuf_appendf (cur->out, "'af+ 0x%08"PFMT64x" %s\n", va, name? name: "");
	}
	if (mode & R_CORE_NEWPRJ_MODE_LOAD) {
		fcn = rprj_function_get_registered (core->anal, va);
		if (!fcn) {
			rprj_function_drop_stale_name (core->anal, name);
			R2ProjectFunctionAttr *attr = pfcn->attr < nattrs? attrs + pfcn->attr: NULL;
			fcn = r_anal_create_function (core->anal, name, va, attr? attr->type: 0, NULL);
		}
		if (fcn && name) {
			r_anal_function_rename (fcn, name);
		}
	}
	if (pfcn->attr < nattrs) {
		rprj_function_attr_load (cur, fcn, attrs + pfcn->attr, name, va, mode);
	}
	*out_va = va;
	*out_fcn = fcn;
	return true;
}

static void rprj_function_diff_block(RPrjCursor *cur, R2ProjectBlock *pbb, RList *pbbs, RColor *colors, ut32 ncolors) {
	R2ProjectDiffBlock *dbb = R_NEW0 (R2ProjectDiffBlock);
	dbb->size = pbb->size;
	rprj_mod_va (cur, &pbb->addr, &dbb->addr);
	rprj_mod_va (cur, &pbb->jump, &dbb->jump);
	rprj_mod_va (cur, &pbb->fail, &dbb->fail);
	if (pbb->color < ncolors) {
		dbb->has_color = true;
		dbb->color = colors[pbb->color];
	}
	r_list_append (pbbs, dbb);
}

static void rprj_function_diff_var(RPrjCursor *cur, R2ProjectVar *pvar, RList *pvars) {
	const char *vname = rprj_st_get (cur->st, pvar->name);
	if (!vname) {
		return;
	}
	R2ProjectDiffVar *dvar = R_NEW0 (R2ProjectDiffVar);
	dvar->name = strdup (vname);
	dvar->type = strdup (r_str_get (rprj_st_get (cur->st, pvar->type)));
	dvar->delta = pvar->delta;
	dvar->kind = pvar->kind;
	dvar->isarg = pvar->isarg;
	r_list_append (pvars, dvar);
}

static void rprj_function_load(RPrjCursor *cur, int mode, ut64 next_entry) {
	RBuffer *b = cur->b;
	RCore *core = cur->core;
	ut32 count = 0;
	ut32 ncolors = 0;
	RColor *colors = NULL;
	R2ProjectFunctionAttr *attrs = NULL;
	RList *pfcns = NULL;
	RList *pbbs = NULL;
	RList *pvars = NULL;
	if (!rprj_entry_has (b, next_entry, sizeof (ncolors)) || !rprj_read_le32 (b, &ncolors)) {
		R_LOG_WARN ("Truncated function entry");
		return;
	}
	ut64 remaining = rprj_entry_remaining (b, next_entry);
	if (ncolors > remaining / RPRJ_COLOR_SIZE) {
		R_LOG_WARN ("Invalid function color table size %u", ncolors);
		return;
	}
	if (ncolors > 0) {
		colors = R_NEWS0 (RColor, ncolors);
		if (!colors) {
			return;
		}
		ut32 i;
		for (i = 0; i < ncolors; i++) {
			if (!rprj_read_color (b, colors + i)) {
				R_LOG_WARN ("Truncated function color record %u/%u", i, ncolors);
				goto cleanup;
			}
		}
	}
	ut32 nattrs = 0;
	if (!rprj_entry_has (b, next_entry, sizeof (nattrs)) || !rprj_read_le32 (b, &nattrs)) {
		R_LOG_WARN ("Truncated function attribute table");
		goto cleanup;
	}
	remaining = rprj_entry_remaining (b, next_entry);
	if (nattrs > remaining / RPRJ_FUNCTION_ATTR_SIZE) {
		R_LOG_WARN ("Invalid function attribute table size %u", nattrs);
		goto cleanup;
	}
	if (nattrs > 0) {
		attrs = R_NEWS0 (R2ProjectFunctionAttr, nattrs);
		if (!attrs) {
			goto cleanup;
		}
		ut32 i;
		for (i = 0; i < nattrs; i++) {
			if (!rprj_function_attr_read (b, attrs + i)) {
				R_LOG_WARN ("Truncated function attribute record %u/%u", i, nattrs);
				goto cleanup;
			}
		}
	}
	if (!rprj_entry_has (b, next_entry, sizeof (count)) || !rprj_read_le32 (b, &count)) {
		R_LOG_WARN ("Truncated function count");
		goto cleanup;
	}
	const ut64 fbmax = rprj_entry_remaining (b, next_entry) / RPRJ_FUNCTION_SIZE;
	if (count > fbmax) {
		R_LOG_WARN ("Invalid function record count %u", count);
		count = (ut32)fbmax;
	}
	const bool diff = (mode & R_CORE_NEWPRJ_MODE_DIFF) != 0;
	pfcns = diff? r_list_newf (free): NULL;
	ut32 i;
	for (i = 0; i < count && r_buf_at (b) < next_entry; i++) {
		R2ProjectFunction pfcn;
		if (!rprj_entry_has (b, next_entry, RPRJ_FUNCTION_SIZE) || !rprj_function_read (b, &pfcn)) {
			R_LOG_WARN ("Truncated function record %u/%u", i, count);
			break;
		}
		ut64 va = UT64_MAX;
		RAnalFunction *fcn = NULL;
		const bool resolved = rprj_function_resolve (cur, mode, &pfcn, attrs, nattrs, pfcns, &va, &fcn);
		if (!resolved) {
			R_LOG_WARN ("Cannot resolve function record %u/%u", i, count);
		}
		pbbs = diff? r_list_newf (free): NULL;
		pvars = diff? r_list_newf ((RListFree)rprj_diff_var_free): NULL;
		const ut64 bbmax = rprj_entry_remaining (b, next_entry) / RPRJ_BLOCK_SIZE;
		if (pfcn.nbbs > bbmax) {
			R_LOG_WARN ("Invalid basic block count %u in function %u/%u", pfcn.nbbs, i, count);
			pfcn.nbbs = (ut32)bbmax;
		}
		ut32 j;
		for (j = 0; j < pfcn.nbbs && r_buf_at (b) < next_entry; j++) {
			R2ProjectBlock pbb;
			if (!rprj_entry_has (b, next_entry, RPRJ_BLOCK_SIZE) || !rprj_block_read (b, &pbb)) {
				R_LOG_WARN ("Truncated basic block record %u/%u in function %u/%u", j, pfcn.nbbs, i, count);
				goto cleanup;
			}
			if (resolved) {
				if (diff) {
					rprj_function_diff_block (cur, &pbb, pbbs, colors, ncolors);
				}
				rprj_block_load (cur, fcn, &pbb, mode, va, colors, ncolors);
			}
		}
		const st64 fstack = pfcn.attr < nattrs? (st64)attrs[pfcn.attr].stack: 0;
		if (resolved && (mode & R_CORE_NEWPRJ_MODE_SCRIPT)) {
			// always emitted, even for an empty frame, because the afvs offsets below are relative to it
			r_strbuf_appendf (cur->out, "'0x%08"PFMT64x"'afS %"PFMT64d"\n", va, fstack);
		}
		const ut64 vbmax = rprj_entry_remaining (b, next_entry) / RPRJ_VAR_SIZE;
		if (pfcn.nvars > vbmax) {
			R_LOG_WARN ("Invalid variable count %u in function %u/%u", pfcn.nvars, i, count);
			pfcn.nvars = (ut32)vbmax;
		}
		for (j = 0; j < pfcn.nvars && r_buf_at (b) < next_entry; j++) {
			R2ProjectVar pvar;
			if (!rprj_entry_has (b, next_entry, RPRJ_VAR_SIZE) || !rprj_var_read (b, &pvar)) {
				R_LOG_WARN ("Truncated variable record %u/%u in function %u/%u", j, pfcn.nvars, i, count);
				goto cleanup;
			}
			if (resolved) {
				if (diff) {
					rprj_function_diff_var (cur, &pvar, pvars);
				}
				rprj_var_load (cur, fcn, &pvar, mode, va, fstack);
			}
		}
		if (diff && resolved) {
			const char *name = rprj_st_get (cur->st, pfcn.name);
			if (!fcn) {
				r_strbuf_appendf (cur->out, "'af- 0x%08"PFMT64x"\n", va);
			} else {
				if (name && strcmp (name, r_str_get (fcn->name))) {
					r_strbuf_appendf (cur->out, "'afn %s 0x%08"PFMT64x"\n", fcn->name, va);
				}
				rprj_diff_function_attrs (cur, fcn, pfcn.attr < nattrs? attrs + pfcn.attr: NULL);
				rprj_diff_function_blocks (cur, fcn, pbbs);
				rprj_diff_function_vars (cur, fcn, pvars);
			}
		}
		r_list_free (pvars);
		r_list_free (pbbs);
		pvars = NULL;
		pbbs = NULL;
	}
	if (diff) {
		RListIter *iter;
		RAnalFunction *fcn;
		RList *fcns = r_anal_get_fcns (core->anal);
		r_list_foreach (fcns, iter, fcn) {
			if (fcn && !rprj_diff_has_addr (pfcns, fcn->addr)) {
				rprj_print_function_script (cur, fcn);
			}
		}
	}
cleanup:
	r_list_free (pvars);
	r_list_free (pbbs);
	r_list_free (pfcns);
	free (attrs);
	free (colors);
}

static void rprj_info_load(RPrjCursor *cur, int mode, ut64 next_entry) {
	RCore *core = cur->core;
	RBuffer *b = cur->b;
	if (!rprj_entry_has (b, next_entry, RPRJ_INFO_SIZE)) {
		R_LOG_WARN ("Truncated project info entry");
		return;
	}
	R2ProjectInfo cmds = {0};
	if (!rprj_info_read (b, &cmds)) {
		R_LOG_WARN ("Truncated project info entry");
		return;
	}
	const char *name = rprj_st_get (cur->st, cmds.name);
	const char *user = rprj_st_get (cur->st, cmds.user);
	if (!name || !user) {
		R_LOG_WARN ("Invalid project info string index (%u,%u)", cmds.name, cmds.user);
		return;
	}
	if (mode & R_CORE_NEWPRJ_MODE_LOG) {
		r_strbuf_append (cur->out, "    ProjectInfo {\n");
		r_strbuf_appendf (cur->out, "      Name: %s\n", name);
		r_strbuf_appendf (cur->out, "      User: %s\n", user);
		r_strbuf_append (cur->out, "    }\n");
	}
	if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
		const char *cur_name = r_config_get (core->config, "prj.name");
		const char *cur_user = r_config_get (core->config, "cfg.user");
		if (strcmp (r_str_get (cur_name), name)) {
			r_strbuf_appendf (cur->out, "'e prj.name=%s\n", r_str_get (cur_name));
		}
		if (strcmp (r_str_get (cur_user), user)) {
			r_strbuf_appendf (cur->out, "'e cfg.user=%s\n", r_str_get (cur_user));
		}
	}
}

static void rprj_meta_load(RPrjCursor *cur, int mode, ut64 next_entry, RAnalMetaType type) {
	RCore *core = cur->core;
	RBuffer *b = cur->b;
	const bool vartype = type == R_META_TYPE_VARTYPE;
	const char *kind = vartype? "type annotation": "comment";
	const bool diff = (mode & R_CORE_NEWPRJ_MODE_DIFF) != 0;
	RList *seen = diff? r_list_newf (free): NULL;
	while (rprj_entry_remaining (b, next_entry) >= RPRJ_CMNT_SIZE) {
		const ut64 at = r_buf_at (b);
		R2ProjectComment cmnt;
		if (!rprj_cmnt_read (b, &cmnt)) {
			R_LOG_WARN ("Truncated %s record at 0x%08"PFMT64x, kind, at);
			break;
		}
		const char *cmnt_text = rprj_st_get (cur->st, cmnt.text);
		if (!cmnt_text) {
			R_LOG_WARN ("Invalid %s string index %u", kind, cmnt.text);
			continue;
		}
		R2ProjectAddr addr = { .mod = cmnt.mod, .delta = cmnt.delta };
		ut64 va = UT64_MAX;
		if (!rprj_mod_va (cur, &addr, &va)) {
			R_LOG_WARN ("Cannot resolve address for %s %s", kind, cmnt_text);
			continue;
		}
		char *b64 = sdb_encode ((const ut8 *)cmnt_text, strlen (cmnt_text));
		if (b64) {
			char *cmd = r_str_newf (vartype? "Ct= base64:%s": "CCu base64:%s", b64);
			if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
				r_strbuf_appendf (cur->out, "'@0x%08"PFMT64x"'%s\n", va, cmd);
			}
			if (mode & R_CORE_NEWPRJ_MODE_LOAD) {
				r_core_call_at (core, va, cmd);
			}
			free (cmd);
			free (b64);
		}
		if (diff) {
			rprj_diff_seen_addr (seen, va);
			const char *current = r_meta_get_string (core->anal, type, va);
			if (strcmp (r_str_get (current), cmnt_text)) {
				rprj_print_meta_script (cur, type, va, current);
			}
		}
	}
	if (diff) {
		RIntervalTreeIter it;
		RAnalMetaItem *item;
		r_interval_tree_foreach (&core->anal->meta, it, item) {
			RIntervalNode *node = r_interval_tree_iter_get (&it);
			if (item->type == type && !rprj_diff_has_addr (seen, node->start)) {
				rprj_print_meta_script (cur, type, node->start, item->str);
			}
		}
	}
	r_list_free (seen);
}

static void rprj_cmnt_load(RPrjCursor *cur, int mode, ut64 next_entry) {
	rprj_meta_load (cur, mode, next_entry, R_META_TYPE_COMMENT);
}

static void rprj_vart_load(RPrjCursor *cur, int mode, ut64 next_entry) {
	rprj_meta_load (cur, mode, next_entry, R_META_TYPE_VARTYPE);
}

typedef struct {
	RCoreAnalArtifactReplacement replacement;
	RCoreAnalArtifactComment *comments;
	RCoreAnalArtifactFlag *flags;
	RAnalRef *xrefs;
} RPrjArtifactSet;

typedef struct {
	ut64 revision;
	bool captured;
} RPrjArtifactRevision;


static void rprj_artifact_sets_free(RPrjArtifactSet *sets, ut32 count) {
	if (sets) {
		ut32 i;
		for (i = 0; i < count; i++) {
			free (sets[i].comments);
			free (sets[i].flags);
			free (sets[i].xrefs);
		}
	}
	free (sets);
}

static bool rprj_artifact_read_addr(RBuffer *buffer, R2ProjectAddr *addr) {
	return rprj_read_le32 (buffer, &addr->mod) && rprj_read_le64 (buffer, &addr->delta);
}

static bool rprj_artifact_read_set(RPrjCursor *cur, int mode, ut64 next_entry, RPrjArtifactSet *set) {
	RBuffer *buffer = cur->b;
	ut32 provider_index;
	ut32 domain_index;
	R2ProjectAddr scope;
	ut32 comment_count;
	ut32 flag_count;
	ut32 xref_count;
	if (!rprj_entry_has (buffer, next_entry, RPRJ_ARTIFACT_SET_SIZE)
			|| !rprj_read_le32 (buffer, &provider_index)
			|| !rprj_read_le32 (buffer, &domain_index)
			|| !rprj_artifact_read_addr (buffer, &scope)
			|| !rprj_read_le32 (buffer, &comment_count)
			|| !rprj_read_le32 (buffer, &flag_count)
			|| !rprj_read_le32 (buffer, &xref_count)) {
		return false;
	}
	const char *provider_id = rprj_st_get (cur->st, provider_index);
	const char *domain_id = rprj_st_get (cur->st, domain_index);
	ut64 scope_id;
	if (!provider_id || !domain_id || !rprj_mod_va (cur, &scope, &scope_id)
			|| comment_count > 4096 || flag_count > 4096 || xref_count > 1 << 20) {
		return false;
	}
	ut64 required = (ut64)comment_count * RPRJ_ARTIFACT_COMMENT_SIZE
		+ (ut64)flag_count * RPRJ_ARTIFACT_FLAG_SIZE
		+ (ut64)xref_count * RPRJ_XREF_SIZE;
	if (required > rprj_entry_remaining (buffer, next_entry)) {
		return false;
	}
	set->comments = comment_count? R_NEWS0 (RCoreAnalArtifactComment, comment_count): NULL;
	set->flags = flag_count? R_NEWS0 (RCoreAnalArtifactFlag, flag_count): NULL;
	set->xrefs = xref_count? R_NEWS0 (RAnalRef, xref_count): NULL;
	if ((comment_count && !set->comments) || (flag_count && !set->flags)
			|| (xref_count && !set->xrefs)) {
		return false;
	}
	ut32 i;
	for (i = 0; i < comment_count; i++) {
		R2ProjectAddr addr;
		ut32 prefix_index;
		ut32 text_index;
		if (!rprj_artifact_read_addr (buffer, &addr)
				|| !rprj_read_le32 (buffer, &prefix_index)
				|| !rprj_read_le32 (buffer, &text_index)
				|| !rprj_mod_va (cur, &addr, &set->comments[i].addr)) {
			return false;
		}
		set->comments[i].prefix = rprj_st_get (cur->st, prefix_index);
		set->comments[i].text = rprj_st_get (cur->st, text_index);
		if (!set->comments[i].prefix || !set->comments[i].text) {
			return false;
		}
	}
	for (i = 0; i < flag_count; i++) {
		ut32 name_index;
		R2ProjectAddr addr;
		if (!rprj_read_le32 (buffer, &name_index)
				|| !rprj_artifact_read_addr (buffer, &addr)
				|| !rprj_read_le64 (buffer, &set->flags[i].size)
				|| !rprj_mod_va (cur, &addr, &set->flags[i].addr)) {
			return false;
		}
		set->flags[i].name = rprj_st_get (cur->st, name_index);
		if (!set->flags[i].name) {
			return false;
		}
	}
	for (i = 0; i < xref_count; i++) {
		R2ProjectAddr from;
		R2ProjectAddr to;
		ut32 type;
		if (!rprj_artifact_read_addr (buffer, &from)
				|| !rprj_artifact_read_addr (buffer, &to)
				|| !rprj_read_le32 (buffer, &type)
				|| !rprj_mod_va (cur, &from, &set->xrefs[i].at)
				|| !rprj_mod_va (cur, &to, &set->xrefs[i].addr)) {
			return false;
		}
		set->xrefs[i].type = type;
	}
	set->replacement = (RCoreAnalArtifactReplacement) {
		.provider_id = provider_id,
		.domain_id = domain_id,
		.scope_id = scope_id,
		.comments = set->comments,
		.comment_count = comment_count,
		.flags = set->flags,
		.flag_count = flag_count,
		.xrefs = set->xrefs,
		.xref_count = xref_count,
	};
	if (mode & R_CORE_NEWPRJ_MODE_LOAD) {
		RAnalFunction *function = r_anal_get_function_at (cur->core->anal, scope_id);
		if (!function || function->addr != scope_id) {
			return false;
		}
		ut64 revision = 0;
		if (!r_core_function_context_hash (cur->core, scope_id, &revision, NULL)) {
			return false;
		}
		set->replacement.expected_function_epoch = r_anal_function_dirty_epoch (function);
		set->replacement.expected_type_epoch = cur->core->anal->type_dirty_epoch;
		set->replacement.expected_snapshot_revision = revision;
	}
	return true;
}

static void rprj_artifact_load(RPrjCursor *cur, int mode, ut64 next_entry) {
	RBuffer *buffer = cur->b;
	ut32 schema_version;
	ut32 set_count;
	if (!rprj_entry_has (buffer, next_entry, RPRJ_ARTIFACT_HEADER_SIZE)
			|| !rprj_read_le32 (buffer, &schema_version)
			|| !rprj_read_le32 (buffer, &set_count)
			|| schema_version != RPRJ_ARTIFACT_SCHEMA_VERSION
			|| set_count > RPRJ_ARTIFACT_MAX_SETS) {
		R_LOG_WARN ("Invalid analysis-artifact project entry");
		cur->failed = true;
		return;
	}
	RPrjArtifactSet *sets = set_count? R_NEWS0 (RPrjArtifactSet, set_count): NULL;
	if (set_count && !sets) {
		cur->failed = true;
		return;
	}
	ut32 i;
	for (i = 0; i < set_count; i++) {
		if (!rprj_artifact_read_set (cur, mode, next_entry, &sets[i])) {
			R_LOG_WARN ("Invalid analysis-artifact set %u/%u", i, set_count);
			rprj_artifact_sets_free (sets, set_count);
			cur->failed = true;
			return;
		}
	}
	if (mode & R_CORE_NEWPRJ_MODE_LOG) {
		r_strbuf_appendf (cur->out, "  schema = %u, sets = %u\n", schema_version, set_count);
	}
	if ((mode & R_CORE_NEWPRJ_MODE_LOAD) && set_count) {
		RCoreAnalArtifactReplacement *replacements = R_NEWS0 (
			RCoreAnalArtifactReplacement, set_count);
		if (!replacements) {
			cur->failed = true;
			rprj_artifact_sets_free (sets, set_count);
			return;
		}
		for (i = 0; i < set_count; i++) {
			replacements[i] = sets[i].replacement;
		}
		RCoreAnalArtifactReplaceResult result = r_core_anal_artifacts_replace (
			cur->core, replacements, set_count);
		if (result.status != R_CORE_ANAL_ARTIFACT_REPLACE_OK) {
			R_LOG_WARN ("Cannot restore analysis-artifact ownership: %u", result.status);
			cur->failed = true;
		}
		free (replacements);
	}
	rprj_artifact_sets_free (sets, set_count);
}

static void rprj_xref_load(RPrjCursor *cur, int mode, ut64 next_entry) {
	RCore *core = cur->core;
	RBuffer *b = cur->b;
	ut32 count = 0;
	if (!rprj_entry_has (b, next_entry, sizeof (count)) || !rprj_read_le32 (b, &count)) {
		R_LOG_WARN ("Truncated xref entry");
		return;
	}
	const ut64 bmax = rprj_entry_remaining (b, next_entry) / RPRJ_XREF_SIZE;
	if (count > bmax) {
		R_LOG_WARN ("Invalid xref record count %u", count);
		count = (ut32)bmax;
	}
	const bool diff = (mode & R_CORE_NEWPRJ_MODE_DIFF) != 0;
	RList *seen = diff? r_list_newf (free): NULL;
	ut32 i;
	for (i = 0; i < count; i++) {
		R2ProjectXref xref;
		if (!rprj_entry_has (b, next_entry, RPRJ_XREF_SIZE) || !rprj_xref_read (b, &xref)) {
			R_LOG_WARN ("Truncated xref record %u/%u", i, count);
			break;
		}
		ut64 from = UT64_MAX;
		ut64 to = UT64_MAX;
		if (!rprj_mod_va (cur, &xref.from, &from) || !rprj_mod_va (cur, &xref.to, &to)) {
			R_LOG_WARN ("Cannot resolve xref record %u/%u", i, count);
			continue;
		}
		if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
			r_strbuf_appendf (cur->out, "'ax%c 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
				(char)R_ANAL_REF_TYPE_MASK (xref.type), to, from);
		}
		if (diff) {
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
				r_strbuf_appendf (cur->out, "'ax- 0x%08"PFMT64x" 0x%08"PFMT64x"\n", to, from);
			}
		}
		if (mode & R_CORE_NEWPRJ_MODE_LOAD) {
			r_anal_xrefs_set (core->anal, from, to, xref.type);
		}
	}
	if (diff) {
		RVecAnalRef *refs = r_anal_refs_get (core->anal, UT64_MAX);
		if (refs) {
			RAnalRef *ref;
			R_VEC_FOREACH (refs, ref) {
				if (!rprj_diff_xref_find (seen, ref->at, ref->addr, ref->type)) {
					rprj_print_xref_script (cur, ref);
				}
			}
			RVecAnalRef_free (refs);
		}
	}
	r_list_free (seen);
}

static void rprj_hint_apply(RPrjCursor *cur, int mode, ut64 va, ut32 hint_kind, int value, RList *seen) {
	RCore *core = cur->core;
	const bool immbase = hint_kind == 1;
	const RAnalAddrHintType ht = immbase? R_ANAL_ADDR_HINT_TYPE_IMMBASE: R_ANAL_ADDR_HINT_TYPE_NEW_BITS;
	if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
		rprj_print_hint_script (cur, va, ht, value);
	}
	if (mode & R_CORE_NEWPRJ_MODE_DIFF) {
		rprj_diff_seen_addr (seen, (va << 8) | (ut64)ht);
		int curval = 0;
		if (!rprj_current_hint_value (core->anal, va, ht, &curval) || curval != value) {
			if (curval) {
				rprj_print_hint_script (cur, va, ht, curval);
			} else {
				// bare ah- clears every hint, so the address must be an argument
				r_strbuf_appendf (cur->out, "'ah- 0x%08"PFMT64x"\n", va);
			}
		}
	}
	if (mode & R_CORE_NEWPRJ_MODE_LOAD) {
		if (immbase) {
			r_anal_hint_set_immbase (core->anal, va, value);
		} else {
			r_anal_hint_set_newbits (core->anal, va, value);
		}
	}
}

static void rprj_hint_load(RPrjCursor *cur, int mode, ut64 next_entry) {
	RBuffer *b = cur->b;
	const bool diff = (mode & R_CORE_NEWPRJ_MODE_DIFF) != 0;
	RList *seen = diff? r_list_newf (free): NULL;
	while (rprj_entry_remaining (b, next_entry) >= RPRJ_HINT_SIZE) {
		const ut64 at = r_buf_at (b);
		R2ProjectHint hint;
		if (!rprj_hint_read (b, &hint)) {
			R_LOG_WARN ("Truncated hint record at 0x%08"PFMT64x, at);
			break;
		}
		R2ProjectAddr addr = { .mod = hint.mod, .delta = hint.delta };
		ut64 va = UT64_MAX;
		if (!rprj_mod_va (cur, &addr, &va) || va == UT64_MAX) {
			R_LOG_WARN ("Cannot resolve hint record at 0x%08"PFMT64x, at);
			continue;
		}
		if (hint.kind == 1 || hint.kind == 2) {
			rprj_hint_apply (cur, mode, va, hint.kind, (int)hint.value, seen);
		}
	}
	if (diff) {
		R2ProjectDiffCtx ctx = { cur, seen };
		r_anal_addr_hints_foreach (cur->core->anal, rprj_diff_hints_cb, &ctx);
	}
	r_list_free (seen);
}

static void rprj_strs_log(RPrjCursor *cur, ut64 next_entry) {
	RBuffer *b = cur->b;
	ut64 size;
	const ut8 *bdata = r_buf_data (b, &size);
	const ut64 at = r_buf_at (b);
	const ut64 data_size = rprj_entry_remaining (b, next_entry);
	if (!bdata || at + data_size > size) {
		return;
	}
	const ut8 *data = bdata + at;
	ut64 i = 0;
	while (i < data_size) {
		const ut8 *nul = memchr (data + i, 0, data_size - i);
		if (!nul) {
			break;
		}
		const ut32 len = (ut32)(nul - (data + i));
		r_strbuf_appendf (cur->out, "      => (%u) %s\n", len, (const char *)data + i);
		i += len + 1;
	}
}

static void rprj_cmds_load(RPrjCursor *cur, int mode, ut64 next_entry) {
	RCore *core = cur->core;
	RBuffer *b = cur->b;
	if (mode & R_CORE_NEWPRJ_MODE_LOG) {
		r_strbuf_append (cur->out, "    [\n");
	}
	while (r_buf_at (b) < next_entry) {
		char *script;
		if (!rprj_string_read (b, next_entry, &script)) {
			R_LOG_ERROR ("Cannot read string");
			break;
		}
		if (mode & R_CORE_NEWPRJ_MODE_LOG) {
			r_strbuf_appendf (cur->out, "      '%s'\n", script);
		}
		if (mode & R_CORE_NEWPRJ_MODE_CMD) {
			r_core_cmd0 (core, script);
		}
		free (script);
	}
	if (mode & R_CORE_NEWPRJ_MODE_LOG) {
		r_strbuf_append (cur->out, "    ]\n");
	}
}

static void rprj_restore_io_maps(RPrjCursor *cur) {
	ut32 mapsize = 0;
	ut8 *mapsbuf = rprj_find (cur->b, RPRJ_MAPS, &mapsize);
	RBuffer *maps = mapsbuf? r_buf_new_with_bytes (mapsbuf, mapsize): NULL;
	if (maps) {
		RBuffer *ob = cur->b;
		cur->b = maps;
		rprj_maps_restore (cur);
		cur->b = ob;
		r_unref (maps);
	}
	free (mapsbuf);
}

static void rprj_load_mods(RPrjCursor *cur, ut8 **out_buf) {
	ut32 modsize = 0;
	*out_buf = rprj_find (cur->b, RPRJ_MODS, &modsize);
	if (!*out_buf) {
		return;
	}
	RBuffer *mods = r_buf_new_with_bytes (*out_buf, modsize);
	if (!mods) {
		return;
	}
	ut32 n = 0;
	while (n + RPRJ_MOD_SIZE <= modsize) {
		R2ProjectMod mod;
		if (!rprj_mods_read (mods, &mod)) {
			R_LOG_ERROR ("Cannot read mod");
			break;
		}
		R_LOG_DEBUG ("MOD: %s + 0x%08"PFMT64x, rprj_st_get (cur->st, mod.name), mod.vmin);
		R2ProjectMod *slot = RVecPrjMod_emplace_back (&cur->mods);
		*slot = mod;
		n += RPRJ_MOD_SIZE;
	}
	rprj_mods_rebase (cur);
	r_unref (mods);
}

static char *r_core_newprj_load(RCore *core, const char *file, int mode) {
	RBuffer *b = r_buf_new_from_file (file);
	if (!b) {
		R_LOG_ERROR ("Cannot open file");
		return NULL;
	}
	R2ProjectHeader hdr;
	if (!rprj_header_read (b, &hdr)) {
		R_LOG_ERROR ("Invalid file type");
		r_unref (b);
		return NULL;
	}
	if (hdr.version < RPRJ_MIN_VERSION || hdr.version > RPRJ_VERSION) {
		R_LOG_ERROR ("Unsupported project version %d (this build understands versions %d-%d)",
			hdr.version, RPRJ_MIN_VERSION, RPRJ_VERSION);
		r_unref (b);
		return NULL;
	}
	R2ProjectStringTable st = {0};
	RStrBuf *out = r_strbuf_new ("");
	RPrjCursor cur = {
		.core = core,
		.st = &st,
		.b = b,
		.out = out,
	};
	if (mode & R_CORE_NEWPRJ_MODE_LOG) {
		r_strbuf_append (out, "Project {\n");
		r_strbuf_append (out, "  Header {\n");
		r_strbuf_appendf (out, "    magic = 0x%08x OK\n", hdr.magic);
		r_strbuf_appendf (out, "    version = %d\n", hdr.version);
		r_strbuf_append (out, "  }\n");
	}
	RVecPrjMod_init (&cur.mods);
	ut8 *modsbuf = NULL;
	st.data = rprj_find (b, RPRJ_STRS, &st.size);
	if (!st.data) {
		R_LOG_ERROR ("Missing string table (RPRJ_STRS) in project file");
		cur.failed = true;
		goto done;
	}
	if (!rprj_st_is_valid (&st)) {
		R_LOG_ERROR ("Invalid string table (RPRJ_STRS) in project file");
		cur.failed = true;
		goto done;
	}
	if (mode & R_CORE_NEWPRJ_MODE_RIO) {
		rprj_restore_io_maps (&cur);
	}
	rprj_load_mods (&cur, &modsbuf);

	R2ProjectEntry entry;
	r_buf_seek (b, RPRJ_HEADER_SIZE, SEEK_SET);
	int n = 0;
	const ut64 bsz = r_buf_size (b);
	while (r_buf_at (b) < bsz) {
		const ut64 entry_at = r_buf_at (b);
		if (!rprj_entry_read (b, &entry)) {
			R_LOG_ERROR ("Cannot read entry");
			cur.failed = true;
			break;
		}
		if (entry.size < RPRJ_ENTRY_SIZE || entry.size > bsz - entry_at) {
			R_LOG_ERROR ("Invalid entry size %u", entry.size);
			cur.failed = true;
			break;
		}
		if (mode & R_CORE_NEWPRJ_MODE_LOG) {
			r_strbuf_appendf (out, "  Entry<%s> {\n", rprj_entry_type_tostring (entry.type));
			r_strbuf_appendf (out, "    type = 0x%02x\n", entry.type);
			r_strbuf_appendf (out, "    size = %d\n", entry.size);
		}
		if (mode & R_CORE_NEWPRJ_MODE_SCRIPT) {
			r_strbuf_appendf (out, "'f entry%d.%s=0x%08"PFMT64x"\n", n, rprj_entry_type_tostring (entry.type), r_buf_at (b));
		}
		const ut64 next_entry = entry_at + entry.size;
		switch (entry.type) {
		case RPRJ_STRS:
			if (mode & R_CORE_NEWPRJ_MODE_LOG) {
				rprj_strs_log (&cur, next_entry);
			}
			break;
		case RPRJ_MODS:
		case RPRJ_MAPS:
			break;
		case RPRJ_CMDS:
			rprj_cmds_load (&cur, mode, next_entry);
			break;
		case RPRJ_INFO:
			rprj_info_load (&cur, mode, next_entry);
			break;
		case RPRJ_CMNT:
			rprj_cmnt_load (&cur, mode, next_entry);
			break;
		case RPRJ_VART:
			rprj_vart_load (&cur, mode, next_entry);
			break;
		case RPRJ_FLAG:
			rprj_flag_load (&cur, mode, next_entry);
			break;
		case RPRJ_EVAL:
			rprj_eval_load (&cur, mode, next_entry);
			break;
		case RPRJ_XREF:
			rprj_xref_load (&cur, mode, next_entry);
			break;
		case RPRJ_ARTF:
			rprj_artifact_load (&cur, mode, next_entry);
			break;
		case RPRJ_FUNC:
			rprj_function_load (&cur, mode, next_entry);
			break;
		case RPRJ_HINT:
			rprj_hint_load (&cur, mode, next_entry);
			break;
		}
		if (cur.failed) {
			break;
		}
		if (mode & R_CORE_NEWPRJ_MODE_LOG) {
			r_strbuf_append (out, "  }\n");
		}
		// skip to the next entry
		r_buf_seek (b, next_entry, SEEK_SET);
		n++;
	}
	if (mode & R_CORE_NEWPRJ_MODE_LOG) {
		r_strbuf_append (out, "}\n");
	}
done:
	free (modsbuf);
	RVecPrjMod_fini (&cur.mods);
	free (st.data);
	r_unref (b);
	if (cur.failed) {
		r_strbuf_free (out);
		return NULL;
	}
	return r_strbuf_drain (out);
}
