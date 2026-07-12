/* radare - MIT - Copyright 2024-2026 - pancake */

#define R_LOG_ORIGIN "prj"

#include "newprj.h"

static ut64 rprj_le32_reserve(RBuffer *b) {
	const ut64 at = r_buf_at (b);
	rprj_write_le32 (b, 0);
	return at;
}

static void rprj_le32_patch(RBuffer *b, ut64 at, ut32 v) {
	ut8 buf[4];
	r_write_le32 (buf, v);
	r_buf_write_at (b, at, buf, sizeof (buf));
}

static ut8 emit_str(RPrjCursor *cur, ut8 bit, const char *s) {
	if (R_STR_ISNOTEMPTY (s)) {
		rprj_write_le32 (cur->b, rprj_st_append (cur->st, s));
		return bit;
	}
	return 0;
}

static void rprj_flag_write_one(RPrjCursor *cur, RFlagItem *fi) {
	R2ProjectAddr addr = rprj_mod_addr (cur, fi->addr);
	const ut32 space_idx = fi->space? fi->space->privtag: UT32_MAX;
	RFlagItemMeta *fim = r_flag_get_meta (cur->core->flags, fi->id);
	const char *rn = (fi->realname && fi->realname != fi->name
			&& strcmp (fi->realname, fi->name))? fi->realname: NULL;
	const char *rw = (R_STR_ISNOTEMPTY (fi->rawname)
			&& strcmp (fi->rawname, fi->name)
			&& (!rn || strcmp (fi->rawname, rn)))? fi->rawname: NULL;
	// Reserve head, emit tail (accumulating extras), patch head.
	ut64 head_at = r_buf_at (cur->b);
		ut8 head[RPRJ_FLAG_SIZE] = {0};
	r_buf_write (cur->b, head, sizeof (head));
	ut8 extras = fi->demangled? RPRJ_FLAG_DEMANGLED: 0;
	if (space_idx != UT32_MAX) {
		extras |= RPRJ_FLAG_SPACE;
		rprj_write_le32 (cur->b, space_idx);
	}
	extras |= emit_str (cur, RPRJ_FLAG_REALNAME, rn);
	extras |= emit_str (cur, RPRJ_FLAG_RAWNAME, rw);
	extras |= emit_str (cur, RPRJ_FLAG_TYPE, fim? fim->type: NULL);
	extras |= emit_str (cur, RPRJ_FLAG_COLOR, fim? fim->color: NULL);
	extras |= emit_str (cur, RPRJ_FLAG_COMMENT, fim? fim->comment: NULL);
	extras |= emit_str (cur, RPRJ_FLAG_ALIAS, fim? fim->alias: NULL);
	r_write_le32 (head + 0, rprj_st_append (cur->st, fi->name));
	r_write_le32 (head + 4, addr.mod);
	r_write_le64 (head + 8, addr.delta);
	r_write_le32 (head + 16, fi->size);
	head[20] = extras;
	r_buf_write_at (cur->b, head_at, head, sizeof (head));
}

static bool flag_foreach_cb(RFlagItem *fi, void *user) {
	rprj_flag_write_one (user, fi);
	return true;
}

static void rprj_flag_write(RPrjCursor *cur) {
	// Seed the privtags first
	RSpaceIter *sit;
	RSpace *sp;
	r_flag_space_foreach (cur->core->flags, sit, sp) {
		if (sp) {
			sp->privtag = R_STR_ISNOTEMPTY (sp->name)
				? rprj_st_append (cur->st, sp->name)
				: UT32_MAX;
		}
	}
	rprj_write_le32 (cur->b, (ut32)r_flag_count (cur->core->flags, NULL));
	r_flag_foreach (cur->core->flags, flag_foreach_cb, cur);
}

static void rprj_cmnt_write_one(RPrjCursor *cur, RIntervalNode *node, RAnalMetaItem *mi) {
	ut64 va = node->start;
	R2ProjectAddr addr = rprj_mod_addr (cur, va);
	const ut64 size = r_meta_node_size (node);
	R2ProjectComment cmnt = {
		.text = rprj_st_append (cur->st, mi->str),
		.mod = addr.mod,
		.delta = addr.delta,
		.size = size,
	};
	rprj_cmnt_write_record (cur->b, &cmnt);
}

static void rprj_meta_write(RPrjCursor *cur, RAnalMetaType type) {
	RIntervalTreeIter it;
	RAnalMetaItem *item;
	r_interval_tree_foreach (&cur->core->anal->meta, it, item) {
		RIntervalNode *node = r_interval_tree_iter_get (&it);
		if (item->type == type && R_STR_ISNOTEMPTY (item->str)) {
			rprj_cmnt_write_one (cur, node, item);
		}
	}
}

static void rprj_cmnt_write(RPrjCursor *cur) {
	rprj_meta_write (cur, R_META_TYPE_COMMENT);
}

static void rprj_vart_write(RPrjCursor *cur) {
	rprj_meta_write (cur, R_META_TYPE_VARTYPE);
}

static void rprj_xref_write_one(RPrjCursor *cur, RAnalRef *ref) {
	R2ProjectAddr from = rprj_mod_addr (cur, ref->at);
	R2ProjectAddr to = rprj_mod_addr (cur, ref->addr);
	rprj_write_project_addr (cur->b, from);
	rprj_write_project_addr (cur->b, to);
	rprj_write_le32 (cur->b, ref->type);
}

static void rprj_xref_write(RPrjCursor *cur) {
	RVecAnalRef *refs = r_anal_refs_get (cur->core->anal, UT64_MAX);
	const ut64 count_at = rprj_le32_reserve (cur->b);
	ut32 count = 0;
	if (refs) {
		RAnalRef *ref;
		R_VEC_FOREACH (refs, ref) {
			rprj_xref_write_one (cur, ref);
			count++;
		}
		RVecAnalRef_free (refs);
	}
	rprj_le32_patch (cur->b, count_at, count);
}

static ut32 rprj_color_index(RVecPrjColor *colors, RColor *color) {
	if (!rprj_color_is_set (color)) {
		return UT32_MAX;
	}
	ut32 idx = 0;
	RColor *it;
	R_VEC_FOREACH (colors, it) {
		if (rprj_color_eq (it, color)) {
			return idx;
		}
		idx++;
	}
	RColor *copy = RVecPrjColor_emplace_back (colors);
	*copy = *color;
	return idx;
}

// Find existing attrs row matching fcn (by content), or intern a new one. Single pass dedup.
static ut32 rprj_fcn_attr_intern(RPrjCursor *cur, RVecPrjFunctionAttr *attrs, RAnalFunction *fcn) {
	const ut32 type = (ut32)fcn->type;
	const ut32 bits = (ut32)fcn->bits;
	const ut32 flags = fcn->is_noreturn? RPRJ_FUNC_ATTR_NORETURN: 0;
	const ut64 stack = (ut64)fcn->maxstack;
	const char *cc = R_STR_ISNOTEMPTY (fcn->callconv)? fcn->callconv: NULL;
	ut32 idx = 0;
	R2ProjectFunctionAttr *it;
	R_VEC_FOREACH (attrs, it) {
		const char *itcc = it->cc != UT32_MAX? rprj_st_get (cur->st, it->cc): NULL;
		if (it->type == type && it->bits == bits && it->flags == flags
				&& it->stack == stack
				&& !strcmp (r_str_get (itcc), r_str_get (cc))) {
			return idx;
		}
		idx++;
	}
	R2ProjectFunctionAttr *slot = RVecPrjFunctionAttr_emplace_back (attrs);
	slot->cc = cc? rprj_st_append (cur->st, cc): UT32_MAX;
	slot->type = type;
	slot->bits = bits;
	slot->flags = flags;
	slot->stack = stack;
	return idx;
}

static void rprj_function_collect_colors(RVecPrjColor *colors, RAnalFunction *fcn) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		rprj_color_index (colors, &bb->color);
	}
}

static void rprj_var_write_one(RPrjCursor *cur, RAnalVar *var) {
	rprj_write_le32 (cur->b, rprj_st_append (cur->st, var->name));
	rprj_write_le32 (cur->b, rprj_st_append (cur->st, var->type));
	rprj_write_le32 (cur->b, (ut32)var->delta);
	rprj_write_u8 (cur->b, (ut8)var->kind);
	rprj_write_u8 (cur->b, var->isarg? 1: 0);
	rprj_write_u8 (cur->b, 0);
	rprj_write_u8 (cur->b, 0);
}

static void rprj_function_write_one(RPrjCursor *cur, RAnalFunction *fcn, ut32 attr_idx, RVecPrjColor *colors) {
	RListIter *iter;
	RAnalBlock *bb;
	ut32 nbbs = 0;
	r_list_foreach (fcn->bbs, iter, bb) {
		nbbs++;
	}
	const ut32 nvars = (ut32)RVecAnalVarPtr_length (&fcn->vars);
	rprj_write_le32 (cur->b, rprj_st_append (cur->st, fcn->name));
	rprj_write_project_addr (cur->b, rprj_mod_addr (cur, fcn->addr));
	rprj_write_le32 (cur->b, attr_idx);
	rprj_write_le32 (cur->b, nbbs);
	rprj_write_le32 (cur->b, nvars);
	r_list_foreach (fcn->bbs, iter, bb) {
		rprj_write_project_addr (cur->b, rprj_mod_addr (cur, bb->addr));
		rprj_write_le64 (cur->b, bb->size);
		rprj_write_project_addr (cur->b, rprj_mod_addr (cur, bb->jump));
		rprj_write_project_addr (cur->b, rprj_mod_addr (cur, bb->fail));
		rprj_write_le32 (cur->b, rprj_color_index (colors, &bb->color));
	}
	RAnalVar **var;
	R_VEC_FOREACH (&fcn->vars, var) {
		rprj_var_write_one (cur, *var);
	}
}

static void rprj_function_write(RPrjCursor *cur) {
	RVecPrjColor colors;
	RVecPrjFunctionAttr attrs;
	RVecPrjColor_init (&colors);
	RVecPrjFunctionAttr_init (&attrs);
	RListIter *iter;
	RAnalFunction *fcn;
	RList *fcns = r_anal_get_fcns (cur->core->anal);
	ut32 nfcns = 0;
	r_list_foreach (fcns, iter, fcn) {
		if (fcn && R_STR_ISNOTEMPTY (fcn->name)) {
			nfcns++;
		}
	}
	ut32 *fcn_attr_idx = nfcns? R_NEWS0 (ut32, nfcns): NULL;
	ut32 ai = 0;
	r_list_foreach (fcns, iter, fcn) {
		if (!fcn || R_STR_ISEMPTY (fcn->name)) {
			continue;
		}
		fcn_attr_idx[ai++] = rprj_fcn_attr_intern (cur, &attrs, fcn);
		rprj_function_collect_colors (&colors, fcn);
	}
	rprj_write_le32 (cur->b, (ut32)RVecPrjColor_length (&colors));
	RColor *color;
	R_VEC_FOREACH (&colors, color) {
		rprj_write_color (cur->b, color);
	}
	rprj_write_le32 (cur->b, (ut32)RVecPrjFunctionAttr_length (&attrs));
	R2ProjectFunctionAttr *attr;
	R_VEC_FOREACH (&attrs, attr) {
		rprj_write_le32 (cur->b, attr->cc);
		rprj_write_le32 (cur->b, attr->type);
		rprj_write_le32 (cur->b, attr->bits);
		rprj_write_le32 (cur->b, attr->flags);
		rprj_write_le64 (cur->b, attr->stack);
	}
	const ut64 count_at = rprj_le32_reserve (cur->b);
	ut32 count = 0;
	ai = 0;
	r_list_foreach (fcns, iter, fcn) {
		if (!fcn || R_STR_ISEMPTY (fcn->name)) {
			continue;
		}
		rprj_function_write_one (cur, fcn, fcn_attr_idx[ai++], &colors);
		count++;
	}
	rprj_le32_patch (cur->b, count_at, count);
	free (fcn_attr_idx);
	RVecPrjFunctionAttr_fini (&attrs);
	RVecPrjColor_fini (&colors);
}

typedef struct {
	RPrjCursor *cur;
} HintsCtx;

static bool rprj_hints_collect_cb(ut64 addr, const RVecAnalAddrHintRecord *records, void *user) {
	HintsCtx *ctx = (HintsCtx*)user;
	RPrjCursor *cur = ctx->cur;
	const RAnalAddrHintRecord *record;
	R_VEC_FOREACH (records, record) {
		ut32 kind = 0;
		ut64 val = 0;
		switch (record->type) {
		case R_ANAL_ADDR_HINT_TYPE_IMMBASE:
			kind = 1;
			val = (ut64)record->immbase;
			break;
		case R_ANAL_ADDR_HINT_TYPE_NEW_BITS:
			kind = 2;
			val = (ut64)record->newbits;
			break;
		default:
			break;
		}
		if (!kind) {
			continue;
		}
		R2ProjectAddr paddr = rprj_mod_addr (cur, addr);
		R2ProjectHint hint = {
			.kind = kind,
			.mod = paddr.mod,
			.delta = paddr.delta,
			.value = val,
		};
		rprj_hint_write (cur->b, &hint);
	}
	return true;
}

static void rprj_hints_write(RPrjCursor *cur) {
	HintsCtx ctx = { cur };
	r_anal_addr_hints_foreach (cur->core->anal, rprj_hints_collect_cb, &ctx);
}

static bool evalkey_is_saveable(RConfigNode *node) {
	if (r_config_node_is_ro (node)) {
		return false;
	}
	if (R_STR_ISEMPTY (node->name)) {
		return false;
	}
	// TODO this information nust be tied to the config vars and this function must go away soon or late
	static const char *skip_prefixes[] = {
		"dir.",
		"bin.limit", //triggers binreload wtf
		"file.",
		"prj.",
		"scr.",
		"env.",
		"stdin",
		"pdb.",
		"cfg.user",
		"cfg.log.",
		"cfg.debug",
		"cfg.prefixdump",
		"cmd.log",
		"dbg.backend",
		"dbg.btalgo",
		"http.",
		"key.",
		NULL,
	};
	const char *n = node->name;
	int i;
	for (i = 0; skip_prefixes[i]; i++) {
		if (r_str_startswith (n, skip_prefixes[i])) {
			return false;
		}
	}
	return true;
}

static void rprj_eval_write(RPrjCursor *cur) {
	RBuffer *b = cur->b;
	const ut64 count_at = rprj_le32_reserve (b);
	ut32 count = 0;
	RListIter *iter;
	RConfigNode *node;
	r_list_foreach (cur->core->config->nodes, iter, node) {
		if (!evalkey_is_saveable (node)) {
			continue;
		}
		const char *val = r_config_get (cur->core->config, node->name);
		const ut32 k = rprj_st_append (cur->st, node->name);
		const ut32 v = rprj_st_append (cur->st, val);
		if (k == UT32_MAX || v == UT32_MAX) {
			continue;
		}
		rprj_write_le32 (b, k);
		rprj_write_le32 (b, v);
		count++;
	}
	rprj_le32_patch (b, count_at, count);
}

static void rprj_info_write_entry(RPrjCursor *cur) {
	const char *prj_name = r_config_get (cur->core->config, "prj.name");
	const char *prj_user = r_config_get (cur->core->config, "cfg.user");
	R2ProjectInfo info = {
		.name = rprj_st_append (cur->st, r_str_get (prj_name)),
		.user = rprj_st_append (cur->st, r_str_get (prj_user)),
		.time = r_time_now ()
	};
	rprj_info_write (cur->b, &info);
}

static void rprj_strs_write_entry(RPrjCursor *cur) {
	rprj_st_write (cur->b, cur->st);
}

typedef void (*RPrjEntryWriter)(RPrjCursor *cur);

static void rprj_write_entry(RPrjCursor *cur, ut32 type, RPrjEntryWriter fn) {
	ut64 at;
	if (rprj_entry_begin (cur->b, &at, type, 1)) {
		fn (cur);
		rprj_entry_end (cur->b, at);
	}
}

static bool r_core_newprj_save(RCore *core, const char *file) {
	RBuffer *b = r_buf_new ();
	rprj_header_write (b);
	R2ProjectStringTable st = {0};
	RPrjCursor cur = {
		.core = core,
		.st = &st,
		.b = b,
	};
	RVecPrjMod_init (&cur.mods);
	cur.maps = rprj_maps_current (&cur);
	rprj_write_entry (&cur, RPRJ_INFO, rprj_info_write_entry);
	rprj_write_entry (&cur, RPRJ_MAPS, rprj_maps_write);
	rprj_write_entry (&cur, RPRJ_MODS, rprj_mods_write);
	rprj_write_entry (&cur, RPRJ_EVAL, rprj_eval_write);
	rprj_write_entry (&cur, RPRJ_FLAG, rprj_flag_write);
	rprj_write_entry (&cur, RPRJ_CMNT, rprj_cmnt_write);
	rprj_write_entry (&cur, RPRJ_VART, rprj_vart_write);
	rprj_write_entry (&cur, RPRJ_HINT, rprj_hints_write);
	rprj_write_entry (&cur, RPRJ_FUNC, rprj_function_write);
	rprj_write_entry (&cur, RPRJ_XREF, rprj_xref_write);
	rprj_write_entry (&cur, RPRJ_STRS, rprj_strs_write_entry);
	RVecPrjMap_free (cur.maps);
	ut64 size;
	const ut8 *data = r_buf_data (b, &size);
	const bool ok = r_file_dump (file, data, size, false);
	if (!ok) {
		R_LOG_ERROR ("Cannot write file");
	}
	r_unref (b);
	RVecPrjMod_fini (&cur.mods);
	free (st.data);
	return ok;
}
