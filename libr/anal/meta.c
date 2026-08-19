/* radare - LGPL - Copyright 2008-2026 - nibble, pancake, thestr4ng3r */

#include <r_core.h>
#include <r_anal_priv.h>

typedef enum {
	META_SHADOW_OP_NONE,
	META_SHADOW_OP_INSERTED,
	META_SHADOW_OP_SET,
	META_SHADOW_OP_DELETE
} RAnalMetaShadowOpType;

typedef struct r_anal_meta_shadow_op_t {
	ut64 addr;
	const RSpace *space;
	RIntervalNode *node;
	RAnalMetaItem *item;
	char *text;
	bool original_exists;
	RAnalMetaShadowOpType type;
	struct r_anal_meta_shadow_op_t *next;
} RAnalMetaShadowOp;

struct r_anal_meta_store_shadow_t {
	RAnal *source_anal;
	RAnalMetaShadowOp *ops;
	bool committed;
	bool lock_held;
};

static void meta_item_free(void *data) {
	RAnalMetaItem *item = data;
	if (item) {
		free (item->str);
		free (item);
	}
}

static bool item_matches_filter(RAnalMetaItem *item, RAnalMetaType type, const RSpace *R_NULLABLE space) {
	return (type == R_META_TYPE_ANY || item->type == type) && (!space || item->space == space);
}

typedef struct {
	RAnalMetaType type;
	const RSpace *space;
	ut64 addr;
	bool exact_space;
	bool exact_start;
	RIntervalNode *node;
} FindCtx;

static bool find_node_cb(RIntervalNode *node, void *user) {
	FindCtx *ctx = user;
	RAnalMetaItem *item = node->data;
	if ((!ctx->exact_start || node->start == ctx->addr) && (ctx->exact_space
			? (ctx->type == R_META_TYPE_ANY || item->type == ctx->type) && item->space == ctx->space
			: item_matches_filter (item, ctx->type, ctx->space))) {
		ctx->node = node;
		return false;
	}
	return true;
}

static RIntervalNode *find_node_at_tree_mode(RIntervalTree *tree, RAnalMetaType type,
		const RSpace *R_NULLABLE space, ut64 addr, bool exact_space, bool exact_start) {
	FindCtx ctx = {
		.type = type,
		.space = space,
		.addr = addr,
		.exact_space = exact_space,
		.exact_start = exact_start,
		.node = NULL
	};
	r_interval_tree_all_at (tree, addr, find_node_cb, &ctx);
	return ctx.node;
}

static RIntervalNode *find_node_at_tree(RIntervalTree *tree, RAnalMetaType type, const RSpace *R_NULLABLE space, ut64 addr) {
	return find_node_at_tree_mode (tree, type, space, addr, false, false);
}

static RIntervalNode *find_node_at_tree_exact(RIntervalTree *tree, RAnalMetaType type, const RSpace *R_NULLABLE space, ut64 addr) {
	return find_node_at_tree_mode (tree, type, space, addr, true, true);
}

static RIntervalNode *find_node_at(RAnal *anal, RAnalMetaType type, const RSpace *R_NULLABLE space, ut64 addr) {
	return find_node_at_tree (&anal->meta, type, space, addr);
}

static RAnalMetaShadowOp *meta_shadow_find_op(RAnalMetaStoreShadow *shadow, const RSpace *space, ut64 addr) {
	RAnalMetaShadowOp *op;
	for (op = shadow->ops; op; op = op->next) {
		if (op->addr == addr && op->space == space) {
			return op;
		}
	}
	return NULL;
}

static RAnalMetaShadowOp *meta_shadow_new_op(RAnalMetaStoreShadow *shadow, const RSpace *space, ut64 addr) {
	RAnalMetaShadowOp *op = R_NEW0 (RAnalMetaShadowOp);
	op->addr = addr;
	op->space = space;
	op->next = shadow->ops;
	shadow->ops = op;
	return op;
}

R_API RAnalMetaStoreShadow *r_meta_store_shadow_prepare(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal && anal->lock, NULL);
	r_th_lock_enter (anal->lock);
	RAnalMetaStoreShadow *shadow = R_NEW0 (RAnalMetaStoreShadow);
	shadow->source_anal = anal;
	shadow->lock_held = true;
	return shadow;
}

R_API bool r_meta_store_shadow_set_comment(RAnalMetaStoreShadow *shadow, const RSpace *space, ut64 addr, const char *text) {
	R_RETURN_VAL_IF_FAIL (shadow && shadow->source_anal && !shadow->committed && text, false);
	RAnalMetaShadowOp *op = meta_shadow_find_op (shadow, space, addr);
	if (op && op->type == META_SHADOW_OP_INSERTED) {
		if (!strcmp (op->item->str, text)) {
			return true;
		}
		char *copy = strdup (text);
		if (!copy) {
			return false;
		}
		free (op->item->str);
		op->item->str = copy;
		return true;
	}
	if (op && op->original_exists && r_str_eq (op->item->str, text)) {
		free (op->text);
		op->text = NULL;
		op->type = META_SHADOW_OP_NONE;
		return true;
	}
	if (op && op->type == META_SHADOW_OP_SET && r_str_eq (op->text, text)) {
		return true;
	}
	char *copy = strdup (text);
	if (!copy) {
		return false;
	}
	RIntervalNode *node = op && op->original_exists
		? op->node
		: find_node_at_tree_exact (&shadow->source_anal->meta, R_META_TYPE_COMMENT, space, addr);
	if (node) {
		RAnalMetaItem *item = node->data;
		if (!op && r_str_eq (item->str, text)) {
			free (copy);
			return true;
		}
		if (!op) {
			op = meta_shadow_new_op (shadow, space, addr);
			op->node = node;
			op->item = item;
			op->original_exists = true;
		}
		free (op->text);
		op->text = copy;
		op->type = META_SHADOW_OP_SET;
		return true;
	}
	RAnalMetaItem *item = R_NEW0 (RAnalMetaItem);
	item->type = R_META_TYPE_COMMENT;
	item->space = space;
	item->str = copy;
	if (!r_interval_tree_insert (&shadow->source_anal->meta, addr, addr, item)) {
		meta_item_free (item);
		return false;
	}
	if (!op) {
		op = meta_shadow_new_op (shadow, space, addr);
	}
	op->node = find_node_at_tree_exact (&shadow->source_anal->meta, R_META_TYPE_COMMENT, space, addr);
	op->item = item;
	op->original_exists = false;
	op->type = META_SHADOW_OP_INSERTED;
	return true;
}

R_API void r_meta_store_shadow_del_comment(RAnalMetaStoreShadow *shadow, const RSpace *space, ut64 addr) {
	R_RETURN_IF_FAIL (shadow && shadow->source_anal && !shadow->committed);
	RAnalMetaShadowOp *op = meta_shadow_find_op (shadow, space, addr);
	if (op && op->type == META_SHADOW_OP_INSERTED) {
		r_interval_tree_delete (&shadow->source_anal->meta, op->node, true);
		op->node = NULL;
		op->item = NULL;
		op->type = META_SHADOW_OP_NONE;
		return;
	}
	RIntervalNode *node = op && op->original_exists
		? op->node
		: find_node_at_tree_exact (&shadow->source_anal->meta, R_META_TYPE_COMMENT, space, addr);
	if (!node) {
		return;
	}
	if (!op) {
		op = meta_shadow_new_op (shadow, space, addr);
		op->node = node;
		op->item = node->data;
		op->original_exists = true;
	}
	free (op->text);
	op->text = NULL;
	op->type = META_SHADOW_OP_DELETE;
}

R_API void r_meta_store_shadow_swap(RAnal *anal, RAnalMetaStoreShadow *shadow) {
	R_RETURN_IF_FAIL (anal && shadow && shadow->source_anal == anal && !shadow->committed);
	RAnalMetaShadowOp *op;
	bool changed = false;
	for (op = shadow->ops; op; op = op->next) {
		switch (op->type) {
		case META_SHADOW_OP_SET:
			free (op->item->str);
			op->item->str = op->text;
			op->text = NULL;
			changed = true;
			break;
		case META_SHADOW_OP_DELETE:
			r_interval_tree_delete (&anal->meta, op->node, true);
			op->node = NULL;
			op->item = NULL;
			changed = true;
			break;
		case META_SHADOW_OP_INSERTED:
			changed = true;
			break;
		default:
			break;
		}
	}
	if (changed) {
		R_DIRTY_SET (anal);
	}
	shadow->committed = true;
	r_th_lock_leave (anal->lock);
	shadow->lock_held = false;
}

R_API void r_meta_store_shadow_free(RAnalMetaStoreShadow *shadow) {
	if (!shadow) {
		return;
	}
	RAnalMetaShadowOp *op = shadow->ops;
	while (op) {
		RAnalMetaShadowOp *next = op->next;
		if (!shadow->committed && op->type == META_SHADOW_OP_INSERTED) {
			r_interval_tree_delete (&shadow->source_anal->meta, op->node, true);
		}
		free (op->text);
		free (op);
		op = next;
	}
	if (shadow->lock_held) {
		r_th_lock_leave (shadow->source_anal->lock);
	}
	free (shadow);
}

static RIntervalNode *find_node_in(RAnal *anal, RAnalMetaType type, const RSpace *R_NULLABLE space, ut64 addr) {
	FindCtx ctx = {
		.type = type,
		.space = space,
		.node = NULL
	};
	r_interval_tree_all_in (&anal->meta, addr, true, find_node_cb, &ctx);
	return ctx.node;
}

typedef struct {
	RAnalMetaType type;
	const RSpace *space;

	RVecIntervalNodePtr *result;
} CollectCtx;

static bool collect_nodes_cb(RIntervalNode *node, void *user) {
	CollectCtx *ctx = user;
	if (item_matches_filter (node->data, ctx->type, ctx->space)) {
		RVecIntervalNodePtr_push_back (ctx->result, &node);
	}
	return true;
}

static RVecIntervalNodePtr *collect_nodes_at(RAnal *anal, RAnalMetaType type, const RSpace *R_NULLABLE space, ut64 addr) {
	CollectCtx ctx = {
		.type = type,
		.space = space,
		.result = RVecIntervalNodePtr_new ()
	};
	if (!ctx.result) {
		return NULL;
	}
	r_interval_tree_all_at (&anal->meta, addr, collect_nodes_cb, &ctx);
	return ctx.result;
}

static RVecIntervalNodePtr *collect_nodes_in(RAnal *anal, RAnalMetaType type, const RSpace *R_NULLABLE space, ut64 addr) {
	CollectCtx ctx = {
		.type = type,
		.space = space,
		.result = RVecIntervalNodePtr_new ()
	};
	if (!ctx.result) {
		return NULL;
	}
	r_interval_tree_all_in (&anal->meta, addr, true, collect_nodes_cb, &ctx);
	return ctx.result;
}

static RVecIntervalNodePtr *collect_nodes_intersect(RAnal *anal, RAnalMetaType type, const RSpace *R_NULLABLE space, ut64 start, ut64 end) {
	CollectCtx ctx = {
		.type = type,
		.space = space,
		.result = RVecIntervalNodePtr_new ()
	};
	if (!ctx.result) {
		return NULL;
	}
	r_interval_tree_all_intersect (&anal->meta, start, end, true, collect_nodes_cb, &ctx);
	return ctx.result;
}

static bool meta_set(RAnal *a, RAnalMetaType type, int subtype, ut64 from, ut64 to, const char *R_NULLABLE str) {
	R_RETURN_VAL_IF_FAIL (a && a->lock, false);
	r_th_lock_enter (a->lock);
	if (to < from) {
		r_th_lock_leave (a->lock);
		return false;
	}
	char *copy = R_STR_ISNOTEMPTY (str)? strdup (str): NULL;
	if (R_STR_ISNOTEMPTY (str) && !copy) {
		r_th_lock_leave (a->lock);
		return false;
	}
	RSpace *space = r_spaces_current (&a->meta_spaces);
	RIntervalNode *node = find_node_at (a, type, space, from);
	if (!node) {
		RAnalMetaItem *item = R_NEW0 (RAnalMetaItem);
		item->type = type;
		item->subtype = subtype;
		item->space = space;
		item->str = copy;
		if (!r_interval_tree_insert (&a->meta, from, to, item)) {
			meta_item_free (item);
			r_th_lock_leave (a->lock);
			return false;
		}
	} else {
		RAnalMetaItem *item = node->data;
		if (node->end != to && !r_interval_tree_resize (&a->meta, node, from, to)) {
			free (copy);
			r_th_lock_leave (a->lock);
			return false;
		}
		item->type = type;
		item->subtype = subtype;
		item->space = space;
		free (item->str);
		item->str = copy;
	}
	R_DIRTY_SET (a);
	r_th_lock_leave (a->lock);
	return true;
}

R_API bool r_meta_set_string(RAnal *a, RAnalMetaType type, ut64 addr, const char *s) {
	R_RETURN_VAL_IF_FAIL (a && s, false);
	return meta_set (a, type, 0, addr, addr, s);
}

R_API const char *r_meta_get_string(RAnal *a, RAnalMetaType type, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (a && a->lock, NULL);
	r_th_lock_enter (a->lock);
	RIntervalNode *node = find_node_at_tree (&a->meta, type, r_spaces_current (&a->meta_spaces), addr);
	const char *result = node? ((RAnalMetaItem *)node->data)->str: NULL;
	r_th_lock_leave (a->lock);
	return result;
}

R_API const char *r_meta_get_string_in_space(RAnal *a, RAnalMetaType type, const RSpace *space, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (a && a->lock, NULL);
	r_th_lock_enter (a->lock);
	RIntervalNode *node = find_node_at_tree_exact (&a->meta, type, space, addr);
	const char *result = node? ((RAnalMetaItem *)node->data)->str: NULL;
	r_th_lock_leave (a->lock);
	return result;
}

static void del(RAnal *a, RAnalMetaType type, const RSpace *space, ut64 addr, ut64 size) {
	R_RETURN_IF_FAIL (a && a->lock);
	r_th_lock_enter (a->lock);
	RVecIntervalNodePtr *victims = NULL;
	if (size == UT64_MAX) {
		// delete everything
		victims = RVecIntervalNodePtr_new ();
		if (!victims) {
			r_th_lock_leave (a->lock);
			return;
		}
		RIntervalTreeIter it;
		RAnalMetaItem *item;
		r_interval_tree_foreach (&a->meta, it, item) {
			if (item_matches_filter (item, type, space)) {
				RIntervalNode *node = r_interval_tree_iter_get (&it);
				RVecIntervalNodePtr_push_back (victims, &node);
			}
		}
	} else {
		ut64 end = size? addr + size - 1: addr;
		if (end < addr) {
			end = UT64_MAX;
		}
		victims = collect_nodes_intersect (a, type, space, addr, end);
		if (!victims) {
			r_th_lock_leave (a->lock);
			return;
		}
	}
	RIntervalNode **it;
	R_VEC_FOREACH (victims, it) {
		r_interval_tree_delete (&a->meta, *it, true);
	}
	RVecIntervalNodePtr_free (victims);
	r_th_lock_leave (a->lock);
}

R_API void r_meta_del(RAnal *a, RAnalMetaType type, ut64 addr, ut64 size) {
	R_RETURN_IF_FAIL (a);
	del (a, type, r_spaces_current (&a->meta_spaces), addr, size);
}

R_API bool r_meta_set(RAnal *a, RAnalMetaType type, ut64 addr, ut64 size, const char *R_NULLABLE str) {
	R_RETURN_VAL_IF_FAIL (a, false);
	return r_meta_set_with_subtype (a, type, 0, addr, size, str);
}

R_API bool r_meta_set_with_subtype(RAnal *m, RAnalMetaType type, int subtype, ut64 addr, ut64 size, const char *str) {
	R_RETURN_VAL_IF_FAIL (m && size, false);
	ut64 end = addr + size - 1;
	if (end < addr) {
		end = UT64_MAX;
	}
	return meta_set (m, type, subtype, addr, end, str);
}

R_API RAnalMetaItem *r_meta_get_at(RAnal *a, ut64 addr, RAnalMetaType type, R_OUT ut64 *R_NULLABLE size) {
	R_RETURN_VAL_IF_FAIL (a && a->lock, NULL);
	r_th_lock_enter (a->lock);
	RIntervalNode *node = find_node_at (a, type, r_spaces_current (&a->meta_spaces), addr);
	if (node && size) {
		*size = r_meta_item_size (node->start, node->end);
	}
	RAnalMetaItem *result = node? node->data: NULL;
	r_th_lock_leave (a->lock);
	return result;
}

R_API RIntervalNode *r_meta_get_in(RAnal *a, ut64 addr, RAnalMetaType type) {
	R_RETURN_VAL_IF_FAIL (a && a->lock, NULL);
	r_th_lock_enter (a->lock);
	RIntervalNode *result = find_node_in (a, type, r_spaces_current (&a->meta_spaces), addr);
	r_th_lock_leave (a->lock);
	return result;
}

R_API RVecIntervalNodePtr *r_meta_get_all_at(RAnal *a, ut64 at) {
	R_RETURN_VAL_IF_FAIL (a && a->lock, NULL);
	r_th_lock_enter (a->lock);
	RVecIntervalNodePtr *result = collect_nodes_at (a, R_META_TYPE_ANY, r_spaces_current (&a->meta_spaces), at);
	r_th_lock_leave (a->lock);
	return result;
}

R_API RVecIntervalNodePtr *r_meta_get_all_in(RAnal *a, ut64 at, RAnalMetaType type) {
	R_RETURN_VAL_IF_FAIL (a && a->lock, NULL);
	r_th_lock_enter (a->lock);
	RVecIntervalNodePtr *result = collect_nodes_in (a, type, r_spaces_current (&a->meta_spaces), at);
	r_th_lock_leave (a->lock);
	return result;
}

R_API RVecIntervalNodePtr *r_meta_get_all_intersect(RAnal *a, ut64 start, ut64 size, RAnalMetaType type) {
	R_RETURN_VAL_IF_FAIL (a && a->lock && size, NULL);
	ut64 end = start + size - 1;
	if (end < start) {
		end = UT64_MAX;
	}
	r_th_lock_enter (a->lock);
	RVecIntervalNodePtr *result = collect_nodes_intersect (a, type, r_spaces_current (&a->meta_spaces), start, end);
	r_th_lock_leave (a->lock);
	return result;
}

static const char *meta_type_tags[] = {
	[R_META_TYPE_BIND] = "Cb",
	[R_META_TYPE_CODE] = "Cc",
	[R_META_TYPE_DATA] = "Cd",
	[R_META_TYPE_STRING] = "Cs",
	[R_META_TYPE_FORMAT] = "Cf",
	[R_META_TYPE_MAGIC] = "Cm",
	[R_META_TYPE_HIDE] = "Ch",
	[R_META_TYPE_COMMENT] = "CCu",
	[R_META_TYPE_RUN] = "Cr",
	[R_META_TYPE_HIGHLIGHT] = "ecHi",
	[R_META_TYPE_VARTYPE] = "Ct",
};

R_API const char *r_meta_type_tostring(int type) {
	if (type > 0 && type < R_ARRAY_SIZE (meta_type_tags) && meta_type_tags[type]) {
		return meta_type_tags[type];
	}
	return "# unknown meta # ";
}

R_API void r_meta_print(RAnal *a, RAnalMetaItem *d, ut64 start, ut64 size, int rad, PJ *pj, RTable *t, bool show_full) {
	R_RETURN_IF_FAIL (! (rad == 'j' && !pj)); // rad == 'j' => pj
	char *pstr, *base64_str;
	RCore *core = a->coreb.core;
	bool esc_bslash = core? core->print->esc_bslash: false;
	if (r_spaces_current (&a->meta_spaces) &&
		r_spaces_current (&a->meta_spaces) != d->space) {
		return;
	}
	char *str = NULL;
	if (d->str) {
		if (d->type == R_META_TYPE_STRING) {
			if (d->subtype == R_STRING_ENC_UTF8) {
				str = r_str_escape_utf8 (d->str, false, esc_bslash);
			} else {
				if (!d->subtype) { /* temporary legacy workaround */
					esc_bslash = false;
				}
				str = r_str_escape_latin1 (d->str, false, esc_bslash, false);
			}
		} else {
			str = r_str_escape (d->str);
		}
	}
	if (str || d->type == R_META_TYPE_DATA || d->type == R_META_TYPE_BIND) {
		if (d->type == R_META_TYPE_STRING && !*str) {
			free (str);
			return;
		}
		if (!str) {
			pstr = "";
		} else if (d->type == 'b') {
			pstr = str;
		} else if (d->type == 'f') {
			pstr = str;
		} else if (d->type == 's') {
			pstr = str;
		} else if (d->type == 't') {
			pstr = str;
		} else if (d->type != 'C') {
			r_name_filter (str, 0);
			pstr = str;
		} else {
			pstr = d->str;
		}
		switch (rad) {
		case 'j':
			pj_o (pj);
			pj_kn (pj, "offset", start);
			pj_ks (pj, "type", r_meta_type_tostring (d->type));

			if (d->type == 'H') {
				pj_k (pj, "color");
				ut8 r = 0, g = 0, b = 0, A = 0;
				const char *esc = strchr (d->str, '\x1b');
				if (esc) {
					r_str_html_rgbparse (esc, &r, &g, &b, &A);
					char *rgb_str = r_cons_rgb_tostring (r, g, b);
					pj_s (pj, rgb_str);
					free (rgb_str);
				} else {
					pj_s (pj, str);
				}
			} else {
				pj_k (pj, "name");
				if (d->type == 's' && (base64_str = r_base64_encode_dyn ((const ut8 *)d->str, -1))) {
					pj_s (pj, base64_str);
				} else {
					pj_s (pj, d->type == R_META_TYPE_VARTYPE? d->str: str);
				}
			}
			if (d->type == 'd') {
				pj_kn (pj, "size", size);
			} else if (d->type == 's') {
				const char *enc;
				switch (d->subtype) {
				case R_STRING_ENC_UTF8:
					enc = "utf8";
					break;
				case 0: /* temporary legacy encoding */
					enc = "iz";
					break;
				default:
					enc = "latin1";
				}
				pj_ks (pj, "enc", enc);
				pj_kb (pj, "ascii", r_str_is_ascii (d->str));
			}

			pj_end (pj);
			break;
		case 0:
		case 1:
		case '*':
		default:
			switch (d->type) {
			case R_META_TYPE_COMMENT:
				{
					const char *type = r_meta_type_tostring (d->type);
					char *s = sdb_encode ((const ut8 *)pstr, -1);
					if (!s) {
						s = strdup (pstr);
					}
					if (rad) {
						if (!strcmp (type, "CCu")) {
							a->cb_printf ("%s base64:%s @ 0x%08" PFMT64x "\n",
								type, s, start);
						} else {
							a->cb_printf ("%s base64:%s @ 0x%08" PFMT64x "\n",
								type, s, start);
						}
					} else {
						if (!strcmp (type, "CCu")) {
							char *mys = r_str_escape (pstr);
							a->cb_printf ("0x%08" PFMT64x " %s \"%s\"\n",
								start, type, mys);
							free (mys);
						} else {
							a->cb_printf ("0x%08" PFMT64x " %s \"%s\"\n",
								start, type, pstr);
						}
					}
					free (s);
				}
				break;
			case R_META_TYPE_STRING:
				if (rad) {
					char cmd[] = "Cs#";
					switch (d->subtype) {
					case 'a':
					case '8':
						cmd[2] = d->subtype;
						break;
					default:
						cmd[2] = 0;
						break;
					}
					a->cb_printf ("'@0x%08" PFMT64x "'%s %" PFMT64u "\n",
						start, cmd, size);
				} else {
					const char *enc;
					switch (d->subtype) {
					case '8':
						enc = "utf8";
						break;
					default:
						enc = r_str_is_ascii (d->str)? "ascii": "latin1";
					}
					if (show_full) {
						a->cb_printf ("0x%08" PFMT64x " %s[%" PFMT64u "] \"%s\"\n",
							start, enc, size, pstr);
					} else {
						a->cb_printf ("%s[%" PFMT64u "] \"%s\"\n",
							enc, size, pstr);
					}
				}
				break;
			case R_META_TYPE_HIDE:
			case R_META_TYPE_DATA:
				if (rad) {
					a->cb_printf ("%s %" PFMT64u " @ 0x%08" PFMT64x "\n",
						r_meta_type_tostring (d->type),
						size, start);
				} else {
					if (show_full) {
						const char *dtype = d->type == 'h'? "hidden": "data";
						a->cb_printf ("0x%08" PFMT64x " %s %s %" PFMT64u "\n",
							start, dtype,
							r_meta_type_tostring (d->type),
							size);
					} else {
						a->cb_printf ("%" PFMT64u "\n", size);
					}
				}
				break;
			case R_META_TYPE_MAGIC:
			case R_META_TYPE_FORMAT:
				if (rad) {
					char *spstr = r_str_sanitize_r2 (pstr);
					a->cb_printf ("'@0x%08" PFMT64x "'%s %" PFMT64u " %s\n",
						start, r_meta_type_tostring (d->type),
						size, spstr);
					free (spstr);
				} else {
					if (show_full) {
						const char *dtype = d->type == 'm'? "magic": "format";
						a->cb_printf ("0x%08" PFMT64x " %s %" PFMT64u " %s\n",
							start, dtype, size, pstr);
					} else {
						a->cb_printf ("%" PFMT64u " %s\n", size, pstr);
					}
				}
				break;
			case R_META_TYPE_BIND:
				if (rad) {
					char *spstr = r_str_sanitize_r2 (pstr);
					a->cb_printf ("'Cb 0x%08" PFMT64x " %s\n", start, r_str_get (spstr));
					free (spstr);
				} else {
					a->cb_printf ("BIND 0x%08" PFMT64x " %s\n", start, pstr);
				}
				break;
			case R_META_TYPE_VARTYPE:
				if (rad) {
					char *s = sdb_encode ((const ut8 *)d->str, -1);
					if (s) {
						a->cb_printf ("'@0x%08" PFMT64x "'%s= base64:%s\n",
							start, r_meta_type_tostring (d->type), s);
						free (s);
					}
				} else {
					a->cb_printf ("0x%08" PFMT64x " %s\n", start, pstr);
				}
				break;
			case R_META_TYPE_HIGHLIGHT:
				{
					ut8 r = 0, g = 0, b = 0, A = 0;
					const char *esc = strchr (d->str, '\x1b');
					r_str_html_rgbparse (esc, &r, &g, &b, &A);
					a->cb_printf ("%s rgb:%02x%02x%02x @ 0x%08" PFMT64x "\n",
						r_meta_type_tostring (d->type), r, g, b, start);
					// TODO: d->size
				}
				break;
			default:
				if (rad) {
					a->cb_printf ("%s %" PFMT64u " 0x%08" PFMT64x " # %s\n",
						r_meta_type_tostring (d->type),
						size, start, pstr);
				} else {
					// TODO: use b64 here
					a->cb_printf ("0x%08" PFMT64x " array[%" PFMT64u "] %s %s\n",
						start, size,
						r_meta_type_tostring (d->type), pstr);
				}
				break;
			}
			break;
		}
		free (str);
	}
}

R_API void r_meta_print_list_at(RAnal *a, ut64 addr, int rad, const char *tq, RTable *t) {
	R_RETURN_IF_FAIL (a && a->lock);
	r_th_lock_enter (a->lock);
	RVecIntervalNodePtr *nodes = collect_nodes_at (a, R_META_TYPE_ANY, r_spaces_current (&a->meta_spaces), addr);
	if (nodes) {
		RIntervalNode **it;
		R_VEC_FOREACH (nodes, it) {
			RIntervalNode *node = *it;
			size_t ns = r_meta_node_size (node);
			r_meta_print (a, node->data, node->start, ns, rad, NULL, t, true);
		}
		RVecIntervalNodePtr_free (nodes);
	}
	r_th_lock_leave (a->lock);
}

static void print_meta_list(RAnal *a, int type, int rad, ut64 addr, ut64 from, ut64 to, const char *tq, RTable *t) {
	RCore *core = a->coreb.core;
	RCons *cons = core->cons;
	PJ *pj = NULL;
	if (rad == ',') {
		if (!t) {
			t = r_table_new ("meta", NULL);
		}
		RTableColumnType *s = r_table_type ("string");
		RTableColumnType *n = r_table_type ("number");
		r_table_add_column (t, n, "addr", 0);
		r_table_add_column (t, n, "size", 0);
		r_table_add_column (t, s, "type", 0);
		r_table_add_column (t, s, "string", 0);
	} else if (rad == 'j') {
		pj = pj_new ();
		if (!pj) {
			return;
		}
		pj_a (pj);
	}

	r_th_lock_enter (a->lock);
	RAnalFunction *fcn = NULL;
	if (addr != UT64_MAX) {
		fcn = r_anal_get_fcn_in (a, addr, 0);
		if (!fcn) {
			goto beach;
		}
	}

	RIntervalTreeIter it;
	RAnalMetaItem *item;
	r_interval_tree_foreach (&a->meta, it, item) {
		RIntervalNode *node = r_interval_tree_iter_get (&it);
		if (type != R_META_TYPE_ANY && item->type != type) {
			continue;
		}
		if (fcn && !r_anal_function_contains (fcn, node->start)) {
			continue;
		}
		if (from != UT64_MAX && (node->start < from || (to != UT64_MAX && node->start >= to))) {
			continue;
		}
		if (t) {
			const char *type = r_meta_type_tostring (item->type);
			const char *name = item->str;
			r_table_add_rowf (t, "xxss",
				node->start,
				r_meta_node_size (node),
				type, name);
		} else {
			r_meta_print (a, item, node->start, r_meta_node_size (node), rad, pj, t, true);
		}
	}
beach:
	r_th_lock_leave (a->lock);
	if (t && tq) {
		if (!r_table_query (t, tq)) {
			pj_free (pj);
			r_table_free (t);
			return;
		}
	}
	if (!tq || !strstr (tq, "?")) {
		if (t) {
			char *s = r_table_tostring (t);
			r_cons_print (cons, s);
			free (s);
		} else if (pj) {
			pj_end (pj);
			r_cons_printf (cons, "%s\n", pj_string (pj));
		}
	}
	pj_free (pj);
}

// TODO: return char*
R_API void r_meta_print_list_all(RAnal *a, int type, int rad, const char *tq, RTable *t) {
	print_meta_list (a, type, rad, UT64_MAX, UT64_MAX, UT64_MAX, tq, t);
}

R_API void r_meta_print_list_in_function(RAnal *a, int type, int rad, ut64 addr, const char *tq, RTable *t) {
	print_meta_list (a, type, rad, addr, UT64_MAX, UT64_MAX, tq, t);
}

R_API void r_meta_print_list_in_range(RAnal *a, int type, int rad, ut64 addr, ut64 size, const char *tq, RTable *t) {
	ut64 to = addr + size;
	if (to < addr) {
		to = UT64_MAX;
	}
	print_meta_list (a, type, rad, UT64_MAX, addr, to, tq, t);
}

R_API void r_meta_rebase(RAnal *anal, ut64 diff) {
	R_RETURN_IF_FAIL (anal && anal->lock);
	if (!diff || diff == UT64_MAX) {
		return;
	}
	r_th_lock_enter (anal->lock);
	RIntervalTree old = anal->meta;
	r_interval_tree_init (&anal->meta, old.free);
	RIntervalTreeIter it;
	RAnalMetaItem *item;
	r_interval_tree_foreach (&old, it, item) {
		RIntervalNode *node = r_interval_tree_iter_get (&it);
		ut64 newstart = node->start + diff;
		ut64 newend = node->end + diff;
		if (newend < newstart) {
			// Can't rebase this
			newstart = node->start;
			newend = node->end;
		}
		r_interval_tree_insert (&anal->meta, newstart, newend, item);
	}
	old.free = NULL;
	r_interval_tree_fini (&old);
	r_th_lock_leave (anal->lock);
}

R_API void r_meta_space_unset_for(RAnal *a, const RSpace *space) {
	del (a, R_META_TYPE_ANY, space, 0, UT64_MAX);
}

R_API ut64 r_meta_get_size(RAnal *a, RAnalMetaType type) {
	R_RETURN_VAL_IF_FAIL (a && a->lock, 0);
	r_th_lock_enter (a->lock);
	if (!a->meta.root) {
		r_th_lock_leave (a->lock);
		return 0;
	}
	ut64 sum = 0;
	RIntervalTreeIter it;
	RAnalMetaItem *item;
	RIntervalNode *prev = NULL;
	r_interval_tree_foreach (&a->meta, it, item) {
		RIntervalNode *node = r_interval_tree_iter_get (&it);
		if (type != R_META_TYPE_ANY && item->type != type) {
			continue;
		}
		ut64 start = R_MAX (prev? prev->end: 0, node->start);
		sum += node->end - start + 1;
		prev = node;
	}
	r_th_lock_leave (a->lock);
	return sum;
}

R_API int r_meta_space_count_for(RAnal *a, const RSpace *space) {
	R_RETURN_VAL_IF_FAIL (a && a->lock && space, 0);
	r_th_lock_enter (a->lock);
	int r = 0;
	RIntervalTreeIter it;
	RAnalMetaItem *item;
	r_interval_tree_foreach (&a->meta, it, item) {
		if (item->space == space) {
			r++;
		}
	}
	r_th_lock_leave (a->lock);
	return r;
}

R_API void r_meta_set_data_at(RAnal *a, ut64 addr, ut64 wordsz) {
	R_RETURN_IF_FAIL (wordsz);
	r_meta_set (a, R_META_TYPE_DATA, addr, wordsz, NULL);
}
