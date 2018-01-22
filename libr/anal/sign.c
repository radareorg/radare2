/* radare - LGPL - Copyright 2009-2018 - pancake, nibble */

#include <r_anal.h>
#include <r_sign.h>
#include <r_search.h>
#include <r_util.h>
#include <r_core.h>

R_LIB_VERSION (r_sign);

const char *getRealRef(RCore *core, ut64 off) {
	RFlagItem *item = NULL;
	RListIter *iter = NULL;

	const RList *list = r_flag_get_list (core->flags, off);
	if (!list) {
		return NULL;
	}

	r_list_foreach (list, iter, item) {
		if (!item->name) {
			continue;
		}
		if (strncmp (item->name, "sym.", 4)) {
			continue;
		}
		return item->name;
	}

	return NULL;
}

R_API RList *r_sign_fcn_refs(RAnal *a, RAnalFunction *fcn) {
	RListIter *iter = NULL;
	RAnalRef *refi = NULL;

	if (!a || !fcn) {
		return NULL;
	}

	RCore *core = a->coreb.core;

	if (!core) {
		return NULL;
	}

	RList *ret = r_list_newf ((RListFree) free);
	RList *refs = r_anal_fcn_get_refs (a, fcn);
	r_list_foreach (refs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_CODE || refi->type == R_ANAL_REF_TYPE_CALL) {
			const char *flag = getRealRef (core, refi->addr);
			if (flag) {
				r_list_append (ret, r_str_newf (flag));
			}
		}
	}
	return ret;
}

static bool deserialize(RAnal *a, RSignItem *it, const char *k, const char *v) {
	char *refs = NULL;
	const char *token = NULL;
	int i = 0, n = 0, nrefs = 0, size = 0;
	bool retval = true;

	char *k2 = r_str_new (k);
	char *v2 = r_str_new (v);
	if (!k2 || !v2) {
		free (k2);
		free (v2);
		return false;
	}

	// Deserialize key: zign|space|name
	n = r_str_split (k2, '|');
	if (n != 3) {
		retval = false;
		goto out;
	}

	// space (1)
	it->space = r_space_add (&a->zign_spaces, r_str_word_get0 (k2, 1));

	// name (2)
	it->name = r_str_new (r_str_word_get0 (k2, 2));

	// Deserialize val: size|bytes|mask|graph|offset|refs
	n = r_str_split (v2, '|');
	if (n != 6) {
		retval = false;
		goto out;
	}

	// pattern size (0)
	size = atoi (r_str_word_get0 (v2, 0));
	if (size > 0) {
		it->bytes = R_NEW0 (RSignBytes);
		if (!it->bytes) {
			goto out;
		}
		it->bytes->size = size;

		// bytes (1)
		token = r_str_word_get0 (v2, 1);
		if (strlen (token) != 2 * it->bytes->size) {
			retval = false;
			goto out;
		}
		it->bytes->bytes = malloc (it->bytes->size);
		if (!it->bytes->bytes) {
		}
		r_hex_str2bin (token, it->bytes->bytes);

		// mask (2)
		token = r_str_word_get0 (v2, 2);
		if (strlen (token) != 2 * it->bytes->size) {
			retval = false;
			goto out;
		}
		it->bytes->mask = malloc (it->bytes->size);
		r_hex_str2bin (token, it->bytes->mask);
	}

	// graph metrics (3)
	token = r_str_word_get0 (v2, 3);
	if (strlen (token) == 2 * sizeof (RSignGraph)) {
		it->graph = R_NEW0 (RSignGraph);
		if (it->graph) {
			r_hex_str2bin (token, (ut8 *) it->graph);
		}
	}

	// offset (4)
	token = r_str_word_get0 (v2, 4);
	it->offset = atoll (token);

	// refs (5)
	token = r_str_word_get0 (v2, 5);
	refs = r_str_new (token);
	nrefs = r_str_split (refs, ',');
	if (nrefs > 0) {
		it->refs = r_list_newf ((RListFree) free);
		for (i = 0; i < nrefs; i++) {
			r_list_append (it->refs, r_str_newf (r_str_word_get0 (refs, i)));
		}
	}
out:
	free (k2);
	free (v2);
	free (refs);

	return retval;
}

static void serializeKey(RAnal *a, int space, const char* name, char *k) {
	snprintf (k, R_SIGN_KEY_MAXSZ, "zign|%s|%s",
		space >= 0? a->zign_spaces.spaces[space]: "*", name);
}

static void serializeKeySpaceStr(RAnal *a, const char *space, const char* name, char *k) {
	snprintf (k, R_SIGN_KEY_MAXSZ, "zign|%s|%s", space, name);
}

static void serialize(RAnal *a, RSignItem *it, char *k, char *v) {
	RListIter *iter = NULL;
	char *hexbytes = NULL, *hexmask = NULL, *hexgraph = NULL;
	char *refs = NULL, *ref = NULL;
	int i = 0, len = 0;
	RSignBytes *bytes = it->bytes;
	RSignGraph *graph = it->graph;

	if (k) {
		serializeKey (a, it->space, it->name, k);
	}

	if (v) {
		if (bytes) {
			len = bytes->size * 2 + 1;
			hexbytes = calloc (1, len);
			hexmask = calloc (1, len);
			r_hex_bin2str (bytes->bytes, bytes->size, hexbytes);
			r_hex_bin2str (bytes->mask, bytes->size, hexmask);
		}
		if (graph) {
			hexgraph = calloc (1, sizeof (RSignGraph) * 2 + 1);
			if (hexgraph) {
				r_hex_bin2str ((ut8 *) graph, sizeof (RSignGraph), hexgraph);
			}
		}
		r_list_foreach (it->refs, iter, ref) {
			if (i > 0) {
				refs = r_str_appendch (refs, ',');
			}
			refs = r_str_append (refs, ref);
			i++;
		}

		snprintf (v, R_SIGN_VAL_MAXSZ, "%d|%s|%s|%s|%"PFMT64d"|%s",
			bytes? bytes->size: 0,
			bytes? hexbytes: "",
			bytes? hexmask: "",
			graph? hexgraph: "",
			it->offset,
			refs? refs: "");

		free (hexbytes);
		free (hexmask);
		free (hexgraph);
		free (refs);
	}
}

static void mergeItem(RSignItem *dst, RSignItem *src) {
	RListIter *iter = NULL;
	char *ref = NULL;

	if (src->bytes) {
		if (dst->bytes) {
			free (dst->bytes->bytes);
			free (dst->bytes->mask);
			free (dst->bytes);
		}
		dst->bytes = R_NEW0 (RSignBytes);
		if (!dst->bytes) {
			return;
		}
		dst->bytes->size = src->bytes->size;
		dst->bytes->bytes = malloc (src->bytes->size);
		if (!dst->bytes->bytes) {
			free (dst->bytes);
			return;
		}
		memcpy (dst->bytes->bytes, src->bytes->bytes, src->bytes->size);
		dst->bytes->mask = malloc (src->bytes->size);
		if (!dst->bytes->mask) {
			free (dst->bytes->bytes);
			free (dst->bytes);
			return;
		}
		memcpy (dst->bytes->mask, src->bytes->mask, src->bytes->size);
	}

	if (src->graph) {
		free (dst->graph);
		dst->graph = R_NEW0 (RSignGraph);
		if (!dst->graph) {
			return;
		}
		*dst->graph = *src->graph;
	}

	if (src->offset != UT64_MAX) {
		dst->offset = src->offset;
	}

	if (src->refs) {
		r_list_free (dst->refs);

		dst->refs = r_list_newf ((RListFree) free);
		r_list_foreach (src->refs, iter, ref) {
			r_list_append (dst->refs, r_str_new (ref));
		}
	}
}

static bool addItem(RAnal *a, RSignItem *it) {
	char key[R_SIGN_KEY_MAXSZ], val[R_SIGN_VAL_MAXSZ];
	const char *curval = NULL;
	bool retval = true;
	RSignItem *curit = r_sign_item_new ();
	if (!curit) {
		return false;
	}

	serialize (a, it, key, val);
	curval = sdb_const_get (a->sdb_zigns, key, 0);
	if (curval) {
		if (!deserialize (a, curit, key, curval)) {
			eprintf ("error: cannot deserialize zign\n");
			retval = false;
			goto out;
		}
		mergeItem (curit, it);
		serialize (a, curit, key, val);
	}
	sdb_set (a->sdb_zigns, key, val, 0);

out:
	r_sign_item_free (curit);

	return retval;
}

static bool addBytes(RAnal *a, const char *name, ut64 size, const ut8 *bytes, const ut8 *mask) {
	bool retval = true;

	if (r_mem_is_zero (mask, size)) {
		eprintf ("error: zero mask\n");
		return false;
	}

	RSignItem *it = r_sign_item_new ();
	if (!it) {
		return false;
	}

	it->name = r_str_new (name);
	if (!it->name) {
		free (it);
		return false;
	}
	it->space = a->zign_spaces.space_idx;
	it->bytes = R_NEW0 (RSignBytes);
	if (!it->bytes) {
		goto fail;
	}
	it->bytes->size = size;
	it->bytes->bytes = malloc (size);
	if (!it->bytes->bytes) {
		goto fail;
	}
	memcpy (it->bytes->bytes, bytes, size);
	it->bytes->mask = malloc (size);
	if (!it->bytes->mask) {
		goto fail;
	}
	memcpy (it->bytes->mask, mask, size);
	retval = addItem (a, it);
	r_sign_item_free (it);
	return retval;
fail:
	if (it) {
		free (it->name);
		if (it->bytes) {
			free (it->bytes->bytes);
			free (it->bytes);
		}
	}
	free (it);
	return false;
}

R_API bool r_sign_add_bytes(RAnal *a, const char *name, ut64 size, const ut8 *bytes, const ut8 *mask) {
	if (!a || !name || size <= 0 || !bytes || !mask) {
		return false;
	}

	return addBytes (a, name, size, bytes, mask);
}

R_API bool r_sign_add_anal(RAnal *a, const char *name, ut64 size, const ut8 *bytes, ut64 at) {
	ut8 *mask = NULL;
	bool retval = true;

	if (!a || !name || size <= 0 || !bytes) {
		return false;
	}

	mask = r_anal_mask (a, size, bytes, at);
	if (!mask) {
		return false;
	}

	retval = addBytes (a, name, size, bytes, mask);

	free (mask);
	return retval;
}

R_API bool r_sign_add_graph(RAnal *a, const char *name, RSignGraph graph) {
	bool retval = true;
	if (!a || !name) {
		return false;
	}
	RSignItem *it = r_sign_item_new ();
	if (!it) {
		return false;
	}
	it->name = r_str_new (name);
	if (!it->name) {
		free (it);
		return false;
	}
	it->space = a->zign_spaces.space_idx;
	it->graph = R_NEW0 (RSignGraph);
	if (!it->graph) {
		free (it->name);
		free (it);
		return false;
	}
	*it->graph = graph;
	retval = addItem (a, it);
	r_sign_item_free (it);

	return retval;
}

R_API bool r_sign_add_offset(RAnal *a, const char *name, ut64 offset) {
	RSignItem *it = NULL;
	bool retval = true;

	if (!a || !name || offset == UT64_MAX) {
		return false;
	}

	it = r_sign_item_new ();

	it->name = r_str_new (name);
	it->space = a->zign_spaces.space_idx;
	it->offset = offset;

	retval = addItem (a, it);

	r_sign_item_free (it);

	return retval;
}

R_API bool r_sign_add_refs(RAnal *a, const char *name, RList *refs) {
	RListIter *iter = NULL;
	char *ref = NULL;

	if (!a || !name || !refs) {
		return false;
	}
	RSignItem *it = r_sign_item_new ();
	if (!it) {
		return false;
	}
	it->name = r_str_new (name);
	if (!it->name) {
		free (it);
		return false;
	}
	it->space = a->zign_spaces.space_idx;
	it->refs = r_list_newf ((RListFree) free);
	r_list_foreach (refs, iter, ref) {
		r_list_append (it->refs, r_str_newf (ref));
	}
	bool retval = addItem (a, it);
	r_sign_item_free (it);

	return retval;
}

struct ctxDeleteCB {
	RAnal *anal;
	char buf[R_SIGN_KEY_MAXSZ];
};

static int deleteBySpaceCB(void *user, const char *k, const char *v) {
	struct ctxDeleteCB *ctx = (struct ctxDeleteCB *) user;

	if (!strncmp (k, ctx->buf, strlen (ctx->buf))) {
		sdb_remove (ctx->anal->sdb_zigns, k, 0);
	}

	return 1;
}

R_API bool r_sign_delete(RAnal *a, const char *name) {
	struct ctxDeleteCB ctx = {0};
	char k[R_SIGN_KEY_MAXSZ];

	if (!a || !name) {
		return false;
	}
	// Remove all zigns
	if (*name == '*') {
		if (a->zign_spaces.space_idx == -1) {
			sdb_reset (a->sdb_zigns);
			return true;
		}
		ctx.anal = a;
		serializeKey (a, a->zign_spaces.space_idx, "", ctx.buf);
		sdb_foreach (a->sdb_zigns, deleteBySpaceCB, &ctx);
		return true;
	}
	// Remove specific zign
	serializeKey (a, a->zign_spaces.space_idx, name, k);
	return sdb_remove (a->sdb_zigns, k, 0);
}

struct ctxListCB {
	RAnal *anal;
	int idx;
	int format;
};

static void listBytes(RAnal *a, RSignItem *it, int format) {
	RSignBytes *bytes = it->bytes;
	char *strbytes = NULL;
	int i = 0;

	for (i = 0; i < bytes->size; i++) {
		if (bytes->mask[i] & 0xf0) {
			strbytes = r_str_appendf (strbytes, "%x", (bytes->bytes[i] & 0xf0) >> 4);
		} else {
			strbytes = r_str_appendf (strbytes, ".");
		}
		if (bytes->mask[i] & 0xf) {
			strbytes = r_str_appendf (strbytes, "%x", bytes->bytes[i] & 0xf);
		} else {
			strbytes = r_str_appendf (strbytes, ".");
		}
	}

	if (strbytes) {
		if (format == '*') {
			a->cb_printf ("za %s b %s\n", it->name, strbytes);
		} else if (format == 'j') {
			a->cb_printf ("\"bytes\":\"%s\",", strbytes);
		} else {
			a->cb_printf ("  bytes: %s\n", strbytes);
		}
		free (strbytes);
	}
}

static void listGraph(RAnal *a, RSignItem *it, int format) {
	RSignGraph *graph = it->graph;

	if (format == '*') {
		a->cb_printf ("za %s g cc=%d nbbs=%d edges=%d ebbs=%d\n",
			it->name, graph->cc, graph->nbbs, graph->edges, graph->ebbs);
	} else if (format == 'j') {
		a->cb_printf ("\"graph\":{\"cc\":\"%d\",\"nbbs\":\"%d\",\"edges\":\"%d\",\"ebbs\":\"%d\"},",
			graph->cc, graph->nbbs, graph->edges, graph->ebbs);
	} else {
		a->cb_printf ("  graph: cc=%d nbbs=%d edges=%d ebbs=%d\n",
			graph->cc, graph->nbbs, graph->edges, graph->ebbs);
	}
}

static void listOffset(RAnal *a, RSignItem *it, int format) {
	if (format == '*') {
		a->cb_printf ("za %s o 0x%08"PFMT64x"\n", it->name, it->offset);
	} else if (format == 'j') {
		a->cb_printf ("\"offset\":%"PFMT64d",", it->offset);
	} else {
		a->cb_printf ("  offset: 0x%08"PFMT64x"\n", it->offset);
	}
}

static void listRefs(RAnal *a, RSignItem *it, int format) {
	RListIter *iter = NULL;
	char *ref = NULL;
	int i = 0;

	if (format == '*') {
		a->cb_printf ("za %s r ", it->name);
	} else if (format == 'j') {
		a->cb_printf ("\"refs\":[");
	} else {
		a->cb_printf ("  refs: ");
	}

	r_list_foreach (it->refs, iter, ref) {
		if (i > 0) {
			if (format == '*') {
				a->cb_printf (" ");
			} else if (format == 'j') {
				a->cb_printf (",");
			} else {
				a->cb_printf (", ");
			}
		}
		if (format == 'j') {
			a->cb_printf ("\"%s\"", ref);
		} else {
			a->cb_printf ("%s", ref);
		}
		i++;
	}

	if (format == 'j') {
		a->cb_printf ("]");
	} else {
		a->cb_printf ("\n");
	}
}

static int listCB(void *user, const char *k, const char *v) {
	struct ctxListCB *ctx = (struct ctxListCB *) user;
	RSignItem *it = r_sign_item_new ();
	RAnal *a = ctx->anal;

	if (!deserialize (a, it, k, v)) {
		eprintf ("error: cannot deserialize zign\n");
		goto out;
	}

	if (a->zign_spaces.space_idx != it->space && a->zign_spaces.space_idx != -1) {
		goto out;
	}

	// Start item
	if (ctx->format == 'j') {
		if (ctx->idx > 0) {
			a->cb_printf (",");
		}
		a->cb_printf ("{");
	}

	// Zignspace and name (except for radare format)
	if (ctx->format == '*') {
		if (it->space >= 0) {
			a->cb_printf ("zs %s\n", a->zign_spaces.spaces[it->space]);
		} else {
			a->cb_printf ("zs *\n");
		}
	} else if (ctx->format == 'j') {
		if (it->space >= 0) {
			a->cb_printf ("{\"zignspace\":\"%s\",", a->zign_spaces.spaces[it->space]);
		}
		a->cb_printf ("\"name\":\"%s\",", it->name);
	} else {
		if (a->zign_spaces.space_idx == -1 && it->space >= 0) {
			a->cb_printf ("(%s) ", a->zign_spaces.spaces[it->space]);
		}
		a->cb_printf ("%s:\n", it->name);
	}

	// Bytes pattern
	if (it->bytes) {
		listBytes (a, it, ctx->format);
	} else if (ctx->format == 'j') {
		a->cb_printf ("\"bytes\":\"\",");
	}

	// Graph metrics
	if (it->graph) {
		listGraph (a, it, ctx->format);
	} else if (ctx->format == 'j') {
		a->cb_printf ("\"graph\":{},");
	}

	// Offset
	if (it->offset != UT64_MAX) {
		listOffset (a, it, ctx->format);
	} else if (ctx->format == 'j') {
		a->cb_printf ("\"offset\":-1,");
	}

	// References
	if (it->refs) {
		listRefs (a, it, ctx->format);
	} else if (ctx->format == 'j') {
		a->cb_printf ("\"refs\":[]");
	}

	// End item
	if (ctx->format == 'j') {
		a->cb_printf ("}");
	}

	ctx->idx++;

out:
	r_sign_item_free (it);

	return 1;
}

R_API void r_sign_list(RAnal *a, int format) {
	struct ctxListCB ctx = { a, 0, format };

	if (!a) {
		return;
	}

	if (format == 'j') {
		a->cb_printf ("[");
	}

	sdb_foreach (a->sdb_zigns, listCB, &ctx);

	if (format == 'j') {
		a->cb_printf ("]\n");
	}
}

struct ctxCountForCB {
	RAnal *anal;
	int idx;
	int count;
};

static int countForCB(void *user, const char *k, const char *v) {
	struct ctxCountForCB *ctx = (struct ctxCountForCB *) user;
	RSignItem *it = r_sign_item_new ();

	if (!deserialize (ctx->anal, it, k, v)) {
		eprintf ("error: cannot deserialize zign\n");
		goto out;
	}

	if (it->space == ctx->idx) {
		ctx->count++;
	}

out:
	r_sign_item_free (it);

	return 1;
}


R_API int r_sign_space_count_for(RAnal *a, int idx) {
	struct ctxCountForCB ctx = { a, idx, 0 };

	if (!a) {
		return 0;
	}

	sdb_foreach (a->sdb_zigns, countForCB, &ctx);

	return ctx.count;
}

struct ctxUnsetForCB {
	RAnal *anal;
	int idx;
};

static int unsetForCB(void *user, const char *k, const char *v) {
	struct ctxUnsetForCB *ctx = (struct ctxUnsetForCB *) user;
	char nk[R_SIGN_KEY_MAXSZ], nv[R_SIGN_VAL_MAXSZ];
	RSignItem *it = r_sign_item_new ();
	Sdb *db = ctx->anal->sdb_zigns;
	RAnal *a = ctx->anal;

	if (!deserialize (a, it, k, v)) {
		eprintf ("error: cannot deserialize zign\n");
		goto out;
	}

	if (it->space != ctx->idx) {
		goto out;
	}

	if (it->space != -1) {
		it->space = -1;
		serialize (a, it, nk, nv);
		sdb_remove (db, k, 0);
		sdb_set (db, nk, nv, 0);
	}

out:
	r_sign_item_free (it);

	return 1;
}

R_API void r_sign_space_unset_for(RAnal *a, int idx) {
	struct ctxUnsetForCB ctx = { a, idx };

	if (!a) {
		return;
	}

	sdb_foreach (a->sdb_zigns, unsetForCB, &ctx);
}

struct ctxRenameForCB {
	RAnal *anal;
	char oprefix[R_SIGN_KEY_MAXSZ];
	char nprefix[R_SIGN_KEY_MAXSZ];
};

static int renameForCB(void *user, const char *k, const char *v) {
	struct ctxRenameForCB *ctx = (struct ctxRenameForCB *) user;
	char nk[R_SIGN_KEY_MAXSZ], nv[R_SIGN_VAL_MAXSZ];
	const char *zigname = NULL;
	Sdb *db = ctx->anal->sdb_zigns;

	if (!strncmp (k, ctx->oprefix, strlen (ctx->oprefix))) {
		zigname = k + strlen (ctx->oprefix);
		snprintf (nk, R_SIGN_KEY_MAXSZ, "%s%s", ctx->nprefix, zigname);
		snprintf (nv, R_SIGN_VAL_MAXSZ, "%s", v);
		sdb_remove (db, k, 0);
		sdb_set (db, nk, nv, 0);
	}

	return 1;
}

R_API void r_sign_space_rename_for(RAnal *a, int idx, const char *oname, const char *nname) {
	struct ctxRenameForCB ctx;

	if (!a || !oname || !nname) {
		return;
	}

	ctx.anal = a;
	serializeKeySpaceStr (a, oname, "", ctx.oprefix);
	serializeKeySpaceStr (a, nname, "", ctx.nprefix);

	sdb_foreach (a->sdb_zigns, renameForCB, &ctx);
}

struct ctxForeachCB {
	RAnal *anal;
	RSignForeachCallback cb;
	void *user;
};

static int foreachCB(void *user, const char *k, const char *v) {
	struct ctxForeachCB *ctx = (struct ctxForeachCB *) user;
	RSignItem *it = r_sign_item_new ();
	RAnal *a = ctx->anal;
	int retval = 1;

	if (!deserialize (a, it, k, v)) {
		eprintf ("error: cannot deserialize zign\n");
		goto out;
	}

	if (a->zign_spaces.space_idx != it->space && a->zign_spaces.space_idx != -1) {
		goto out;
	}

	if (ctx->cb) {
		retval = ctx->cb (it, ctx->user);
	}

out:
	r_sign_item_free (it);

	return retval;
}

R_API bool r_sign_foreach(RAnal *a, RSignForeachCallback cb, void *user) {
	struct ctxForeachCB ctx = { a, cb, user };

	if (!a || !cb) {
		return false;
	}

	return sdb_foreach (a->sdb_zigns, foreachCB, &ctx);
}

R_API RSignSearch *r_sign_search_new() {
	RSignSearch *ret = R_NEW0 (RSignSearch);

	ret->search = r_search_new (R_SEARCH_KEYWORD);
	ret->items = r_list_newf ((RListFree) r_sign_item_free);

	return ret;
}

R_API void r_sign_search_free(RSignSearch *ss) {
	if (!ss) {
		return;
	}

	r_search_free (ss->search);
	r_list_free (ss->items);
	free (ss);
}

static int searchHitCB(RSearchKeyword *kw, void *user, ut64 addr) {
	RSignSearch *ss = (RSignSearch *) user;

	if (ss->cb) {
		return ss->cb ((RSignItem *) kw->data, kw, addr, ss->user);
	}

	return 1;
}

struct ctxAddSearchKwCB {
	RSignSearch *ss;
	int minsz;
};

static int addSearchKwCB(RSignItem *it, void *user) {
	struct ctxAddSearchKwCB *ctx = (struct ctxAddSearchKwCB *) user;
	RSignSearch *ss = ctx->ss;
	RSignBytes *bytes = it->bytes;
	RSearchKeyword *kw = NULL;
	RSignItem *it2 = NULL;

	if (!bytes) {
		return 1;
	}

	if (bytes->size < ctx->minsz) {
		return 1;
	}

	it2 = r_sign_item_dup (it);
	r_list_append (ss->items, it2);

	// TODO(nibble): change arg data in r_search_keyword_new to void*
	kw = r_search_keyword_new (bytes->bytes, bytes->size, bytes->mask, bytes->size, (const char *) it2);
	r_search_kw_add (ss->search, kw);

	return 1;
}

R_API void r_sign_search_init(RAnal *a, RSignSearch *ss, int minsz, RSignSearchCallback cb, void *user) {
	struct ctxAddSearchKwCB ctx = { ss, minsz };

	if (!a || !ss || !cb) {
		return;
	}

	ss->cb = cb;
	ss->user = user;

	r_list_purge (ss->items);
	r_search_reset (ss->search, R_SEARCH_KEYWORD);

	r_sign_foreach (a, addSearchKwCB, &ctx);
	r_search_begin (ss->search);
	r_search_set_callback (ss->search, searchHitCB, ss);
}

R_API int r_sign_search_update(RAnal *a, RSignSearch *ss, ut64 *at, const ut8 *buf, int len) {
	if (!a || !ss || !buf || len <= 0) {
		return 0;
	}
	return r_search_update (ss->search, *at, buf, len);
}

static bool fcnMetricsCmp(RSignItem *it, RAnalFunction *fcn) {
	RSignGraph *graph = it->graph;
	int ebbs = -1;

	if (graph->cc != -1 && graph->cc != r_anal_fcn_cc (fcn)) {
		return false;
	}
	if (graph->nbbs != -1 && graph->nbbs != r_list_length (fcn->bbs)) {
		return false;
	}
	if (graph->edges != -1 && graph->edges != r_anal_fcn_count_edges (fcn, &ebbs)) {
		return false;
	}
	if (graph->ebbs != -1 && graph->ebbs != ebbs) {
		return false;
	}
	return true;
}

struct ctxFcnMatchCB {
	RAnal *anal;
	RAnalFunction *fcn;
	RSignGraphMatchCallback cb;
	void *user;
	int mincc;
};

static int graphMatchCB(RSignItem *it, void *user) {
	struct ctxFcnMatchCB *ctx = (struct ctxFcnMatchCB *) user;
	RSignGraph *graph = it->graph;

	if (!graph) {
		return 1;
	}

	if (graph->cc < ctx->mincc) {
		return 1;
	}

	if (!fcnMetricsCmp (it, ctx->fcn)) {
		return 1;
	}

	if (ctx->cb) {
		return ctx->cb (it, ctx->fcn, ctx->user);
	}

	return 1;
}

R_API bool r_sign_match_graph(RAnal *a, RAnalFunction *fcn, int mincc, RSignGraphMatchCallback cb, void *user) {
	struct ctxFcnMatchCB ctx = { a, fcn, cb, user, mincc };

	if (!a || !fcn || !cb) {
		return false;
	}

	return r_sign_foreach (a, graphMatchCB, &ctx);
}

static int offsetMatchCB(RSignItem *it, void *user) {
	struct ctxFcnMatchCB *ctx = (struct ctxFcnMatchCB *) user;

	if (it->offset == UT64_MAX) {
		return 1;
	}

	if (it->offset != ctx->fcn->addr) {
		return 1;
	}

	if (ctx->cb) {
		return ctx->cb (it, ctx->fcn, ctx->user);
	}

	return 1;
}

R_API bool r_sign_match_offset(RAnal *a, RAnalFunction *fcn, RSignOffsetMatchCallback cb, void *user) {
	struct ctxFcnMatchCB ctx = { a, fcn, cb, user, 0 };

	if (!a || !fcn || !cb) {
		return false;
	}

	return r_sign_foreach (a, offsetMatchCB, &ctx);
}

static int refsMatchCB(RSignItem *it, void *user) {
	struct ctxFcnMatchCB *ctx = (struct ctxFcnMatchCB *) user;
	RList *refs = NULL;
	char *ref_a = NULL, *ref_b = NULL;
	int i = 0, retval = 1;

	if (!it->refs) {
		return 1;
	}

	// TODO(nibble): slow operation, add cache
	refs = r_sign_fcn_refs (ctx->anal, ctx->fcn);
	if (!refs) {
		return 1;
	}

	for (i = 0; ; i++) {
		ref_a = (char *) r_list_get_n (it->refs, i);
		ref_b = (char *) r_list_get_n (refs, i);

		if (!ref_a || !ref_b) {
			if (ref_a != ref_b) {
				retval = 1;
				goto out;
			}
			break;
		}
		if (strcmp (ref_a, ref_b)) {
			retval = 1;
			goto out;
		}
	}

	if (ctx->cb) {
		retval = ctx->cb (it, ctx->fcn, ctx->user);
		goto out;
	}

out:
	r_list_free (refs);

	return retval;
}

R_API bool r_sign_match_refs(RAnal *a, RAnalFunction *fcn, RSignRefsMatchCallback cb, void *user) {
	struct ctxFcnMatchCB ctx = { a, fcn, cb, user, 0 };

	if (!a || !fcn || !cb) {
		return false;
	}

	return r_sign_foreach (a, refsMatchCB, &ctx);
}


R_API RSignItem *r_sign_item_new() {
	RSignItem *ret = R_NEW0 (RSignItem);

	ret->offset = UT64_MAX;
	ret->space = -1;

	return ret;
}

R_API RSignItem *r_sign_item_dup(RSignItem *it) {
	RListIter *iter = NULL;
	char *ref = NULL;
	if (!it) {
		return NULL;
	}
	RSignItem *ret = r_sign_item_new ();
	if (!ret) {
		return false;
	}
	ret->name = r_str_new (it->name);
	ret->space = it->space;

	if (it->bytes) {
		ret->bytes = R_NEW0 (RSignBytes);
		if (!ret->bytes) {
			r_sign_item_free (ret);
			return false;
		}
		ret->bytes->size = it->bytes->size;
		ret->bytes->bytes = malloc (it->bytes->size);
		memcpy (ret->bytes->bytes, it->bytes->bytes, it->bytes->size);
		ret->bytes->mask = malloc (it->bytes->size);
		memcpy (ret->bytes->mask, it->bytes->mask, it->bytes->size);
	}

	if (it->graph) {
		ret->graph = R_NEW0 (RSignGraph);
		if (!ret->graph) {
			r_sign_item_free (ret);
			return false;
		}
		*ret->graph = *it->graph;
	}

	ret->refs = r_list_newf ((RListFree) free);
	r_list_foreach (it->refs, iter, ref) {
		r_list_append (ret->refs, r_str_new (ref));
	}

	return ret;
}

R_API void r_sign_item_free(RSignItem *item) {
	if (!item) {
		return;
	}
	free (item->name);
	if (item->bytes) {
		free (item->bytes->bytes);
		free (item->bytes->mask);
		free (item->bytes);
	}
	free (item->graph);
	r_list_free (item->refs);

	free (item);
}

static int loadCB(void *user, const char *k, const char *v) {
	RAnal *a = (RAnal *) user;
	char nk[R_SIGN_KEY_MAXSZ], nv[R_SIGN_VAL_MAXSZ];
	RSignItem *it = r_sign_item_new ();

	if (!deserialize (a, it, k, v)) {
		eprintf ("error: cannot deserialize zign\n");
		goto out;
	}

	serialize (a, it, nk, nv);
	sdb_set (a->sdb_zigns, nk, nv, 0);
out:
	r_sign_item_free (it);
	return 1;
}

R_API char *r_sign_path(RAnal *a, const char *file) {
	char *abs = r_file_abspath (file);
	if (abs) {
		if (r_file_is_regular (abs)) {
			return abs;
		}
		free (abs);
	}

	if (a->zign_path) {
		char *path = r_str_newf ("%s%s%s", a->zign_path, R_SYS_DIR, file);
		abs = r_file_abspath (path);
		free (path);
		if (r_file_is_regular (abs)) {
			return abs;
		}
		free (abs);
	} else {
		char *home = r_str_home (".config/radare2/zigns/");
		abs = r_str_newf ("%s%s%s", home, R_SYS_DIR, file);
		free (home);
		if (r_file_is_regular (abs)) {
			return abs;
		}
		free (abs);
	}

	/// XXX mixed / and R_SYS_DIR
	const char *pfx = "/share/radare2/" R2_VERSION "/zigns";
	abs = r_str_newf ("%s%s%s%s", r_sys_prefix (NULL), pfx, R_SYS_DIR, file);
	if (r_file_is_regular (abs)) {
		return abs;
	}
	free (abs);

	return NULL;
}

R_API bool r_sign_load(RAnal *a, const char *file) {
	if (!a || !file) {
		return false;
	}
	char *path = r_sign_path (a, file);
	if (!r_file_exists (path)) {
		eprintf ("error: file %s does not exist\n", file);
		free (path);
		return false;
	}
	Sdb *db = sdb_new (NULL, path, 0);
	if (!db) {
		free (path);
		return false;
	}
	sdb_foreach (db, loadCB, a);
	sdb_close (db);
	sdb_free (db);
	free (path);
	return true;
}

R_API bool r_sign_load_gz(RAnal *a, const char *filename) {
	ut8 *buf = NULL;
	int size = 0;
	char *tmpfile = NULL;
	bool retval = true;

	char *path = r_sign_path (a, filename);
	if (!r_file_exists (path)) {
		eprintf ("error: file %s does not exist\n", filename);
		retval = false;
		goto out;
	}

	if (!(buf = r_file_gzslurp (path, &size, 0))) {
		eprintf ("error: cannot decompress file\n");
		retval = false;
		goto out;
	}

	if (!(tmpfile = r_file_temp ("r2zign"))) {
		eprintf ("error: cannot create temp file\n");
		retval = false;
		goto out;
	}

	if (!r_file_dump (tmpfile, buf, size, 0)) {
		eprintf ("error: cannot dump file\n");
		retval = false;
		goto out;
	}

	if (!r_sign_load (a, tmpfile)) {
		eprintf ("error: cannot load file\n");
		retval = false;
		goto out;
	}

	if (!r_file_rm (tmpfile)) {
		eprintf ("error: cannot delete temp file\n");
		retval = false;
		goto out;
	}

out:
	free (buf);
	free (tmpfile);
	free (path);

	return retval;
}

R_API bool r_sign_save(RAnal *a, const char *file) {
	bool retval = true;

	if (!a || !file) {
		return false;
	}
	
	if (sdb_count (a->sdb_zigns) == 0) {
		eprintf ("WARNING: no zignatures to save\n");
		return false;
	}

	Sdb *db = sdb_new (NULL, file, 0);
	if (!db) {
		return false;
	}
	sdb_merge (db, a->sdb_zigns);
	retval = sdb_sync (db);
	sdb_close (db);
	sdb_free (db);

	return retval;
}
