/* radare - LGPL - Copyright 2009-2017 - pancake, nibble */

#include <r_anal.h>
#include <r_sign.h>
#include <r_search.h>
#include <r_util.h>

R_LIB_VERSION (r_sign);

static bool deserialize(RAnal *a, RSignItem *it, const char *k, const char *v) {
	char *k2 = NULL, *v2 = NULL, *ptr = NULL, *token = NULL;
	int i = 0, size = 0;
	bool retval = true;

	k2 = r_str_new (k);
	v2 = r_str_new (v);

	// Deserialize key: zign|space|name
	for (ptr = k2, i = 0;; ptr = NULL, i++) {
		token = strtok (ptr, "|");
		if (!token) {
			break;
		}

		switch (i) {
		case 0:
			// Const "zign" string
			break;
		case 1:
			it->space = r_space_add (&a->zign_spaces, token);
			break;
		case 2:
			it->name = r_str_new (token);
			break;
		}
	}

	// Deserialize val: size|bytes|mask|graph
	for (ptr = v2, i = 0;; ptr = NULL, i++) {
		token = strtok (ptr, "|");
		if (!token) {
			break;
		}

		switch (i) {
		case 0:
			size = sdb_atoi (token);
			if (size > 0) {
				it->bytes = R_NEW0 (RSignBytes);
				it->bytes->size = size;
			}
			break;
		case 1:
			if (it->bytes) {
				if (strlen (token) != 2 * it->bytes->size) {
					retval = false;
					goto exit_function;
				}
				it->bytes->bytes = malloc (it->bytes->size);
				r_hex_str2bin (token, it->bytes->bytes);
			}
			break;
		case 2:
			if (it->bytes) {
				if (strlen (token) != 2 * it->bytes->size) {
					retval = false;
					goto exit_function;
				}
				it->bytes->mask = malloc (it->bytes->size);
				r_hex_str2bin (token, it->bytes->mask);
			}
			break;
		case 3:
			if (strlen (token) == 2 * sizeof (RSignGraph)) {
				it->graph = R_NEW0 (RSignGraph);
				r_hex_str2bin (token, (ut8 *) it->graph);
			}
			break;
		default:
			retval = false;
			goto exit_function;
		}
	}

exit_function:
	free (k2);
	free (v2);

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
	char *hexbytes = NULL, *hexmask = NULL, *hexgraph = NULL;
	int len = 0;
	RSignBytes *bytes = it->bytes;
	RSignGraph *graph = it->graph;

	if (k) {
		serializeKey(a, it->space, it->name, k);
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
			r_hex_bin2str ((ut8 *) graph, sizeof (RSignGraph), hexgraph);
		}

		snprintf (v, R_SIGN_VAL_MAXSZ, "%d|%s|%s|%s",
			bytes? bytes->size: 0,
			bytes? hexbytes: "0",
			bytes? hexmask: "0",
			graph? hexgraph: "0");

		free (hexbytes);
		free (hexmask);
		free (hexgraph);
	}
}

static void mergeItem(RSignItem *dst, RSignItem *src) {
	if (src->bytes) {
		if (dst->bytes) {
			free (dst->bytes->bytes);
			free (dst->bytes->mask);
			free (dst->bytes);
		}

		dst->bytes = R_NEW0 (RSignBytes);
		dst->bytes->size = src->bytes->size;
		dst->bytes->bytes = malloc (src->bytes->size);
		memcpy (dst->bytes->bytes, src->bytes->bytes, src->bytes->size);
		dst->bytes->mask = malloc (src->bytes->size);
		memcpy (dst->bytes->mask, src->bytes->mask, src->bytes->size);
	}

	if (src->graph) {
		if (dst->graph) {
			free (dst->graph);
		}

		dst->graph = R_NEW0 (RSignGraph);
		*dst->graph = *src->graph;
	}
}

static bool addItem(RAnal *a, RSignItem *it) {
	char key[R_SIGN_KEY_MAXSZ], val[R_SIGN_VAL_MAXSZ];
	const char *curval;
	bool retval = true;
	RSignItem *curit = R_NEW0 (RSignItem);

	serialize (a, it, key, val);
	curval = sdb_const_get (a->sdb_zigns, key, 0);
	if (curval) {
		if (!deserialize (a, curit, key, curval)) {
			eprintf ("error: cannot deserialize zign\n");
			retval = false;
			goto exit_function;
		}
		mergeItem (curit, it);
		serialize (a, curit, key, val);
	}
	sdb_set (a->sdb_zigns, key, val, 0);

exit_function:
	free (curit);

	return retval;
}

static bool addBytes(RAnal *a, const char *name, ut64 size, const ut8 *bytes, const ut8 *mask) {
	RSignItem *it = R_NEW0 (RSignItem);
	bool retval = true;

	if (r_mem_is_zero (mask, size)) {
		eprintf ("error: zero mask\n");
		retval = false;
		goto exit_function;
	}

	it->name = r_str_new (name);
	it->space = a->zign_spaces.space_idx;
	it->bytes = R_NEW0 (RSignBytes);
	it->bytes->size = size;
	it->bytes->bytes = malloc (size);
	memcpy (it->bytes->bytes, bytes, size);
	it->bytes->mask = malloc (size);
	memcpy (it->bytes->mask, mask, size);

	retval = addItem (a, it);

exit_function:
	r_sign_item_free (it);

	return retval;
}

R_API bool r_sign_add_bytes(RAnal *a, const char *name, ut64 size, const ut8 *bytes, const ut8 *mask) {
	return addBytes (a, name, size, bytes, mask);
}

R_API bool r_sign_add_anal(RAnal *a, const char *name, ut64 size, const ut8 *bytes, ut64 at) {
	ut8 *mask = NULL;
	bool retval = true;

	mask = r_anal_mask (a, size, bytes, at);
	retval = addBytes (a, name, size, bytes, mask);

	free (mask);
	return retval;
}

R_API bool r_sign_add_graph(RAnal *a, const char *name, RSignGraph graph) {
	RSignItem *it = R_NEW0 (RSignItem);
	bool retval = true;

	it->name = r_str_new (name);
	it->space = a->zign_spaces.space_idx;
	it->graph = R_NEW0 (RSignGraph);
	*it->graph = graph;

	retval = addItem (a, it);

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
	struct ctxDeleteCB ctx;
	char k[R_SIGN_KEY_MAXSZ];

	// Remove all zigns
	if (name[0] == '*') {
		if (a->zign_spaces.space_idx == -1) {
			sdb_reset (a->sdb_zigns);
			return true;
		} else {
			ctx.anal = a;
			serializeKey (a, a->zign_spaces.space_idx, "", ctx.buf);
			sdb_foreach (a->sdb_zigns, deleteBySpaceCB, &ctx);
			return true;
		}
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
	int i;

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

	if (format == '*') {
		a->cb_printf ("za %s b %s\n", it->name, strbytes);
	} else if (format == 'j') {
		a->cb_printf ("\"bytes\":{\"bytes\":\"%s\"}", strbytes);
	} else {
		a->cb_printf ("  bytes: %s\n", strbytes);
	}

	free (strbytes);
}

static void listGraph(RAnal *a, RSignItem *it, int format) {
	RSignGraph *graph = it->graph;

	if (format == '*') {
		a->cb_printf ("za %s g cc=%d nbbs=%d edges=%d ebbs=%d\n",
			it->name, graph->cc, graph->nbbs, graph->edges, graph->ebbs);
	} else if (format == 'j') {
		a->cb_printf ("\"graph\":{\"cc\":\"%d\",\"nbbs\":\"%d\",\"edges\":\"%d\",\"ebbs\":\"%d\"}",
			graph->cc, graph->nbbs, graph->edges, graph->ebbs);
	} else {
		a->cb_printf ("  graph: cc=%d nbbs=%d edges=%d ebbs=%d\n",
			graph->cc, graph->nbbs, graph->edges, graph->ebbs);
	}
}

static int listCB(void *user, const char *k, const char *v) {
	struct ctxListCB *ctx = (struct ctxListCB *) user;
	RSignItem *it = R_NEW0 (RSignItem);
	RAnal *a = ctx->anal;

	if (!deserialize (a, it, k, v)) {
		eprintf ("error: cannot deserialize zign\n");
		goto exit_function;
	}

	if (a->zign_spaces.space_idx != it->space && a->zign_spaces.space_idx != -1) {
		goto exit_function;
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
	}

	// Graph metrics
	if (it->graph) {
		if (ctx->format == 'j') {
			a->cb_printf (",");
		}
		listGraph (a, it, ctx->format);
	}

	// End item
	if (ctx->format == 'j') {
		a->cb_printf ("}");
	}

	ctx->idx++;

exit_function:
	r_sign_item_free (it);

	return 1;
}

R_API void r_sign_list(RAnal *a, int format) {
	struct ctxListCB ctx = { a, 0, format };

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
	RSignItem *it = R_NEW0 (RSignItem);

	if (!deserialize (ctx->anal, it, k, v)) {
		eprintf ("error: cannot deserialize zign\n");
		goto exit_function;
	}

	if (it->space == ctx->idx) {
		ctx->count++;
	}

exit_function:
	r_sign_item_free (it);

	return 1;
}


R_API int r_sign_space_count_for(RAnal *a, int idx) {
	struct ctxCountForCB ctx = { a, idx, 0 };

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
	RSignItem *it = R_NEW0 (RSignItem);
	Sdb *db = ctx->anal->sdb_zigns;
	RAnal *a = ctx->anal;

	if (!deserialize (a, it, k, v)) {
		eprintf ("error: cannot deserialize zign\n");
		goto exit_function;
	}

	if (it->space != ctx->idx) {
		goto exit_function;
	}

	if (it->space != -1) {
		it->space = -1;
		serialize (a, it, nk, nv);
		sdb_remove (db, k, 0);
		sdb_set (db, nk, nv, 0);
	}

exit_function:
	r_sign_item_free (it);

	return 1;
}

R_API void r_sign_space_unset_for(RAnal *a, int idx) {
	struct ctxUnsetForCB ctx = { a, idx };

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
	const char *zigname;
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
	RSignItem *it = R_NEW0 (RSignItem);
	RAnal *a = ctx->anal;
	int retval = 1;

	if (!deserialize (a, it, k, v)) {
		eprintf ("error: cannot deserialize zign\n");
		goto exit_function;
	}

	if (a->zign_spaces.space_idx != it->space && a->zign_spaces.space_idx != -1) {
		goto exit_function;
	}

	if (ctx->cb) {
		retval = ctx->cb (it, ctx->user);
	}

exit_function:
	r_sign_item_free (it);

	return retval;
}

R_API bool r_sign_foreach(RAnal *a, RSignForeachCallback cb, void *user) {
	struct ctxForeachCB ctx = { a, cb, user };

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
		return ss->cb (kw, (RSignItem *) kw->data, addr, ss->user);
	}

	return 1;
}

static int searchCB(RSignItem *it, void *user) {
	RSignSearch *ss = (RSignSearch *) user;
	RSearchKeyword *kw;
	RSignItem *it2;
	RSignBytes *bytes = it->bytes;

	if (!bytes) {
		return 1;
	}

	it2 = r_sign_item_dup (it);
	r_list_append(ss->items, it2);

	// TODO(nibble): change arg data in r_search_keyword_new to void*
	kw = r_search_keyword_new (bytes->bytes, bytes->size, bytes->mask, bytes->size, (const char *) it2);
	r_search_kw_add (ss->search, kw);

	return 1;
}

R_API void r_sign_search_init(RAnal *a, RSignSearch *ss, RSignSearchCallback cb, void *user) {
	ss->cb = cb;
	ss->user = user;

	r_list_purge (ss->items);
	r_search_reset (ss->search, R_SEARCH_KEYWORD);

	r_sign_foreach (a, searchCB, ss);
	r_search_begin (ss->search);
	r_search_set_callback (ss->search, searchHitCB, ss);
}

R_API int r_sign_search_update(RAnal *a, RSignSearch *ss, ut64 *at, const ut8 *buf, int len) {
	return r_search_update (ss->search, at, buf, len);
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

struct ctxMetricMatchCB {
	RAnal *anal;
	RAnalFunction *fcn;
	RSignGraphMatchCallback cb;
	void *user;
};

static int graphMatchCB(RSignItem *it, void *user) {
	struct ctxMetricMatchCB *ctx = (struct ctxMetricMatchCB *) user;

	if (!it->graph) {
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

R_API int r_sign_match_graph(RAnal *a, RAnalFunction *fcn, RSignGraphMatchCallback cb, void *user) {
	struct ctxMetricMatchCB ctx = { a, fcn, cb, user };

	r_sign_foreach (a, graphMatchCB, &ctx);

	return 0;
}

R_API RSignItem *r_sign_item_dup(RSignItem *it) {
	RSignItem *ret = R_NEW0 (RSignItem);

	ret->name = r_str_new (it->name);
	ret->space = it->space;

	if (it->bytes) {
		ret->bytes = R_NEW0 (RSignBytes);
		ret->bytes->size = it->bytes->size;
		ret->bytes->bytes = malloc (it->bytes->size);
		memcpy (ret->bytes->bytes, it->bytes->bytes, it->bytes->size);
		ret->bytes->mask = malloc (it->bytes->size);
		memcpy (ret->bytes->mask, it->bytes->mask, it->bytes->size);
	}

	if (it->graph) {
		ret->graph = R_NEW0 (RSignGraph);
		*ret->graph = *it->graph;
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
	if (item->graph) {
		free (item->graph);
	}
	free (item);
}

static int loadCB(void *user, const char *k, const char *v) {
	RAnal *a = (RAnal *) user;
	char nk[R_SIGN_KEY_MAXSZ], nv[R_SIGN_VAL_MAXSZ];
	RSignItem *it = R_NEW0 (RSignItem);

	if (!deserialize (a, it, k, v)) {
		eprintf ("error: cannot deserialize zign\n");
		goto exit_function;
	}

	serialize (a, it, nk, nv);
	sdb_set (a->sdb_zigns, nk, nv, 0);

exit_function:
	r_sign_item_free (it);

	return 1;
}

R_API bool r_sign_load(RAnal *a, const char *file) {
	if (!r_file_exists (file)) {
		eprintf ("error: file %s does not exist\n", file);
		return false;
	}

	Sdb *db = sdb_new (NULL, file, 0);
	sdb_foreach (db, loadCB, a);
	sdb_close (db);
	sdb_free (db);

	return true;
}

R_API bool r_sign_save(RAnal *a, const char *file) {
	bool retval = true;

	Sdb *db = sdb_new (NULL, file, 0);
	sdb_merge (db, a->sdb_zigns);
	retval = sdb_sync (db);
	sdb_close (db);
	sdb_free (db);

	return retval;
}
