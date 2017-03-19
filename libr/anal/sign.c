/* radare - LGPL - Copyright 2009-2017 - pancake, nibble */

#include <r_anal.h>
#include <r_sign.h>
#include <r_search.h>

R_LIB_VERSION (r_sign);

static bool deserialize(RSignItem *it, const char *k, const char *v) {
	char *k2 = NULL, *v2 = NULL, *ptr = NULL, *token = NULL;
	int i = 0;
	bool retval = true;

	k2 = r_str_new (k);
	v2 = r_str_new (v);

	// Deserialize key: zign|<space>|<name>
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
			it->space = atoi (token);
			break;
		case 2:
			it->name = r_str_new (token);
			break;
		}
	}

	// Deserialize val: type|size|bytes|mask|metrics
	for (ptr = v2, i = 0;; ptr = NULL, i++) {
		token = strtok (ptr, "|");
		if (!token) {
			break;
		}

		switch (i) {
		case 0:
			it->type = token[0];
			break;
		case 1:
			it->size = sdb_atoi (token);
			break;
		case 2:
			if (it->size > 0) {
				if (strlen (token) != 2 * it->size) {
					retval = false;
					goto exit_function;
				}
				it->bytes = malloc (it->size);
				r_hex_str2bin (token, it->bytes);
			}
			break;
		case 3:
			if (it->size > 0) {
				if (strlen (token) != 2 * it->size) {
					retval = false;
					goto exit_function;
				}
				it->mask = malloc (it->size);
				r_hex_str2bin (token, it->mask);
			}
			break;
		case 4:
			if (strlen (token) != 2 * sizeof (RSignMetrics)) {
				retval = false;
				goto exit_function;
			}
			r_hex_str2bin (token, (ut8 *) &it->metrics);
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

static void serialize(RSignItem *it, char *k, char *v) {
	char *hexbytes = NULL, *hexmask = NULL, *hexmetrics = NULL;
	int len = 0;

	if (k) {
		snprintf (k, R_SIGN_KEY_MAXSZ, "zign|%d|%s", it->space, it->name);
	}

	if (v) {
		if (it->size > 0) {
			len = it->size * 2 + 1;
			hexbytes = calloc (1, len);
			hexmask = calloc (1, len);
			r_hex_bin2str (it->bytes, it->size, hexbytes);
			r_hex_bin2str (it->mask, it->size, hexmask);
		}

		hexmetrics = calloc (1, sizeof (RSignMetrics) * 2 + 1);
		r_hex_bin2str ((ut8 *) &it->metrics, sizeof (RSignMetrics), hexmetrics);

		snprintf (v, R_SIGN_VAL_MAXSZ, "%c|%d|%s|%s|%s",
				it->type, it->size,
				it->size > 0? hexbytes: "00",
				it->size > 0? hexmask: "00",
				hexmetrics);

		free (hexbytes);
		free (hexmask);
		free (hexmetrics);
	}
}

static bool add(RAnal *a, RSignItem *it) {
	char key[R_SIGN_KEY_MAXSZ], val[R_SIGN_VAL_MAXSZ];

	serialize (it, key, val);

	if (sdb_exists (a->sdb_zigns, key)) {
		eprintf ("error: zignature already exists\n");
		return false;
	}

	sdb_set (a->sdb_zigns, key, val, 0);

	return true;
}

static bool addBytes(RAnal *a, int type, const char *name, ut64 size, const ut8 *bytes, const ut8 *mask) {
	RSignItem *it = R_NEW0 (RSignItem);
	bool retval = true;

	it->type = type;
	it->name = r_str_new (name);
	it->space = a->zign_spaces.space_idx;
	it->size = size;
	it->bytes = malloc (size);
	memcpy (it->bytes, bytes, size);
	it->mask = malloc (size);
	memcpy (it->mask, mask, size);

	retval = add (a, it);

	r_sign_item_free (it);

	return retval;
}

R_API bool r_sign_add_exact(RAnal *a, const char *name, ut64 size, const ut8 *bytes, const ut8 *mask) {
	return addBytes (a, R_SIGN_EXACT, name, size, bytes, mask);
}

R_API bool r_sign_add_anal(RAnal *a, const char *name, ut64 size, const ut8 *bytes) {
	ut8 *mask = NULL;
	bool retval = true;

	mask = r_anal_mask (a, size, bytes);
	retval = addBytes (a, R_SIGN_ANAL, name, size, bytes, mask);

	free (mask);
	return retval;
}

R_API bool r_sign_add_metric(RAnal *a, const char *name, RSignMetrics metrics) {
	RSignItem *it = R_NEW0 (RSignItem);
	bool retval = true;

	it->type = R_SIGN_METRIC;
	it->name = r_str_new (name);
	it->space = a->zign_spaces.space_idx;
	it->metrics = metrics;

	retval = add (a, it);

	r_sign_item_free (it);

	return retval;
}

struct ctxDeleteCB {
	char buf[R_SIGN_KEY_MAXSZ];
	RAnal *anal;
};

static int deleteCB(void *user, const char *k, const char *v) {
	struct ctxDeleteCB *ctx = (struct ctxDeleteCB *) user;

	if (r_str_cmp (k, ctx->buf, strlen (ctx->buf))) {
		sdb_remove (ctx->anal->sdb_zigns, k, 0);
	}

	return 1;
}

R_API bool r_sign_delete(RAnal *a, const char *name) {
	RSignItem it;
	char buf[R_SIGN_KEY_MAXSZ];
	struct ctxDeleteCB ctx;

	// Remove all flags
	if (name[0] == '*') {
		if (a->zign_spaces.space_idx == -1) {
			sdb_reset (a->sdb_zigns);
			return true;
		} else {
			snprintf (ctx.buf, R_SIGN_KEY_MAXSZ, "zign|%d|", a->zign_spaces.space_idx);
			ctx.anal = a;
			sdb_foreach (a->sdb_zigns, deleteCB, &ctx);
			return true;
		}
	}

	// Remove specific zign
	it.name = (char *) name;
	it.space = a->zign_spaces.space_idx;
	serialize (&it, buf, NULL);
	return sdb_remove (a->sdb_zigns, buf, 0);
}

struct ctxListCB {
	int idx;
	int format;
	RAnal *anal;
};

static void listBytes(RAnal *a, RSignItem *it, int format) {
	char *bytes = NULL;
	int i;

	for (i = 0; i < it->size; i++) {
		if (it->mask[i] & 0xf0) {
			bytes = r_str_appendf (bytes, "%x", (it->bytes[i] & 0xf0) >> 4);
		} else {
			bytes = r_str_appendf (bytes, ".");
		}
		if (it->mask[i] & 0xf) {
			bytes = r_str_appendf (bytes, "%x", it->bytes[i] & 0xf);
		} else {
			bytes = r_str_appendf (bytes, ".");
		}
	}

	if (format == '*') {
		if (it->space >= 0) {
			a->cb_printf ("zs %s\n", a->zign_spaces.spaces[it->space]);
		} else {
			a->cb_printf ("zs *\n");
		}
		a->cb_printf ("zae %s %s\n", it->name, bytes);
	} else if (format == 'j') {
		if (it->space >= 0) {
			a->cb_printf ("{\"zignspace\": \"%s\", ", a->zign_spaces.spaces[it->space]);
		} else {
			a->cb_printf ("{");
		}
		a->cb_printf ("\"name\": \"%s\", \"type\": \"%c\", \"bytes\": \"%s\"}",
			it->name, it->type, bytes);
	} else {
		if (it->space >= 0) {
			a->cb_printf ("%s.", a->zign_spaces.spaces[it->space]);
		}
		a->cb_printf ("%s %c %s\n", it->name, it->type, bytes);
	}

	free (bytes);
}

static void listMetric(RAnal *a, RSignItem *it, int format) {
	if (format == '*') {
		if (it->space >= 0) {
			a->cb_printf ("zs %s\n", a->zign_spaces.spaces[it->space]);
		} else {
			a->cb_printf ("zs *\n");
		}
		a->cb_printf ("zam %s cc=%d nbbs=%d edges=%d ebbs=%d\n",
			it->name, it->metrics.cc, it->metrics.nbbs, it->metrics.edges, it->metrics.ebbs);
	} else if (format == 'j') {
		if (it->space >= 0) {
			a->cb_printf ("{\"zignspace\": \"%s\", ", a->zign_spaces.spaces[it->space]);
		} else {
			a->cb_printf ("{");
		}
		a->cb_printf ("\"name\": \"%s\", \"type\": \"%c\", \"metrics\": \"cc=%d nbbs=%d edges=%d ebbs=%d\"}",
			it->name, it->type, it->metrics.cc, it->metrics.nbbs, it->metrics.edges, it->metrics.ebbs);
	} else {
		if (it->space >= 0) {
			a->cb_printf ("%s.", a->zign_spaces.spaces[it->space]);
		}
		a->cb_printf ("%s %c cc=%d nbbs=%d edges=%d ebbs=%d\n",
			it->name, it->type, it->metrics.cc, it->metrics.nbbs, it->metrics.edges, it->metrics.ebbs);
	}
}

static int listCB(void *user, const char *k, const char *v) {
	struct ctxListCB *ctx = (struct ctxListCB *) user;
	RSignItem *it = R_NEW0 (RSignItem);
	RAnal *a = ctx->anal;

	if (!deserialize (it, k, v)) {
		eprintf ("error: cannot deserialize zign\n");
		goto exit_function;
	}

	if (a->zign_spaces.space_idx != it->space && a->zign_spaces.space_idx != -1) {
		goto exit_function;
	}

	if (ctx->format == 'j' && ctx->idx > 0) {
		a->cb_printf (",");
	}

	switch (it->type) {
	case R_SIGN_EXACT:
	case R_SIGN_ANAL:
		listBytes (a, it, ctx->format);
		break;
	case R_SIGN_METRIC:
		listMetric (a, it, ctx->format);
		break;
	}

	ctx->idx++;

exit_function:
	r_sign_item_free (it);

	return 1;
}

R_API void r_sign_list(RAnal *a, int format) {
	struct ctxListCB ctx = { 0, format, a };

	if (format == 'j') {
		a->cb_printf ("[");
	}

	sdb_foreach (a->sdb_zigns, listCB, &ctx);

	if (format == 'j') {
		a->cb_printf ("]\n");
	}
}

struct ctxCountForCB {
	int idx;
	int count;
};

static int countForCB(void *user, const char *k, const char *v) {
	struct ctxCountForCB *ctx = (struct ctxCountForCB *) user;
	RSignItem *it = R_NEW0 (RSignItem);

	if (!deserialize (it, k, v)) {
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
	struct ctxCountForCB ctx = { idx, 0 };

	sdb_foreach (a->sdb_zigns, countForCB, &ctx);

	return ctx.count;
}

struct ctxUnsetForCB {
	int idx;
	RAnal *anal;
};

static int unsetForCB(void *user, const char *k, const char *v) {
	struct ctxUnsetForCB *ctx = (struct ctxUnsetForCB *) user;
	char nk[R_SIGN_KEY_MAXSZ], nv[R_SIGN_VAL_MAXSZ];
	RSignItem *it = R_NEW0 (RSignItem);
	Sdb *db = ctx->anal->sdb_zigns;

	if (!deserialize (it, k, v)) {
		eprintf ("error: cannot deserialize zign\n");
		goto exit_function;
	}

	if (it->space != ctx->idx) {
		goto exit_function;
	}

	if (it->space != -1) {
		it->space = -1;
		serialize (it, nk, nv);
		sdb_remove (db, k, 0);
		sdb_set (db, nk, nv, 0);
	}

exit_function:
	r_sign_item_free (it);

	return 1;
}

R_API void r_sign_space_unset_for(RAnal *a, int idx) {
	struct ctxUnsetForCB ctx = { idx, a };

	sdb_foreach (a->sdb_zigns, unsetForCB, &ctx);
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

	if (!deserialize (it, k, v)) {
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

	if (it->type != R_SIGN_EXACT && it->type != R_SIGN_ANAL) {
		return 1;
	}

	it2 = r_sign_item_dup (it);
	r_list_append(ss->items, it2);

	// TODO(nibble): change arg data in r_search_keyword_new to void*
	kw = r_search_keyword_new (it->bytes, it->size, it->mask, it->size, (const char *) it2);
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
	int ebbs = -1;

	if (it->metrics.cc != -1 && it->metrics.cc != r_anal_fcn_cc (fcn)) {
		return false;
	}
	if (it->metrics.nbbs != -1 && it->metrics.nbbs != r_list_length (fcn->bbs)) {
		return false;
	}
	if (it->metrics.edges != -1 && it->metrics.edges != r_anal_fcn_count_edges (fcn, &ebbs)) {
		return false;
	}
	if (it->metrics.ebbs != -1 && it->metrics.ebbs != ebbs) {
		return false;
	}

	return true;
}

struct ctxMetricMatchCB {
	RAnal *anal;
	RAnalFunction *fcn;
	RSignMetricMatchCallback cb;
	void *user;
};

static int metricMatchCB(RSignItem *it, void *user) {
	struct ctxMetricMatchCB *ctx = (struct ctxMetricMatchCB *) user;

	if (it->type != R_SIGN_METRIC) {
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

R_API int r_sign_match_metric(RAnal *a, RAnalFunction *fcn, RSignMetricMatchCallback cb, void *user) {
	struct ctxMetricMatchCB ctx = { a, fcn, cb, user };

	r_sign_foreach (a, metricMatchCB, &ctx);

	return 0;
}

R_API RSignItem *r_sign_item_dup(RSignItem *it) {
	RSignItem *ret = R_NEW0 (RSignItem);

	ret->name = r_str_new (it->name);
	ret->space = it->space;
	ret->type = it->type;
	ret->size = it->size;
	ret->bytes = malloc (it->size);
	memcpy (ret->bytes, it->bytes, it->size);
	ret->mask = malloc (it->size);
	memcpy (ret->mask, it->mask, it->size);

	return ret;
}

R_API void r_sign_item_free(void *_item) {
	if (!_item) {
		return;
	}

	RSignItem *item = _item;
	free (item->name);
	free (item->bytes);
	free (item->mask);
	free (item);
}

static int loadCB(void *user, const char *k, const char *v) {
	RAnal *a = (RAnal *) user;
	char nk[R_SIGN_KEY_MAXSZ], nv[R_SIGN_VAL_MAXSZ];
	RSignItem *it = R_NEW0 (RSignItem);

	if (!deserialize (it, k, v)) {
		eprintf ("error: cannot deserialize zign\n");
		goto exit_function;
	}

	it->space = a->zign_spaces.space_idx;
	serialize (it, nk, nv);
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
