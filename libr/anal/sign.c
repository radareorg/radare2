/* radare - LGPL - Copyright 2009-2021 - pancake, nibble */

#include <r_anal.h>
#include <r_sign.h>
#include <r_search.h>
#include <r_core.h>

R_LIB_VERSION (r_sign);

#define SIGN_DIFF_MATCH_BYTES_THRESHOLD 1.0
#define SIGN_DIFF_MATCH_GRAPH_THRESHOLD 1.0

const char *getRealRef(RCore *core, ut64 off) {
	RFlagItem *item;
	RListIter *iter;

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

int list_str_cmp (const void *a, const void *b) {
	// prevent silent failure if RListComparator changes
	return strcmp ((const char *)a, (const char *)b);
}

R_API RList *r_sign_fcn_vars(RAnal *a, RAnalFunction *fcn) {
	r_return_val_if_fail (a && fcn, NULL);

	RCore *core = a->coreb.core;

	if (!core) {
		return NULL;
	}

	RListIter *iter;
	RAnalVar *var;
	RList *ret = r_list_newf ((RListFree) free);
	if (!ret) {
		return NULL;
	}
	RList *reg_vars = r_anal_var_list (core->anal, fcn, R_ANAL_VAR_KIND_REG);
	RList *spv_vars = r_anal_var_list (core->anal, fcn, R_ANAL_VAR_KIND_SPV);
	RList *bpv_vars = r_anal_var_list (core->anal, fcn, R_ANAL_VAR_KIND_BPV);
	r_list_foreach (bpv_vars, iter, var) {
		r_list_append (ret, r_str_newf ("b%d", var->delta));
	}
	r_list_foreach (spv_vars, iter, var) {
		r_list_append (ret, r_str_newf ("s%d", var->delta));
	}
	r_list_foreach (reg_vars, iter, var) {
		r_list_append (ret, r_str_newf ("r%d", var->delta));
	}
	r_list_free (reg_vars);
	r_list_free (bpv_vars);
	r_list_free (spv_vars);
	return ret;
}

R_API RList *r_sign_fcn_types(RAnal *a, RAnalFunction *fcn) {

	// From anal/types/*:
	// Get key-value types from sdb matching "func.%s", fcn->name
	// Get func.%s.args (number of args)
	// Get type,name pairs
	// Put everything in RList following the next format:
	// types: main.ret=%type%, main.args=%num%, main.arg.0="int,argc", ...

	r_return_val_if_fail (a && fcn, NULL);

	RList *ret = r_list_newf ((RListFree) free);
	if (!ret) {
		return NULL;
	}

	char *scratch = r_str_newf ("func.%s.args", fcn->name);
	if (!scratch) {
		return NULL;
	}
	const char *fcntypes = sdb_const_get (a->sdb_types, scratch, 0);
	free (scratch);

	scratch = r_str_newf ("func.%s.ret", fcn->name);
	if (!scratch) {
		return NULL;
	}
	const char *ret_type = sdb_const_get (a->sdb_types, scratch, 0);
	free (scratch);

	if (fcntypes) {
		if (ret_type) {
			r_list_append (ret, r_str_newf ("func.%s.ret=%s", fcn->name, ret_type));
		}
		int argc = atoi (fcntypes);
		r_list_append (ret, r_str_newf ("func.%s.args=%d", fcn->name, argc));
		int i;
		for (i = 0; i < argc; i++) {
			char *k = r_str_newf ("func.%s.arg.%d", fcn->name, i);
			if (k) {
				const char *arg = sdb_const_get (a->sdb_types, k, 0);
				r_list_append (ret, r_str_newf ("func.%s.arg.%d=\"%s\"", fcn->name, i, arg));
				free (k);
			}
		}
	}

	return ret;
}

R_API RList *r_sign_fcn_xrefs(RAnal *a, RAnalFunction *fcn) {
	RListIter *iter = NULL;
	RAnalRef *refi = NULL;

	r_return_val_if_fail (a && fcn, NULL);

	RCore *core = a->coreb.core;

	if (!core) {
		return NULL;
	}

	RList *ret = r_list_newf ((RListFree) free);
	RList *xrefs = r_anal_function_get_xrefs (fcn);
	r_list_foreach (xrefs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_CODE || refi->type == R_ANAL_REF_TYPE_CALL) {
			const char *flag = getRealRef (core, refi->addr);
			if (flag) {
				r_list_append (ret, r_str_new (flag));
			}
		}
	}
	r_list_free (xrefs);
	return ret;
}

R_API RList *r_sign_fcn_refs(RAnal *a, RAnalFunction *fcn) {
	RListIter *iter = NULL;
	RAnalRef *refi = NULL;

	r_return_val_if_fail (a && fcn, NULL);

	RCore *core = a->coreb.core;

	if (!core) {
		return NULL;
	}

	RList *ret = r_list_newf ((RListFree) free);
	RList *refs = r_anal_function_get_refs (fcn);
	r_list_foreach (refs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_CODE || refi->type == R_ANAL_REF_TYPE_CALL) {
			const char *flag = getRealRef (core, refi->addr);
			if (flag) {
				r_list_append (ret, r_str_new (flag));
			}
		}
	}
	r_list_free (refs);
	return ret;
}

static RList *zign_types_to_list(RAnal *a, const char *types) {
	RList *ret = r_list_newf ((RListFree)free);
	if (!ret) {
		return NULL;
	}

	unsigned int i = 0, prev = 0, len = strlen (types);
	bool quoted = false;
	char *token = NULL;
	for (i = 0; i <= len; i++) {
		if (types[i] == '"') {
			quoted = !quoted;
		} else if ((types[i] == ',' && !quoted) || types[i] == '\0') {
			token = r_str_ndup (types + prev, i - prev);
			if (token) {
				prev = i + 1;
				r_list_append (ret, token);
				token = NULL;
			}
		}
	}

	return ret;
}

static RList *do_reflike_sig(const char *token) {
	RList *list = NULL;
	char *scratch = r_str_new (token);
	int cnt = r_str_split (scratch, ',');
	if (cnt > 0 && (list = r_list_newf ((RListFree)free))) {
		int i;
		for (i = 0; i < cnt; i++) {
			r_list_append (list, r_str_new (r_str_word_get0 (scratch, i)));
		}
	}
	free (scratch);
	return list;
}

#define DBL_VAL_FAIL(x,y) \
	if (x) { \
		eprintf ("Warning: Skipping signature with multiple %c signatures (%s)\n", y, k); \
		success = false; \
		goto out; \
	}
R_API bool r_sign_deserialize(RAnal *a, RSignItem *it, const char *k, const char *v) {
	r_return_val_if_fail (a && it && k && v, false);

	bool success = true;
	char *k2 = r_str_new (k);
	char *v2 = r_str_new (v);
	if (!k2 || !v2) {
		success = false;
		goto out;
	}

	// Deserialize key: zign|space|name
	int n = r_str_split (k2, '|');
	if (n != 3) {
		eprintf ("Warning: Skipping signature with invalid key (%s)\n", k);
		success = false;
		goto out;
	}
	if (strcmp (r_str_word_get0 (k2, 0), "zign")) {
		eprintf ("Warning: Skipping signature with invalid value (%s)\n", k);
		success = false;
		goto out;
	}

	it->space = r_spaces_add (&a->zign_spaces, r_str_word_get0 (k2, 1));
	it->name = r_str_new (r_str_word_get0 (k2, 2));

	// remove newline at end
	strtok (v2, "\n");
	// Deserialize value: |k:v|k:v|k:v|...
	n = r_str_split (v2, '|');
	const char *token = NULL;
	int w, size;
	for (w = 0; w < n; w++) {
		const char *word = r_str_word_get0 (v2, w);
		if (!word) {
			break;
		}
		if (!*word) {
			continue;
		}
		token = word + 2;
		if (!strcmp (word, "*")) {
			continue;
		}
		if (strlen (word) < 3 || word[1] != ':') {
			eprintf ("Warning: Skipping signature with corrupted serialization (%s:%s)\n", k, word);
			success = false;
			goto out;
		}
		RSignType st = (RSignType)*word;
		switch (st) {
		case R_SIGN_ANAL:
			eprintf ("Unsupported\n");
			break;
		case R_SIGN_NAME:
			DBL_VAL_FAIL (it->realname, R_SIGN_NAME);
			it->realname = strdup (token);
			break;
		case R_SIGN_COMMENT:
			DBL_VAL_FAIL (it->comment, R_SIGN_COMMENT);
			it->comment = strdup (token);
			break;
		case R_SIGN_GRAPH:
			DBL_VAL_FAIL (it->graph, R_SIGN_GRAPH);
			if (strlen (token) == 2 * sizeof (RSignGraph)) {
				it->graph = R_NEW0 (RSignGraph);
				if (it->graph) {
					r_hex_str2bin (token, (ut8 *)it->graph);
				}
			}
			break;
		case R_SIGN_OFFSET:
			DBL_VAL_FAIL ((it->addr != UT64_MAX), R_SIGN_OFFSET);
			it->addr = atoll (token);
			break;
		case R_SIGN_REFS:
			DBL_VAL_FAIL (it->refs, R_SIGN_REFS);
			if (!(it->refs = do_reflike_sig (token))) {
				success = false;
				goto out;
			}
			break;
		case R_SIGN_XREFS:
			DBL_VAL_FAIL (it->xrefs, R_SIGN_XREFS);
			if (!(it->xrefs = do_reflike_sig (token))) {
				success = false;
				goto out;
			}
			break;
		case R_SIGN_VARS:
			DBL_VAL_FAIL (it->vars, R_SIGN_VARS);
			if (!(it->vars = do_reflike_sig (token))) {
				success = false;
				goto out;
			}
			break;
		case R_SIGN_TYPES:
			DBL_VAL_FAIL (it->types, R_SIGN_TYPES);
			it->types = zign_types_to_list (a, token);
			break;
		case R_SIGN_COLLISIONS:
			DBL_VAL_FAIL (it->collisions, R_SIGN_COLLISIONS);
			it->collisions = zign_types_to_list (a, token);
			break;
		case R_SIGN_BBHASH:
			DBL_VAL_FAIL (it->hash, R_SIGN_BBHASH);
			if (token[0] != 0) {
				it->hash = R_NEW0 (RSignHash);
				if (it->hash) {
					it->hash->bbhash = r_str_new (token);
				}
			}
			break;
		case R_SIGN_BYTES:
			// following two errors are not due to double entries
			if (!it->bytes) {
				eprintf ("Warning: Skipping signature with no bytes size (%s)\n", k);
				success = false;
				goto out;
			}
			if (strlen (token) != 2 * it->bytes->size) {
				eprintf ("Warning: Skipping signature with invalid size (%s)\n", k);
				success = false;
				goto out;
			}
			DBL_VAL_FAIL (it->bytes->bytes, R_SIGN_BYTES);
			it->bytes->bytes = malloc (it->bytes->size);
			if (it->bytes->bytes) {
				r_hex_str2bin (token, it->bytes->bytes);
			}
			break;
		case R_SIGN_BYTES_MASK:
			// following two errors are not due to double entries
			if (!it->bytes) {
				eprintf ("Warning: Skipping signature with no mask size (%s)\n", k);
				success = false;
				goto out;
			}
			if (strlen (token) != 2 * it->bytes->size) {
				eprintf ("Warning: Skipping signature invalid mask size (%s)\n", k);
				success = false;
				goto out;
			}
			DBL_VAL_FAIL (it->bytes->mask, R_SIGN_BYTES);
			it->bytes->mask = malloc (it->bytes->size);
			if (!it->bytes->mask) {
				goto out;
			}
			r_hex_str2bin (token, it->bytes->mask);
			break;
		case R_SIGN_BYTES_SIZE:
			// allocate
			size = atoi (token);
			if (size > 0) {
				DBL_VAL_FAIL (it->bytes, R_SIGN_BYTES_SIZE);
				it->bytes = R_NEW0 (RSignBytes);
				if (!it->bytes) {
					goto out;
				}
				it->bytes->size = size;
			}
			break;
		default:
			eprintf ("Unsupported (%s)\n", word);
			break;
		}
	}
out:
	free (k2);
	free (v2);
	return success;
}
#undef DBL_VAL_FAIL

static inline char *str_serialize_key(const char *sp, const char *name) {
	return r_str_newf ("zign|%s|%s", sp, name);
}

static inline char *space_serialize_key(const RSpace *space, const char *name) {
	const char *sp = space? space->name: "*";
	return str_serialize_key (sp, name);
}

static inline char *item_serialize_key(RSignItem *it) {
	return space_serialize_key (it->space, it->name);
}

static bool serialize_str_list(RList *l, RStrBuf *sb, RSignType t) {
	if (!l || l->length == 0) {
		return true;
	}
	if (!r_strbuf_appendf (sb, "|%c:", t)) {
		return false;
	}
	char *e, *c = "";
	RListIter *iter;
	r_list_foreach (l, iter, e) {
		if (!r_strbuf_appendf (sb, "%s%s", c, e)) {
			return false;
		}
		if (!*c) {
			c = ",";
		}
	}
	return true;
}

static inline size_t serial_val_reserv(RSignItem *it) {
	// does not have to be exact, just save time on re-alloc+copy
	size_t reserve = 32;
	if (it->bytes) {
		reserve += it->bytes->size * 4 + 10;
	}
	if (it->graph) {
		reserve += sizeof (RSignGraph) * 2 + 1;
	}
	if (it->hash && it->hash->bbhash) {
		reserve += 64;
	}
	int mul = 5;
	if (it->refs) {
		reserve += mul * r_list_length (it->refs);
	}
	if (it->xrefs) {
		reserve += mul * r_list_length (it->xrefs);
	}
	if (it->vars) {
		reserve += mul * r_list_length (it->vars);
	}
	if (it->types) {
		reserve += mul * r_list_length (it->types);
	}
	return reserve;
}

#define FreeRet_on_fail(exp, buf) \
	if (!exp) { \
		r_strbuf_free (buf); \
		return NULL; \
	}

static char *serialize_value(RSignItem *it) {
	r_return_val_if_fail (it, false);

	size_t reserve = 0;
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_reserve (sb, serial_val_reserv (it));

	if (it->bytes) {
		reserve += it->bytes->size * 2;
	}

	RSignBytes *bytes = it->bytes;
	if (bytes && bytes->bytes && bytes->mask) {
		RSignBytes *bytes = it->bytes;
		size_t len = bytes->size * 2 + 1;
		char *hexbytes = calloc (1, len);
		char *hexmask = calloc (1, len);
		bool success = false;
		if (hexbytes && hexmask) {
			r_hex_bin2str (bytes->bytes, bytes->size, hexbytes);
			r_hex_bin2str (bytes->mask, bytes->size, hexmask);
			success = r_strbuf_appendf (sb, "|%c:%d|%c:%s|%c:%s",
				R_SIGN_BYTES_SIZE, bytes->size, R_SIGN_BYTES, hexbytes,
				R_SIGN_BYTES_MASK, hexmask);
			free (hexbytes);
			free (hexmask);
		}
		FreeRet_on_fail (success, sb);
	}

	if (it->addr != UT64_MAX) {
		FreeRet_on_fail (r_strbuf_appendf (sb, "|%c:%" PFMT64d, R_SIGN_OFFSET, it->addr), sb);
	}

	if (it->graph) {
		char *hexgraph = calloc (1, sizeof (RSignGraph) * 2 + 1);
		bool success = false;
		if (hexgraph) {
			r_hex_bin2str ((ut8 *)it->graph, sizeof (RSignGraph), hexgraph);
			success = r_strbuf_appendf (sb, "|%c:%s", R_SIGN_GRAPH, hexgraph);
			free (hexgraph);
		}
		FreeRet_on_fail (success, sb);
	}

	FreeRet_on_fail (serialize_str_list (it->refs, sb, R_SIGN_REFS), sb);
	FreeRet_on_fail (serialize_str_list (it->xrefs, sb, R_SIGN_XREFS), sb);
	FreeRet_on_fail (serialize_str_list (it->vars, sb, R_SIGN_VARS), sb);
	FreeRet_on_fail (serialize_str_list (it->types, sb, R_SIGN_TYPES), sb);
	FreeRet_on_fail (serialize_str_list (it->collisions, sb, R_SIGN_COLLISIONS), sb);

	if (it->comment) {
		FreeRet_on_fail (r_strbuf_appendf (sb, "|%c:%s", R_SIGN_COMMENT, it->comment), sb);
	}

	if (it->realname) {
		FreeRet_on_fail (r_strbuf_appendf (sb, "|%c:%s", R_SIGN_NAME, it->realname), sb);
	}

	if (it->hash && it->hash->bbhash) {
		FreeRet_on_fail (r_strbuf_appendf (sb, "|%c:%s", R_SIGN_BBHASH, it->hash->bbhash), sb);
	}

	return r_strbuf_drain (sb);
}

static RList *deserialize_sign_space(RAnal *a, RSpace *space) {
	r_return_val_if_fail (a && space, NULL);

	char *key = space_serialize_key (space, "");
	if (!key) {
		return NULL;
	}
	SdbList *zigns = sdb_foreach_match (a->sdb_zigns, key, false);
	free (key);

	SdbListIter *iter;
	SdbKv *kv;
	RList *ret = r_list_newf ((RListFree)r_sign_item_free);
	if (ret) {
		ls_foreach (zigns, iter, kv) {
			RSignItem *it = r_sign_item_new ();
			if (!it) {
				break;
			}
			if (r_sign_deserialize (a, it, kv->base.key, kv->base.value)) {
				r_list_append (ret, it);
			} else {
				r_sign_item_free (it);
			}
		}
	}
	ls_free (zigns);
	return ret;
}

static inline bool merge_list (RList **dst, RList *src) {
	if (!src) {
		return true;
	}
	r_list_free (*dst);
	if (!(*dst = r_list_newf (free))) {
		return false;
	}
	RListIter *iter;
	char *s, *dup;
	r_list_foreach (src, iter, s) {
		if (!(dup = strdup (s))) {
			return false;
		}
		r_list_append (*dst, dup);
	}
	return true;
}

static bool mergeItem(RSignItem *dst, RSignItem *src) {
	dst->space = src->space;
	if (src->bytes) {
		// ensure we have a dst->bytes
		if (!dst->bytes && !(dst->bytes = R_NEW0 (RSignBytes))) {
			return false;
		}
		// ensure we have space in dst->bytes->[bytes|mask]
		if (src->bytes->size > dst->bytes->size) {
			free (dst->bytes->bytes);
			free (dst->bytes->mask);
			dst->bytes->bytes = R_NEWS (ut8, src->bytes->size);
			dst->bytes->mask = R_NEWS (ut8, src->bytes->size);
			if (!dst->bytes->bytes || !dst->bytes->mask) {
				return false;
			}
		}
		// do copy
		dst->bytes->size = src->bytes->size;
		memcpy (dst->bytes->bytes, src->bytes->bytes, src->bytes->size);
		memcpy (dst->bytes->mask, src->bytes->mask, src->bytes->size);
	}

	if (src->graph) {
		if (!dst->graph && !(dst->graph = R_NEW0 (RSignGraph))) {
			return false;
		}
		*dst->graph = *src->graph;
	}

	if (src->comment) {
		free (dst->comment);
		if (!(dst->comment = strdup (src->comment))) {
			return false;
		}
		dst->comment = src->comment;
		src->comment = NULL;
	}

	if (src->realname) {
		free (dst->realname);
		if (!(dst->realname = strdup (src->realname))) {
			return false;
		}
	}

	if (src->addr != UT64_MAX) {
		dst->addr = src->addr;
	}

	if (!merge_list (&dst->refs, src->refs)) {
		return false;
	}
	if (!merge_list (&dst->xrefs, src->xrefs)) {
		return false;
	}
	if (!merge_list (&dst->vars, src->vars)) {
		return false;
	}
	if (!merge_list (&dst->types, src->types)) {
		return false;
	}
	if (!merge_list (&dst->collisions, src->collisions)) {
		return false;
	}

	if (src->hash && src->hash->bbhash) {
		if (!dst->hash && !(dst->hash = R_NEW0 (RSignHash))) {
			return false;
		}
		free (dst->hash->bbhash);
		dst->hash->bbhash = strdup (src->hash->bbhash);
	}
	return true;
}

static RSignItem *sign_get_sdb_item(RAnal *a, const char *key) {
	RSignItem *it = NULL;
	const char *value = sdb_const_get (a->sdb_zigns, key, 0);
	if (value && (it = r_sign_item_new ())) {
		if (r_sign_deserialize (a, it, key, value)) {
			return it;
		}
		r_sign_item_free (it);
	}
	return NULL;
}

static bool r_sign_set_item(Sdb *sdb, RSignItem *it, char *key_optional) {
	bool retval = false;
	char *key = NULL, *mykey = key_optional;
	if (!mykey) {
		key = mykey = item_serialize_key (it);
	}
	char *value = serialize_value (it);
	if (mykey && value) {
		sdb_set (sdb, mykey, value, 0);
		retval = true;
	}
	free (key);
	free (value);
	return retval;
}

R_API RSignItem *r_sign_get_item(RAnal *a, const char *name) {
	char *k = space_serialize_key (r_spaces_current (&a->zign_spaces), name);
	if (k) {
		RSignItem *it = sign_get_sdb_item (a, k);
		free (k);
		return it;
	}
	return NULL;
}

R_API bool r_sign_add_item(RAnal *a, RSignItem *it) {
	char *key = item_serialize_key (it);
	RSignItem *current = sign_get_sdb_item (a, key);

	bool retval = false;
	if (current) {
		if (mergeItem (current, it)) {
			retval = r_sign_set_item (a->sdb_zigns, current, key);
			r_sign_item_free (current);
		}
	} else {
		retval = r_sign_set_item (a->sdb_zigns, it, key);
	}
	free (key);
	return retval;
}

static bool addHash(RAnal *a, const char *name, int type, const char *val) {
	RSignItem *it = r_sign_item_new ();
	if (!it) {
		r_sign_item_free (it);
		return false;
	}
	it->name = r_str_new (name);
	if (!it->name) {
		r_sign_item_free (it);
		return false;
	}
	it->hash = R_NEW0 (RSignHash);
	if (!it->hash) {
		r_sign_item_free (it);
		return false;
	}
	it->space = r_spaces_current (&a->zign_spaces);

	bool retval = false;
	switch (type) {
	case R_SIGN_BBHASH:
		it->hash->bbhash = strdup (val);
		retval = r_sign_add_item (a, it);
		r_sign_item_free (it);
		break;
	}

	return retval;
}

static bool addBBHash(RAnal *a, RAnalFunction *fcn, const char *name) {
	bool retval = false;
	RSignItem *it = r_sign_item_new ();
	if (!it) {
		goto beach;
	}
	it->name = r_str_new (name);
	if (!it->name) {
		goto beach;
	}
	it->space = r_spaces_current (&a->zign_spaces);

	if (r_sign_addto_item (a, it, fcn, R_SIGN_BBHASH)) {
		retval = r_sign_add_item (a, it);
	}
beach:
	r_sign_item_free (it);
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
	it->space = r_spaces_current (&a->zign_spaces);
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
	retval = r_sign_add_item (a, it);
	r_sign_item_free (it);
	return retval;
fail:
	if (it) {
		free (it->name);
		r_sign_bytes_free (it->bytes);
	}
	free (it);
	return false;
}

R_API bool r_sign_add_hash(RAnal *a, const char *name, int type, const char *val, int len) {
	r_return_val_if_fail (a && name && type && val && len > 0, false);
	if (type != R_SIGN_BBHASH) {
		eprintf ("error: hash type unknown");
		return false;
	}
	int digestsize = r_hash_size (R_ZIGN_HASH) * 2;
	if (len != digestsize) {
		eprintf ("error: invalid hash size: %d (%s digest size is %d)\n", len, ZIGN_HASH, digestsize);
		return false;
	}
	return addHash (a, name, type, val);
}

R_API bool r_sign_add_bb_hash(RAnal *a, RAnalFunction *fcn, const char *name) {
	r_return_val_if_fail (a && fcn && name, false);
	return addBBHash (a, fcn, name);
}

R_API bool r_sign_add_bytes(RAnal *a, const char *name, ut64 size, const ut8 *bytes, const ut8 *mask) {
	r_return_val_if_fail (a && name && size > 0 && bytes && mask, false);
	return addBytes (a, name, size, bytes, mask);
}

R_API bool r_sign_add_anal(RAnal *a, const char *name, ut64 size, const ut8 *bytes, ut64 at) {
	bool retval = false;
	r_return_val_if_fail (a && name && size > 0 && bytes, false);
	ut8 *mask = r_anal_mask (a, size, bytes, at);
	if (mask) {
		retval = addBytes (a, name, size, bytes, mask);
		free (mask);
	}
	return retval;
}

static RSignGraph *r_sign_fcn_graph(RAnalFunction *fcn) {
	r_return_val_if_fail (fcn, false);
	RSignGraph *graph = R_NEW0 (RSignGraph);
	if (graph) {
		graph->cc = r_anal_function_complexity (fcn),
		graph->nbbs = r_list_length (fcn->bbs);
		graph->edges = r_anal_function_count_edges (fcn, &graph->ebbs);
		graph->bbsum = r_anal_function_realsize (fcn);
	}
	return graph;
}

static int bb_sort_by_addr(const void *x, const void *y) {
	RAnalBlock *a = (RAnalBlock *)x;
	RAnalBlock *b = (RAnalBlock *)y;
	if (a->addr > b->addr) {
		return 1;
	}
	if (a->addr < b->addr) {
		return -1;
	}
	return 0;
}

static RSignBytes *r_sign_func_empty_mask(RAnal *a, RAnalFunction *fcn) {
	r_return_val_if_fail (a && fcn && fcn->bbs && fcn->bbs->head, false);

	// get size
	RCore *core = a->coreb.core;
	int maxsz = a->coreb.cfggeti (core, "zign.maxsz");
	r_list_sort (fcn->bbs, &bb_sort_by_addr);
	ut64 ea = fcn->addr;
	RAnalBlock *bb = (RAnalBlock *)fcn->bbs->tail->data;
	int size = R_MIN (bb->addr + bb->size - ea, maxsz);

	// alloc space for signature
	RSignBytes *sig = R_NEW0 (RSignBytes);
	if (sig) {
		sig->bytes = malloc (size);
		sig->mask = R_NEWS0 (ut8, size);
		sig->size = size;
		if (sig->bytes && sig->mask && a->iob.read_at (a->iob.io, ea, sig->bytes, size)) {
			return sig;
		}
	}
	r_sign_bytes_free (sig);
	return NULL;
}

static RSignBytes *r_sign_fcn_bytes(RAnal *a, RAnalFunction *fcn) {
	r_return_val_if_fail (a && fcn && fcn->bbs && fcn->bbs->head, false);
	RSignBytes *sig = r_sign_func_empty_mask (a, fcn);
	if (!sig) {
		return NULL;
	}

	ut64 ea = fcn->addr;
	int size = sig->size;
	ut8 *tmpmask = NULL;
	RAnalBlock *bb;
	RListIter *iter;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr >= ea) {
			size_t delta = bb->addr - ea;
			size_t rsize = bb->size;

			// bounds check
			if (delta >= size) {
				break;
			}
			if (size - delta < rsize) {
				rsize = size - delta;
			}

			// get mask for block
			if (!(tmpmask = r_anal_mask (a, rsize, sig->bytes + delta, ea))) {
				r_sign_bytes_free (sig);
				return NULL;
			}
			if (rsize > 0) {
				memcpy (sig->mask + delta, tmpmask, rsize);
			}
			free (tmpmask);
		}
	}
	return sig;
}

static RSignHash *r_sign_fcn_bbhash(RAnal *a, RAnalFunction *fcn) {
	r_return_val_if_fail (a && fcn, NULL);
	RSignHash *hash = R_NEW0 (RSignHash);
	if (!hash) {
		return NULL;
	}

	char *digest_hex = r_sign_calc_bbhash (a, fcn);
	if (!digest_hex) {
		free (hash);
		return NULL;
	}
	hash->bbhash = digest_hex;
	return hash;
}

R_API bool r_sign_addto_item(RAnal *a, RSignItem *it, RAnalFunction *fcn, RSignType type) {
	r_return_val_if_fail (a && it && fcn, false);
	switch (type) {
	case R_SIGN_GRAPH:
		return !it->graph && (it->graph = r_sign_fcn_graph (fcn));
	case R_SIGN_BYTES:
		return !it->bytes && (it->bytes = r_sign_fcn_bytes (a, fcn));
	case R_SIGN_XREFS:
		return !it->xrefs && (it->xrefs = r_sign_fcn_xrefs (a, fcn));
	case R_SIGN_REFS:
		return !it->refs && (it->refs = r_sign_fcn_refs (a, fcn));
	case R_SIGN_VARS:
		return !it->vars && (it->vars = r_sign_fcn_vars (a, fcn));
	case R_SIGN_TYPES:
		return !it->types && (it->types = r_sign_fcn_types (a, fcn));
	case R_SIGN_BBHASH:
		return !it->hash && (it->hash = r_sign_fcn_bbhash (a, fcn));
	case R_SIGN_OFFSET:
		it->addr = fcn->addr;
		return true;
	case R_SIGN_NAME:
		if (!it->realname && it->name) {
			if (strcmp (it->name, fcn->name)) {
				it->realname = strdup (fcn->name);
			}
			return true;
		}
		break;
	default:
		eprintf ("Error: %s Can not handle type %c\n", __FUNCTION__, type);
	}

	return false;
}

R_API bool r_sign_add_graph(RAnal *a, const char *name, RSignGraph graph) {
	r_return_val_if_fail (a && !R_STR_ISEMPTY (name), false);
	bool retval = true;
	RSignItem *it = r_sign_item_new ();
	if (!it) {
		return false;
	}
	it->name = r_str_new (name);
	if (!it->name) {
		free (it);
		return false;
	}
	it->space = r_spaces_current (&a->zign_spaces);
	it->graph = R_NEW0 (RSignGraph);
	if (!it->graph) {
		free (it->name);
		free (it);
		return false;
	}
	*it->graph = graph;
	retval = r_sign_add_item (a, it);
	r_sign_item_free (it);

	return retval;
}

R_API bool r_sign_add_comment(RAnal *a, const char *name, const char *comment) {
	r_return_val_if_fail (a && name && comment, false);

	RSignItem *it = r_sign_item_new ();
	if (!it) {
		return false;
	}
	it->name = r_str_new (name);
	it->space = r_spaces_current (&a->zign_spaces);
	it->comment = strdup (comment);
	bool retval = r_sign_add_item (a, it);
	r_sign_item_free (it);
	return retval;
}

R_API bool r_sign_add_name(RAnal *a, const char *name, const char *realname) {
	r_return_val_if_fail (a && name && realname, false);
	RSignItem *it = r_sign_item_new ();
	if (it) {
		it->name = r_str_new (name);
		it->realname = strdup (realname);
		it->space = r_spaces_current (&a->zign_spaces);
		bool retval = r_sign_add_item (a, it);
		r_sign_item_free (it);
		return retval;
	}
	return false;
}

R_API bool r_sign_add_addr(RAnal *a, const char *name, ut64 addr) {
	r_return_val_if_fail (a && name && addr != UT64_MAX, false);

	RSignItem *it = r_sign_item_new ();
	if (!it) {
		return false;
	}
	it->name = r_str_new (name);
	it->space = r_spaces_current (&a->zign_spaces);
	it->addr = addr;

	bool retval = r_sign_add_item (a, it);

	r_sign_item_free (it);

	return retval;
}

R_API bool r_sign_add_vars(RAnal *a, const char *name, RList *vars) {
	r_return_val_if_fail (a && name && vars, false);

	RListIter *iter;
	char *var;

	RSignItem *it = r_sign_item_new ();
	if (!it) {
		return false;
	}
	it->name = r_str_new (name);
	if (!it->name) {
		r_sign_item_free (it);
		return false;
	}
	it->space = r_spaces_current (&a->zign_spaces);
	it->vars = r_list_newf ((RListFree)free);
	r_list_foreach (vars, iter, var) {
		r_list_append (it->vars, strdup (var));
	}
	bool retval = r_sign_add_item (a, it);
	r_sign_item_free (it);

	return retval;
}

R_API bool r_sign_add_types(RAnal *a, const char *name, RList *types) {
	r_return_val_if_fail (a && name && types, false);

	RListIter *iter;
	char *type;

	RSignItem *it = r_sign_item_new ();
	if (!it) {
		return false;
	}
	it->name = r_str_new (name);
	if (!it->name) {
		r_sign_item_free (it);
		return false;
	}
	it->space = r_spaces_current (&a->zign_spaces);
	it->types = r_list_newf ((RListFree) free);
	r_list_foreach (types, iter, type) {
		r_list_append (it->types, strdup (type));
	}
	bool retval = r_sign_add_item (a, it);
	r_sign_item_free (it);

	return retval;
}

R_API bool r_sign_add_refs(RAnal *a, const char *name, RList *refs) {
	r_return_val_if_fail (a && name && refs, false);

	char *ref;
	RListIter *iter;
	RSignItem *it = r_sign_item_new ();
	if (!it) {
		return false;
	}
	it->name = r_str_new (name);
	if (!it->name) {
		free (it);
		return false;
	}
	it->space = r_spaces_current (&a->zign_spaces);
	it->refs = r_list_newf ((RListFree) free);
	r_list_foreach (refs, iter, ref) {
		r_list_append (it->refs, strdup (ref));
	}
	bool retval = r_sign_add_item (a, it);
	r_sign_item_free (it);

	return retval;
}

R_API bool r_sign_add_xrefs(RAnal *a, const char *name, RList *xrefs) {
	r_return_val_if_fail (a && name && xrefs, false);

	RListIter *iter = NULL;
	char *ref = NULL;
	RSignItem *it = r_sign_item_new ();
	if (!it) {
		return false;
	}
	it->name = r_str_new (name);
	if (!it->name) {
		free (it);
		return false;
	}
	it->space = r_spaces_current (&a->zign_spaces);
	it->xrefs = r_list_newf ((RListFree) free);
	r_list_foreach (xrefs, iter, ref) {
		r_list_append (it->xrefs, strdup (ref));
	}
	bool retval = r_sign_add_item (a, it);
	r_sign_item_free (it);

	return retval;
}

struct ctxDeleteCB {
	RAnal *anal;
	char *key;
	size_t len;
};

static bool deleteBySpaceCB(void *user, const char *k, const char *v) {
	struct ctxDeleteCB *ctx = (struct ctxDeleteCB *) user;
	if (!strncmp (k, ctx->key, ctx->len)) {
		sdb_remove (ctx->anal->sdb_zigns, k, 0);
	}
	return true;
}

R_API bool r_sign_delete(RAnal *a, const char *name) {
	r_return_val_if_fail (a && name, false);
	bool retval = false;

	// Remove all zigns
	if (*name == '*') {
		if (!r_spaces_current (&a->zign_spaces)) {
			sdb_reset (a->sdb_zigns);
			return true;
		}
		struct ctxDeleteCB ctx = { .anal = a };
		ctx.key = space_serialize_key (r_spaces_current (&a->zign_spaces), "");
		if (ctx.key) {
			ctx.len = strlen (ctx.key);
			retval = sdb_foreach (a->sdb_zigns, deleteBySpaceCB, &ctx);
			free (ctx.key);
		}
	} else {
		// Remove specific zign
		char *key = space_serialize_key (r_spaces_current (&a->zign_spaces), name);
		if (key) {
			retval = sdb_remove (a->sdb_zigns, key, 0);
			free (key);
		}
	}
	return retval;
}

static ut8 * build_combined_bytes(RSignBytes *bsig) {
	r_return_val_if_fail (bsig && bsig->bytes && bsig->mask, NULL);
	ut8 *buf = (ut8 *)malloc (bsig->size);
	if (buf) {
		size_t i;
		for (i = 0; i < bsig->size; i++) {
			buf[i] = bsig->bytes[i] & bsig->mask[i];
		}
	}
	return buf;
}

static double cmp_bytesig_to_buff(RSignBytes *sig, ut8 *buf, int len) {
	r_return_val_if_fail (sig && buf && len >= 0, (double)-1.0);
	ut8 *sigbuf = build_combined_bytes (sig);
	double sim = -1.0;
	if (sigbuf) {
		r_diff_buffers_distance (NULL, sigbuf, sig->size, buf, len, NULL, &sim);
		free (sigbuf);
	}
	return sim;
}

static double matchBytes(RSignItem *a, RSignItem *b) {
	double result = 0.0;

	if (!a->bytes || !b->bytes) {
		return result;
	}

	size_t min_size = R_MIN ((size_t)a->bytes->size, (size_t)b->bytes->size);
	if (!min_size) {
		return result;
	}

	ut8 *combined_mask = NULL;
	if (a->bytes->mask || b->bytes->mask) {
		combined_mask = (ut8*)malloc (min_size);
		if (!combined_mask) {
			return result;
		}
		memcpy (combined_mask, a->bytes->mask, min_size);
		if (b->bytes->mask) {
			int i;
			for (i = 0; i != min_size; i++) {
				combined_mask[i] &= b->bytes->mask[i];
			}
		}
	}

	if ((combined_mask && !r_mem_cmp_mask (a->bytes->bytes, b->bytes->bytes, combined_mask, min_size)) ||
		(!combined_mask && !memcmp (a->bytes->bytes, b->bytes->bytes, min_size))) {
		result = (double)min_size / (double)R_MAX (a->bytes->size, b->bytes->size);
	}

	free (combined_mask);

	return result;
}

#define SIMILARITY(a, b) \
	((a) == (b)? 1.0: (R_MAX ((a), (b)) == 0.0? 0.0: (double)R_MIN ((a), (b)) / (double)R_MAX ((a), (b))))

static double matchGraph(RSignItem *a, RSignItem *b) {
	if (!a->graph || !b->graph) {
		return 0.0;
	}

	double total = 0.0;

	total += SIMILARITY (a->graph->cc, b->graph->cc);
	total += SIMILARITY (a->graph->nbbs, b->graph->nbbs);
	total += SIMILARITY (a->graph->ebbs, b->graph->ebbs);
	total += SIMILARITY (a->graph->edges, b->graph->edges);
	total += SIMILARITY (a->graph->bbsum, b->graph->bbsum);

	return total / 5.0;
}

static int score_cmpr(const void *a, const void *b) {
	double sa = ((RSignCloseMatch *)a)->score;
	double sb = ((RSignCloseMatch *)b)->score;

	if (sa < sb) {
		return 1;
	}
	if (sa > sb) {
		return -1;
	}
	return 0;
}

typedef struct {
	RSignItem *test;
	RList *output;
	size_t count;
	double score_threshold;
	ut8 *bytes_combined;

	// greatest lower bound. Thanks lattice theory for helping name variables
	double infimum;
} ClosestMatchData;

static bool closest_match_update(RSignItem *it, ClosestMatchData *data) {
	// quantify how close the signature matches
	int div = 0;
	double score = 0.0;
	double gscore = -1.0;
	if (it->graph && data->test->graph) {
		gscore = matchGraph (it, data->test);
		score += gscore;
		div++;
	}
	double bscore = -1.0;
	bool list_full = (r_list_length (data->output) == data->count);

	// value to beat to enter the list
	double pivot = data->score_threshold;
	if (list_full) {
		pivot = R_MAX (pivot, data->infimum);
	}

	if (it->bytes && data->bytes_combined) {
		int sizea = it->bytes->size;
		int sizeb = data->test->bytes->size;
		if (pivot > 0.0) {
			// bytes distance is slow. To avoid it, we can do quick maths to
			// see if the highest possible score would be good enough to change
			// results
			double maxscore = R_MIN (sizea, sizeb) / R_MAX (sizea, sizeb);
			if (div > 0) {
				maxscore = (maxscore + score) / div;
			}
			if (maxscore < pivot) {
				r_sign_item_free (it);
				return true;
			}
		}

		// get true byte score
		bscore = cmp_bytesig_to_buff (it->bytes, data->bytes_combined, sizeb);
		score += bscore;
		div++;
	}
	if (div == 0) {
		r_sign_item_free (it);
		return true;
	}
	score /= div;

	// score is too low, don't bother doing any more work
	if (score < pivot) {
		r_sign_item_free (it);
		return true;
	}

	// add new element
	RSignCloseMatch *row = R_NEW (RSignCloseMatch);
	if (!row) {
		r_sign_item_free (it);
		return false;
	}
	row->score = score;
	row->gscore = gscore;
	row->bscore = bscore;
	row->item = it;
	r_list_add_sorted (data->output, (void *)row, &score_cmpr);

	if (list_full) {
		// remove smallest element
		r_sign_close_match_free (r_list_pop (data->output));

		// get new infimum
		row = r_list_get_top (data->output);
		data->infimum = row->score;
	}
	return true;
}

R_API void r_sign_close_match_free(RSignCloseMatch *match) {
	if (match) {
		r_sign_item_free (match->item);
		free (match);
	}
}

static int _closest_match_cb(RSignItem *it, void *user) {
	return closest_match_update (it, (ClosestMatchData *)user)? 1: 0;
}

R_API RList *r_sign_find_closest_fcn(RAnal *a, RSignItem *it, int count, double score_threshold) {
	r_return_val_if_fail (a && it && count > 0 && score_threshold >= 0 && score_threshold <= 1, NULL);
	r_return_val_if_fail (it->bytes || it->graph, NULL);

	RList *output = r_list_newf ((RListFree)r_sign_close_match_free);
	if (!output) {
		return NULL;
	}

	ClosestMatchData data;
	data.output = output;
	data.count = count;
	data.score_threshold = score_threshold;
	data.infimum = 0.0;
	data.test = it;
	if (it->bytes) {
		data.bytes_combined = build_combined_bytes (it->bytes);
	} else {
		data.bytes_combined = NULL;
	}

	RAnalFunction *fcn;
	RListIter *iter;
	r_list_foreach (a->fcns, iter, fcn) {
		// turn function into signature item
		RSignItem *fsig = r_sign_item_new ();
		if (!fsig) {
			r_list_free (output);
			return NULL;
		}
		if (data.bytes_combined) {
			r_sign_addto_item (a, fsig, fcn, R_SIGN_BYTES);
		}
		if (it->graph) {
			r_sign_addto_item (a, fsig, fcn, R_SIGN_GRAPH);
		}
		r_sign_addto_item (a, fsig, fcn, R_SIGN_OFFSET);
		fsig->name = r_str_new (fcn->name);

		// maybe add signature item to output list
		closest_match_update (fsig, &data);
	}
	free (data.bytes_combined);
	return output;
}

R_API bool r_sign_diff(RAnal *a, RSignOptions *options, const char *other_space_name) {
	r_return_val_if_fail (a && other_space_name, false);

	RSpace *current_space = r_spaces_current (&a->zign_spaces);
	if (!current_space) {
		return false;
	}
	RSpace *other_space = r_spaces_get (&a->zign_spaces, other_space_name);
	if (!other_space) {
		return false;
	}

	RList *la = deserialize_sign_space (a, current_space);
	if (!la) {
		return false;
	}
	RList *lb = deserialize_sign_space (a, other_space);
	if (!lb) {
		r_list_free (la);
		return false;
	}

	eprintf ("Diff %d %d\n", (int)ls_length (la), (int)ls_length (lb));

	RListIter *itr;
	RListIter *itr2;
	RSignItem *si;
	RSignItem *si2;

	// do the sign diff here
	r_list_foreach (la, itr, si) {
		if (strstr (si->name, "imp.")) {
			continue;
		}
		r_list_foreach (lb, itr2, si2) {
			if (strstr (si2->name, "imp.")) {
				continue;
			}
			double bytesScore = matchBytes (si, si2);
			double graphScore = matchGraph (si, si2);
			bool bytesMatch = bytesScore >= (options ? options->bytes_diff_threshold : SIGN_DIFF_MATCH_BYTES_THRESHOLD);
			bool graphMatch = graphScore >= (options ? options->graph_diff_threshold : SIGN_DIFF_MATCH_GRAPH_THRESHOLD);

			if (bytesMatch) {
				a->cb_printf ("0x%08" PFMT64x " 0x%08"PFMT64x " %02.5lf B %s\n", si->addr, si2->addr, bytesScore, si->name);
			}

			if (graphMatch) {
				a->cb_printf ("0x%08" PFMT64x " 0x%08"PFMT64x" %02.5lf G %s\n", si->addr, si2->addr, graphScore, si->name);
			}
		}
	}

	r_list_free (la);
	r_list_free (lb);
	return true;
}

R_API bool r_sign_diff_by_name(RAnal *a, RSignOptions *options, const char *other_space_name, bool not_matching) {
	r_return_val_if_fail (a && other_space_name, false);

	RSpace *current_space = r_spaces_current (&a->zign_spaces);
	if (!current_space) {
		return false;
	}
	RSpace *other_space = r_spaces_get (&a->zign_spaces, other_space_name);
	if (!other_space) {
		return false;
	}

	RList *la = deserialize_sign_space (a, current_space);
	if (!la) {
		return false;
	}
	RList *lb = deserialize_sign_space (a, other_space);
	if (!lb) {
		return false;
	}

	eprintf ("Diff by name %d %d (%s)\n", (int)ls_length (la), (int)ls_length (lb), not_matching? "not matching" : "matching");

	RListIter *itr;
	RListIter *itr2;
	RSignItem *si;
	RSignItem *si2;
	size_t current_space_name_len = strlen (current_space->name);
	size_t other_space_name_len = strlen (other_space->name);

	r_list_foreach (la, itr, si) {
		if (strstr (si->name, "imp.")) {
			continue;
		}
		r_list_foreach (lb, itr2, si2) {
			if (strcmp (si->name + current_space_name_len + 1, si2->name + other_space_name_len + 1)) {
				continue;
			}
			// TODO: add config variable for threshold
			double bytesScore = matchBytes (si, si2);
			double graphScore = matchGraph (si, si2);
			bool bytesMatch = bytesScore >= (options ? options->bytes_diff_threshold : SIGN_DIFF_MATCH_BYTES_THRESHOLD);
			bool graphMatch = graphScore >= (options ? options->graph_diff_threshold : SIGN_DIFF_MATCH_GRAPH_THRESHOLD);
			if ((bytesMatch && !not_matching) || (!bytesMatch && not_matching)) {
				a->cb_printf ("0x%08"PFMT64x" 0x%08"PFMT64x" %02.5f B %s\n", si->addr, si2->addr, bytesScore, si->name);
			}
			if ((graphMatch && !not_matching) || (!graphMatch && not_matching)) {
				a->cb_printf ("0x%08"PFMT64x" 0x%08"PFMT64x" %02.5f G %s\n", si->addr, si2->addr, graphScore, si->name);
			}
		}
	}

	r_list_free (la);
	r_list_free (lb);

	return true;
}

struct ctxListCB {
	RAnal *anal;
	int idx;
	int format;
	PJ *pj;
};

static void listBytes(RAnal *a, RSignItem *it, PJ *pj, int format) {
	RSignBytes *bytes = it->bytes;

	if (!bytes->bytes) {
		return;
	}

	int masked = 0, i = 0;
	for (i = 0; i < bytes->size; i++) {
		masked += bytes->mask[i] == 0xff;
	}

	char * strbytes = r_hex_bin2strdup (bytes->bytes, bytes->size);
	if (!strbytes) {
		return;
	}
	char * strmask = r_hex_bin2strdup (bytes->mask, bytes->size);
	if (!strmask) {
		free (strbytes);
		return;
	}

	if (format == '*') {
		if (masked == bytes->size) {
			a->cb_printf ("za %s b %s\n", it->name, strbytes);
		} else {
			a->cb_printf ("za %s b %s:%s\n", it->name, strbytes, strmask);
		}
	} else if (format == 'q') {
		a->cb_printf (" b(%d/%d)", masked, bytes->size);
	} else if (format == 'j') {
		pj_ks (pj, "bytes", strbytes);
		pj_ks (pj, "mask", strmask);
	} else {
		a->cb_printf ("  bytes: %s\n", strbytes);
		a->cb_printf ("  mask: %s\n", strmask);
	}

	free (strbytes);
	free (strmask);
}

static void listGraph(RAnal *a, RSignItem *it, PJ *pj, int format) {
	RSignGraph *graph = it->graph;

	if (format == 'q') {
		a->cb_printf (" g(cc=%d,nb=%d,e=%d,eb=%d,h=%d)",
			graph->cc, graph->nbbs, graph->edges, graph->ebbs, graph->bbsum);
	} else if (format == '*') {
		a->cb_printf ("za %s g cc=%d nbbs=%d edges=%d ebbs=%d bbsum=%d\n",
			it->name, graph->cc, graph->nbbs, graph->edges, graph->ebbs, graph->bbsum);
	} else if (format == 'j') {
		pj_ko (pj, "graph");
		pj_kN (pj, "cc", graph->cc);
		pj_kN (pj, "nbbs", graph->nbbs);
		pj_kN (pj, "edges", graph->edges);
		pj_kN (pj, "ebbs", graph->ebbs);
		pj_kN (pj, "bbsum", graph->bbsum);
		pj_end (pj);
	} else {
		a->cb_printf ("  graph: cc=%d nbbs=%d edges=%d ebbs=%d bbsum=%d\n",
			graph->cc, graph->nbbs, graph->edges, graph->ebbs, graph->bbsum);
	}
}

static void listComment(RAnal *a, RSignItem *it, PJ *pj, int format) {
	if (it->comment) {
		if (format == 'q') {
			//	a->cb_printf (" addr(0x%08"PFMT64x")", it->addr);
			a->cb_printf ("\n ; %s\n", it->comment);
		} else if (format == '*') {
			a->cb_printf ("%s\n", it->comment); // comment injection via CCu..
		} else if (format == 'j') {
			pj_ks (pj, "comments", it->comment);
		} else {
			a->cb_printf ("  comment: 0x%08" PFMT64x "\n", it->addr);
		}
	}
}

static void listRealname(RAnal *a, RSignItem *it, PJ *pj, int format) {
	if (it->realname) {
		if (format == 'q') {
			//	a->cb_printf (" addr(0x%08"PFMT64x")", it->addr);
		} else if (format == '*') {
			a->cb_printf ("za %s n %s\n", it->name, it->realname);
			a->cb_printf ("afn %s @ 0x%08"PFMT64x"\n", it->realname, it->addr);
		} else if (format == 'j') {
			pj_ks (pj, "realname", it->realname);
		} else {
			a->cb_printf ("  realname: %s\n", it->realname);
		}
	}
}

static void listOffset(RAnal *a, RSignItem *it, PJ *pj, int format) {
	if (format == 'q') {
		//	a->cb_printf (" addr(0x%08"PFMT64x")", it->addr);
	} else if (format == '*') {
		a->cb_printf ("za %s o 0x%08"PFMT64x"\n", it->name, it->addr);
	} else if (format == 'j') {
		pj_kN (pj, "addr", it->addr);
	} else {
		a->cb_printf ("  addr: 0x%08"PFMT64x"\n", it->addr);
	}
}

static void print_function_args_json(PJ *pj, char *arg_type) {
	char *arg_name = strchr (arg_type, ',');

	if (arg_name == NULL) {
		return;
	}

	*arg_name = '\0';
	++arg_name;

	size_t len_arg_name = strlen (arg_name);
	arg_name[len_arg_name - 1] = '\0';

	pj_o (pj);
	pj_ks (pj, "name", arg_name);
	pj_ks (pj, "type", arg_type + 1);
	pj_end (pj);
}

static void list_types_json(RSignItem *it, PJ *pj) {
	pj_ka (pj, "types");

	int i = 0;
	char *element = NULL;
	RListIter *iter = NULL;
	r_list_foreach (it->types, iter, element) {
		char *t = strdup (element);
		char *sep = NULL;
		if (i > 0 && (sep = strchr (t, '='))) {
			*sep = '\0';
			++sep;
			print_function_args_json (pj, sep);
		}
		free (t);
		i++;
	}
	pj_end (pj);
}

static void list_sign_list(RAnal *a, RList *l, PJ *pj, int fmt, int type, const char *name) {
	const char *tname = r_sign_type_to_name (type);
	switch (fmt) {
	case '*':
		a->cb_printf ("za %s %c ", name, type);
		break;
	case 'q':
		a->cb_printf (" %s(%d)", tname, r_list_length (l));
		return;
	case 'j':
		pj_ka (pj, tname);
		break;
	default:
		if (l && !r_list_empty (l)) {
			a->cb_printf ("  %s: ", tname);
		}
	}

	int i = 0;
	char *ref = NULL;
	RListIter *iter = NULL;
	r_list_foreach (l, iter, ref) {
		if (i > 0) {
			if (fmt == '*') {
				a->cb_printf (" ");
			} else if (fmt != 'j') {
				a->cb_printf (", ");
			}
		}
		if (fmt == 'j') {
			pj_s (pj, ref);
		} else {
			a->cb_printf ("%s", ref);
		}
		i++;
	}

	if (fmt == 'j') {
		pj_end (pj);
	} else {
		a->cb_printf ("\n");
	}
}

static void listHash(RAnal *a, RSignItem *it, PJ *pj, int format) {
	if (!it->hash) {
		return;
	}
	switch (format) {
	case 'q':
		if (it->hash->bbhash) {
			a->cb_printf (" h(%08x)", r_str_hash (it->hash->bbhash));
		}
		break;
	case '*':
		if (it->hash->bbhash) {
			a->cb_printf ("za %s h %s\n", it->name, it->hash->bbhash);
		}
		break;
	case 'j':
		pj_ko (pj, "hash");
		if (it->hash->bbhash) {
			pj_ks (pj, "bbhash", it->hash->bbhash);
		}
		pj_end (pj);
		break;
	default:
		if (it->hash->bbhash) {
			a->cb_printf ("  bbhash: %s\n", it->hash->bbhash);
		}
		break;
	}
}

static int listCB(RSignItem *it, void *user) {
	struct ctxListCB *ctx = (struct ctxListCB *)user;
	RAnal *a = ctx->anal;

	// Start item
	if (ctx->format == 'j') {
		pj_o (ctx->pj);
	}

	// Zignspace and name (except for radare format)
	if (ctx->format == '*') {
		if (it->space) {
			a->cb_printf ("zs %s\n", it->space->name);
		} else {
			a->cb_printf ("zs *\n");
		}
	} else if (ctx->format == 'q') {
		a->cb_printf ("0x%08" PFMT64x " ", it->addr);
		const char *pad = r_str_pad (' ', 30 - strlen (it->name));
		a->cb_printf ("%s:%s", it->name, pad);
	} else if (ctx->format == 'j') {
		if (it->space) {
			pj_ks (ctx->pj, "zignspace", it->space->name);
		}
		pj_ks (ctx->pj, "name", it->name);
	} else {
		if (!r_spaces_current (&a->zign_spaces) && it->space) {
			a->cb_printf ("(%s) ", it->space->name);
		}
		a->cb_printf ("%s:\n", it->name);
	}

	// TODO: listCollisions, listXRefs, listRefs... all just dump RList's of
	// strings, replace them with something more abstract

	// Bytes pattern
	if (it->bytes) {
		listBytes (a, it, ctx->pj, ctx->format);
	} else if (ctx->format == 'j') {
		pj_ks (ctx->pj, "bytes", "");
	}
	// Graph metrics
	if (it->graph) {
		listGraph (a, it, ctx->pj, ctx->format);
	} else if (ctx->format == 'j') {
		pj_ko (ctx->pj, "graph");
		pj_end (ctx->pj);
	}
	// Offset
	if (it->addr != UT64_MAX) {
		listOffset (a, it, ctx->pj, ctx->format);
	} else if (ctx->format == 'j') {
		pj_kN (ctx->pj, "addr", -1);
	}
	// Name
	if (it->realname) {
		listRealname (a, it, ctx->pj, ctx->format);
	}
	// Comments
	if (it->comment) {
		listComment (a, it, ctx->pj, ctx->format);
	}
	// References
	if (it->refs) {
		list_sign_list (a, it->refs, ctx->pj, ctx->format, R_SIGN_REFS, it->name);
	} else if (ctx->format == 'j') {
		pj_ka (ctx->pj, "refs");
		pj_end (ctx->pj);
	}
	// XReferences
	if (it->xrefs) {
		list_sign_list (a, it->xrefs, ctx->pj, ctx->format, R_SIGN_XREFS, it->name);
	} else if (ctx->format == 'j') {
		pj_ka (ctx->pj, "xrefs");
		pj_end (ctx->pj);
	}
	// Vars
	if (it->vars) {
		list_sign_list (a, it->vars, ctx->pj, ctx->format, R_SIGN_VARS, it->name);
	} else if (ctx->format == 'j') {
		pj_ka (ctx->pj, "vars");
		pj_end (ctx->pj);
	}
	// Types
	if (it->types) {
		if (ctx->format == 'j') {
			list_types_json (it, ctx->pj);
		} else {
			list_sign_list (a, it->types, ctx->pj, ctx->format, R_SIGN_TYPES, it->name);
		}
	} else if (ctx->format == 'j') {
		pj_ka (ctx->pj, "types");
		pj_end (ctx->pj);
	}

	// Collisions
	if (it->collisions) {
		list_sign_list (a, it->collisions, ctx->pj, ctx->format, R_SIGN_COLLISIONS, it->name);
	} else if (ctx->format == 'j') {
		pj_ka (ctx->pj, "collisions");
		pj_end (ctx->pj);
	}

	// Hash
	if (it->hash) {
		listHash (a, it, ctx->pj, ctx->format);
	} else if (ctx->format == 'j') {
		pj_ko (ctx->pj, "hash");
		pj_end (ctx->pj);
	}

	// End item
	if (ctx->format == 'j') {
		pj_end (ctx->pj);
	}
	if (ctx->format == 'q') {
		a->cb_printf ("\n");
	}

	ctx->idx++;
	return true;
}

R_API void r_sign_list(RAnal *a, int format) {
	r_return_if_fail (a);
	PJ *pj = NULL;

	if (format == 'j') {
		pj = a->coreb.pjWithEncoding (a->coreb.core);
		pj_a (pj);
	}

	struct ctxListCB ctx = { a, 0, format, pj };
	r_sign_foreach (a, listCB, &ctx);

	if (format == 'j') {
		pj_end (pj);
		a->cb_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
}

static int listGetCB(RSignItem *it, void *user) {
	r_list_append ((RList *)user, it);
	return 1;
}

R_API const char *r_sign_type_to_name(int type) {
	switch (type) {
	case R_SIGN_BYTES:
		return "bytes";
	case R_SIGN_BYTES_MASK:
		return "mask";
	case R_SIGN_BYTES_SIZE:
		return "size";
	case R_SIGN_COMMENT:
		return "comment";
	case R_SIGN_GRAPH:
		return "graph";
	case R_SIGN_OFFSET:
		return "addr";
	case R_SIGN_NAME:
		return "name";
	case R_SIGN_REFS:
		return "refs";
	case R_SIGN_XREFS:
		return "xrefs";
	case R_SIGN_VARS:
		return "vars";
	case R_SIGN_TYPES:
		return "types";
	case R_SIGN_COLLISIONS:
		return "collisions";
	case R_SIGN_BBHASH:
		return "bbhash";
	default:
		r_warn_if_reached ();
		return "UnkownType";
	}
}

static int cmpaddr(const void *_a, const void *_b) {
	const RAnalBlock *a = _a, *b = _b;
	return (a->addr - b->addr);
}

R_API char *r_sign_calc_bbhash(RAnal *a, RAnalFunction *fcn) {
	RListIter *iter = NULL;
	RAnalBlock *bbi = NULL;
	char *digest_hex = NULL;
	RHash *ctx = r_hash_new (true, R_ZIGN_HASH);
	if (!ctx) {
		goto beach;
	}
	r_list_sort (fcn->bbs, &cmpaddr);
	r_hash_do_begin (ctx, R_ZIGN_HASH);
	r_list_foreach (fcn->bbs, iter, bbi) {
		ut8 *buf = malloc (bbi->size);
		if (!buf) {
			goto beach;
		}
		if (!a->iob.read_at (a->iob.io, bbi->addr, buf, bbi->size)) {
			goto beach;
		}
		if (!r_hash_do_sha256 (ctx, buf, bbi->size)) {
			goto beach;
		}
		free (buf);
	}
	r_hash_do_end (ctx, R_ZIGN_HASH);

	digest_hex = r_hex_bin2strdup (ctx->digest, r_hash_size (R_ZIGN_HASH));
beach:
	free (ctx);
	return digest_hex;
}

static int countForCB(RSignItem *it, void *user) {
	(*(int *)user)++;
	return 1;
}

static int unsetForCB(RSignItem *it, void *user) {
	Sdb *db = (Sdb *)user;
	char *key = item_serialize_key (it);
	if (key) {
		sdb_remove (db, key, 0);
		free (key);
	}
	it->space = NULL;
	r_sign_set_item (db, it, NULL);
	return true;
}

struct ctxRenameForCB {
	RAnal *anal;
	char *oprefix; // old prefix
	const char *newname;
	size_t oldlen;
};

static bool renameForCB(void *user, const char *k, const char *v) {
	struct ctxRenameForCB *ctx = (struct ctxRenameForCB *) user;
	Sdb *db = ctx->anal->sdb_zigns;
	if (!strncmp (k, ctx->oprefix, ctx->oldlen)) {
		char *nk = str_serialize_key (ctx->newname, k + ctx->oldlen);
		char *nv = strdup (v);
		if (nk && nv) {
			// must remove before set, must alloc new nk and nv before hand
			sdb_remove (db, k, 0);
			sdb_set (db, nk, nv, 0);
		}
		free (nv);
		free (nk);
	}
	return true;
}

R_API void r_sign_space_rename_for(RAnal *a, const RSpace *space, const char *oname, const char *nname) {
	r_return_if_fail (a && space && oname && nname);
	struct ctxRenameForCB ctx = { .anal = a, .newname = nname };
	ctx.oprefix = str_serialize_key (oname, "");
	if (ctx.oprefix) {
		ctx.oldlen = strlen (ctx.oprefix);
		sdb_foreach (a->sdb_zigns, renameForCB, &ctx);
	}
	free (ctx.oprefix);
}

struct ctxForeachCB {
	RAnal *anal;
	RSignForeachCallback cb;
	const RSpace *space;
	bool freeit;
	void *user;
};

static bool foreachCB(void *user, const char *k, const char *v) {
	struct ctxForeachCB *ctx = (struct ctxForeachCB *) user;
	r_return_val_if_fail (ctx && ctx->cb, false);
	RSignItem *it = r_sign_item_new ();
	RAnal *a = ctx->anal;

	if (it && r_sign_deserialize (a, it, k, v)) {
		if (!ctx->space || ctx->space == it->space) {
			ctx->cb (it, ctx->user);
		}
	} else {
		eprintf ("error: cannot deserialize zign\n");
	}
	if (ctx->freeit) {
		r_sign_item_free (it);
	}
	return true;
}

static inline bool local_foreach_item(RAnal *a, RSignForeachCallback cb, const RSpace *sp, bool freeit, void *user) {
	r_return_val_if_fail (a && cb, false);
	struct ctxForeachCB ctx = { a, cb, sp, freeit, user };
	return sdb_foreach (a->sdb_zigns, foreachCB, &ctx);
}

static bool r_sign_foreach_nofree(RAnal *a, RSignForeachCallback cb, void *user) {
	return local_foreach_item (a, cb, r_spaces_current (&a->zign_spaces), false, user);
}

R_API int r_sign_space_count_for(RAnal *a, const RSpace *space) {
	int count = 0;
	local_foreach_item (a, countForCB, space, true, &count);
	return count;
}

R_API void r_sign_space_unset_for(RAnal *a, const RSpace *space) {
	local_foreach_item (a, unsetForCB, space, true, a->sdb_zigns);
}

R_API bool r_sign_foreach(RAnal *a, RSignForeachCallback cb, void *user) {
	return local_foreach_item (a, cb, r_spaces_current (&a->zign_spaces), true, user);
}

R_API RList *r_sign_get_list(RAnal *a) {
	r_return_val_if_fail (a, NULL);
	RList *l = r_list_newf ((RListFree)r_sign_item_free);
	if (l) {
		local_foreach_item (a, listGetCB, NULL, false, (void *)l);
	}
	return l;
}

R_API RSignSearch *r_sign_search_new(void) {
	RSignSearch *ret = R_NEW0 (RSignSearch);
	if (ret) {
		ret->search = r_search_new (R_SEARCH_KEYWORD);
		ret->items = r_list_newf ((RListFree) r_sign_item_free);
	}
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

R_API RList *r_sign_find_closest_sig(RAnal *a, RSignItem *it, int count, double score_threshold) {
	r_return_val_if_fail (a && it && count > 0 && score_threshold >= 0 && score_threshold <= 1, NULL);

	// need at least one acceptable signature type
	r_return_val_if_fail (it->bytes || it->graph, NULL);

	ClosestMatchData data;
	RList *output = r_list_newf ((RListFree)r_sign_close_match_free);
	if (!output) {
		return NULL;
	}

	data.output = output;
	data.count = count;
	data.score_threshold = score_threshold;
	data.infimum = 0.0;
	data.test = it;
	if (it->bytes) {
		data.bytes_combined = build_combined_bytes (it->bytes);
	} else {
		data.bytes_combined = NULL;
	}

	if (!r_sign_foreach_nofree (a, _closest_match_cb, &data)) {
		r_list_free (output);
		output = NULL;
	}

	free (data.bytes_combined);
	return output;
}

static int searchHitCB(RSearchKeyword *kw, void *user, ut64 addr) {
	RSignSearch *ss = (RSignSearch *) user;
	return ss->cb? ss->cb ((RSignItem *) kw->data, kw, addr, ss->user): 1;
}

struct ctxAddSearchKwCB {
	RSignSearch *ss;
	int minsz;
};

static int addSearchKwCB(RSignItem *it, void *user) {
	struct ctxAddSearchKwCB *ctx = (struct ctxAddSearchKwCB *) user;
	RSignSearch *ss = ctx->ss;
	RSignBytes *bytes = it->bytes;

	if (!bytes) {
		eprintf ("Cannot find bytes for this signature: %s\n", it->name);
		r_sign_item_free (it);
		return 1;
	}

	if (ctx->minsz && bytes->size < ctx->minsz) {
		r_sign_item_free (it);
		return 1;
	}
	r_list_append (ss->items, it);
	// TODO(nibble): change arg data in r_search_keyword_new to void*
	RSearchKeyword *kw = r_search_keyword_new (bytes->bytes, bytes->size, bytes->mask, bytes->size, (const char *)it);
	r_search_kw_add (ss->search, kw);
	return 1;
}

R_API void r_sign_search_init(RAnal *a, RSignSearch *ss, int minsz, RSignSearchCallback cb, void *user) {
	struct ctxAddSearchKwCB ctx = { ss, minsz };
	r_return_if_fail (a && ss && cb);
	ss->cb = cb;
	ss->user = user;
	r_list_purge (ss->items);
	r_search_reset (ss->search, R_SEARCH_KEYWORD);
	r_sign_foreach_nofree (a, addSearchKwCB, &ctx);
	r_search_begin (ss->search);
	r_search_set_callback (ss->search, searchHitCB, ss);
}

R_API int r_sign_search_update(RAnal *a, RSignSearch *ss, ut64 *at, const ut8 *buf, int len) {
	r_return_val_if_fail (a && ss && buf && len > 0, 0);
	return r_search_update (ss->search, *at, buf, len);
}

// allow ~10% of margin error
static int matchCount(int a, int b) {
	int m = R_MAX (a, b);
	if (m > 100) {
		return R_ABS (a - b) < m / 10;
	}
	return a == b;
}

static int sig_graph_diff(RSignItem *ia, RSignItem *ib) {
	RSignGraph *a = ia->graph;
	RSignGraph *b = ib->graph;
	if (!a || !b) {
		return 1;
	}
	if (a->cc != -1 && a->cc != b->cc) {
		return 1;
	}
	if (a->nbbs != -1 && a->nbbs != b->nbbs) {
		return 1;
	}
	if (a->edges != -1 && a->edges != b->edges) {
		return 1;
	}
	if (a->ebbs != -1 && a->ebbs != b->ebbs) {
		return 1;
	}
	if (a->bbsum > 0 && !matchCount (a->bbsum, b->bbsum)) {
		return 1;
	}
	return 0;
}

#define SORT_EMPY_LAST(x, y) \
	if (!x) { \
		return !y? 1: 0; \
	} \
	if (!y) { \
		return -1; \
	}

static int sig_graph_cmp(RSignItem *ia, RSignItem *ib) {
	RSignGraph *a = ia->graph;
	RSignGraph *b = ib->graph;

	SORT_EMPY_LAST (a, b);

	int diff = a->bbsum - b->bbsum;
	if (diff) {
		return diff;
	}

	diff = a->cc - b->cc;
	if (diff) {
		return diff;
	}

	diff = a->nbbs - b->nbbs;
	if (diff) {
		return diff;
	}

	diff = a->edges - b->edges;
	if (diff) {
		return diff;
	}

	diff = a->ebbs - b->ebbs;
	if (diff) {
		return diff;
	}
	return 0;
}

// this is to compare a byte signature to a function, that math is slightly
// different
static int sig_bytes_diff(RSignItem *isig, RSignItem *ifunc) {
	RSignBytes *sig = isig->bytes;
	RSignBytes *func = ifunc->bytes;
	r_return_val_if_fail (sig && func, 1);

	if (sig->size != func->size) {
		return 1;
	}
	int i;
	for (i = 0; i < sig->size; i++) {
		char m = sig->mask[i];
		if (m && (sig->bytes[i] & m) != (func->bytes[i] & m)) {
			return 1;
		}
	}
	return 0;
}

static int sig_bytes_cmp(RSignItem *ia, RSignItem *ib) {
	RSignBytes *a = ia->bytes;
	RSignBytes *b = ib->bytes;
	SORT_EMPY_LAST (a, b);
	int i = a->size - b->size;
	if (i) {
		return i;
	}
	for (i = 0; i < a->size; i++) {
		int cmp = a->bytes[i] & a->mask[i];
		cmp -= b->bytes[i] & b->mask[i];
		if (cmp) {
			return cmp;
		}
	}
	return 0;
}

static int sig_addr_cmp(ut64 a, ut64 b) {
	if (a < b) {
		return 1;
	}
	return a > b? -1: 0;
}

static int sig_hash_cmp(RSignHash *a, RSignHash *b) {
	if (!a) {
		return b? -1: 0;
	}
	if (!b) {
		return 1;
	}
	return strcmp (a->bbhash, b->bbhash);
}

static int str_list_cmp(RList *la, RList *lb) {
	if (!la) {
		return lb? -1: 0;
	}
	if (!lb) {
		return 1;
	}

	int len = r_list_length (la);
	int dif = len - r_list_length (lb);
	if (dif) {
		return dif;
	}

	size_t i;
	for (i = 0; i < len; i++) {
		const char *a = r_list_get_n (la, i);
		const char *b = r_list_get_n (lb, i);
		if ((dif = strcmp (a, b))) {
			return dif;
		}
	}
	return 0;
}

static bool type_in_array(RSignType *arr, RSignType needle) {
	while (*arr != R_SIGN_END) {
		if (*arr == needle) {
			return true;
		}
		arr++;
	}
	return false;
}

static RListIter *collision_skip_unused(RListIter *iter, RSignType *used) {
	char *n = (char *)r_list_iter_get_data (iter);
	if (!n) {
		return r_list_iter_get_next (iter);
	}
	RSignType skip = n[0];
	if (type_in_array (used, skip)) {
		return iter;
	}
	RListIter *next;
	while ((next = r_list_iter_get_next (iter))) {
		n = r_list_iter_get_data (next);
		if (n) {
			RSignType t = n[0];
			if (skip != t) {
				if (type_in_array (used, t)) {
					return iter;
				}
			}
		}
		iter = next;
	}
	return iter;
}

// return NULL one error, otherwise return a, possibly empty, list of
// collisions. Relies on sets being ordered in groups of types
static RList *check_collisions(RList *collisions, RSignType *types) {
	if (!collisions || types[0] == R_SIGN_END) {
		return r_list_new ();
	}

	RListIter *iter = r_list_iterator (collisions);
	if (!iter) {
		return NULL;
	}

	// skip over types that were not matched against
	if (!(iter = collision_skip_unused (iter, types))) {
		return r_list_new ();
	}

	char *col = (char *)r_list_iter_get_data (iter);
	if (!col || col[1] != ':') {
		return NULL;
	}

	RList *set = r_list_new ();
	if (!set) {
		return NULL;
	}
	RList *holder = NULL;

	// add the names from first matched type to return set
	RSignType thistype = col[0];
	while (iter) {
		r_list_append (set, col + 2);
		if ((iter = r_list_iter_get_next (iter))) {
			col = (char *)r_list_iter_get_data (iter);
			if (!col || col[1] != ':') {
				goto collerr;
			}
			RSignType t = col[1];
			if (t != thistype) {
				break;
			}
		}
	}

	holder = r_list_new ();
	if (!holder) {
		goto collerr;
	}

	// now we interset return set with next relevent type and repeat
	while (iter && (iter = collision_skip_unused (iter, types))) { // loop over new type group
		col = (char *)r_list_iter_get_data (iter);
		if (!col || col[1] != ':') {
			goto collerr;
		}

		// interset current type
		RSignType t = col[0];
		RSignType nexttype = t;
		while (t == nexttype) {
			char *name = col + 2;
			if (r_list_find (set, name, list_str_cmp)) {
				r_list_append (holder, col + 2);
			}
			nexttype = R_SIGN_END;
			if ((iter = r_list_iter_get_next (iter))) {
				col = (char *)r_list_iter_get_data (iter);
				if (!col || col[1] != ':') {
					goto collerr;
				}
				nexttype = col[1];
			}
		}
		r_list_purge (set);
		RList *tmplist = set;
		set = holder;
		holder = tmplist;
	}

	r_list_free (holder);
	return set;

collerr:
	r_list_free (set);
	r_list_free (holder);
	return NULL;
}

struct metric_ctx {
	int matched;
	RSignItem *it;
	RSignSearchMetrics *sm;
};

static int match_metrics(RSignItem *it, void *user) {
	struct metric_ctx *ctx = (struct metric_ctx *)user;
	RSignSearchMetrics *sm = ctx->sm;
	RSignItem *fit = ctx->it;
	RSignType types[7];
	int count = 0;

	if (it->bytes && it->bytes->size >= sm->minsz && !sig_bytes_diff (it, fit)) {
		types[count++] = R_SIGN_BYTES;
	}
	if (it->graph && it->graph->cc >= sm->mincc && !sig_graph_diff (it, fit)) {
		types[count++] = R_SIGN_GRAPH;
	}
	if (fit->addr != UT64_MAX && !sig_addr_cmp (it->addr, fit->addr)) {
		types[count++] = R_SIGN_OFFSET;
	}
	if (fit->hash && !sig_hash_cmp (it->hash, fit->hash)) {
		types[count++] = R_SIGN_BBHASH;
	}
	if (fit->refs && !str_list_cmp (it->refs, fit->refs)) {
		types[count++] = R_SIGN_REFS;
	}
	if (fit->vars && !str_list_cmp (it->vars, fit->vars)) {
		types[count++] = R_SIGN_VARS;
	}
	if (fit->types && !str_list_cmp (it->types, fit->types)) {
		types[count++] = R_SIGN_TYPES;
	}

	if (count) {
		RList *col = check_collisions (it->collisions, types);
		ctx->matched += count;
		types[count] = R_SIGN_END;
		sm->cb (it, sm->fcn, types, sm->user, col);
		r_list_free (col);
		return 1;
	}
	return 0;
}

static int _sig_to_vec_cb(RSignItem *it, void *user) {
	if (it->collisions) {
		r_list_free (it->collisions);
		it->collisions = NULL;
	}
	return r_pvector_push ((RPVector *)user, it)? 1: 0;
}

static bool item_addto_collisions(RSignItem *it, const char *add) {
	r_return_val_if_fail (it, false);
	if (!it->collisions) {
		it->collisions = r_list_newf (free);
		if (!it->collisions) {
			return false;
		}
	}
	RList *l = it->collisions;
	if (r_list_find (l, (void *)add, list_str_cmp)) {
		return true;
	}
	char *dup = strdup (add);
	if (!dup) {
		return false;
	}
	return r_list_append (l, dup)? true: false;
}

static bool update_collide(RPVector *sigs, int start, int end, int type) {
	r_return_val_if_fail (start >= 0 && end > 0 && sigs, false);
	int i, ii;
	for (i = start; i <= end; i++) {
		RSignItem *it = (RSignItem *)r_pvector_at (sigs, i);
		if (!it) {
			return false;
		}
		char *fmt = r_str_newf ("%c:%s", type, it->name);
		if (!fmt) {
			return false;
		}
		for (ii = start; ii <= end; ii++) {
			if (i != ii) {
				RSignItem *itt = (RSignItem *)r_pvector_at (sigs, ii);
				if (!item_addto_collisions (itt, fmt)) {
					free (fmt);
					return false;
				}
			}
		}
		free (fmt);
	}
	return true;
}

static bool item_has_type(RSignItem *it, RSignType t) {
	switch (t) {
	case R_SIGN_BYTES:
	case R_SIGN_BYTES_MASK:
	case R_SIGN_BYTES_SIZE:
		return it->bytes? true: false;
	case R_SIGN_COMMENT:
		return it->comment? true: false;
	case R_SIGN_GRAPH:
		return it->graph? true: false;
	case R_SIGN_OFFSET:
		return it->addr != UT64_MAX? true: false;
	case R_SIGN_NAME:
		return it->realname? true: false;
	case R_SIGN_REFS:
		return it->refs? true: false;
	case R_SIGN_XREFS:
		return it->xrefs? true: false;
	case R_SIGN_VARS:
		return it->vars? true: false;
	case R_SIGN_TYPES:
		return it->types? true: false;
	case R_SIGN_COLLISIONS:
		return it->collisions? true: false;
	case R_SIGN_BBHASH:
		return (it->hash && it->hash->bbhash)? true: false;
	default:
		return false;
	}
}

typedef int (*RSignSorter) (RSignItem *, RSignItem *);
RSignSorter type_to_cmp(int type, bool exact) {
	switch (type) {
	case R_SIGN_GRAPH:
		if (exact) {
			return sig_graph_diff;
		}
		return sig_graph_cmp;
	case R_SIGN_BYTES:
		return sig_bytes_cmp;
	default:
		return NULL;
	}
}

static inline bool sign_collide_by(RPVector *sigs, RSignType type) {
	RSignSorter cmp = type_to_cmp (type, false);
	if (!cmp) {
		return false;
	}
	r_pvector_sort (sigs, (RPVectorComparator)cmp);
	// sorting and matching can be slightly different
	cmp = type_to_cmp (type, true);

	void **p;
	int i, start, end;
	RSignItem *old = NULL;
	i = 0;
	start = end = -1;
	r_pvector_foreach (sigs, p) {
		RSignItem *it = *p;
		if (!item_has_type (it, type)) {
			// sort algs should put NULL at bottom
			break;
		}
		if (old) {
			if (!cmp (old, it)) {
				// signature collisions
				if (start < 0) {
					start = i - 1;
					end = i;
				} else {
					end++;
				}
			} else if (start >= 0) {
				// not a collision, but had a collision before
				if (!update_collide (sigs, start, end, type)) {
					return false;
				}
				start = end = -1;
			}
		}
		old = it;
		i++;
	}
	if (start >= 0 && !update_collide (sigs, start, end, type)) {
		return false;
	}
	return true;
}

R_API bool r_sign_resolve_collisions(RAnal *a) {
	r_return_val_if_fail (a, false);
	RPVector *sigs = r_pvector_new ((RPVectorFree)r_sign_item_free);
	if (!sigs) {
		return false;
	}

	if (!r_sign_foreach_nofree (a, _sig_to_vec_cb, (void *)sigs)) {
		r_pvector_free (sigs);
		return false;
	}
	int i = 0;
	RSignType types[] = { R_SIGN_BYTES, R_SIGN_GRAPH, R_SIGN_END };
	for (i = 0; types[i] != R_SIGN_END; i++) {
		sign_collide_by (sigs, types[i]);
	}

	// save updated signatures
	void **p;
	r_pvector_foreach (sigs, p) {
		RSignItem *it = *p;
		if (it->collisions) {
			r_list_sort (it->collisions, list_str_cmp);
			r_sign_add_item (a, it);
		}
	}

	r_pvector_free (sigs);
	return true;
}

R_API int r_sign_fcn_match_metrics(RSignSearchMetrics *sm) {
	r_return_val_if_fail (sm && sm->mincc >= 0 && sm->anal && sm->fcn, -1);
	RSignItem *it = r_sign_item_new ();
	if (!it) {
		return -1;
	}

	RSignType *t = sm->types;
	while (*t != R_SIGN_END) {
		if (*t == R_SIGN_BYTES) {
			// no need for mask
			it->bytes = r_sign_func_empty_mask (sm->anal, sm->fcn);
		} else {
			r_sign_addto_item (sm->anal, it, sm->fcn, *t);
		}
		t++;
	}

	if (it->graph && it->graph->cc < sm->mincc) {
		r_sign_graph_free (it->graph);
		it->graph = NULL;
	}
	struct metric_ctx ctx = { 0, it, sm };
	r_sign_foreach (sm->anal, match_metrics, (void *)&ctx);
	r_sign_item_free (it);
	return ctx.matched;
}

R_API RSignItem *r_sign_item_new(void) {
	RSignItem *ret = R_NEW0 (RSignItem);
	if (ret) {
		ret->addr = UT64_MAX;
		ret->space = NULL;
	}
	return ret;
}

R_API void r_sign_item_free(RSignItem *item) {
	if (item) {
		free (item->name);
		r_sign_bytes_free (item->bytes);
		r_sign_hash_free (item->hash);
		r_sign_graph_free (item->graph);
		free (item->comment);
		free (item->realname);
		r_list_free (item->refs);
		r_list_free (item->vars);
		r_list_free (item->xrefs);
		r_list_free (item->types);
		r_list_free (item->collisions);
		free (item);
	}
}

R_API void r_sign_graph_free(RSignGraph *graph) {
	free (graph);
}

R_API void r_sign_bytes_free(RSignBytes *bytes) {
	if (bytes) {
		free (bytes->bytes);
		free (bytes->mask);
		free (bytes);
	}
}

R_API void r_sign_hash_free(RSignHash *hash) {
	if (hash) {
		free (hash->bbhash);
		free (hash);
	}
}

static bool loadCB(void *user, const char *k, const char *v) {
	RAnal *a = (RAnal *)user;
	RSignItem *it = r_sign_item_new ();
	if (it && r_sign_deserialize (a, it, k, v)) {
		r_sign_set_item (a->sdb_zigns, it, NULL);
	} else {
		eprintf ("error: cannot deserialize zign\n");
	}
	r_sign_item_free (it);
	return true;
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
		char *home = r_str_home (R2_HOME_ZIGNS);
		abs = r_str_newf ("%s%s%s", home, R_SYS_DIR, file);
		free (home);
		if (r_file_is_regular (abs)) {
			return abs;
		}
		free (abs);
	}

	abs = r_str_newf (R_JOIN_3_PATHS ("%s", R2_ZIGNS, "%s"), r_sys_prefix (NULL), file);
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
	r_return_val_if_fail (a && file, false);

	if (sdb_isempty (a->sdb_zigns)) {
		eprintf ("Warning: no zignatures to save\n");
		return false;
	}

	Sdb *db = sdb_new (NULL, file, 0);
	if (!db) {
		return false;
	}
	sdb_merge (db, a->sdb_zigns);
	bool retval = sdb_sync (db);
	sdb_close (db);
	sdb_free (db);

	return retval;
}

R_API RSignOptions *r_sign_options_new(const char *bytes_thresh, const char *graph_thresh) {
	RSignOptions *options = R_NEW0 (RSignOptions);
	if (!options) {
		return NULL;
	}

	options->bytes_diff_threshold = r_num_get_float (NULL, bytes_thresh);
	options->graph_diff_threshold = r_num_get_float (NULL, graph_thresh);

	if (options->bytes_diff_threshold > 1.0) {
		options->bytes_diff_threshold = 1.0;
	}
	if (options->bytes_diff_threshold < 0) {
		options->bytes_diff_threshold = 0.0;
	}
	if (options->graph_diff_threshold > 1.0) {
		options->graph_diff_threshold = 1.0;
	}
	if (options->graph_diff_threshold < 0) {
		options->graph_diff_threshold = 0.0;
	}

	return options;
}

R_API void r_sign_options_free(RSignOptions *options) {
	R_FREE (options);
}
