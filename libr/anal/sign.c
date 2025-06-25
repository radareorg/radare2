/* radare - LGPL - Copyright 2009-2024 - pancake, nibble */

#include <r_core.h>
#include <r_vec.h>
#include <r_util/r_json.h>

R_LIB_VERSION (r_sign);

#define SIGN_DIFF_MATCH_BYTES_THRESHOLD 1.0
#define SIGN_DIFF_MATCH_GRAPH_THRESHOLD 1.0

R_VEC_TYPE (RVecAnalRef, RAnalRef);

static inline const char *get_xrefname(RCore *core, ut64 addr) {
	RAnalFunction *f = r_anal_get_fcn_in (core->anal, addr, 0);
	return f? f->name: NULL;
}

static const char *get_refname(RCore *core, ut64 addr) {
	RFlagItem *item;
	RListIter *iter;

	const RList *list = r_flag_get_list (core->flags, addr);
	if (!list) {
		return NULL;
	}

	r_list_foreach (list, iter, item) {
		if (!item->name || !r_str_startswith (item->name, "sym.")) {
			continue;
		}
		return item->name;
	}

	return NULL;
}

static int list_str_cmp(const void *a, const void *b) {
	// prevent silent failure if RListComparator changes
	return strcmp ((const char *)a, (const char *)b);
}

static ut64 valstr(const void *_a) {
	const char *a = _a;
	return r_str_hash64 (a);
}

R_API RList *r_sign_fcn_xrefs(RAnal *a, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (a && fcn, NULL);

	RCore *core = a->coreb.core;

	if (!core) {
		return NULL;
	}

	RList *ret = r_list_newf ((RListFree) free);
	RVecAnalRef *xrefs = r_anal_xrefs_get (a, fcn->addr);
	if (!xrefs) {
		return ret;
	}

	RAnalRef *refi;
	R_VEC_FOREACH (xrefs, refi) {
		// RAnalRefType rt = R_ANAL_REF_TYPE_MASK (refi->type);
		// if (rt == R_ANAL_REF_TYPE_CODE || rt == R_ANAL_REF_TYPE_CALL) {
			const char *flag = get_xrefname (core, refi->addr);
			if (flag) {
				r_list_append (ret, strdup (flag));
			}
		// }
	}

	r_list_uniq (ret, valstr);
	RVecAnalRef_free (xrefs);
	return ret;
}

R_API RList *r_sign_fcn_refs(RAnal *a, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (a && fcn, NULL);
	RAnalRef *refi = NULL;
	RCore *core = a->coreb.core;
	if (!core) {
		return NULL;
	}

	RList *ret = r_list_newf ((RListFree) free);
	RVecAnalRef *refs = r_anal_function_get_refs (fcn);
	if (!refs) {
		return ret;
	}

	R_VEC_FOREACH (refs, refi) {
		// RAnalRefType rt = R_ANAL_REF_TYPE_MASK (refi->type);
		// if (rt == R_ANAL_REF_TYPE_CODE || rt == R_ANAL_REF_TYPE_CALL) {
			const char *flag = get_refname (core, refi->addr);
			if (flag) {
				r_list_append (ret, strdup (flag));
			}
		// }
	}
	RVecAnalRef_free (refs);
	return ret;
}

static RSignBytes *des_bytes_norm(const char *in) {
	// "444444:ffffff" or "44444444"
	RSignBytes *b = R_NEW0 (RSignBytes);
	if (b && (b->size = r_hex_str2bin_until_new (in, &b->bytes)) > 0) {
		in += 2 * b->size;
		if (!*in && (b->mask = malloc (b->size))) {
			// no mask, set it to f's
			memset (b->mask, 0xff, b->size);
			return b;
		}
		if (*in++ == ':') {
			// get mask
			int size = r_hex_str2bin_until_new (in, &b->mask);
			in += 2 * size;
			if (size == b->size && !*in) {
				return b;
			}
		}
	}
	r_sign_bytes_free (b);
	return NULL;
}

static RSignBytes *deserialize_bytes(const char *in) {
	RSignBytes *b = des_bytes_norm (in);
	if (b) {
		return b;
	}

	// "44..44.."
	b = R_NEW0 (RSignBytes);
	size_t len = strlen (in) + 3;
	b->bytes = malloc (len);
	b->mask = malloc (len);
	if (b && b->bytes && b->mask) {
		b->size = r_hex_str2binmask (in, b->bytes, b->mask);
		if (b->size > 0) {
			return b;
		}
	}
	r_sign_bytes_free (b);
	return NULL;
}

static RSignBytes *deserialize_anal(RAnal *a, const char *in) {
	RSignBytes *b = R_NEW0 (RSignBytes);
	if (b && (b->size = r_hex_str2bin_until_new (in, &b->bytes)) > 0) {
		in += 2 * b->size;
		if (!*in && (b->mask = r_anal_mask (a, b->size, b->bytes, 0))) {
			return b;
		}
	}
	r_sign_bytes_free (b);
	return NULL;
}

static inline RList *sign_vars(RAnalFunction *fcn) {
	RList *l = r_anal_var_get_prots (fcn);
	if (l && r_list_empty (l)) {
		r_list_free (l);
		l = NULL;
	}
	return l;
}

// TODO: use primitives from r_types
#define ALPH(x) (x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z')
#define VALID_TOKEN_CHR(x) (ALPH (x) || isdigit (x) || x == '_' || x == '*' || x == ' ' || x == '.')
static bool types_sig_valid(const char *types) {
	// quick state machine parser to validate types being sent to tcc_compile
	int state = 0; // before, inside, or after ()
	char ch;
	const char *t = types;
	int paren_cnt = 0;
	while ((ch = *(t++)) && state >= 0) {
		switch (state) {
		case 0:
			if (ch == '(') {
				state++;
			} else if (!VALID_TOKEN_CHR (ch) && ch != '.') {
				state = -1;
			}
			break;
		case 1:
			if (ch == '(') {
				paren_cnt++;
			} else if (ch == ')') {
				if (paren_cnt == 0) {
					state++;
				} else if (paren_cnt > 0) {
					paren_cnt--;
				} else {
					state = -1;
				}
			} else if (!VALID_TOKEN_CHR (ch) && ch != ',') {
				state = -1;
			}
			break;
		case 2:
			state = -1;
			break;
		}
	}
	return state == 2? true: false;
}
#undef ALPH
#undef VALID_TOKEN_CHR

#define DBL_VAL_FAIL(x,y) \
	if (x) { \
		R_LOG_WARN ("Skipping signature with multiple %c signatures (%s)", y, k); \
		success = false; \
		goto out; \
	}
R_API bool r_sign_deserialize(RAnal *a, RSignItem *it, const char *k, const char *v) {
	R_RETURN_VAL_IF_FAIL (a && it && k && v, false);

	bool success = true;
	char *k2 = strdup (k);
	char *v2 = strdup (v);
	if (!k2 || !v2) {
		success = false;
		goto out;
	}

	// Deserialize key: zign|space|name
	int n = r_str_split (k2, '|');
	if (n != 3) {
		R_LOG_WARN ("Skipping signature with invalid key (%s)", k);
		success = false;
		goto out;
	}
	if (strcmp (r_str_word_get0 (k2, 0), "zign")) {
		R_LOG_WARN ("Skipping signature with invalid value (%s)", k);
		success = false;
		goto out;
	}

	it->space = r_spaces_add (&a->zign_spaces, r_str_word_get0 (k2, 1));
	it->name = R_STR_DUP (r_str_word_get0 (k2, 2));

	// remove newline at end
	char *save_ptr = NULL;
	r_str_tok_r (v2, "\n", &save_ptr);
	// Deserialize value: |k:v|k:v|k:v|...
	n = r_str_split (v2, '|');
	const char *token = NULL;
	int w;
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
			R_LOG_WARN ("Skipping signature with corrupted serialization (%s:%s)", k, word);
			success = false;
			goto out;
		}
		RSignType st = (RSignType)*word;
		switch (st) {
		case R_SIGN_NAME:
			DBL_VAL_FAIL (it->realname, R_SIGN_NAME);
			it->realname = strdup (token);
			break;
		case R_SIGN_COMMENT:
			DBL_VAL_FAIL (it->comment, R_SIGN_COMMENT);
			it->comment = strdup (token);
			break;
		case R_SIGN_NEXT:
			DBL_VAL_FAIL (it->next, R_SIGN_NEXT);
			it->next = strdup (token);
			break;
		case R_SIGN_TYPES:
			DBL_VAL_FAIL (it->types, R_SIGN_TYPES);
			if (!types_sig_valid (token)) {
				R_LOG_ERROR ("Invalid types: ```%s``` in signatuer for %s", token, k);
				success = false;
				goto out;
			}
			it->types = strdup (token);
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
			if (!(it->refs = r_str_split_duplist (token, ",", true))) {
				success = false;
				goto out;
			}
			break;
		case R_SIGN_XREFS:
			DBL_VAL_FAIL (it->xrefs, R_SIGN_XREFS);
			if (!(it->xrefs = r_str_split_duplist (token, ",", true))) {
				success = false;
				goto out;
			}
			break;
		case R_SIGN_VARS:
			DBL_VAL_FAIL (it->vars, R_SIGN_VARS);
			if (!(it->vars = r_anal_var_deserialize (token))) {
				success = false;
				goto out;
			}
			break;
		case R_SIGN_COLLISIONS:
			DBL_VAL_FAIL (it->collisions, R_SIGN_COLLISIONS);
			if (!(it->collisions = r_str_split_duplist (token, ",", true))) {
				success = false;
				goto out;
			}
			break;
		case R_SIGN_BBHASH:
			DBL_VAL_FAIL (it->hash, R_SIGN_BBHASH);
			if (token[0] != 0) {
				it->hash = R_NEW0 (RSignHash);
				if (it->hash) {
					it->hash->bbhash = strdup (token);
				}
			}
			break;
		case R_SIGN_BYTES:
			DBL_VAL_FAIL (it->bytes, R_SIGN_BYTES);
			if (!(it->bytes = des_bytes_norm (token))) {
				success = false;
				goto out;
			}
			break;
		default:
			R_LOG_ERROR ("Unsupported (%c)", st);
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
	if (!sp || !name) {
		return NULL;
	}
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
		if (strchr (e, ',')) {
			return false;
		}
		if (strchr (e, ',') || !r_strbuf_appendf (sb, "%s%s", c, e)) {
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
	if (it->realname) {
		reserve += 0x10;
	}
	if (it->next) {
		reserve += 0x20;
	}
	if (it->types) {
		reserve += 0x20;
	}
	if (it->hash && it->hash->bbhash) {
		reserve += 64;
	}
	int mul = 10;
	if (it->refs) {
		reserve += mul * r_list_length (it->refs);
	}
	if (it->xrefs) {
		reserve += mul * r_list_length (it->xrefs);
	}
	if (it->vars) {
		reserve += mul * r_list_length (it->vars);
	}
	return reserve;
}

#define FreeRet_on_fail(exp, buf) \
	if (!exp) { \
		r_strbuf_free (buf); \
		return NULL; \
	}

static char *serialize_value(RSignItem *it) {
	R_RETURN_VAL_IF_FAIL (it, false);

	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_reserve (sb, serial_val_reserv (it));

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
			success = r_strbuf_appendf (sb, "|%c:%s:%s", R_SIGN_BYTES,
				hexbytes, hexmask);
		}
		free (hexbytes);
		free (hexmask);
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
	FreeRet_on_fail (serialize_str_list (it->collisions, sb, R_SIGN_COLLISIONS), sb);

	if (it->vars && !r_list_empty (it->vars)) {
		char *vrs = r_anal_var_prot_serialize (it->vars, false);
		bool vars_good = false;
		if (vrs) {
			vars_good = r_strbuf_appendf (sb, "|%c:%s", R_SIGN_VARS, vrs);
			free (vrs);
		}
		FreeRet_on_fail (vars_good, sb);
	}

	if (it->comment && !strchr (it->comment, '|')) {
		FreeRet_on_fail (r_strbuf_appendf (sb, "|%c:%s", R_SIGN_COMMENT, it->comment), sb);
	}

	if (it->realname && !strchr (it->realname, '|')) {
		FreeRet_on_fail (r_strbuf_appendf (sb, "|%c:%s", R_SIGN_NAME, it->realname), sb);
	}

	if (it->types && !strchr (it->types, '|')) {
		FreeRet_on_fail (r_strbuf_appendf (sb, "|%c:%s", R_SIGN_TYPES, it->types), sb);
	}

	if (it->next && !strchr (it->next, '|')) {
		FreeRet_on_fail (r_strbuf_appendf (sb, "|%c:%s", R_SIGN_NEXT, it->next), sb);
	}

	if (it->hash && it->hash->bbhash) {
		FreeRet_on_fail (r_strbuf_appendf (sb, "|%c:%s", R_SIGN_BBHASH, it->hash->bbhash), sb);
	}

	return r_strbuf_drain (sb);
}

static RList *deserialize_sign_space(RAnal *a, RSpace *space) {
	R_RETURN_VAL_IF_FAIL (a && space, NULL);

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

#define quick_merge(x, freefunc) \
	if (src->x) { \
		freefunc (dst->x); \
		dst->x = src->x; \
		src->x = NULL; \
	}

// clobbers src for speed but also garentee success
static inline void merge_item_clobber(RSignItem *dst, RSignItem *src) {
	dst->space = src->space;
	if (src->addr != UT64_MAX) {
		dst->addr = src->addr;
	}

	// uniquee free for each
	quick_merge (bytes, r_sign_bytes_free);
	quick_merge (graph, r_sign_graph_free);
	quick_merge (hash, r_sign_hash_free);

	// strings
	quick_merge (comment, free);
	quick_merge (realname, free);
	quick_merge (next, free);
	quick_merge (types, free);

	// lists
	quick_merge (refs, r_list_free);
	quick_merge (xrefs, r_list_free);
	quick_merge (vars, r_list_free);
	quick_merge (collisions, r_list_free);
}
#undef quick_merge

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
	R_RETURN_VAL_IF_FAIL (a && name, NULL);
	char *k = space_serialize_key (r_spaces_current (&a->zign_spaces), name);
	if (k) {
		RSignItem *it = sign_get_sdb_item (a, k);
		free (k);
		return it;
	}
	return NULL;
}

static bool validate_item(RSignItem *it) {
	R_RETURN_VAL_IF_FAIL (it, false);
	// TODO: validate more
	if (!r_name_check (it->name)) {
		R_LOG_ERROR ("Bad name in signature: %s", it->name);
		return false;
	}

	if (it->space && it->space->name && !r_name_check (it->space->name)) {
		R_LOG_ERROR ("Bad space name in signature: %s", it->space->name);
		return false;
	}

	if (it->bytes) {
		RSignBytes *b = it->bytes;
		if (!b->mask || !b->bytes || b->size <= 0) {
			R_LOG_ERROR ("Signature '%s' has empty byte field", it->name);
			return false;
		}
		if (b->mask[0] == '\0') {
			R_LOG_ERROR ("Signature '%s' mask starts empty", it->name);
			return false;
		}
	}
	return true;
}

R_API bool r_sign_add_item(RAnal *a, RSignItem *it) {
	R_RETURN_VAL_IF_FAIL (a && it, false);
	r_name_filter (it->name, -1);
	if (!validate_item (it)) {
		return false;
	}
	char *key = item_serialize_key (it);
	if (!key) {
		return false;
	}
	RSignItem *current = sign_get_sdb_item (a, key);

	bool retval = false;
	if (current) {
		merge_item_clobber (current, it);
		retval = r_sign_set_item (a->sdb_zigns, current, key);
		r_sign_item_free (current);
	} else {
		retval = r_sign_set_item (a->sdb_zigns, it, key);
	}
	free (key);
	return retval;
}

static RSignItem *item_new_named(RAnal *a, const char *n) {
	RSignItem *it = r_sign_item_new ();
	if (it && (it->name = strdup (n))) {
		it->space = r_spaces_current (&a->zign_spaces);
		return it;
	}
	r_sign_item_free (it);
	return NULL;
}

static bool addHash(RAnal *a, const char *name, int type, const char *val) {
	RSignItem *it = item_new_named (a, name);
	if (!it) {
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
	RSignItem *it = item_new_named (a, name);
	if (it && r_sign_addto_item (a, it, fcn, R_SIGN_BBHASH)) {
		retval = r_sign_add_item (a, it);
	}
	r_sign_item_free (it);
	return retval;
}

R_API bool r_sign_add_hash(RAnal *a, const char *name, int type, const char *val, int len) {
	R_RETURN_VAL_IF_FAIL (a && name && type && val && len > 0, false);
	if (type != R_SIGN_BBHASH) {
		R_LOG_ERROR ("hash type unknown");
		return false;
	}
	int digestsize = r_hash_size (R_ZIGN_HASH) * 2;
	if (len != digestsize) {
		R_LOG_ERROR ("invalid hash size: %d (%s digest size is %d)", len, ZIGN_HASH, digestsize);
		return false;
	}
	return addHash (a, name, type, val);
}

R_API bool r_sign_add_bb_hash(RAnal *a, RAnalFunction *fcn, const char *name) {
	R_RETURN_VAL_IF_FAIL (a && fcn && name, false);
	return addBBHash (a, fcn, name);
}

R_API bool r_sign_add_bytes(RAnal *a, const char *name, const char *val) {
	R_RETURN_VAL_IF_FAIL (a && name && val, false);
	bool ret = false;
	RSignItem *it = item_new_named (a, name);
	if (it && (it->bytes = deserialize_bytes (val))) {
		ret = r_sign_add_item (a, it);
	}
	r_sign_item_free (it);
	return ret;
}

R_API bool r_sign_add_anal(RAnal *a, const char *name, const char *val) {
	R_RETURN_VAL_IF_FAIL (a && name && val, false);
	bool ret = false;
	RSignItem *it = item_new_named (a, name);
	if (it && (it->bytes = deserialize_anal (a, val))) {
		ret = r_sign_add_item (a, it);
	}
	r_sign_item_free (it);
	return ret;
}

static RSignGraph *r_sign_fcn_graph(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, false);
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
	R_RETURN_VAL_IF_FAIL (a && fcn && fcn->bbs && fcn->bbs->head, false);

	// get size
	RCore *core = a->coreb.core;
	int maxsz = a->coreb.cfgGetI (core, "zign.maxsz");
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
	R_RETURN_VAL_IF_FAIL (a && fcn && fcn->bbs && fcn->bbs->head, false);
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
	R_RETURN_VAL_IF_FAIL (a && fcn, NULL);
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

static RSignItem *item_from_func(RAnal *a, RAnalFunction *fcn, const char *name) {
	if (r_list_empty (fcn->bbs)) {
		R_LOG_WARN ("Function with no basic blocks at 0x%08"PFMT64x, fcn->addr);
		return false;
	}
	RSignItem *it = item_new_named (a, name? name: fcn->name);
	if (it) {
		if (name && strcmp (name, fcn->name)) {
			it->realname = strdup (name);
		}
		r_sign_addto_item (a, it, fcn, R_SIGN_GRAPH);
		r_sign_addto_item (a, it, fcn, R_SIGN_BYTES);
		r_sign_addto_item (a, it, fcn, R_SIGN_XREFS);
		r_sign_addto_item (a, it, fcn, R_SIGN_REFS);
		r_sign_addto_item (a, it, fcn, R_SIGN_VARS);
		r_sign_addto_item (a, it, fcn, R_SIGN_TYPES);
		r_sign_addto_item (a, it, fcn, R_SIGN_BBHASH);
		r_sign_addto_item (a, it, fcn, R_SIGN_OFFSET);
		r_sign_addto_item (a, it, fcn, R_SIGN_NAME);
	}
	return it;
}

static int fcn_sort(const void *va, const void *vb) {
	ut64 a = ((const RAnalFunction *)va)->addr;
	ut64 b = ((const RAnalFunction *)vb)->addr;
	if (a < b) {
		return -1;
	} else if (a > b) {
		return 1;
	}
	return 0;
}

static bool name_exists(Sdb *sdb, const char *n, const RSpace *sp) {
	char *key = space_serialize_key (sp, n);
	bool exist = false;
	if (key) {
		exist = sdb_exists (sdb, key);
		free (key);
	}
	return exist;
}

static char *get_unique_name(Sdb *sdb, const char *name, const RSpace *sp) {
	ut32 i;
	for (i = 2; i < UT32_MAX; i++) {
		char *unique = r_str_newf ("%s_%d", name, i);
		if (!name_exists (sdb, unique, sp)) {
			return unique;
		}
		free (unique);
	}
	return NULL;
}

static char *real_function_name(RAnal *a, RAnalFunction *fcn) {
	RCore *core = a->coreb.core;
#if 0
	if (fcn->realname) {
	//	return strdup (fcn->realname); // r_bin_name_tostring2 (fcn->name, 'o'));
	}
	return strdup (fcn->name); // r_bin_name_tostring2 (fcn->name, 'o'));
#endif
#if 1
	ut64 addr = fcn->addr;
	const char *name = fcn->name;
	// resolve the manged name
	char *res = a->coreb.cmdStrF (core, "is,vaddr/eq/0x%"PFMT64x",demangled/cols,a/head/1,:quiet", addr);
	if (res) {
		r_str_trim (res);
		if (*res) {
			return res;
		}
	}
	return strdup (name);
#endif
}

R_API int r_sign_all_functions(RAnal *a, bool merge) {
	R_RETURN_VAL_IF_FAIL (a, 0);
	RCore *core = a->coreb.core;
	RCons *cons = core->cons;
	RAnalFunction *fcn = NULL;
	RListIter *iter = NULL;
	int count = 0;
	r_list_sort (a->fcns, fcn_sort);
	const RSpace *sp = r_spaces_current (&a->zign_spaces);
	char *prev_name = NULL;
	r_cons_break_push (cons, NULL, NULL);
	RCoreBind cb = a->coreb;
	RCore *core = cb.core;
	bool do_mangled = cb.cfgGetI (core, "zign.mangled");
	bool zign_dups = a->opt.zigndups;
	r_list_foreach_prev (a->fcns, iter, fcn) {
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		char *realname = do_mangled? strdup (fcn->name): real_function_name (a, fcn);
		RSignItem *it = NULL;
		if (merge || !name_exists (a->sdb_zigns, realname, sp)) {
			it = item_from_func (a, fcn, realname);
		} else if (zign_dups) {
			char *name = get_unique_name (a->sdb_zigns, fcn->name, sp);
			if (name) {
				it = item_from_func (a, fcn, name);
			}
			free (name);
		}
		free (realname);
		if (it) {
			if (prev_name) {
				it->next = prev_name;
			}
			prev_name = strdup (it->name);
			r_sign_add_item (a, it);
			r_sign_item_free (it);
			count++;
		} else {
			free (prev_name);
			prev_name = NULL;
		}
	}
	r_cons_break_pop (cons);
	free (prev_name);
	return count;
}

R_API bool r_sign_add_func(RAnal *a, RAnalFunction *fcn, const char *name) {
	R_RETURN_VAL_IF_FAIL (a && fcn, false);
	RSignItem *it = item_from_func (a, fcn, name);
	if (it) {
		r_sign_add_item (a, it);
		r_sign_item_free (it);
		return true;
	}
	return false;
}

R_API bool r_sign_addto_item(RAnal *a, RSignItem *it, RAnalFunction *fcn, RSignType type) {
	R_RETURN_VAL_IF_FAIL (a && it && fcn, false);
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
		return !it->vars && (it->vars = sign_vars (fcn));
	case R_SIGN_TYPES:
		if (!it->types) {
			it->types = r_anal_function_get_signature (fcn);
			if (it->types) {
				size_t l = strlen (it->types) - 1;
				if (l > 0 && it->types[l] == ';') {
					it->types[l] = '\0';
					return true;
				} else {
					free (it->types);
				}
			}
		}
		return false;
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
		R_LOG_ERROR ("%s Can not handle type %c", __FUNCTION__, type);
	}

	return false;
}

R_API bool r_sign_add_graph(RAnal *a, const char *name, RSignGraph graph) {
	R_RETURN_VAL_IF_FAIL (a && !R_STR_ISEMPTY (name), false);
	bool retval = false;
	RSignItem *it = item_new_named (a, name);
	if (it && (it->graph = R_NEW0 (RSignGraph))) {
		*it->graph = graph;
		retval = r_sign_add_item (a, it);
	}
	r_sign_item_free (it);
	return retval;
}

R_API bool r_sign_add_comment(RAnal *a, const char *name, const char *comment) {
	R_RETURN_VAL_IF_FAIL (a && name && comment, false);

	bool retval = false;
	RSignItem *it = item_new_named (a, name);
	if (it && (it->comment = strdup (comment))) {
		retval = r_sign_add_item (a, it);
	}
	r_sign_item_free (it);
	return retval;
}

R_API bool r_sign_add_name(RAnal *a, const char *name, const char *realname) {
	R_RETURN_VAL_IF_FAIL (a && name && realname, false);

	if (strchr (realname, ' ')) {
		R_LOG_ERROR ("Realname sig can't contain spaces");
		return false;
	}

	bool retval = false;
	RSignItem *it = item_new_named (a, name);
	if (it && (it->realname = strdup (realname))) {
		retval = r_sign_add_item (a, it);
	}
	r_sign_item_free (it);
	return retval;
}

R_API bool r_sign_add_types(RAnal *a, const char *name, const char *types) {
	R_RETURN_VAL_IF_FAIL (a && name && types, false);
	if (!types_sig_valid (types)) {
		R_LOG_ERROR ("Invalid types signature: %s", types);
		return false;
	}

	bool retval = false;
	RSignItem *it = item_new_named (a, name);
	if (it) {
		it->types = strdup (types);
		retval = r_sign_add_item (a, it);
		r_sign_item_free (it);
	}
	return retval;
}

R_API bool r_sign_add_addr(RAnal *a, const char *name, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (a && name && addr != UT64_MAX, false);

	bool retval = false;
	RSignItem *it = item_new_named (a, name);
	if (it) {
		it->addr = addr;
		retval = r_sign_add_item (a, it);
		r_sign_item_free (it);
	}
	return retval;
}

R_API bool r_sign_add_vars(RAnal *a, const char *name, const char *vars) {
	R_RETURN_VAL_IF_FAIL (a && name && vars, false);

	bool retval = false;
	RSignItem *it = item_new_named (a, name);
	if (it && (it->vars = r_anal_var_deserialize (vars))) {
		retval = r_sign_add_item (a, it);
	}
	r_sign_item_free (it);
	return retval;
}

R_API bool r_sign_add_refs(RAnal *a, const char *name, RList *refs) {
	R_RETURN_VAL_IF_FAIL (a && name && refs, false);

	bool retval = false;
	RSignItem *it = item_new_named (a, name);
	if (it && (it->refs = r_list_newf ((RListFree)free))) {
		RListIter *iter;
		char *ref;
		r_list_foreach (refs, iter, ref) {
			r_list_append (it->refs, strdup (ref));
		}
		retval = r_sign_add_item (a, it);
	}
	r_sign_item_free (it);
	return retval;
}

R_API bool r_sign_add_xrefs(RAnal *a, const char *name, RList *xrefs) {
	R_RETURN_VAL_IF_FAIL (a && name && xrefs, false);

	bool retval = false;
	RSignItem *it = item_new_named (a, name);
	if (it && (it->xrefs = r_list_newf ((RListFree)free))) {
		RListIter *iter;
		char *xref;
		r_list_foreach (xrefs, iter, xref) {
			r_list_append (it->xrefs, strdup (xref));
		}
		retval = r_sign_add_item (a, it);
	}
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
	R_RETURN_VAL_IF_FAIL (a && name, false);
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

static ut8 *build_combined_bytes(RSignBytes *bsig) {
	R_RETURN_VAL_IF_FAIL (bsig && bsig->bytes && bsig->mask, NULL);
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
	R_RETURN_VAL_IF_FAIL (sig && buf && len >= 0, (double)-1.0);
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
		row = r_list_last (data->output);
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

static bool _closest_match_cb(RSignItem *it, void *user) {
	return closest_match_update (it, (ClosestMatchData *)user);
}

R_API RList *r_sign_find_closest_fcn(RAnal *a, RSignItem *it, int count, double score_threshold) {
	R_RETURN_VAL_IF_FAIL (a && it && count > 0 && score_threshold >= 0 && score_threshold <= 1, NULL);
	R_RETURN_VAL_IF_FAIL (it->bytes || it->graph, NULL);

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
			free (data.bytes_combined);
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
		fsig->name = strdup (fcn->name);

		// maybe add signature item to output list
		closest_match_update (fsig, &data);
	}
	free (data.bytes_combined);
	return output;
}

R_API bool r_sign_diff(RAnal *a, RSignOptions *options, const char *other_space_name) {
	R_RETURN_VAL_IF_FAIL (a && other_space_name, false);

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

	R_LOG_INFO ("Diff %d %d", (int)ls_length (la), (int)ls_length (lb));

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
	R_RETURN_VAL_IF_FAIL (a && other_space_name, false);

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

	R_LOG_INFO ("Diff by name %d %d (%s)", (int)ls_length (la), (int)ls_length (lb), not_matching? "not matching" : "matching");

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
	ut64 addr;
};

static void list_sanitise_warn(char *s, const char *name, const char *field) {
	if (s) { // NULL value accepted and sane
		bool sanitized = false;
		for (; *s; s++) {
			switch (*name) {
			case '`':
			case '$':
			case '{':
			case '}':
			case '~':
			case '|':
			case '#':
			case '@':
			case '&':
			case '<':
			case '>':
			case ',':
				*s = '_';
				sanitized = true;
				continue;
			}
		}
		if (sanitized) {
			R_LOG_INFO ("%s->%s needs to be sanitized", name, field);
			R_WARN_IF_REACHED ();
		}
	}
}

static void listBytes(RAnal *a, RSignItem *it, PJ *pj, int format) {
	RSignBytes *bytes = it->bytes;

	if (!bytes->bytes) {
		return;
	}

	int masked = 0, i = 0;
	for (i = 0; i < bytes->size; i++) {
		masked += bytes->mask[i] == 0xff;
	}

	char *strbytes = r_hex_bin2strdup (bytes->bytes, bytes->size);
	if (!strbytes) {
		return;
	}
	char *strmask = r_hex_bin2strdup (bytes->mask, bytes->size);
	if (!strmask) {
		free (strbytes);
		return;
	}

	list_sanitise_warn (strbytes, it->name, "bytes");
	list_sanitise_warn (strmask, it->name, "mask");
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

static void liststring(RAnal *a, RSignType t, char *value, PJ *pj, int format, char *name) {
	if (value) {
		if (format == 'j') {
			pj_ks (pj, r_sign_type_to_name (t), value);
		} else {
			const char *type = r_sign_type_to_name (t);
			list_sanitise_warn (value, name, type);
			if (format == 'q') {
				a->cb_printf ("\n ; %s\n", value);
			} else if (format == '*') {
				// comment injection via CCu..
				a->cb_printf ("za %s %c %s\n", name, t, value);
			} else {
				a->cb_printf ("  %s: %s\n", type, value);
			}
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

static void inline list_vars_abs(RAnal *a, RSignItem *it, bool rad) {
	if (it->vars && !r_list_empty (it->vars)) {
		char *ser = r_anal_var_prot_serialize (it->vars, true);
		if (ser) {
			// sholdn't do anyting, but just in case
			list_sanitise_warn (ser, it->name, "var");
			if (rad) {
				a->cb_printf ("za %s %c %s\n", it->name, R_SIGN_VARS, ser);
			} else {
				a->cb_printf ("  vars: %s\n", ser);
			}
		}
		free (ser);
	}
}

static void inline list_vars_json(RSignItem *it, PJ *pj) {
	pj_ka (pj, "vars");
	if (it->vars) {
		RAnalVarProt *v;
		RListIter *iter;
		r_list_foreach (it->vars, iter, v) {
			char kind[] = { v->kind, '\0' };
			pj_o (pj);
			pj_ks (pj, "name", v->name);
			pj_ks (pj, "type", v->type);
			pj_ks (pj, "kind", kind);
			pj_kN (pj, "delta", v->delta);
			pj_kb (pj, "isarg", v->isarg);
			pj_end (pj);
		}
	}
	pj_end (pj);
}

static void inline list_vars(RAnal *a, RSignItem *it, PJ *pj, int fmt) {
	switch (fmt) {
	case '*':
		list_vars_abs (a, it, true);
		break;
	case 'q':
		if (it->vars) {
			a->cb_printf (" vars[%d]", r_list_length (it->vars));
		}
		break;
	case 'j':
		list_vars_json (it, pj);
		break;
	default:
		list_vars_abs (a, it, false);
		break;
	}
}

static void list_sign_list(RAnal *a, RList *l, PJ *pj, int fmt, int type, const char *name) {
	const char *tname = r_sign_type_to_name (type);
	switch (fmt) {
	case '*':
		a->cb_printf ("za %s %c ", name, type);
		break;
	case 'q':
		a->cb_printf (" %s[%d]", tname, r_list_length (l));
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
			list_sanitise_warn (it->hash->bbhash, it->name, "bbhash");
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
			list_sanitise_warn (it->hash->bbhash, it->name, "bbhash");
			a->cb_printf ("  bbhash: %s\n", it->hash->bbhash);
		}
		break;
	}
}

static bool listCB(RSignItem *it, void *user) {
	struct ctxListCB *ctx = (struct ctxListCB *)user;
	RAnal *a = ctx->anal;
	if (!validate_item (it)) {
		return true;
	}

	if (ctx->addr != UT64_MAX) {
		if (it->addr != ctx->addr) {
			return true;
		}
	}

	// Start item
	if (ctx->format == 'j') {
		pj_o (ctx->pj);
	}

	// Zignspace and name (except for radare format)
	switch (ctx->format) {
	case '*':
		if (it->space) {
			a->cb_printf ("zs %s\n", it->space->name);
		} else {
			a->cb_printf ("zs *\n");
		}
		break;
	case 'q':
		a->cb_printf ("0x%08" PFMT64x " ", it->addr);
		const char *pad = r_str_pad (' ', 30 - strlen (it->name));
		a->cb_printf ("%s:%s", it->name, pad);
		break;
	case 'j':
		if (it->space) {
			pj_ks (ctx->pj, "zignspace", it->space->name);
		}
		pj_ks (ctx->pj, "name", it->name);
		break;
	default:
		if (!r_spaces_current (&a->zign_spaces) && it->space) {
			a->cb_printf ("(%s) ", it->space->name);
		}
		a->cb_printf ("%s:\n", it->name);
		break;
	}

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

	liststring (a, R_SIGN_NAME, it->realname, ctx->pj, ctx->format, it->name);
	liststring (a, R_SIGN_COMMENT, it->comment, ctx->pj, ctx->format, it->name);
	liststring (a, R_SIGN_NEXT, it->next, ctx->pj, ctx->format, it->name);
	liststring (a, R_SIGN_TYPES, it->types, ctx->pj, ctx->format, it->name);

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
	// Collisions
	if (it->collisions) {
		list_sign_list (a, it->collisions, ctx->pj, ctx->format, R_SIGN_COLLISIONS, it->name);
	} else if (ctx->format == 'j') {
		list_sign_list (a, it->collisions, ctx->pj, ctx->format, R_SIGN_COLLISIONS, it->name);
	}

	// Vars
	list_vars (a, it, ctx->pj, ctx->format);

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
	R_RETURN_IF_FAIL (a);
	PJ *pj = NULL;

	if (format == 'j') {
		pj = a->coreb.pjWithEncoding (a->coreb.core);
		pj_a (pj);
	}

	{ // R2_600 - we need to pass addr as argument
		RCore *core = a->coreb.core;
		ut64 addr = core? core->addr: UT64_MAX;
		struct ctxListCB ctx = { a, 0, format, pj, addr};
		r_sign_foreach (a, listCB, &ctx);
	}

	if (format == 'j') {
		pj_end (pj);
		a->cb_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
}

static bool listGetCB(RSignItem *it, void *user) {
	r_list_append ((RList *)user, it);
	return true;
}

R_API const char *r_sign_type_to_name(int type) {
	switch (type) {
	case R_SIGN_BYTES:
		return "bytes";
	case R_SIGN_COMMENT:
		return "comment";
	case R_SIGN_GRAPH:
		return "graph";
	case R_SIGN_OFFSET:
		return "addr";
	case R_SIGN_NAME:
		return "realname";
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
	case R_SIGN_NEXT:
		return "next";
	case R_SIGN_BBHASH:
		return "bbhash";
	default:
		R_WARN_IF_REACHED ();
		return "UnknownType";
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

static bool countForCB(RSignItem *it, void *user) {
	(*(int *)user)++;
	return true;
}

static bool unsetForCB(RSignItem *it, void *user) {
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
	R_RETURN_IF_FAIL (a && space && oname && nname);
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
	R_RETURN_VAL_IF_FAIL (ctx && ctx->cb, false);
	RSignItem *it = r_sign_item_new ();
	RAnal *a = ctx->anal;

	bool keep_going = true;
	if (it && r_sign_deserialize (a, it, k, v)) {
		if (!ctx->space || ctx->space == it->space) {
			keep_going = ctx->cb (it, ctx->user);
		}
	} else {
		R_LOG_ERROR ("cannot deserialize zign");
	}
	if (ctx->freeit) {
		r_sign_item_free (it);
	}
	return keep_going;
}

static inline bool local_foreach_item(RAnal *a, RSignForeachCallback cb, const RSpace *sp, bool freeit, void *user) {
	R_RETURN_VAL_IF_FAIL (a && cb, false);
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
	R_RETURN_VAL_IF_FAIL (a, NULL);
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
	R_RETURN_VAL_IF_FAIL (a && it && count > 0 && score_threshold >= 0 && score_threshold <= 1, NULL);

	// need at least one acceptable signature type
	R_RETURN_VAL_IF_FAIL (it->bytes || it->graph, NULL);

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

static bool addSearchKwCB(RSignItem *it, void *user) {
	struct ctxAddSearchKwCB *ctx = (struct ctxAddSearchKwCB *) user;
	RSignSearch *ss = ctx->ss;
	RSignBytes *bytes = it->bytes;

	if (!bytes) {
		R_LOG_ERROR ("Cannot find bytes for this signature: %s", it->name);
		r_sign_item_free (it);
		return true;
	}

	if (ctx->minsz && bytes->size < ctx->minsz) {
		r_sign_item_free (it);
		return true;
	}
	r_list_append (ss->items, it);
	// TODO(nibble): change arg data in r_search_keyword_new to void*
	RSearchKeyword *kw = r_search_keyword_new (bytes->bytes, bytes->size, bytes->mask, bytes->size, (const char *)it);
	r_search_kw_add (ss->search, kw);
	return true;
}

R_API void r_sign_search_init(RAnal *a, RSignSearch *ss, int minsz, RSignSearchCallback cb, void *user) {
	struct ctxAddSearchKwCB ctx = { ss, minsz };
	R_RETURN_IF_FAIL (a && ss && cb);
	ss->cb = cb;
	ss->user = user;
	r_list_purge (ss->items);
	r_search_reset (ss->search, R_SEARCH_KEYWORD);
	r_sign_foreach_nofree (a, addSearchKwCB, &ctx);
	r_search_begin (ss->search);
	r_search_set_callback (ss->search, searchHitCB, ss);
}

R_API int r_sign_search_update(RAnal *a, RSignSearch *ss, ut64 *at, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (a && ss && buf && len > 0, 0);
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
	if (!sig || !func) {
		return 1;
	}

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

static int sig_var_diff(RList *la, RList *lb) {
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
		const RAnalVarProt *a = r_list_get_n (la, i);
		const RAnalVarProt *b = r_list_get_n (lb, i);

		// shouldn't happen, but try to keep it together if it does
		R_RETURN_VAL_IF_FAIL (a, -1);
		R_RETURN_VAL_IF_FAIL (b, 1);

		dif = a->delta - b->delta;
		if (dif) {
			return dif;
		}
		if (a->isarg != b->isarg) {
			return a->isarg? 1: -1;
		}
		dif = a->kind - b->kind;
		if (dif) {
			return dif;
		}
	}
	return 0;
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
// collisions. Relies on sets being ordered in groups of types. Returns NULL no
// error, otherwise an RList of collisions. RList will be empty when there are
// no collisions
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
	RAnalFunction *fcn;
	char *suggest; // holds suggestion for next function match, must be freed
};

static bool match_metrics(RSignItem *it, struct metric_ctx *ctx) {
	R_RETURN_VAL_IF_FAIL (it && ctx, false);
	RSignSearchMetrics *sm = ctx->sm;
	RSignItem *fit = ctx->it;
	RSignType types[R_SIGN_TYPEMAX];
	int count = 0;

	if (it->bytes && (it->bytes->size >= sm->minsz || ctx->suggest) && !sig_bytes_diff (it, fit)) {
		types[count++] = R_SIGN_BYTES;
	}
	if (it->graph && it->graph->cc >= sm->mincc && !sig_graph_diff (it, fit)) {
		types[count++] = R_SIGN_GRAPH;
	}
	if (fit->addr != UT64_MAX && !sig_addr_cmp (it->addr, fit->addr)) {
		types[count++] = R_SIGN_OFFSET;
	}
	if (fit->hash && it->hash && !sig_hash_cmp (it->hash, fit->hash)) {
		types[count++] = R_SIGN_BBHASH;
	}
	if (fit->refs && it->refs && !str_list_cmp (it->refs, fit->refs)) {
		types[count++] = R_SIGN_REFS;
	}
	if (fit->vars && it->vars && !sig_var_diff (it->vars, fit->vars)) {
		types[count++] = R_SIGN_VARS;
	}
	if (fit->types && it->types && !strcmp (it->types, fit->types)) {
		types[count++] = R_SIGN_TYPES;
	}

	bool keep_searching = true;
	if (count) {
		RList *col = NULL;
		if (ctx->suggest) {
			// Collisions are not possible here, assuming collisions are being
			// used. This is b/c we would not recieve a suggestion unless the
			// previous match lacked a collision.
			types[count++] = R_SIGN_NEXT;
			free (ctx->suggest);
			ctx->suggest = NULL;
			col = r_list_new ();
			types[count] = R_SIGN_END;
		} else {
			types[count] = R_SIGN_END;
			col = check_collisions (it->collisions, types);
		}

		ctx->matched += count;
		types[count] = R_SIGN_END;
		sm->cb (it, ctx->fcn, types, sm->user, col);

		// is match unique?
		if (col && r_list_length (col) == 0) {
			keep_searching = false;
			// suggest next signature from this match
			ctx->suggest = it->next;
			it->next = NULL;
		}
		r_list_free (col);
	} else {
		free (ctx->suggest);
		ctx->suggest = NULL;
	}
	return keep_searching;
}

static bool _sig_to_vec_cb(RSignItem *it, void *user) {
	if (it->collisions) {
		r_list_free (it->collisions);
		it->collisions = NULL;
	}
	return r_pvector_push ((RPVector *)user, it)? true: false;
}

static bool item_addto_collisions(RSignItem *it, const char *add) {
	R_RETURN_VAL_IF_FAIL (it, false);
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
	R_RETURN_VAL_IF_FAIL (start >= 0 && end > 0 && sigs, false);
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

static RSignSorter type_to_cmp(int type, bool exact) {
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

static inline RSignItem *metric_build_item(RSignSearchMetrics *sm, RAnalFunction *fcn) {
	RSignItem *it = r_sign_item_new ();
	if (it) {
		RSignType *t = sm->stypes;
		while (*t != R_SIGN_END) {
			if (*t == R_SIGN_BYTES) {
				// no need for mask
				it->bytes = r_sign_func_empty_mask (sm->anal, fcn);
			} else {
				r_sign_addto_item (sm->anal, it, fcn, *t);
			}
			t++;
		}

		if (it->graph && it->graph->cc < sm->mincc) {
			r_sign_graph_free (it->graph);
			it->graph = NULL;
		}
	}
	return it;
}

R_API bool r_sign_resolve_collisions(RAnal *a) {
	R_RETURN_VAL_IF_FAIL (a, false);
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

// returns true if you should keep searching
static inline bool suggest_check(RAnal *a, struct metric_ctx *ctx) {
	int ret = true;
	if (ctx && ctx->suggest) {
		RSignItem *it = r_sign_get_item (a, ctx->suggest);
		if (it) {
			ret = match_metrics (it, ctx);
			r_sign_item_free (it);
		}
	}
	return ret;
}

R_API int r_sign_metric_search(RAnal *a, RSignSearchMetrics *sm) {
	R_RETURN_VAL_IF_FAIL (a && sm, -1);
	RListIter *iter;
	RCore *core = a->coreb.core;
	RCons *cons = core->cons;
	r_list_sort (a->fcns, fcn_sort);
	r_cons_break_push (cons, NULL, NULL);
	struct metric_ctx ctx = { 0, NULL, sm, NULL, NULL };
	r_list_foreach (a->fcns, iter, ctx.fcn) {
		if (r_cons_is_breaked (cons)) {
			break;
		}
		ctx.it = metric_build_item (sm, ctx.fcn);
		if (ctx.it && suggest_check (sm->anal, &ctx)) {
			r_sign_foreach (sm->anal, (RSignForeachCallback)match_metrics, (void *)&ctx);
		}
		r_sign_item_free (ctx.it);
	}
	r_cons_break_pop (core->cons);
	free (ctx.suggest);
	return ctx.matched;
}

R_API int r_sign_fcn_match_metrics(RSignSearchMetrics *sm, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (sm && sm->mincc >= 0 && sm->anal && fcn, -1);
	struct metric_ctx ctx = { 0, metric_build_item (sm, fcn), sm, fcn, NULL };
	if (ctx.it) {
		r_sign_foreach (sm->anal, (RSignForeachCallback)match_metrics, (void *)&ctx);
		r_sign_item_free (ctx.it);
		free (ctx.suggest);
	}
	return ctx.matched;
}

R_API RSignItem *r_sign_item_new(void) {
	RSignItem *ret = R_NEW0 (RSignItem);
	if (ret) {
		ret->addr = UT64_MAX;
	}
	return ret;
}

R_API void r_sign_item_free(RSignItem *item) {
	if (item) {
		free (item->name);
		free (item->next);
		r_sign_bytes_free (item->bytes);
		r_sign_hash_free (item->hash);
		r_sign_graph_free (item->graph);
		free (item->comment);
		free (item->realname);
		free (item->types);
		r_list_free (item->refs);
		r_list_free (item->vars);
		r_list_free (item->xrefs);
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

struct load_sign_data {
	RAnal *anal;
	bool merge;
};

static bool loadCB(void *user, const char *k, const char *v) {
	struct load_sign_data *u = (struct load_sign_data *)user;
	RAnal *a = u->anal;
	RSignItem *it = r_sign_item_new ();
	if (it && r_sign_deserialize (a, it, k, v)) {
		if (u->merge || !name_exists (a->sdb_zigns, it->name, it->space)) {
			sdb_set (a->sdb_zigns, k, v, 0);
		} else {
			char *name = get_unique_name (a->sdb_zigns, it->name, it->space);
			if (name) {
				if (!it->realname) {
					it->realname = it->name;
				} else {
					free (it->name);
				}
				it->name = name;
				r_sign_set_item (a->sdb_zigns, it, NULL);
			}
		}
	} else {
		R_LOG_ERROR ("cannot deserialize zign");
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
		char *home = r_xdg_datadir ("zigns");
		abs = r_file_new (home, file, NULL);
		free (home);
		if (r_file_is_regular (abs)) {
			return abs;
		}
		free (abs);
	}

	// abs = r_str_newf (R_JOIN_3_PATHS ("%s", R2_ZIGNS, "%s"), r_sys_prefix (NULL), file);
	abs = r_file_new (r_sys_prefix (NULL), R2_ZIGNS, file, NULL);
	if (r_file_is_regular (abs)) {
		return abs;
	}
	free (abs);

	return NULL;
}

enum {
	SIGNDB_TYPE_SDB,
	SIGNDB_TYPE_KV,
	SIGNDB_TYPE_JSON,
	SIGNDB_TYPE_R2,
	SIGNDB_TYPE_INVALID = -1,
};

static int signdb_type(const char *file) {
	if (r_str_endswith (file, ".sdb")) {
		return SIGNDB_TYPE_SDB;
	}
	if (r_str_endswith (file, ".sdb.txt")) {
		return SIGNDB_TYPE_KV;
	}
	if (r_str_endswith (file, ".json")) {
		return SIGNDB_TYPE_JSON;
	}
	if (r_str_endswith (file, ".r2")) {
		return SIGNDB_TYPE_R2;
	}
	int i, sz = 0;
	char *data = r_file_slurp_range (file, 0, 0x200, &sz);
	if (!data) {
		return SIGNDB_TYPE_INVALID;
	}
	if (sz < 1) {
		free (data);
		return SIGNDB_TYPE_INVALID;
	}
	data[sz - 1] = 0;
	sz = R_MIN (sz, 0x200);
	int is_sdb = 16;
	int is_kv = 4;
	int is_r2 = 2;
	int t = SIGNDB_TYPE_INVALID;
	if (r_str_startswith (data, "[{\"name\":")) {
		t = SIGNDB_TYPE_JSON;
	} else {
		for (i = 0; i < sz; i++) {
			if (!strncmp (data + i, "\nza ", 4)) {
				is_r2--;
				i += 3;
				continue;
			}
			if ((i & 3) == 3 && data[i] == 0) {
				is_sdb--;
				continue;
			}
			if (data[i] == '=' || data[i] == '\n') {
				is_kv--;
				continue;
			}
		}
		if (is_sdb < 0) {
			t = SIGNDB_TYPE_SDB;
		} else if (is_r2 < 0) {
			t = SIGNDB_TYPE_R2;
		} else if (is_kv < 0) {
			t = SIGNDB_TYPE_KV;
		}
	}
#if defined(__GNUC__)
	// XXX looks like a false positive bug in gcc 9.4 (debian CI)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfree-nonheap-object"
	free (data);
#pragma GCC diagnostic pop
#else
	free (data);
#endif
	return t;
}

static bool sign_load_r2(RAnal *a, const char *path) {
	char *cmd = r_str_newf ("'. %s", path);
	a->coreb.cmd (a->coreb.core, cmd);
	free (cmd);
	return true;
}

static bool load_json_signature(RAnal *a, const RJson *child) {
	const char *n = r_json_type (child);
	if (strcmp (n, "object")) {
		return false;
	}
	RSignItem *it = r_sign_item_new ();

#if 1
	const RJson *name = r_json_get (child, "name");
	if (name && name->type == R_JSON_STRING) {
		it->name = strdup (name->str_value);
	}
	const RJson *rname = r_json_get (child, "rawname");
	if (!rname) {
		rname = r_json_get (child, "realname");
	}
#else
	const RJson *name = r_json_get (child, "flagname");
	if (!name) {
		name = r_json_get (child, "name");
	}
	if (name && name->type == R_JSON_STRING) {
		it->name = strdup (name->str_value);
	}
	const RJson *rname = r_json_get (child, "rawname");
	if (!rname) {
		rname = r_json_get (child, "realname");
	}
#endif
	if (rname && rname->type == R_JSON_STRING) {
		it->realname = strdup (rname->str_value);
	}
	const RJson *bytes = r_json_get (child, "bytes");
	const RJson *mask = r_json_get (child, "mask");
	if (bytes && mask) {
		it->bytes = R_NEW0 (RSignBytes);
		it->bytes->bytes = (ut8*)strdup (bytes->str_value);
		it->bytes->size = r_hex_str2bin (bytes->str_value, it->bytes->bytes);
		it->bytes->mask = (ut8*)strdup (mask->str_value);
		(void)r_hex_str2bin (mask->str_value, it->bytes->mask);
	}

	const RJson *types = r_json_get (child, "types");
	if (types && types->type == R_JSON_STRING) {
		it->types = strdup (types->str_value);
	}

	const RJson *next = r_json_get (child, "next");
	if (next && next->type == R_JSON_STRING) {
		it->next = strdup (next->str_value);
	}
	const RJson *addr = r_json_get (child, "addr");
	if (addr) {
		it->addr = addr->num.u_value;
	}
	const RJson *graph = r_json_get (child, "graph");
	if (graph && graph ->type == R_JSON_OBJECT) {
		const RJson *bcc = r_json_get (graph, "cc");
		const RJson *nbb = r_json_get (graph, "nbbs");
		const RJson *edg = r_json_get (graph, "edges");
		const RJson *ebb = r_json_get (graph, "ebbs");
		const RJson *bbs = r_json_get (graph, "bbsum");
		it->graph = R_NEW0 (RSignGraph);
		it->graph->cc = bcc? bcc->num.u_value: 0;
		it->graph->nbbs = nbb? nbb->num.u_value: 0;
		it->graph->edges = edg? edg->num.u_value: 0;
		it->graph->ebbs = ebb? ebb->num.u_value: 0;
		it->graph->bbsum = bbs? bbs->num.u_value: 0;
	}
	const RJson *refs = r_json_get (child, "refs");
	if (refs) {
		it->refs = r_list_new ();
		RJson *p = refs->children.first;
		while (p) {
			if (p->type == R_JSON_STRING) {
				r_list_append (it->refs, strdup (p->str_value));
			}
			p = p->next;
		}
	}
	const RJson *xrefs = r_json_get (child, "xrefs");
	if (xrefs) {
		it->xrefs = r_list_new ();
		RJson *p = xrefs->children.first;
		while (p) {
			if (p->type == R_JSON_STRING) {
				r_list_append (it->xrefs, strdup (p->str_value));
			}
			p = p->next;
		}
	}
	const RJson *hash = r_json_get (child, "hash");
	if (hash && hash->type == R_JSON_OBJECT) {
		const RJson *bbhash = r_json_get (hash, "bbhash");
		it->hash = R_NEW0 (RSignHash);
		it->hash->bbhash = strdup (bbhash->str_value);
	}

	r_sign_set_item (a->sdb_zigns, it, NULL);
	r_sign_item_free (it);
	return true;
}

static bool sign_load_json(RAnal *a, const char *path) {
	size_t sz;
	char *text = r_file_slurp (path, &sz);
	if (!text) {
		return false;
	}
	bool res = false;
	RJson *rj = r_json_parse (text);
	if (rj->type != R_JSON_ARRAY) {
		R_LOG_ERROR ("Invalid json");
	} else {
		res = true;
		// walk the array
		int i = 0;
		for (i = 0;; i++) {
			const RJson *child = r_json_item (rj, i);
			if (!child) {
				break;
			}
			if (!load_json_signature (a, child)) {
				R_LOG_WARN ("invalid json");
				res = false;
				break;
			}
		}
	}
	r_json_free (rj);
	return res;
}

static bool sign_load_sdb(RAnal *a, const char *path, bool merge) {
	Sdb *db = sdb_new (NULL, path, 0);
	if (db) {
		struct load_sign_data u = {
			.anal = a,
			.merge = merge
		};
		sdb_foreach (db, loadCB, &u);
		sdb_close (db);
		sdb_free (db);
		return true;
	}
	return false;
}

R_API bool r_sign_load(RAnal *a, const char *file, bool merge) {
	R_RETURN_VAL_IF_FAIL (a && file, false);
	char *path = r_sign_path (a, file);
	if (!path) {
		R_LOG_ERROR ("file %s not found in sign path", file);
		return false;
	}
	if (!r_file_exists (path)) {
		R_LOG_ERROR ("file %s does not exist", file);
		free (path);
		return false;
	}
	bool res = false;
	const int type = signdb_type (path);
	switch (type) {
	case SIGNDB_TYPE_R2:
		res = sign_load_r2 (a, path);
		break;
	case SIGNDB_TYPE_JSON:
		res = sign_load_json (a, path);
		break;
	case SIGNDB_TYPE_KV:
	case SIGNDB_TYPE_SDB:
		res = sign_load_sdb (a, path, merge);
		break;
	default:
		R_LOG_ERROR ("Unsupported signature file format");
		break;
	}
	free (path);
	return res;
}

R_API bool r_sign_load_gz(RAnal *a, const char *filename, bool merge) {
	R_RETURN_VAL_IF_FAIL (a && filename, false);
	ut8 *buf = NULL;
	int size = 0;
	char *tmpfile = NULL;
	bool retval = true;
	char *path = r_sign_path (a, filename);
	if (!path) {
		R_LOG_ERROR ("file %s not found in sign path", filename);
		return false;
	}
	if (!r_file_exists (path)) {
		R_LOG_ERROR ("file %s does not exist", filename);
		retval = false;
		goto out;
	}
	if (!(buf = r_file_gzslurp (path, &size, 0))) {
		R_LOG_ERROR ("cannot decompress file");
		retval = false;
		goto out;
	}
	if (!(tmpfile = r_file_temp ("r2zign"))) {
		R_LOG_ERROR ("cannot create temp file");
		retval = false;
		goto out;
	}
	if (!r_file_dump (tmpfile, buf, size, 0)) {
		R_LOG_ERROR ("cannot dump file");
		retval = false;
		goto out;
	}
	if (!r_sign_load (a, tmpfile, merge)) {
		R_LOG_ERROR ("cannot load file");
		retval = false;
		goto out;
	}
	if (!r_file_rm (tmpfile)) {
		R_LOG_ERROR ("cannot delete temp file");
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
	R_RETURN_VAL_IF_FAIL (a && file, false);

	if (sdb_isempty (a->sdb_zigns)) {
		R_LOG_WARN ("no zignatures to save");
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
	R_RETURN_VAL_IF_FAIL (bytes_thresh && graph_thresh, NULL);
	RSignOptions *options = R_NEW0 (RSignOptions);
	if (!options) {
		return NULL;
	}

	options->bytes_diff_threshold = r_num_get_double (NULL, bytes_thresh);
	options->graph_diff_threshold = r_num_get_double (NULL, graph_thresh);

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
	free (options);
}
