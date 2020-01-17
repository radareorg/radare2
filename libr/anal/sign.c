/* radare - LGPL - Copyright 2009-2019 - pancake, nibble */

#include <r_anal.h>
#include <r_sign.h>
#include <r_search.h>
#include <r_util.h>
#include <r_core.h>
#include <r_hash.h>

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
	char *args_expr = r_str_newf ("func.%s.args", fcn->name), *arg = NULL;
	const char *ret_type = sdb_const_get (a->sdb_types, r_str_newf ("func.%s.ret", fcn->name), 0);
	const char *fcntypes = sdb_const_get (a->sdb_types, args_expr, 0);
	int argc = 0;
	int i;

	if (fcntypes) {
		if (ret_type) {
			r_list_append (ret, r_str_newf ("func.%s.ret=%s", fcn->name, ret_type));
		}
		argc = atoi (fcntypes);
		r_list_append (ret, r_str_newf ("func.%s.args=%d", fcn->name, argc));
		for (i = 0; i < argc; i++) {
			arg = sdb_get (a->sdb_types, r_str_newf ("func.%s.arg.%d", fcn->name, i), 0);
			r_list_append (ret, r_str_newf ("func.%s.arg.%d=\"%s\"", fcn->name, i, arg));
		}
	}

	free (arg);
	free (args_expr);
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
	RList *xrefs = r_anal_fcn_get_xrefs (a, fcn);
	r_list_foreach (xrefs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_CODE || refi->type == R_ANAL_REF_TYPE_CALL) {
			const char *flag = getRealRef (core, refi->addr);
			if (flag) {
				r_list_append (ret, r_str_newf (flag));
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
	RList *refs = r_anal_fcn_get_refs (a, fcn);
	r_list_foreach (refs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_CODE || refi->type == R_ANAL_REF_TYPE_CALL) {
			const char *flag = getRealRef (core, refi->addr);
			if (flag) {
				r_list_append (ret, r_str_newf (flag));
			}
		}
	}
	r_list_free (refs);
	return ret;
}

static RList *zign_types_to_list(RAnal *a, char *types) {
	RList *ret = r_list_newf ((RListFree) free);
	unsigned int i = 0, prev = 0, len = strlen (types);
	bool quoted = false;
	char *token = NULL;

	for (i = 0; i <= len; i++) {
		if (types[i] == '"') {
			quoted = !quoted;
		}
		else if ((types[i] == ',' && !quoted) || types[i] == '\0') {
			token = r_str_ndup (types + prev, i - prev);
			if (token) {
				prev = i + 1;
				r_list_append (ret, strdup (token));
				free (token);
				token = NULL;
			}
		}
	}

	free (token);
	return ret;
}

R_API bool r_sign_deserialize(RAnal *a, RSignItem *it, const char *k, const char *v) {
	char *refs = NULL;
	char *vars = NULL;
	char *types = NULL;
	const char *token = NULL;
	int i = 0, n = 0, nrefs = 0, nvars = 0, size = 0, w = 0;

	r_return_val_if_fail (a && it && k && v, false);

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
		goto out;
	}
	if (strcmp (r_str_word_get0 (k2, 0), "zign")) {
		eprintf ("Invalid entry in the zigns database\n");
		goto out;
	}

	// space (1)
	it->space = r_spaces_add (&a->zign_spaces, r_str_word_get0 (k2, 1));

	// name (2)
	it->name = r_str_new (r_str_word_get0 (k2, 2));
//	it->space = r_spaces_current (&a->zign_spaces);

	// Deserialize value: |k:v|k:v|k:v|...
	n = r_str_split (v2, '|');
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
			eprintf ("Corrupted zignatures database (%s)\n", word);
			break;
		}
		RSignType st = (RSignType)*word;
		switch (st) {
		case R_SIGN_ANAL:
			eprintf ("Unsupported\n");
			break;
		case R_SIGN_NAME:
			it->realname = strdup (token);
			break;
		case R_SIGN_COMMENT:
			it->comment = strdup (token);
			break;
		case R_SIGN_GRAPH:
			if (strlen (token) == 2 * sizeof (RSignGraph)) {
				it->graph = R_NEW0 (RSignGraph);
				if (it->graph) {
					r_hex_str2bin (token, (ut8 *) it->graph);
				}
			}
			break;
		case R_SIGN_OFFSET:
			it->addr = atoll (token);
			break;
		case R_SIGN_REFS:
			refs = r_str_new (token);
			nrefs = r_str_split (refs, ',');
			if (nrefs > 0) {
				it->refs = r_list_newf ((RListFree) free);
				for (i = 0; i < nrefs; i++) {
					r_list_append (it->refs, r_str_newf (r_str_word_get0 (refs, i)));
				}
			}
			break;
		case R_SIGN_XREFS:
			refs = r_str_new (token);
			nrefs = r_str_split (refs, ',');
			if (nrefs > 0) {
				it->xrefs = r_list_newf ((RListFree) free);
				for (i = 0; i < nrefs; i++) {
					r_list_append (it->xrefs, r_str_newf (r_str_word_get0 (refs, i)));
				}
			}
			break;
		case R_SIGN_VARS:
			vars = r_str_new (token);
			nvars = r_str_split (vars, ',');
			if (nvars > 0) {
				it->vars = r_list_newf ((RListFree) free);
				for (i = 0; i < nvars; i++) {
					r_list_append (it->vars, r_str_newf (r_str_word_get0 (vars, i)));
				}
			}
			break;
		case R_SIGN_TYPES:
			types = r_str_new (token);
			it->types = zign_types_to_list (a, types);
			break;
		case R_SIGN_BBHASH:
			if (token[0] != 0) {
				it->hash = R_NEW0 (RSignHash);
				if (it->hash) {
					it->hash->bbhash = r_str_new (token);
				}
			}
			break;
		case R_SIGN_BYTES:
			if (!it->bytes) {
				eprintf ("Missing bytes-size command before bytes\n");
				break;
			}
			if (strlen (token) != 2 * it->bytes->size) {
				goto out;
			}
			it->bytes->bytes = malloc (it->bytes->size);
			if (it->bytes->bytes) {
				r_hex_str2bin (token, it->bytes->bytes);
			}
			break;
		case R_SIGN_BYTES_MASK:
			if (!it->bytes) {
				eprintf ("Missing bytes-size command before bytes-mask\n");
				break;
			}
			if (strlen (token) != 2 * it->bytes->size) {
				goto out;
			}
			free (it->bytes->mask);
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
				free (it->bytes);
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
	free (refs);
	free (vars);
	free (types);
	return (w == n);
}

static void serializeKey(RAnal *a, const RSpace *space, const char* name, char *k) {
	snprintf (k, R_SIGN_KEY_MAXSZ, "zign|%s|%s", space? space->name: "*", name);
}

static void serializeKeySpaceStr(RAnal *a, const char *space, const char* name, char *k) {
	snprintf (k, R_SIGN_KEY_MAXSZ, "zign|%s|%s", space, name);
}

static void serialize(RAnal *a, RSignItem *it, char *k, char *v) {
	RListIter *iter = NULL;
	char *hexbytes = NULL, *hexmask = NULL, *hexgraph = NULL;
	char *refs = NULL, *xrefs = NULL, *ref = NULL, *var, *vars = NULL;
	char *type, *types = NULL;
	int i = 0, len = 0;
	RSignBytes *bytes = it->bytes;
	RSignGraph *graph = it->graph;
	RSignHash *hash = it->hash;

	if (k) {
		serializeKey (a, it->space, it->name, k);
	}
	if (v) {
		if (bytes) {
			len = bytes->size * 2 + 1;
			hexbytes = calloc (1, len);
			hexmask = calloc (1, len);
			if (!hexbytes || !hexmask) {
				free (hexbytes);
				free (hexmask);
				return;
			}
			if (!bytes->bytes) {
				bytes->bytes = malloc ((bytes->size + 1) * 3);
			}
			r_hex_bin2str (bytes->bytes, bytes->size, hexbytes);
			if (!bytes->mask) {
				bytes->mask = malloc ((bytes->size + 1) * 3);
			}
			r_hex_bin2str (bytes->mask, bytes->size, hexmask);
		}
		if (graph) {
			hexgraph = calloc (1, sizeof (RSignGraph) * 2 + 1);
			if (hexgraph) {
				r_hex_bin2str ((ut8 *) graph, sizeof (RSignGraph), hexgraph);
			}
		}
		i = 0;
		r_list_foreach (it->refs, iter, ref) {
			if (i > 0) {
				refs = r_str_appendch (refs, ',');
			}
			refs = r_str_append (refs, ref);
			i++;
		}
		i = 0;
		r_list_foreach (it->xrefs, iter, ref) {
			if (i > 0) {
				xrefs = r_str_appendch (xrefs, ',');
			}
			xrefs = r_str_append (xrefs, ref);
			i++;
		}
		i = 0;
		r_list_foreach (it->vars, iter, var) {
			if (i > 0) {
				vars = r_str_appendch (vars, ',');
			}
			vars = r_str_append (vars, var);
			i++;
		}
		i = 0;
		r_list_foreach (it->types, iter, type) {
			if (i > 0) {
				types = r_str_appendch (types, ',');
			}
			types = r_str_append (types, type);
			i++;
		}
		RStrBuf *sb = r_strbuf_new ("");
		if (bytes) {
			// TODO: do not hardcoded s,b,m here, use RSignType enum
			r_strbuf_appendf (sb, "|s:%d|b:%s|m:%s", bytes->size, hexbytes, hexmask);
		}
		if (it->addr != UT64_MAX) {
			r_strbuf_appendf (sb, "|%c:%"PFMT64d, R_SIGN_OFFSET, it->addr);
		}
		if (graph) {
			r_strbuf_appendf (sb, "|%c:%s", R_SIGN_GRAPH, hexgraph);
		}
		if (refs) {
			r_strbuf_appendf (sb, "|%c:%s", R_SIGN_REFS, refs);
		}
		if (xrefs) {
			r_strbuf_appendf (sb, "|%c:%s", R_SIGN_XREFS, xrefs);
		}
		if (vars) {
			r_strbuf_appendf (sb, "|%c:%s", R_SIGN_VARS, vars);
		}
		if (types) {
			r_strbuf_appendf (sb, "|%c:%s", R_SIGN_TYPES, types);
		}
		if (it->comment) {
			// b64 encoded
			r_strbuf_appendf (sb, "|%c:%s", R_SIGN_COMMENT, it->comment);
		}
		if (it->realname) {
			// b64 encoded
			r_strbuf_appendf (sb, "|%c:%s", R_SIGN_NAME, it->realname);
		}
		if (hash && hash->bbhash) {
			r_strbuf_appendf (sb, "|%c:%s", R_SIGN_BBHASH, hash->bbhash);
		}
		if (r_strbuf_length (sb) >= R_SIGN_VAL_MAXSZ) {
			eprintf ("Signature limit reached for 0x%08"PFMT64x" (%s)\n", it->addr, it->name);
		}
		char *res = r_strbuf_drain (sb);
		if (res) {
			strncpy (v, res, R_SIGN_VAL_MAXSZ);
			free (res);
		}

		free (hexbytes);
		free (hexmask);
		free (hexgraph);
		free (refs);
		free (vars);
		free (xrefs);
		free (types);
	}
}

static void mergeItem(RSignItem *dst, RSignItem *src) {
	RListIter *iter = NULL;
	char *ref, *var, *type;

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
		dst->space = src->space;
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

	if (src->comment) {
		dst->comment = strdup (src->comment);
	}

	if (src->realname) {
		dst->realname = strdup (src->realname);
	}

	if (src->addr != UT64_MAX) {
		dst->addr = src->addr;
	}

	if (src->refs) {
		r_list_free (dst->refs);

		dst->refs = r_list_newf ((RListFree) free);
		r_list_foreach (src->refs, iter, ref) {
			r_list_append (dst->refs, r_str_new (ref));
		}
	}

	if (src->vars) {
		r_list_free (dst->vars);

		dst->vars = r_list_newf ((RListFree) free);
		r_list_foreach (src->vars, iter, var) {
			r_list_append (dst->vars, r_str_new (var));
		}
	}

	if (src->types) {
		r_list_free (dst->types);

		dst->types = r_list_newf ((RListFree) free);
		r_list_foreach (src->types, iter, type) {
			r_list_append (dst->types, r_str_new (type));
		}
	}

	if (src->hash) {
		if (!dst->hash) {
			dst->hash = R_NEW0 (RSignHash);
			if (!dst->hash) {
				return;
			}
		}
		if (src->hash->bbhash) {
			dst->hash->bbhash = strdup (src->hash->bbhash);
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
		if (!r_sign_deserialize (a, curit, key, curval)) {
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
		retval = addItem (a, it);
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
	it->hash = R_NEW0 (RSignHash);
	it->space = r_spaces_current (&a->zign_spaces);
	if (!it->hash) {
		goto beach;
	}

	char *digest_hex = r_sign_calc_bbhash (a, fcn);
	if (!digest_hex) {
		free (digest_hex);
		goto beach;
	}
	it->hash->bbhash = digest_hex;
	retval = addItem (a, it);
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
	it->space = r_spaces_current (&a->zign_spaces);
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

R_API bool r_sign_add_comment(RAnal *a, const char *name, const char *comment) {
	r_return_val_if_fail (a && name && comment, false);

	RSignItem *it = r_sign_item_new ();
	if (!it) {
		return false;
	}
	it->name = r_str_new (name);
	it->space = r_spaces_current (&a->zign_spaces);
	it->comment = strdup (comment);
	bool retval = addItem (a, it);
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
		bool retval = addItem (a, it);
		r_sign_item_free (it);
		return retval;
	}
	return false;
}

R_API bool r_sign_add_addr(RAnal *a, const char *name, ut64 addr) {
	r_return_val_if_fail (a && name && addr != UT64_MAX, false);

	RSignItem *it = r_sign_item_new ();
	if (!it) {
		return NULL;
	}
	it->name = r_str_new (name);
	it->space = r_spaces_current (&a->zign_spaces);
	it->addr = addr;

	bool retval = addItem (a, it);

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
	it->vars = r_list_newf ((RListFree) free);
	r_list_foreach (vars, iter, var) {
		r_list_append (it->vars, strdup (var));
	}
	bool retval = addItem (a, it);
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
	bool retval = addItem (a, it);
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
	bool retval = addItem (a, it);
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
		if (!r_spaces_current (&a->zign_spaces)) {
			sdb_reset (a->sdb_zigns);
			return true;
		}
		ctx.anal = a;
		serializeKey (a, r_spaces_current (&a->zign_spaces), "", ctx.buf);
		sdb_foreach (a->sdb_zigns, deleteBySpaceCB, &ctx);
		return true;
	}
	// Remove specific zign
	serializeKey (a, r_spaces_current (&a->zign_spaces), name, k);
	return sdb_remove (a->sdb_zigns, k, 0);
}

static double matchBytes(RSignItem *a, RSignItem *b) {
	double result = 0.0;

	if (!a->bytes || !b->bytes) {
		return result;
	}

	size_t min_size = R_MIN ((size_t) a->bytes->size, (size_t) b->bytes->size);
	if (!min_size) {
		return result;
	}

	ut8 *combined_mask = NULL;
	if (a->bytes->mask || b->bytes->mask) {
		combined_mask = (ut8*) malloc (min_size);
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
		result = (double) min_size / (double) R_MAX (a->bytes->size, b->bytes->size);
	}

	free (combined_mask);

	return result;
}

#define SIMILARITY(a,b) \
	((a) == (b) ? 1.0 : (R_MAX ((a),(b)) == 0.0 ? 0.0 : (double) R_MIN ((a), (b)) / (double) R_MAX ((a), (b))))

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

R_API bool r_sign_diff(RAnal *a, RSignOptions *options, const char *other_space_name) {
	char k[R_SIGN_KEY_MAXSZ];

	r_return_val_if_fail (a && other_space_name, false);

	RSpace *current_space = r_spaces_current (&a->zign_spaces);
	if (!current_space) {
		return false;
	}
	RSpace *other_space = r_spaces_get (&a->zign_spaces, other_space_name);
	if (!other_space) {
		return false;
	}

	serializeKey (a, current_space, "", k);
	SdbList *current_zigns = sdb_foreach_match (a->sdb_zigns, k, false);

	serializeKey (a, other_space, "", k);
	SdbList *other_zigns = sdb_foreach_match (a->sdb_zigns, k, false);

	eprintf ("Diff %d %d\n", (int)ls_length (current_zigns), (int)ls_length (other_zigns));

	SdbListIter *iter;
	SdbKv *kv;
	RList *lb = NULL;
	RList *la = r_list_new ();
	if (!la) {
		goto beach;
	}
	ls_foreach (current_zigns, iter, kv) {
		RSignItem *it = r_sign_item_new ();
		if (!it) {
			goto beach;
		}
		if (r_sign_deserialize (a, it, kv->base.key, kv->base.value)) {
			r_list_append (la, it);
		} else {
			r_sign_item_free (it);
		}
	}
	lb = r_list_new ();
	if (!lb) {
		goto beach;
	}
	ls_foreach (other_zigns, iter, kv) {
		RSignItem *it = r_sign_item_new ();
		if (!it) {
			goto beach;
		}
		if (r_sign_deserialize (a, it, kv->base.key, kv->base.value)) {
			r_list_append (lb, it);
		} else {
			r_sign_item_free (it);
		}
	}

	ls_free (current_zigns);
	ls_free (other_zigns);

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
				a->cb_printf ("0x%08"PFMT64x" 0x%08"PFMT64x " %02.5lf B %s\n", si->addr, si2->addr, bytesScore, si->name);
			}

			if (graphMatch) {
				a->cb_printf ("0x%08"PFMT64x" 0x%08"PFMT64x" %02.5lf G %s\n", si->addr, si2->addr, graphScore, si->name);
			}
		}
	}

	r_list_free (la);
	r_list_free (lb);

	return true;
beach:
	ls_free (current_zigns);
	ls_free (other_zigns);
	r_list_free (la);
	r_list_free (lb);

	return false;
}

R_API bool r_sign_diff_by_name(RAnal *a, RSignOptions * options, const char *other_space_name, bool not_matching) {
	char k[R_SIGN_KEY_MAXSZ];

	r_return_val_if_fail (a && other_space_name, false);

	RSpace *current_space = r_spaces_current (&a->zign_spaces);
	if (!current_space) {
		return false;
	}
	RSpace *other_space = r_spaces_get (&a->zign_spaces, other_space_name);
	if (!other_space) {
		return false;
	}

	serializeKey (a, current_space, "", k);
	SdbList *current_zigns = sdb_foreach_match (a->sdb_zigns, k, false);

	serializeKey (a, other_space, "", k);
	SdbList *other_zigns = sdb_foreach_match (a->sdb_zigns, k, false);

	eprintf ("Diff by name %d %d (%s)\n", (int)ls_length (current_zigns), (int)ls_length (other_zigns), not_matching ? "not matching" : "matching");

	SdbListIter *iter;
	SdbKv *kv;
	RList *lb = NULL;
	RList *la = r_list_new ();
	if (!la) {
		goto beach;
	}
	ls_foreach (current_zigns, iter, kv) {
		RSignItem *it = r_sign_item_new ();
		if (!it) {
			goto beach;
		}
		if (r_sign_deserialize (a, it, kv->base.key, kv->base.value)) {
			r_list_append (la, it);
		} else {
			r_sign_item_free (it);
		}
	}
	lb = r_list_new ();
	if (!la) {
		goto beach;
	}
	ls_foreach (other_zigns, iter, kv) {
		RSignItem *it = r_sign_item_new ();
		if (!it) {
			goto beach;
		}
		if (r_sign_deserialize (a, it, kv->base.key, kv->base.value)) {
			r_list_append (lb, it);
		} else {
			r_sign_item_free (it);
		}
	}

	ls_free (current_zigns);
	ls_free (other_zigns);

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
beach:
	ls_free (current_zigns);
	ls_free (other_zigns);
	r_list_free (la);
	r_list_free (lb);

	return false;
}

struct ctxListCB {
	RAnal *anal;
	int idx;
	int format;
};

struct ctxGetListCB {
	RAnal *anal;
	RList *list;
};

static void listBytes(RAnal *a, RSignItem *it, int format) {
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
		a->cb_printf ("\"bytes\":\"%s\",", strbytes);
		a->cb_printf ("\"mask\":\"%s\",", strmask);
	} else {
		a->cb_printf ("  bytes: %s\n", strbytes);
		a->cb_printf ("  mask: %s\n", strmask);
	}

	free (strbytes);
	free (strmask);
}

static void listGraph(RAnal *a, RSignItem *it, int format) {
	RSignGraph *graph = it->graph;

	if (format == 'q') {
		a->cb_printf (" g(cc=%d,nb=%d,e=%d,eb=%d,h=%d)",
			graph->cc, graph->nbbs, graph->edges, graph->ebbs, graph->bbsum);
	} else if (format == '*') {
		a->cb_printf ("za %s g cc=%d nbbs=%d edges=%d ebbs=%d bbsum=%d\n",
			it->name, graph->cc, graph->nbbs, graph->edges, graph->ebbs, graph->bbsum);
	} else if (format == 'j') {
		a->cb_printf ("\"graph\":{\"cc\":%d,\"nbbs\":%d,\"edges\":%d,\"ebbs\":%d,\"bbsum\":%d},",
			graph->cc, graph->nbbs, graph->edges, graph->ebbs, graph->bbsum);
	} else {
		a->cb_printf ("  graph: cc=%d nbbs=%d edges=%d ebbs=%d bbsum=%d\n",
			graph->cc, graph->nbbs, graph->edges, graph->ebbs, graph->bbsum);
	}
}

static void listComment(RAnal *a, RSignItem *it, int format) {
	if (it->comment) {
		if (format == 'q') {
			//	a->cb_printf (" addr(0x%08"PFMT64x")", it->addr);
			a->cb_printf ("\n ; %s\n", it->comment);
		} else if (format == '*') {
			a->cb_printf ("%s\n", it->comment); // comment injection via CCu..
		} else if (format == 'j') {
			a->cb_printf ("\"comments\":\"%s\",", it->comment);
		} else {
			a->cb_printf ("  comment: 0x%08"PFMT64x"\n", it->addr);
		}
	}
}

static void listRealname(RAnal *a, RSignItem *it, int format) {
	if (it->realname) {
		if (format == 'q') {
			//	a->cb_printf (" addr(0x%08"PFMT64x")", it->addr);
		} else if (format == '*') {
			a->cb_printf ("za %s n %s\n", it->name, it->realname);
			a->cb_printf ("afn %s @ 0x%08"PFMT64x"\n", it->realname, it->addr);
		} else if (format == 'j') {
			a->cb_printf ("\"realname\":\"%s\",", it->realname);
		} else {
			a->cb_printf ("  realname: %s\n", it->realname);
		}
	}
}

static void listOffset(RAnal *a, RSignItem *it, int format) {
	if (format == 'q') {
	//	a->cb_printf (" addr(0x%08"PFMT64x")", it->addr);
	} else if (format == '*') {
		a->cb_printf ("za %s o 0x%08"PFMT64x"\n", it->name, it->addr);
	} else if (format == 'j') {
		a->cb_printf ("\"addr\":%"PFMT64d",", it->addr);
	} else {
		a->cb_printf ("  addr: 0x%08"PFMT64x"\n", it->addr);
	}
}

static void listVars(RAnal *a, RSignItem *it, int format) {
	RListIter *iter = NULL;
	char *var = NULL;
	int i = 0;

	if (format == '*') {
		a->cb_printf ("za %s v ", it->name);
	} else if (format == 'q') {
		a->cb_printf (" vars(%d)", r_list_length (it->vars));
		return;
	} else if (format == 'j') {
		a->cb_printf ("\"vars\":[");
	} else {
		a->cb_printf ("  vars: ");
	}

	r_list_foreach (it->vars, iter, var) {
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
			a->cb_printf ("\"%s\"", var);
		} else {
			a->cb_printf ("%s", var);
		}
		i++;
	}

	if (format == 'j') {
		a->cb_printf ("],");
	} else {
		a->cb_printf ("\n");
	}
}

static void listTypes(RAnal *a, RSignItem *it, int format) {
	RListIter *iter = NULL;
	char *type = NULL;
	int i = 0;

	if (format == '*') {
		a->cb_printf ("za %s t ", it->name);
	} else if (format == 'q') {
		a->cb_printf (" types(%d)", r_list_length (it->types));
		return;
	} else if (format == 'j') {
		a->cb_printf ("\"types\":[");
	} else {
		a->cb_printf ("  types: ");
	}

	r_list_foreach (it->types, iter, type) {
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
			a->cb_printf ("\"%s\"", type);
		} else {
			a->cb_printf ("%s", type);
		}
		i++;
	}

	if (format == 'j') {
		a->cb_printf ("],");
	} else {
		a->cb_printf ("\n");
	}
}

static void listXRefs(RAnal *a, RSignItem *it, int format) {
	RListIter *iter = NULL;
	char *ref = NULL;
	int i = 0;

	if (format == '*') {
		a->cb_printf ("za %s x ", it->name);
	} else if (format == 'q') {
		a->cb_printf (" xrefs(%d)", r_list_length (it->xrefs));
		return;
	} else if (format == 'j') {
		a->cb_printf ("\"xrefs\":[");
	} else {
		if (it->xrefs && !r_list_empty (it->xrefs)) {
			a->cb_printf ("  xrefs: ");
		}
	}

	r_list_foreach (it->xrefs, iter, ref) {
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
		a->cb_printf ("],");
	} else {
		a->cb_printf ("\n");
	}
}

static void listRefs(RAnal *a, RSignItem *it, int format) {
	RListIter *iter = NULL;
	char *ref = NULL;
	int i = 0;

	if (format == '*') {
		a->cb_printf ("za %s r ", it->name);
	} else if (format == 'q') {
		a->cb_printf (" refs(%d)", r_list_length (it->refs));
		return;
	} else if (format == 'j') {
		a->cb_printf ("\"refs\":[");
	} else {
		if (it->refs && !r_list_empty (it->refs)) {
			a->cb_printf ("  refs: ");
		}
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
		a->cb_printf ("],");
	} else {
		a->cb_printf ("\n");
	}
}

static void listHash(RAnal *a, RSignItem *it, int format) {
	if (!it->hash) {
		return;
	}
	switch (format) {
	case 'q':
		if (it->hash->bbhash) {
			a->cb_printf (" h(%08x)", r_str_hash(it->hash->bbhash));
		}
		break;
	case '*':
		if (it->hash->bbhash) {
			a->cb_printf ("za %s h %s\n", it->name, it->hash->bbhash);
		}
		break;
	case 'j':
		a->cb_printf ("\"hash\":{");
		if (it->hash->bbhash) {
			a->cb_printf ("\"bbhash\":\"%s\"", it->hash->bbhash);
		}
		a->cb_printf ("}");
		break;
	default:
		if (it->hash->bbhash) {
			a->cb_printf ("  bbhash: %s\n", it->hash->bbhash);
		}
		break;
	}
}

static int listCB(void *user, const char *k, const char *v) {
	struct ctxListCB *ctx = (struct ctxListCB *) user;
	RSignItem *it = r_sign_item_new ();
	RAnal *a = ctx->anal;

	if (!r_sign_deserialize (a, it, k, v)) {
		eprintf ("error: cannot deserialize zign\n");
		goto out;
	}

	RSpace *cur = r_spaces_current (&a->zign_spaces);
	if (cur != it->space && cur) {
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
		if (it->space) {
			a->cb_printf ("zs %s\n", it->space->name);
		} else {
			a->cb_printf ("zs *\n");
		}
	} else if (ctx->format == 'q') {
		a->cb_printf ("0x%08"PFMT64x" ", it->addr);
		const char *pad = r_str_pad (' ', 30- strlen (it->name));
		a->cb_printf ("%s:%s", it->name, pad);
	} else if (ctx->format == 'j') {
		if (it->space) {
			a->cb_printf ("{\"zignspace\":\"%s\",", it->space->name);
		}
		a->cb_printf ("\"name\":\"%s\",", it->name);
	} else {
		if (!r_spaces_current (&a->zign_spaces) && it->space) {
			a->cb_printf ("(%s) ", it->space->name);
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
	if (it->addr != UT64_MAX) {
		listOffset (a, it, ctx->format);
	} else if (ctx->format == 'j') {
		a->cb_printf ("\"addr\":-1,");
	}
	// Name
	if (it->realname) {
		listRealname (a, it, ctx->format);
	}
	if (it->comment) {
		listComment (a, it, ctx->format);
	}
	// References
	if (it->refs) {
		listRefs (a, it, ctx->format);
	} else if (ctx->format == 'j') {
		a->cb_printf ("\"refs\":[],");
	}
	// XReferences
	if (it->xrefs) {
		listXRefs (a, it, ctx->format);
	} else if (ctx->format == 'j') {
		a->cb_printf ("\"xrefs\":[],");
	}
	// Vars
	if (it->vars) {
		listVars (a, it, ctx->format);
	} else if (ctx->format == 'j') {
		a->cb_printf ("\"vars\":[],");
	}
	if (it->types) {
		listTypes (a, it, ctx->format);
	} else if (ctx->format == 'j') {
		a->cb_printf ("\"types\":[],");
	}
	// Hash
	if (it->hash) {
		listHash (a, it, ctx->format);
	} else if (ctx->format == 'j') {
		a->cb_printf ("\"hash\":{}");
	}

	// End item
	if (ctx->format == 'j') {
		a->cb_printf ("}");
	}

	ctx->idx++;
	if (ctx->format == 'q') {
		a->cb_printf ("\n");
	}

out:
	r_sign_item_free (it);

	return 1;
}

R_API void r_sign_list(RAnal *a, int format) {
	r_return_if_fail (a);
	struct ctxListCB ctx = { a, 0, format };

	if (format == 'j') {
		a->cb_printf ("[");
	}

	sdb_foreach (a->sdb_zigns, listCB, &ctx);

	if (format == 'j') {
		a->cb_printf ("]\n");
	}
}

static int listGetCB(void *user, const char *key, const char *val) {
	struct ctxGetListCB *ctx = user;
	RSignItem *item = r_sign_item_new ();
	if (!item) {
		return false;
	}
	if (!r_sign_deserialize (ctx->anal, item, key, val)) {
		r_sign_item_free (item);
		return false;
	}
	r_list_append (ctx->list, item);

	return 1;
}

R_API RList *r_sign_get_list(RAnal *a) {
	r_return_val_if_fail (a, NULL);
	struct ctxGetListCB ctx = { a, r_list_newf ((RListFree)r_sign_item_free) };
	sdb_foreach (a->sdb_zigns, listGetCB, &ctx);
	return ctx.list;
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

struct ctxCountForCB {
	RAnal *anal;
	const RSpace *space;
	int count;
};

static int countForCB(void *user, const char *k, const char *v) {
	struct ctxCountForCB *ctx = (struct ctxCountForCB *) user;
	RSignItem *it = r_sign_item_new ();

	if (r_sign_deserialize (ctx->anal, it, k, v)) {
		if (it->space == ctx->space) {
			ctx->count++;
		}
	} else {
		eprintf ("error: cannot deserialize zign\n");
	}
	r_sign_item_free (it);

	return 1;
}

R_API int r_sign_space_count_for(RAnal *a, const RSpace *space) {
	struct ctxCountForCB ctx = { a, space, 0 };
	r_return_val_if_fail (a, 0);
	sdb_foreach (a->sdb_zigns, countForCB, &ctx);
	return ctx.count;
}

struct ctxUnsetForCB {
	RAnal *anal;
	const RSpace *space;
};

static int unsetForCB(void *user, const char *k, const char *v) {
	struct ctxUnsetForCB *ctx = (struct ctxUnsetForCB *) user;
	char nk[R_SIGN_KEY_MAXSZ], nv[R_SIGN_VAL_MAXSZ];
	RSignItem *it = r_sign_item_new ();
	Sdb *db = ctx->anal->sdb_zigns;

	if (r_sign_deserialize (ctx->anal, it, k, v)) {
		if (it->space && it->space == ctx->space) {
			it->space = NULL;
			serialize (ctx->anal, it, nk, nv);
			sdb_remove (db, k, 0);
			sdb_set (db, nk, nv, 0);
		}
	} else {
		eprintf ("error: cannot deserialize zign\n");
	}
	r_sign_item_free (it);

	return 1;
}

R_API void r_sign_space_unset_for(RAnal *a, const RSpace *space) {
	r_return_if_fail (a);
	struct ctxUnsetForCB ctx = { a, space };
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

R_API void r_sign_space_rename_for(RAnal *a, const RSpace *space, const char *oname, const char *nname) {
	r_return_if_fail (a && space && oname && nname);
	struct ctxRenameForCB ctx = {.anal = a};
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

	if (r_sign_deserialize (a, it, k, v)) {
		RSpace *cur = r_spaces_current (&a->zign_spaces);
		if (ctx->cb && cur == it->space) {
			ctx->cb (it, ctx->user);
		}
	} else {
		eprintf ("error: cannot deserialize zign\n");
	}
	r_sign_item_free (it);
	return retval;
}

R_API bool r_sign_foreach(RAnal *a, RSignForeachCallback cb, void *user) {
	r_return_val_if_fail (a && cb, false);
	struct ctxForeachCB ctx = { a, cb, user };
	return sdb_foreach (a->sdb_zigns, foreachCB, &ctx);
}

R_API RSignSearch *r_sign_search_new() {
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
	RSearchKeyword *kw = NULL;

	if (!bytes) {
		eprintf ("Cannot find bytes for this signature: %s\n", it->name);
		return 1;
	}

	if (ctx->minsz && bytes->size < ctx->minsz) {
		return 1;
	}
	RSignItem *it2 = r_sign_item_dup (it);
	if (it2) {
		r_list_append (ss->items, it2);
		// TODO(nibble): change arg data in r_search_keyword_new to void*
		kw = r_search_keyword_new (bytes->bytes, bytes->size, bytes->mask, bytes->size, (const char *) it2);
		r_search_kw_add (ss->search, kw);
	}
	return 1;
}

R_API void r_sign_search_init(RAnal *a, RSignSearch *ss, int minsz, RSignSearchCallback cb, void *user) {
	struct ctxAddSearchKwCB ctx = { ss, minsz };
	r_return_if_fail (a && ss && cb);
	ss->cb = cb;
	ss->user = user;
	r_list_purge (ss->items);
	r_search_reset (ss->search, R_SEARCH_KEYWORD);
	r_sign_foreach (a, addSearchKwCB, &ctx);
	r_search_begin (ss->search);
	r_search_set_callback (ss->search, searchHitCB, ss);
}

R_API int r_sign_search_update(RAnal *a, RSignSearch *ss, ut64 *at, const ut8 *buf, int len) {
	r_return_val_if_fail (a && ss && buf && len > 0, 0);
	return r_search_update (ss->search, *at, buf, len);
}

// allow ~10% of margin error
static int matchCount(int a, int b) {
	int c = a - b;
	int m = a / 10;
	return R_ABS (c) < m;
}

static bool fcnMetricsCmp(RSignItem *it, RAnalFunction *fcn) {
	RSignGraph *graph = it->graph;
	int ebbs = -1;

	if (graph->cc != -1 && graph->cc != r_anal_fcn_cc (NULL, fcn)) {
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
	if (graph->bbsum > 0 && matchCount (graph->bbsum, r_anal_function_linear_size (fcn))) {
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
	r_return_val_if_fail (a && fcn && cb, false);
	struct ctxFcnMatchCB ctx = { a, fcn, cb, user, mincc };
	return r_sign_foreach (a, graphMatchCB, &ctx);
}

static int addrMatchCB(RSignItem *it, void *user) {
	struct ctxFcnMatchCB *ctx = (struct ctxFcnMatchCB *) user;

	if (it->addr == UT64_MAX) {
		return 1;
	}

	if (it->addr != ctx->fcn->addr) {
		return 1;
	}

	if (ctx->cb) {
		return ctx->cb (it, ctx->fcn, ctx->user);
	}

	return 1;
}

R_API bool r_sign_match_addr(RAnal *a, RAnalFunction *fcn, RSignOffsetMatchCallback cb, void *user) {
	r_return_val_if_fail (a && fcn && cb, false);
	struct ctxFcnMatchCB ctx = { a, fcn, cb, user, 0 };
	return r_sign_foreach (a, addrMatchCB, &ctx);
}

static int hashMatchCB(RSignItem *it, void *user) {
	struct ctxFcnMatchCB *ctx = (struct ctxFcnMatchCB *) user;
	RSignHash *hash = it->hash;

	if (!hash || !hash->bbhash || hash->bbhash[0] == 0) {
		return 1;
	}

	char *digest_hex = r_sign_calc_bbhash (ctx->anal, ctx->fcn);
	bool retval = false;
	if (digest_hex && strcmp (hash->bbhash, digest_hex)) {
		goto beach;
	}

	if (ctx->cb) {
		retval = ctx->cb (it, ctx->fcn, ctx->user);
	}
beach:
	free (digest_hex);
	return retval;
}

R_API bool r_sign_match_hash(RAnal *a, RAnalFunction *fcn, RSignHashMatchCallback cb, void *user) {
	r_return_val_if_fail (a && fcn && cb, false);
	struct ctxFcnMatchCB ctx = { a, fcn, cb, user, 0 };
	return r_sign_foreach (a, hashMatchCB, &ctx);
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
	r_return_val_if_fail (a && fcn && cb, false);
	struct ctxFcnMatchCB ctx = { a, fcn, cb, user, 0 };
	return r_sign_foreach (a, refsMatchCB, &ctx);
}

static int varsMatchCB(RSignItem *it, void *user) {
	struct ctxFcnMatchCB *ctx = (struct ctxFcnMatchCB *) user;
	RList *vars = NULL;
	char *var_a = NULL, *var_b = NULL;
	int i = 0, retval = 1;

	if (!it->vars) {
		return 1;
	}

	// TODO(nibble): slow operation, add cache
	vars = r_sign_fcn_vars (ctx->anal, ctx->fcn);
	if (!vars) {
		return 1;
	}

	for (i = 0; ; i++) {
		var_a = (char *) r_list_get_n (it->vars, i);
		var_b = (char *) r_list_get_n (vars, i);

		if (!var_a || !var_b) {
			if (var_a != var_b) {
				retval = 1;
				goto out;
			}
			break;
		}
		if (strcmp (var_a, var_b)) {
			retval = 1;
			goto out;
		}
	}

	if (ctx->cb) {
		retval = ctx->cb (it, ctx->fcn, ctx->user);
		goto out;
	}

out:
	r_list_free (vars);

	return retval;
}

R_API bool r_sign_match_vars(RAnal *a, RAnalFunction *fcn, RSignVarsMatchCallback cb, void *user) {
	r_return_val_if_fail (a && fcn && cb, false);
	struct ctxFcnMatchCB ctx = { a, fcn, cb, user, 0 };
	return r_sign_foreach (a, varsMatchCB, &ctx);
}

static int typesMatchCB(RSignItem *it, void *user) {
	struct ctxFcnMatchCB *ctx = (struct ctxFcnMatchCB *) user;
	RList *types = NULL;
	char *type_a = NULL, *type_b = NULL;
	int i = 0, retval = 1;

	if (!it->types) {
		return 1;
	}
	// TODO(nibble | oxcabe): slow operation, add cache
	types = r_sign_fcn_types (ctx->anal, ctx->fcn);
	if (!types) {
		return 1;
	}
	for (i = 0; ; i++) {
		type_a = (char *) r_list_get_n (it->types, i);
		type_b = (char *) r_list_get_n (types, i);

		if (!type_a || !type_b) {
			if (type_a != type_b) {
				retval = 1;
				goto out;
			}
			break;
		}
		if (strcmp (type_a, type_b)) {
			retval = 1;
			goto out;
		}
	}

	if (ctx->cb) {
		retval = ctx->cb (it, ctx->fcn, ctx->user);
		goto out;
	}

out:
	r_list_free (types);

	return retval;
}

R_API bool r_sign_match_types(RAnal *a, RAnalFunction *fcn, RSignVarsMatchCallback cb, void *user) {
	r_return_val_if_fail (a && fcn && cb, false);
	struct ctxFcnMatchCB ctx = { a, fcn, cb, user, 0 };
	return r_sign_foreach (a, typesMatchCB, &ctx);
}

R_API RSignItem *r_sign_item_new() {
	RSignItem *ret = R_NEW0 (RSignItem);
	if (ret) {
		ret->addr = UT64_MAX;
		ret->space = NULL;
	}
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
		return NULL;
	}
	ret->name = r_str_new (it->name);
	if (it->realname) {
		ret->realname = r_str_newf (it->realname);
	}
	if (it->comment) {
		ret->comment = r_str_newf (it->comment);
	}
	ret->space = it->space;

	if (it->bytes) {
		ret->bytes = R_NEW0 (RSignBytes);
		if (!ret->bytes) {
			r_sign_item_free (ret);
			return NULL;
		}
		ret->bytes->size = it->bytes->size;
		ret->bytes->bytes = malloc (it->bytes->size);
		if (!ret->bytes->bytes) {
			r_sign_item_free (ret);
			return NULL;
		}
		memcpy (ret->bytes->bytes, it->bytes->bytes, it->bytes->size);
		ret->bytes->mask = malloc (it->bytes->size);
		if (!ret->bytes->mask) {
			r_sign_item_free (ret);
			return NULL;
		}
		memcpy (ret->bytes->mask, it->bytes->mask, it->bytes->size);
	}

	if (it->graph) {
		ret->graph = R_NEW0 (RSignGraph);
		if (!ret->graph) {
			r_sign_item_free (ret);
			return NULL;
		}
		*ret->graph = *it->graph;
	}

	ret->refs = r_list_newf ((RListFree) free);
	r_list_foreach (it->refs, iter, ref) {
		r_list_append (ret->refs, r_str_new (ref));
	}
	ret->xrefs = r_list_newf ((RListFree) free);
	r_list_foreach (it->xrefs, iter, ref) {
		r_list_append (ret->xrefs, r_str_new (ref));
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
	if (item->hash) {
		free (item->hash->bbhash);
		free (item->hash);
	}
	free (item->graph);
	free (item->comment);
	free (item->realname);
	r_list_free (item->refs);
	r_list_free (item->vars);
	free (item);
}

static int loadCB(void *user, const char *k, const char *v) {
	RAnal *a = (RAnal *) user;
	char nk[R_SIGN_KEY_MAXSZ], nv[R_SIGN_VAL_MAXSZ];
	RSignItem *it = r_sign_item_new ();
	if (it && r_sign_deserialize (a, it, k, v)) {
		serialize (a, it, nk, nv);
		sdb_set (a->sdb_zigns, nk, nv, 0);
	} else {
		eprintf ("error: cannot deserialize zign\n");
	}
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
		eprintf ("WARNING: no zignatures to save\n");
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
