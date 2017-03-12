/* radare - LGPL - Copyright 2009-2017 - pancake, nibble */

#include <r_sign.h>
#include <r_anal.h>

#define R_SIGN_KEY_MAXSZ 1024
#define R_SIGN_VAL_MAXSZ 10240

R_LIB_VERSION (r_sign);

static bool deserialize(RSignItem *it, const char *k, const char *v) {
	char *k2 = NULL, *v2 = NULL, *ptr = NULL, *token = NULL;
	int i = 0;
	bool retval = true;

	k2 = r_str_new (k);
	v2 = r_str_new (v);

	// Deserialize key: zign,<space>,<name>
	for (ptr = k2, i = 0; ; ptr = NULL, i++) {
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

	// Deserialize val: <type>,size,bytes,mask
	for (ptr = v2, i = 0; ; ptr = NULL, i++) {
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
			it->bytes = malloc (it->size);
			r_hex_str2bin(token, it->bytes);
			break;
		case 3:
			it->mask = malloc (it->size);
			r_hex_str2bin(token, it->mask);
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
	char *hexbytes = NULL, *hexmask = NULL;
	int len;

	if (k) {
		snprintf (k, R_SIGN_KEY_MAXSZ, "zign|%d|%s", it->space, it->name);
	}

	if (v) {
		len = it->size * 2 + 1;

		hexbytes = calloc (1, len);
		hexmask = calloc (1, len);

		r_hex_bin2str (it->bytes, it->size, hexbytes);
		r_hex_bin2str (it->mask, it->size, hexmask);

		snprintf (v, R_SIGN_VAL_MAXSZ, "%c|%d|%s|%s", it->type, it->size, hexbytes, hexmask);

		free (hexbytes);
		free (hexmask);
	}
}

R_API bool r_sign_add(RAnal *a, int type, const char *name, ut64 size, const ut8 *bytes, const ut8 *mask) {
	RSignItem *it = R_NEW0 (RSignItem);
	char key[R_SIGN_KEY_MAXSZ], val[R_SIGN_VAL_MAXSZ];
	bool retval = true;

	it->type = type;
	it->name = r_str_new (name);
	it->space = a->zign_spaces.space_idx;
	it->size = size;

	it->bytes = malloc (size);
	memcpy (it->bytes, bytes, size);
	it->mask = malloc (size);
	memcpy (it->mask, mask, size);

	serialize (it, key, val);

	if (sdb_exists (a->sdb_zigns, key)) {
		eprintf ("error: zignature already exists\n");
		retval = false;
		goto exit_function;
	}

	sdb_set (a->sdb_zigns, key, val, 0);

exit_function:
	r_sign_item_free (it);

	return retval;
}

R_API bool r_sign_add_anal(RAnal *a, const char *name, ut64 size, const ut8 *bytes) {
	ut8 *mask = NULL;
	bool retval = true;

	mask = r_anal_mask (a, size, bytes);
	retval = r_sign_add(a, R_SIGN_ANAL, name, size, bytes, mask);

	free (mask);
	return retval;
}

struct ctxDeleteCB {
	char buf[R_SIGN_KEY_MAXSZ];
	RAnal *anal;
};

int zignDeleteCB(void *user, const char *k, const char *v) {
	struct ctxDeleteCB *ctx = (struct ctxDeleteCB *)user;

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
			sdb_foreach (a->sdb_zigns, zignDeleteCB, &ctx);
			return true;
		}
	}

	// Remove specific zign
	it.name = (char*)name;
	it.space = a->zign_spaces.space_idx;
	serialize (&it, buf, NULL);
	return sdb_remove (a->sdb_zigns, buf, 0);
}

struct ctxListCB {
	int idx;
	int format;
	RAnal *anal;
};

int zignListCB(void *user, const char *k, const char *v) {
	struct ctxListCB *ctx = (struct ctxListCB *)user;
	RSignItem *it = R_NEW0 (RSignItem);
	RAnal *a = ctx->anal;
	char *bytes = NULL;
	int i;

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

	for (i = 0; i < it->size; i++){
		if (!it->mask[i]) {
			bytes = r_str_concatf (bytes, "..");
		} else {
			bytes = r_str_concatf (bytes, "%02x", it->bytes[i]);
		}
	}

	if (ctx->format == '*') {
		if (it->space >= 0) {
			a->cb_printf ("zs %s\n", a->zign_spaces.spaces[it->space]);
		} else {
			a->cb_printf ("zs *\n");
		}
		a->cb_printf ("z%c %s %s\n", it->type, it->name, bytes);
	} else if (ctx->format == 'j') {
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

	ctx->idx++;

exit_function:
	r_sign_item_free (it);
	free (bytes);

	return 1;
}

R_API void r_sign_list(RAnal *a, int format) {
	struct ctxListCB ctx = {0, format, a};

	if (format == 'j') {
		a->cb_printf ("[");
	}

	sdb_foreach (a->sdb_zigns, zignListCB, &ctx);

	if (format == 'j') {
		a->cb_printf ("]\n");
	}
}

struct ctxCountForCB {
	int idx;
	int count;
};

int zignCountForCB(void *user, const char *k, const char *v) {
	struct ctxCountForCB *ctx = (struct ctxCountForCB *)user;
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
	struct ctxCountForCB ctx = {idx, 0};

	sdb_foreach (a->sdb_zigns, zignCountForCB, &ctx);

	return ctx.count;
}

struct ctxUnsetForCB {
	int idx;
	RAnal *anal;
};

int zignUnsetForCB(void *user, const char *k, const char *v) {
	struct ctxUnsetForCB *ctx = (struct ctxUnsetForCB *)user;
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
	struct ctxUnsetForCB ctx = {idx, a};

	sdb_foreach (a->sdb_zigns, zignUnsetForCB, &ctx);
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
