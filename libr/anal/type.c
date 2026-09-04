/* radare - LGPL - Copyright 2019-2023 - pancake, oddcoder, Anton Kochkov */

#include <r_anal.h>
#include <r_anal_priv.h>
#include <stdarg.h>
#include <string.h>
#include <sdb/sdb.h>
#include "function_snapshot.h"

#define KSZ 256

// XXX this function needs to be rewritten
static char *is_type(char *type) {
	char *name = NULL;
	if ((name = strstr (type, "=type")) ||
			(name = strstr (type, "=struct")) ||
			(name = strstr (type, "=union")) ||
			(name = strstr (type, "=enum")) ||
			(name = strstr (type, "=typedef")) ||
			(name = strstr (type, "=func"))) {
		return name;
	}
	return NULL;
}

static char *get_type_data(Sdb *sdb_types, const char *type, const char *sname) {
	const char *value = sdb_const_getf (sdb_types, NULL, "%s.%s", type, sname);
	return value? strdup (value): NULL;
}

static void sdb_concat_by_path(Sdb *s, const char *path) {
	R_RETURN_IF_FAIL (s && path);
	Sdb *db = sdb_new (0, path, 0);
	if (db) {
		sdb_merge (s, db);
		sdb_close (db);
		sdb_free (db);
	}
}

static void load_types_from(RAnal *anal, const char *fmt, ...) {
	R_RETURN_IF_FAIL (anal && fmt);
	va_list ap;
	va_start (ap, fmt);
	char *s = r_str_newvf (fmt, ap);
	va_end (ap);
	if (!s) {
		return;
	}
	SdbGperf *gp = r_anal_get_gperf_types (s);
	if (gp) {
#if HAVE_GPERF
		Sdb *gd = sdb_new0 ();
		if (gd) {
			sdb_open_gperf (gd, gp);
			sdb_merge (anal->sdb_types, gd);
			sdb_close (gd);
			sdb_free (gd);
		}
#endif
	} else {
		const char *dir_prefix = R_ANAL_PRIV (anal)->dir_prefix;
		if (R_STR_ISNOTEMPTY (dir_prefix)) {
			char *dbpath = r_str_newf ("%s/%s/%s.sdb", dir_prefix, R2_SDB_FCNSIGN, s);
			if (dbpath && r_file_exists (dbpath)) {
				sdb_concat_by_path (anal->sdb_types, dbpath);
			}
			free (dbpath);
		}
	}
	free (s);
}

R_IPI void r_anal_types_ensure_loaded(RAnal *anal) {
	R_RETURN_IF_FAIL (anal && anal->config && anal->sdb_types);
	RAnalPriv *priv = R_ANAL_PRIV (anal);
	const char *arch = anal->config->arch;
	const int bits = anal->config->bits;
	const char *os = anal->config->os;
	const bool merge = !priv->types_loaded_bits && !sdb_isempty (anal->sdb_types);

	if (!priv->types_dirty && priv->types_loaded_bits == bits) {
		return;
	}
	if (!arch) {
		arch = "";
	}
	if (!os) {
		os = "";
	}
	if (!merge) {
		sdb_reset (anal->sdb_types);
	}
	load_types_from (anal, "types");
	load_types_from (anal, "types-%s", arch);
	load_types_from (anal, "types-%s", os);
	if (!strcmp (os, "ios") || !strcmp (os, "macos")) {
		load_types_from (anal, "types-darwin");
	}
	if (!strcmp (os, "android")) {
		load_types_from (anal, "types-jni");
	}
	load_types_from (anal, "types-%d", bits);
	load_types_from (anal, "types-%s-%d", os, bits);
	load_types_from (anal, "types-%s-%d", arch, bits);
	load_types_from (anal, "types-%s-%s", arch, os);
	load_types_from (anal, "types-%s-%s-%d", arch, os, bits);
	priv->types_dirty = false;
	priv->types_loaded_bits = bits;
	r_anal_types_bump_dirty_epoch (anal);
}

R_API void r_anal_types_reload(RAnal *anal, const char *dir_prefix, const char *os, const char *subsystem) {
	R_RETURN_IF_FAIL (anal && anal->config && anal->sdb_types);
	RAnalPriv *priv = R_ANAL_PRIV (anal);
	if (R_STR_ISNOTEMPTY (dir_prefix)) {
		free (priv->dir_prefix);
		priv->dir_prefix = strdup (dir_prefix);
	}
	const char *arch = anal->config->arch;
	const int bits = anal->config->bits;
	// Check if types need to be reloaded due to bits change
	if (!priv->types_dirty && priv->types_loaded_bits == bits) {
		return;
	}
	if (!arch) {
		arch = "";
	}
	if (!os) {
		os = anal->config->os;
	}
	if (!os) {
		os = "";
	}
	sdb_reset (anal->sdb_types);
	load_types_from (anal, "types");
	load_types_from (anal, "types-%s", arch);
	load_types_from (anal, "types-%s", os);
	if (!strcmp (os, "ios") || !strcmp (os, "macos")) {
		load_types_from (anal, "types-darwin");
	}
	if (subsystem && !strcmp (subsystem, "xnu")) {
		load_types_from (anal, "types-iokit");
	}
	if (!strcmp (os, "android")) {
		load_types_from (anal, "types-jni");
	}
	load_types_from (anal, "types-%d", bits);
	load_types_from (anal, "types-%s-%d", os, bits);
	load_types_from (anal, "types-%s-%d", arch, bits);
	load_types_from (anal, "types-%s-%s", arch, os);
	load_types_from (anal, "types-%s-%s-%d", arch, os, bits);
	priv->types_dirty = false;
	priv->types_loaded_bits = bits;
	r_anal_types_bump_dirty_epoch (anal);
}

R_API void r_anal_types_load_sdb(RAnal *anal, const char *name) {
	R_RETURN_IF_FAIL (anal && name);
	load_types_from (anal, "%s", name);
	r_anal_types_bump_dirty_epoch (anal);
}

// a pointer is one target word wide, which r_type_get_bitsize cannot know from the sdb alone
R_API ut64 r_anal_type_bitsize(RAnal *anal, const char *type) {
	R_RETURN_VAL_IF_FAIL (anal && anal->config && type, 0);
	// resolve first: "typedef char *string" is a pointer with no star in its name
	char *resolved = r_type_resolve_typedef (anal->sdb_types, type);
	const char *effective = resolved? resolved: type;
	const ut64 bits = strchr (effective, '*')
		? anal->config->bits
		: r_type_get_bitsize (anal->sdb_types, type);
	free (resolved);
	return bits;
}

R_API void r_anal_remove_parsed_type(RAnal *anal, const char *name) {
	R_RETURN_IF_FAIL (anal && name);
	Sdb *TDB = anal->sdb_types;
	SdbKv *kv;
	SdbListIter *iter;
	const char *type = sdb_const_get (TDB, name, 0);
	if (!type) {
		return;
	}

	// Create a subkey before the call to r_type_del (which leaves the type string invalid)
	char *subkey = r_str_newf ("%s.%s.", type, name);
	r_type_del (TDB, name);

	// TODO: This loop should be optimized
	SdbList *l = sdb_foreach_list (TDB, true);
	size_t subkey_len = strlen (subkey);
	ls_foreach (l, iter, kv) {
		const char *key = sdbkv_key (kv);
		if (!strncmp (key, subkey, subkey_len)) {
			r_type_del (TDB, key);
		}
	}
	ls_free (l);
	free (subkey);
	r_anal_types_bump_dirty_epoch (anal);
}

// RENAME TO r_anal_types_save(); // parses the string and imports the types
R_API void r_anal_save_parsed_type(RAnal *anal, const char *parsed) {
	R_RETURN_IF_FAIL (anal && parsed);
	r_anal_types_ensure_loaded (anal);

	// First, if any parsed types exist, let's remove them.
	char *type = strdup (parsed);
	if (type) {
		char *cur = type;
		while (1) {
			cur = is_type (cur);
			if (!cur) {
				break;
			}
			char *name = cur++;
			*name = 0;
			while (name > type && *(name - 1) != '\n') {
				name--;
			}
			r_anal_remove_parsed_type (anal, name);
		}
		free (type);
	}

	// Now add the type to sdb.
	sdb_query_lines (anal->sdb_types, parsed);
	r_anal_types_bump_dirty_epoch (anal);
}

R_API bool r_anal_import_c_decls(RAnal *anal, const char *decls, char **errmsg) {
	R_RETURN_VAL_IF_FAIL (anal && decls, false);
	if (errmsg) {
		*errmsg = NULL;
	}
	char *error_msg = NULL;
	char *out = r_anal_cparse (anal, decls, &error_msg);
	if (out) {
		r_anal_save_parsed_type (anal, out);
	}
	if (errmsg) {
		*errmsg = error_msg;
	} else {
		free (error_msg);
	}
	bool success = out != NULL;
	free (out);
	return success;
}

static ut64 typecmp_val(const void *a) {
	return r_str_hash64 (a);
}

R_API RList *r_anal_types_from_fcn(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, NULL);
	RList *type_used = r_list_new ();
	if (!type_used) {
		return NULL;
	}
	RAnalVar **it;
	R_VEC_FOREACH (&fcn->vars, it) {
		RAnalVar *var = *it;
		r_list_append (type_used, var->type);
	}
	r_list_uniq_inplace (type_used, typecmp_val);
	return type_used;
}

static RAnalBaseType *get_enum_type(RAnal *anal, const char *sname) {
	R_RETURN_VAL_IF_FAIL (anal && sname, NULL);

	RAnalBaseType *base_type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ENUM);
	if (!base_type) {
		return NULL;
	}
	const ut64 recorded = sdb_num_getf (anal->sdb_types, NULL, "type.%s.size", sname);
	base_type->size = recorded? recorded: 32;

	char *members = get_type_data (anal->sdb_types, "enum", sname);
	if (!members) {
		goto error;
	}

	RVecAnalEnumCase *cases = &base_type->enum_data.cases;
	if (!RVecAnalEnumCase_reserve (cases, (size_t)sdb_alen (members))) {
		goto error;
	}

	char *cur;
	sdb_aforeach (cur, members) {
		const char *value = sdb_const_getf (anal->sdb_types, NULL, "enum.%s.%s", sname, cur);

		if (!value) { // if nothing is found, ret NULL
			goto error;
		}

		RAnalEnumCase cas = { .name = strdup (cur), .val = strtol (value, NULL, 16) };
		if (!cas.name) {
			goto error;
		}
		RAnalEnumCase *element = RVecAnalEnumCase_emplace_back (cases);
		if (!element) {
			free (cas.name);
			goto error;
		}
		*element = cas;

		sdb_aforeach_next (cur);
	}
	free (members);

	return base_type;

error:
	free (members);
	r_anal_base_type_free (base_type);
	return NULL;
}

// values is "type,offset,count"; split from the end since the type may itself contain commas
static void split_member_csv(char *values, const char **offset, const char **count) {
	*offset = NULL;
	*count = NULL;
	char *last = (char *)r_str_rchr (values, NULL, ',');
	if (!last) {
		return;
	}
	*last = 0;
	char *mid = (char *)r_str_rchr (values, last - 1, ',');
	if (mid) {
		*mid = 0;
		*offset = mid + 1;
		*count = last + 1;
	} else {
		*offset = last + 1;
	}
}

static RAnalBaseType *get_composite_type(RAnal *anal, const char *sname, RAnalBaseTypeKind kind) {
	R_RETURN_VAL_IF_FAIL (anal && sname, NULL);

	RAnalBaseType *base_type = r_anal_base_type_new (kind);
	if (!base_type) {
		return NULL;
	}

	const char *kindstr = (kind == R_ANAL_BASE_TYPE_KIND_UNION)? "union": "struct";
	char *sdb_members = get_type_data (anal->sdb_types, kindstr, sname);
	if (!sdb_members) {
		goto error;
	}

	RVecAnalTypeMember *members = r_anal_base_type_members (base_type);
	if (!RVecAnalTypeMember_reserve (members, (size_t)sdb_alen (sdb_members))) {
		goto error;
	}

	char *cur;
	sdb_aforeach (cur, sdb_members) {
		const char *value = sdb_const_getf (anal->sdb_types, NULL, "%s.%s.%s", kindstr, sname, cur);
		char *values = value? strdup (value): NULL;

		if (!values) {
			goto error;
		}
		const char *offset = NULL;
		const char *count = NULL;
		split_member_csv (values, &offset, &count);
		RAnalTypeMember memb = {
			.name = strdup (cur),
			.type = strdup (values),
			.offset = offset? strtoul (offset, NULL, 10): 0,
			.count = R_STR_ISNOTEMPTY (count)? strtoul (count, NULL, 10): 0
		};
		free (values);
		if (!memb.name || !memb.type) {
			anal_type_member_fini (&memb);
			goto error;
		}
		RAnalTypeMember *element = RVecAnalTypeMember_emplace_back (members);
		if (!element) {
			anal_type_member_fini (&memb);
			goto error;
		}
		*element = memb;

		sdb_aforeach_next (cur);
	}
	free (sdb_members);
	base_type->size = sdb_num_getf (anal->sdb_types, NULL, "type.%s.size", sname);

	return base_type;

error:
	r_anal_base_type_free (base_type);
	free (sdb_members);
	return NULL;
}

static RAnalBaseType *get_typedef_type(RAnal *anal, const char *sname) {
	R_RETURN_VAL_IF_FAIL (anal && R_STR_ISNOTEMPTY (sname), NULL);

	RAnalBaseType *base_type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_TYPEDEF);
	if (!base_type) {
		return NULL;
	}

	base_type->type = get_type_data (anal->sdb_types, "typedef", sname);
	if (!base_type->type) {
		goto error;
	}
	return base_type;

error:
	r_anal_base_type_free (base_type);
	return NULL;
}

static RAnalBaseType *get_atomic_type(RAnal *anal, const char *sname) {
	R_RETURN_VAL_IF_FAIL (anal && R_STR_ISNOTEMPTY (sname), NULL);
	RAnalBaseType *base_type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	if (base_type) {
		base_type->type = get_type_data (anal->sdb_types, "type", sname);
		if (base_type->type) {
			base_type->size = sdb_num_getf (anal->sdb_types, NULL, "type.%s.size", sname);
			return base_type;
		}
		r_anal_base_type_free (base_type);
	}
	return NULL;
}

// returns NULL if name is not found or any failure happened
R_API RAnalBaseType *r_anal_get_base_type(RAnal *anal, const char *name) {
	R_RETURN_VAL_IF_FAIL (anal && name, NULL);

	// a base type is saved under its C spelling; composites and typedefs still under the sanitized one
	char *sname = strdup (name);
	const char *type = sdb_const_get (anal->sdb_types, sname, NULL);
	if (!type) {
		free (sname);
		sname = r_str_sanitize_sdb_key (name);
		type = sdb_const_get (anal->sdb_types, sname, NULL);
	}
	if (!type) {
		free (sname);
		return NULL;
	}

	RAnalBaseType *base_type = NULL;
	if (!strcmp (type, "struct")) {
		base_type = get_composite_type (anal, sname, R_ANAL_BASE_TYPE_KIND_STRUCT);
	} else if (!strcmp (type, "enum")) {
		base_type = get_enum_type (anal, sname);
	} else if (!strcmp (type, "union")) {
		base_type = get_composite_type (anal, sname, R_ANAL_BASE_TYPE_KIND_UNION);
	} else if (!strcmp (type, "typedef")) {
		base_type = get_typedef_type (anal, sname);
	} else if (!strcmp (type, "type")) {
		base_type = get_atomic_type (anal, sname);
	}

	if (base_type) {
		base_type->name = sname;
	} else {
		free (sname);
	}

	return base_type;
}

static int base_type_name_cmp(const void *a, const void *b) {
	const RAnalBaseType *ta = (const RAnalBaseType *)a;
	const RAnalBaseType *tb = (const RAnalBaseType *)b;
	return strcmp (ta && ta->name? ta->name: "", tb && tb->name? tb->name: "");
}

static RAnalBaseType *get_base_type_for_kind(RAnal *anal, const char *kind, const char *sname) {
	R_RETURN_VAL_IF_FAIL (anal && R_STR_ISNOTEMPTY (kind) && R_STR_ISNOTEMPTY (sname), NULL);
	if (!strcmp (kind, "struct")) {
		return get_composite_type (anal, sname, R_ANAL_BASE_TYPE_KIND_STRUCT);
	}
	if (!strcmp (kind, "enum")) {
		return get_enum_type (anal, sname);
	}
	if (!strcmp (kind, "union")) {
		return get_composite_type (anal, sname, R_ANAL_BASE_TYPE_KIND_UNION);
	}
	if (!strcmp (kind, "typedef")) {
		return get_typedef_type (anal, sname);
	}
	if (!strcmp (kind, "type")) {
		return get_atomic_type (anal, sname);
	}
	return NULL;
}

typedef enum {
	BASE_TYPE_APPEND_OK,
	BASE_TYPE_APPEND_SKIPPED,
	BASE_TYPE_APPEND_ERROR,
} BaseTypeAppendResult;

static BaseTypeAppendResult append_base_type_if_unseen(RAnal *anal, RList *types, Sdb *seen, const char *kind, const char *sname) {
	R_RETURN_VAL_IF_FAIL (anal && types && seen && R_STR_ISNOTEMPTY (kind) && R_STR_ISNOTEMPTY (sname), BASE_TYPE_APPEND_ERROR);
	char *seen_key = r_str_newf ("%s.%s", kind, sname);
	if (!seen_key) {
		return BASE_TYPE_APPEND_ERROR;
	}
	if (sdb_exists (seen, seen_key)) {
		free (seen_key);
		return BASE_TYPE_APPEND_SKIPPED;
	}
	RAnalBaseType *base_type = get_base_type_for_kind (anal, kind, sname);
	if (!base_type) {
		free (seen_key);
		return BASE_TYPE_APPEND_ERROR;
	}
	base_type->name = strdup (sname);
	if (!base_type->name || !sdb_set (seen, seen_key, "1", 0)
		|| !r_list_append (types, base_type)) {
		sdb_unset (seen, seen_key, 0);
		r_anal_base_type_free (base_type);
		free (seen_key);
		return BASE_TYPE_APPEND_ERROR;
	}
	free (seen_key);
	return BASE_TYPE_APPEND_OK;
}

static bool split_base_type_namespace_key(const char *key, const char **kind, const char **sname) {
	static const char *kinds[] = { "struct", "union", "enum", "typedef", "type", NULL };
	R_RETURN_VAL_IF_FAIL (key && kind && sname, false);
	size_t i;
	for (i = 0; kinds[i]; i++) {
		const char *candidate = kinds[i];
		const size_t len = strlen (candidate);
		if (strncmp (key, candidate, len) || key[len] != '.') {
			continue;
		}
		const char *name = key + len + 1;
		if (R_STR_ISEMPTY (name) || strchr (name, '.')) {
			return false;
		}
		*kind = candidate;
		*sname = name;
		return true;
	}
	return false;
}

typedef struct {
	size_t base_types;
	size_t children;
	size_t string_bytes;
} RAnalTypeSnapshotBudget;

static bool type_snapshot_budget_add(size_t *total, size_t amount, size_t maximum) {
	size_t next;
	if (r_add_overflow_size_t (*total, amount, &next) || next > maximum) {
		return false;
	}
	*total = next;
	return true;
}

static bool type_snapshot_budget_add_string(RAnalTypeSnapshotBudget *budget, size_t length) {
	size_t owned_bytes;
	return !r_add_overflow_size_t (length, 1, &owned_bytes)
		&& type_snapshot_budget_add (&budget->string_bytes, owned_bytes, SIZE_MAX);
}

static bool type_snapshot_budget_fits(
	const RAnalTypeSnapshotBudget *used,
	const RAnalTypeSnapshotBudget *added,
	const RAnalFunctionSnapshotLimits *limits) {
	size_t total;
	return !r_add_overflow_size_t (used->base_types, added->base_types, &total)
		&& total <= limits->max_base_types
		&& !r_add_overflow_size_t (used->children, added->children, &total)
		&& total <= limits->max_base_type_children
		&& !r_add_overflow_size_t (used->string_bytes, added->string_bytes, &total)
		&& total <= limits->max_base_type_string_bytes;
}

static bool type_snapshot_budget_commit(
	RAnalTypeSnapshotBudget *used,
	const RAnalTypeSnapshotBudget *added,
	const RAnalFunctionSnapshotLimits *limits) {
	if (!type_snapshot_budget_fits (used, added, limits)) {
		return false;
	}
	return type_snapshot_budget_add (&used->base_types, added->base_types, SIZE_MAX)
		&& type_snapshot_budget_add (&used->children, added->children, SIZE_MAX)
		&& type_snapshot_budget_add (&used->string_bytes, added->string_bytes, SIZE_MAX);
}

static bool type_snapshot_kind_supported(const char *kind) {
	return !strcmp (kind, "struct") || !strcmp (kind, "union")
		|| !strcmp (kind, "enum") || !strcmp (kind, "typedef")
		|| !strcmp (kind, "type");
}

static size_t type_snapshot_member_type_length(const char *value) {
	const char *last = strrchr (value, ',');
	if (!last) {
		return strlen (value);
	}
	const char *middle = NULL;
	const char *cursor;
	for (cursor = value; cursor < last; cursor++) {
		if (*cursor == ',') {
			middle = cursor;
		}
	}
	return (size_t)((middle? middle: last) - value);
}

static bool type_snapshot_preflight_one(
	RAnal *anal,
	Sdb *seen,
	RAnalTypeSnapshotBudget *used,
	const RAnalFunctionSnapshotLimits *limits,
	const char *kind,
	const char *sname) {
	const char *data = sdb_const_getf (anal->sdb_types, NULL, "%s.%s", kind, sname);
	if (!data) {
		return true;
	}
	size_t name_bytes;
	if (r_add_overflow_size_t (strlen (sname), 1, &name_bytes)
		|| name_bytes > limits->max_base_type_string_bytes) {
		return false;
	}
	char *seen_key = r_str_newf ("%s.%s", kind, sname);
	if (!seen_key) {
		return false;
	}
	if (sdb_exists (seen, seen_key)) {
		free (seen_key);
		return true;
	}
	RAnalTypeSnapshotBudget added = { .base_types = 1 };
	if (!type_snapshot_budget_add_string (&added, strlen (sname))
		|| !type_snapshot_budget_fits (used, &added, limits)) {
		free (seen_key);
		return false;
	}
	if (!strcmp (kind, "typedef") || !strcmp (kind, "type")) {
		if (!type_snapshot_budget_add_string (&added, strlen (data))) {
			free (seen_key);
			return false;
		}
	} else {
		const bool composite = strcmp (kind, "enum");
		const char *cursor = data;
		while (*cursor) {
			const char *comma = strchr (cursor, ',');
			const size_t name_length = comma? (size_t)(comma - cursor): strlen (cursor);
			if (!name_length) {
				cursor = comma? comma + 1: cursor + 1;
				continue;
			}
			if (!type_snapshot_budget_add (&added.children, 1, SIZE_MAX)
				|| !type_snapshot_budget_add_string (&added, name_length)
				|| !type_snapshot_budget_fits (used, &added, limits)) {
				free (seen_key);
				return false;
			}
			char *child_name = r_str_ndup (cursor, name_length);
			char *child_key = child_name
				? r_str_newf ("%s.%s.%s", kind, sname, child_name): NULL;
			free (child_name);
			if (!child_key) {
				free (seen_key);
				return false;
			}
			const char *value = sdb_const_get (anal->sdb_types, child_key, NULL);
			free (child_key);
			if (!value) {
				free (seen_key);
				return true;
			}
			if (composite
				&& (!type_snapshot_budget_add_string (
						&added, type_snapshot_member_type_length (value))
					|| !type_snapshot_budget_fits (used, &added, limits))) {
				free (seen_key);
				return false;
			}
			if (!comma) {
				break;
			}
			cursor = comma + 1;
		}
	}
	if (!type_snapshot_budget_commit (used, &added, limits)
		|| !sdb_set (seen, seen_key, "1", 0)) {
		free (seen_key);
		return false;
	}
	free (seen_key);
	return true;
}

typedef struct {
	RAnal *anal;
	Sdb *seen;
	RAnalTypeSnapshotBudget budget;
	const RAnalFunctionSnapshotLimits *limits;
} TypeSnapshotPreflightContext;

static bool types_snapshot_preflight_cb(void *user, const char *name, const char *kind) {
	TypeSnapshotPreflightContext *ctx = user;
	if (R_STR_ISEMPTY (name) || R_STR_ISEMPTY (kind)) {
		return true;
	}
	const char *namespace_kind = NULL;
	const char *namespace_name = NULL;
	if (split_base_type_namespace_key (name, &namespace_kind, &namespace_name)) {
		return type_snapshot_preflight_one (
			ctx->anal, ctx->seen, &ctx->budget, ctx->limits, namespace_kind, namespace_name);
	}
	if (!strchr (name, '.') && type_snapshot_kind_supported (kind)) {
		return type_snapshot_preflight_one (
			ctx->anal, ctx->seen, &ctx->budget, ctx->limits, kind, name);
	}
	return true;
}

static bool types_snapshot_preflight(RAnal *anal, const RAnalFunctionSnapshotLimits *limits, RAnalTypeSnapshotBudget *result) {
	TypeSnapshotPreflightContext ctx = {
		.anal = anal,
		.seen = sdb_new0 (),
		.limits = limits,
	};
	if (!ctx.seen) {
		return false;
	}
	const bool valid = sdb_foreach (anal->sdb_types, types_snapshot_preflight_cb, &ctx);
	sdb_free (ctx.seen);
	if (valid) {
		*result = ctx.budget;
	}
	return valid;
}

typedef struct {
	RAnal *anal;
	RList *types;
	Sdb *seen;
	bool fail_closed;
	bool valid;
} TypeSnapshotCloneContext;

static bool types_snapshot_clone_cb(void *user, const char *name, const char *kind) {
	TypeSnapshotCloneContext *ctx = user;
	if (R_STR_ISEMPTY (name) || R_STR_ISEMPTY (kind)) {
		return true;
	}
	BaseTypeAppendResult result = BASE_TYPE_APPEND_SKIPPED;
	const char *namespace_kind = NULL;
	const char *namespace_name = NULL;
	if (split_base_type_namespace_key (name, &namespace_kind, &namespace_name)) {
		if (!sdb_const_getf (ctx->anal->sdb_types, NULL, "%s.%s",
				namespace_kind, namespace_name)) {
			return true;
		}
		result = append_base_type_if_unseen (
			ctx->anal, ctx->types, ctx->seen, namespace_kind, namespace_name);
	} else if (!strchr (name, '.') && type_snapshot_kind_supported (kind)) {
		if (!sdb_const_getf (ctx->anal->sdb_types, NULL, "%s.%s", kind, name)) {
			return true;
		}
		result = append_base_type_if_unseen (
			ctx->anal, ctx->types, ctx->seen, kind, name);
	}
	if (result == BASE_TYPE_APPEND_ERROR && ctx->fail_closed) {
		ctx->valid = false;
		return false;
	}
	return true;
}

static RList *types_baselist_with_limits(RAnal *anal, const RAnalFunctionSnapshotLimits *limits) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	RAnalTypeSnapshotBudget expected = {0};
	if (limits && !types_snapshot_preflight (anal, limits, &expected)) {
		return NULL;
	}
	RList *types = r_list_newf ((RListFree)r_anal_base_type_free);
	if (!types) {
		return NULL;
	}
	TypeSnapshotCloneContext ctx = {
		.anal = anal,
		.types = types,
		.seen = sdb_new0 (),
		.fail_closed = limits != NULL,
		.valid = true,
	};
	if (!ctx.seen) {
		if (limits) {
			r_list_free (types);
			return NULL;
		}
		return types;
	}
	const bool completed = sdb_foreach (anal->sdb_types, types_snapshot_clone_cb, &ctx);
	sdb_free (ctx.seen);
	r_list_sort (types, base_type_name_cmp);
	if (limits && (!completed || !ctx.valid
			|| (size_t)r_list_length (types) != expected.base_types)) {
		r_list_free (types);
		return NULL;
	}
	return types;
}

// canonical serialization of a struct/union member value: "type,offset,arraycount"
static char *member_value_kv(const char *type, size_t offset, size_t count) {
	return r_str_newf ("%s,%u,%u", type, (unsigned int)offset, (unsigned int)count);
}

/* Serialize a struct or union base type into the sdb-types text lines that
 * get_struct_type/get_union_type read back:
 *   name=struct
 *   struct.name.member=type,offset,arraycount
 *   struct.name=member1,member2
 * The returned string can be applied with sdb_query_lines() and is the
 * canonical schema shared with the C parser (c2/kv.c). */
R_API char *r_anal_base_type_to_kv(const RAnalBaseType *type) {
	R_RETURN_VAL_IF_FAIL (type && type->name, NULL);
	const char *kind;
	switch (type->kind) {
	case R_ANAL_BASE_TYPE_KIND_STRUCT:
		kind = "struct";
		break;
	case R_ANAL_BASE_TYPE_KIND_UNION:
		kind = "union";
		break;
	default:
		// enum/typedef/atomic serialization is not unified through here yet
		return NULL;
	}
	char *sname = r_str_sanitize_sdb_key (type->name);
	RStrBuf *sb = r_strbuf_new ("");
	RStrBuf *list = r_strbuf_new ("");
	r_strbuf_appendf (sb, "%s=%s\n", sname, kind);
	int i = 0;
	RAnalTypeMember *member;
	R_VEC_FOREACH (r_anal_base_type_members (type), member) {
		char *mname = r_str_sanitize_sdb_key (member->name);
		char *value = member_value_kv (member->type, member->offset, member->count);
		r_strbuf_appendf (sb, "%s.%s.%s=%s\n", kind, sname, mname, value);
		r_strbuf_appendf (list, "%s%s", i++? ",": "", mname);
		free (value);
		free (mname);
	}
	char *lists = r_strbuf_drain (list);
	r_strbuf_appendf (sb, "%s.%s=%s\n", kind, sname, lists);
	free (lists);
	free (sname);
	return r_strbuf_drain (sb);
}

static void save_composite(const RAnal *anal, const RAnalBaseType *type) {
	const char *kind = (type->kind == R_ANAL_BASE_TYPE_KIND_UNION)? "union": "struct";
	/*
		C:
		struct name {type param1; type param2; type paramN;};
		Sdb:
		name=struct
		struct.name=param1,param2,paramN
		struct.name.param1=type,0,0
		struct.name.param2=type,4,0
		struct.name.paramN=type,8,0
	*/
	RVecAnalTypeMember *members = r_anal_base_type_members (type);
	Sdb *db = anal->sdb_types;
	char *sname = r_str_sanitize_sdb_key (type->name);
	char *key = r_str_newf ("%s.%s", kind, sname);
	char *old = sdb_get (db, key, 0);
	if (old && RVecAnalTypeMember_empty (members)) {
		// a forward declaration must not clobber the full definition
		R_LOG_DEBUG ("Ignoring overwrite of type '%s' with an empty declaration", key);
		free (old);
		free (key);
		free (sname);
		return;
	}
	if (old) {
		// drop the members of the replaced definition before writing the new ones
		char *p;
		sdb_aforeach (p, old) {
			r_strf_var (mk, KSZ, "%s.%s.%s", kind, sname, p);
			sdb_unset (db, mk, 0);
			sdb_aforeach_next (p);
		}
		free (old);
	}
	// name=struct
	sdb_set (db, sname, kind, 0);
	// a DWARF definition carries its width; a C one is measured by walking the members
	if (type->size) {
		sdb_num_setf (db, type->size, 0, "type.%s.size", sname);
	} else {
		sdb_unsetf (db, 0, "type.%s.size", sname);
	}

	RStrBuf *arglist = r_strbuf_new ("");

	int i = 0;
	RAnalTypeMember *member;
	R_VEC_FOREACH (members, member) {
		// struct.name.param=type,offset,arraycount
		// The member list has to name members by the same key that addresses
		// them, so it stores the sanitized form. Listing the raw name instead
		// makes every member whose name needs sanitizing unreadable: the reader
		// would look up a key that was never written, and the stale-member
		// cleanup above would fail to unset the key that was.
		char *member_sname = r_str_sanitize_sdb_key (member->name);
		if (!member_sname) {
			break;
		}
		r_strf_var (k, KSZ, "%s.%s.%s", kind, sname, member_sname);
		sdb_set_owned (db, k,
			member_value_kv (member->type, member->offset, member->count), 0);

		r_strbuf_appendf (arglist, (i++ == 0) ? "%s" : ",%s", member_sname);
		free (member_sname);
	}
	// struct.name=param1,param2,paramN
	sdb_set_owned (db, key, r_strbuf_drain (arglist), 0);

	free (key);
	free (sname);
}

R_API RList *r_anal_types_snapshot(RAnal *anal) {
	return types_baselist_with_limits (anal, NULL);
}


R_API void r_anal_types_snapshot_free(RList *snapshot) {
	r_list_free (snapshot);
}

R_API ut64 r_anal_types_dirty_epoch(const RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal, 0);
	return anal->type_dirty_epoch;
}

R_API ut64 r_anal_types_bump_dirty_epoch(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal, 0);
	anal->type_dirty_epoch++;
	if (!anal->type_dirty_epoch) {
		anal->type_dirty_epoch++;
	}
	anal->type_context_hash_cache = 0;
	anal->type_context_hash_epoch = 0;
	return anal->type_dirty_epoch;
}

static ut64 type_context_hash_mix(ut64 hash, ut64 value) {
	hash ^= value + 0x9e3779b97f4a7c15ULL + (hash << 6) + (hash >> 2);
	return hash;
}

static ut64 type_context_hash_string(ut64 hash, const char *value) {
	return type_context_hash_mix (hash, R_STR_ISNOTEMPTY (value)? r_str_hash64 (value): 0);
}

static bool type_context_hash_should_include_sdb_key(const char *key) {
	return r_str_startswith (key, "link.")
		|| r_str_startswith (key, "offset.")
		|| r_str_startswith (key, "fcnlink.");
}

typedef struct {
	ut64 xor_hash;
	ut64 sum_hash;
	ut64 count;
} TypeContextLinkHash;

static bool type_context_hash_link_cb(void *user, const char *key, const char *value) {
	TypeContextLinkHash *links = user;
	if (type_context_hash_should_include_sdb_key (key)) {
		ut64 item = type_context_hash_string (0xcbf29ce484222325ULL, key);
		item = type_context_hash_string (item, value);
		links->xor_hash ^= item;
		links->sum_hash += item;
		links->count++;
	}
	return true;
}

static ut64 types_context_hash_from_snapshot(RAnal *anal, const RList *types, ut64 type_dirty_epoch) {
	if (type_dirty_epoch == r_anal_types_dirty_epoch (anal)
		&& anal->type_context_hash_cache
		&& anal->type_context_hash_epoch == type_dirty_epoch) {
		return anal->type_context_hash_cache;
	}
	ut64 hash = 0xcbf29ce484222325ULL;
	hash = type_context_hash_mix (hash, type_dirty_epoch);
	RListIter *iter;
	RAnalBaseType *type;
	r_list_foreach (types, iter, type) {
		if (!type) {
			continue;
		}
		hash = type_context_hash_string (hash, type->name);
		hash = type_context_hash_string (hash, type->type);
		hash = type_context_hash_mix (hash, (ut64)type->size);
		hash = type_context_hash_mix (hash, (ut64)type->kind);
		switch (type->kind) {
		case R_ANAL_BASE_TYPE_KIND_STRUCT: {
			RAnalStructMember *member;
			R_VEC_FOREACH (&type->struct_data.members, member) {
				hash = type_context_hash_string (hash, member->name);
				hash = type_context_hash_string (hash, member->type);
				hash = type_context_hash_mix (hash, (ut64)member->offset);
				hash = type_context_hash_mix (hash, (ut64)member->bitsize);
				hash = type_context_hash_mix (hash, (ut64)member->count);
			}
			break;
		}
		case R_ANAL_BASE_TYPE_KIND_UNION: {
			RAnalUnionMember *member;
			R_VEC_FOREACH (&type->union_data.members, member) {
				hash = type_context_hash_string (hash, member->name);
				hash = type_context_hash_string (hash, member->type);
				hash = type_context_hash_mix (hash, (ut64)member->offset);
				hash = type_context_hash_mix (hash, (ut64)member->bitsize);
				hash = type_context_hash_mix (hash, (ut64)member->count);
			}
			break;
		}
		case R_ANAL_BASE_TYPE_KIND_ENUM: {
			RAnalEnumCase *cas;
			R_VEC_FOREACH (&type->enum_data.cases, cas) {
				hash = type_context_hash_string (hash, cas->name);
				hash = type_context_hash_mix (hash, (ut64)(st64)cas->val);
			}
			break;
		}
		default:
			break;
		}
	}
	TypeContextLinkHash links = {0};
	(void)sdb_foreach (anal->sdb_types, type_context_hash_link_cb, &links);
	if (links.count) {
		hash = type_context_hash_mix (hash, links.xor_hash);
		hash = type_context_hash_mix (hash, links.sum_hash);
		hash = type_context_hash_mix (hash, links.count);
	}
	if (!hash) {
		hash = 1;
	}
	if (type_dirty_epoch == r_anal_types_dirty_epoch (anal)) {
		anal->type_context_hash_cache = hash;
		anal->type_context_hash_epoch = type_dirty_epoch;
	}
	return hash;
}


R_API ut64 r_anal_types_context_hash(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal, 0);
	if (anal->type_context_hash_cache && anal->type_context_hash_epoch == anal->type_dirty_epoch) {
		return anal->type_context_hash_cache;
	}
	const ut64 type_dirty_epoch = r_anal_types_dirty_epoch (anal);
	RList *types = r_anal_types_snapshot (anal);
	if (!types) {
		return 0;
	}
	ut64 hash = types_context_hash_from_snapshot (anal, types, type_dirty_epoch);
	r_anal_types_snapshot_free (types);
	return hash;
}

R_API bool r_anal_types_set_link(RAnal *anal, const char *type, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (anal && anal->sdb_types && R_STR_ISNOTEMPTY (type), false);
	if (r_type_set_link (anal->sdb_types, type, addr) <= 0) {
		return false;
	}
	r_anal_types_bump_dirty_epoch (anal);
	return true;
}

R_API bool r_anal_types_set_link_expression(RAnal *anal, const char *type, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (anal && anal->sdb_types && R_STR_ISNOTEMPTY (type), false);
	if (r_type_set_link_expression (anal->sdb_types, type, addr) <= 0) {
		return false;
	}
	r_anal_types_bump_dirty_epoch (anal);
	return true;
}

R_API bool r_anal_types_set_link_offset(RAnal *anal, const char *type, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (anal && anal->sdb_types && R_STR_ISNOTEMPTY (type), false);
	if (r_type_link_offset (anal->sdb_types, type, addr) <= 0) {
		return false;
	}
	r_anal_types_bump_dirty_epoch (anal);
	return true;
}

R_API bool r_anal_types_unlink(RAnal *anal, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (anal && anal->sdb_types, false);
	if (r_type_unlink (anal->sdb_types, addr) <= 0) {
		return false;
	}
	r_anal_types_bump_dirty_epoch (anal);
	return true;
}

static void save_enum(const RAnal *anal, const RAnalBaseType *type) {
	R_RETURN_IF_FAIL (anal && type && type->name);
	R_RETURN_IF_FAIL (type->kind == R_ANAL_BASE_TYPE_KIND_ENUM);
	/*
		C:
			enum name {case1 = 1, case2 = 2, caseN = 3};
		Sdb:
		name=enum
		enum.name=arg1,arg2,argN
		enum.MyEnum.0x1=arg1
		enum.MyEnum.0x3=arg2
		enum.MyEnum.0x63=argN
		enum.MyEnum.arg1=0x1
		enum.MyEnum.arg2=0x63
		enum.MyEnum.argN=0x3
	*/
	char *sname = r_str_sanitize_sdb_key (type->name);
	sdb_set (anal->sdb_types, sname, "enum", 0);
	if (type->size) {
		sdb_num_setf (anal->sdb_types, type->size, 0, "type.%s.size", sname);
	}

	RStrBuf *arglist = r_strbuf_new ("");
	int i = 0;
	RAnalEnumCase *cas;
	R_VEC_FOREACH (&type->enum_data.cases, cas) {
		// enum.name.arg1=type,offset,???
		// As with struct members, the case list has to name cases by the key
		// that addresses them. get_enum_type looks each list entry up as
		// enum.<name>.<entry>, so listing the raw name makes an enum with a
		// sanitized case name unreadable in its entirety.
		char *case_sname = r_str_sanitize_sdb_key (cas->name);
		if (!case_sname) {
			break;
		}
		r_strf_var (param_val, KSZ, "0x%" PFMT32x, cas->val);
		sdb_setf (anal->sdb_types, param_val, 0, "enum.%s.%s", sname, case_sname);
		sdb_setf (anal->sdb_types, case_sname, 0, "enum.%s.0x%" PFMT32x, sname, cas->val);
		r_strbuf_appendf (arglist, (i++ == 0) ? "%s" : ",%s", case_sname);
		free (case_sname);
	}
	// enum.name=arg1,arg2,argN
	char *key = r_str_newf ("enum.%s", sname);
	sdb_set_owned (anal->sdb_types, key, r_strbuf_drain (arglist), 0);
	free (key);

	free (sname);
}

// a base type's key is the C spelling typedefs and members refer to it by; only what sdb cannot key is refused
static char *atomic_type_key(const char *name) {
	if (R_STR_ISEMPTY (name) || strpbrk (name, "=,\n")) {
		return NULL;
	}
	return strdup (name);
}

static void save_atomic_type(const RAnal *anal, const RAnalBaseType *type) {
	r_strf_buffer (KSZ);
	R_RETURN_IF_FAIL (anal && type && type->name);
	R_RETURN_IF_FAIL (type->kind == R_ANAL_BASE_TYPE_KIND_ATOMIC);
	/*
		C: (cannot define a custom atomic type)
		Sdb:
		char=type
		type.char=c
		type.char.size=8
	*/
	char *sname = atomic_type_key (type->name);
	if (!sname) {
		return;
	}
	sdb_set (anal->sdb_types, sname, "type", 0);
#if 0
	sdb_num_set (anal->sdb_types, r_strf ("type.%s.size", sname), type->size, 0);
#else
	char *ns = r_str_newf ("%" PFMT64u, (ut64)type->size);
	sdb_set_owned (anal->sdb_types, r_strf ("type.%s.size", sname), ns, 0);
#endif
	sdb_setf (anal->sdb_types, type->type, 0, "type.%s", sname);
	free (sname);
}

static void save_typedef(const RAnal *anal, const RAnalBaseType *type) {
	R_RETURN_IF_FAIL (anal && type && type->name && type->kind == R_ANAL_BASE_TYPE_KIND_TYPEDEF);
	/*
		C:
		typedef char byte;
		Sdb:
		// type.byte=typedef
		byte=typedef
		typedef.byte=char
	*/
	char *sname = r_str_sanitize_sdb_key (type->name);
	sdb_set (anal->sdb_types, sname, "typedef", 0);
	sdb_setf (anal->sdb_types, type->type, 0, "typedef.%s", sname);
#if 0
	sdb_set (anal->sdb_types, r_strf ("type.%s", sname), "typedef", 0);
#endif
	free (sname);
}

R_API void r_anal_base_type_free(RAnalBaseType *type) {
	R_RETURN_IF_FAIL (type);
	free (type->name);
	free (type->type);

	switch (type->kind) {
	case R_ANAL_BASE_TYPE_KIND_STRUCT:
	case R_ANAL_BASE_TYPE_KIND_UNION:
		RVecAnalTypeMember_fini (r_anal_base_type_members (type));
		break;
	case R_ANAL_BASE_TYPE_KIND_ENUM:
		RVecAnalEnumCase_fini (&type->enum_data.cases);
		break;
	case R_ANAL_BASE_TYPE_KIND_TYPEDEF:
	case R_ANAL_BASE_TYPE_KIND_ATOMIC:
		break;
	default:
		break;
	}
	free (type);
}

R_API RAnalBaseType *r_anal_base_type_new(RAnalBaseTypeKind kind) {
	RAnalBaseType *type = R_NEW0 (RAnalBaseType);
	if (type) {
		type->kind = kind;
		switch (type->kind) {
		case R_ANAL_BASE_TYPE_KIND_STRUCT:
		case R_ANAL_BASE_TYPE_KIND_UNION:
			RVecAnalTypeMember_init (r_anal_base_type_members (type));
			break;
		case R_ANAL_BASE_TYPE_KIND_ENUM:
			RVecAnalEnumCase_init (&type->enum_data.cases);
			break;
		default:
			break;
		}
	}
	return type;
}

/**
 * @brief Saves RAnalBaseType into the SDB
 *
 * @param anal
 * @param type RAnalBaseType to save
 * @param name Name of the type
 */
R_API void r_anal_save_base_type(const RAnal *anal, const RAnalBaseType *type) {
	R_RETURN_IF_FAIL (anal && type && type->name);

	// TODO, solve collisions, if there are 2 types with the same name and kind

	switch (type->kind) {
	case R_ANAL_BASE_TYPE_KIND_STRUCT:
	case R_ANAL_BASE_TYPE_KIND_UNION:
		save_composite (anal, type);
		break;
	case R_ANAL_BASE_TYPE_KIND_ENUM:
		save_enum (anal, type);
		break;
	case R_ANAL_BASE_TYPE_KIND_TYPEDEF:
		save_typedef (anal, type);
		break;
	case R_ANAL_BASE_TYPE_KIND_ATOMIC:
		save_atomic_type (anal, type);
		break;
	default:
		break;
	}
	r_anal_types_bump_dirty_epoch ((RAnal *)anal);
}
