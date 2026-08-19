/* radare - LGPL - Copyright 2026 - pancake */

#include <r_core.h>
#include <r_core_priv.h>
#include <r_anal_priv.h>
#include <r_flag_priv.h>
#include <ctype.h>

#define R_CORE_ANAL_ARTIFACT_INDEX_NONE ((size_t)-1)

typedef struct {
	ut64 addr;
	char *prefix;
	char *text;
} RCoreOwnedArtifactComment;

typedef struct {
	char *name;
	ut64 addr;
	ut64 size;
} RCoreOwnedArtifactFlag;

typedef struct {
	ut64 from;
	ut64 to;
	RAnalRefType type;
} RCoreOwnedArtifactXref;

typedef struct {
	char *provider_id;
	char *domain_id;
	ut64 scope_id;
	RList *comments;
	RList *flags;
	RList *xrefs;
} RCoreOwnedArtifactSet;

struct r_core_anal_artifact_store_t {
	RList *sets;
	ut64 revision;
};

static RCoreAnalArtifactReplaceResult artifacts_replace_internal(RCore *core,
	const RCoreAnalArtifactReplacement *replacements, size_t replacement_count,
	bool require_source);

static void owned_artifact_comment_free(void *data) {
	RCoreOwnedArtifactComment *comment = data;
	if (comment) {
		free (comment->prefix);
		free (comment->text);
		free (comment);
	}
}

static void owned_artifact_flag_free(void *data) {
	RCoreOwnedArtifactFlag *flag = data;
	if (flag) {
		free (flag->name);
		free (flag);
	}
}

static void owned_artifact_xref_free(void *data) {
	free (data);
}

static void owned_artifact_set_free(void *data) {
	RCoreOwnedArtifactSet *set = data;
	if (set) {
		free (set->provider_id);
		free (set->domain_id);
		r_list_free (set->comments);
		r_list_free (set->flags);
		r_list_free (set->xrefs);
		free (set);
	}
}

R_IPI RCoreAnalArtifactStore *r_core_anal_artifact_store_new(void) {
	RCoreAnalArtifactStore *store = R_NEW0 (RCoreAnalArtifactStore);
	store->sets = r_list_newf (owned_artifact_set_free);
	if (!store->sets) {
		free (store);
		return NULL;
	}
	return store;
}

R_IPI void r_core_anal_artifact_store_free(RCoreAnalArtifactStore *store) {
	if (store) {
		r_list_free (store->sets);
		free (store);
	}
}

R_API bool r_core_anal_artifacts_reset(RCore *core) {
	R_RETURN_VAL_IF_FAIL (core && core->priv && core->lock, false);
	bool success = false;
	r_th_lock_enter (core->lock);
	RCorePriv *priv = core->priv;
	RCoreAnalArtifactStore *store = priv->anal_artifacts;
	if (!store) {
		success = true;
		goto beach;
	}
	const size_t count = r_list_length (store->sets);
	if (!count) {
		success = true;
		goto beach;
	}
	size_t replacement_bytes;
	if (r_mul_overflow_size_t (count, sizeof (RCoreAnalArtifactReplacement),
			&replacement_bytes)) {
		goto beach;
	}
	RCoreAnalArtifactReplacement *replacements = calloc (1, replacement_bytes);
	if (!replacements) {
		goto beach;
	}
	size_t index = 0;
	RListIter *iter;
	RCoreOwnedArtifactSet *set;
	r_list_foreach (store->sets, iter, set) {
		replacements[index++] = (RCoreAnalArtifactReplacement) {
			.provider_id = set->provider_id,
			.domain_id = set->domain_id,
			.scope_id = set->scope_id,
		};
	}
	RCoreAnalArtifactReplaceResult result = artifacts_replace_internal (
		core, replacements, count, false);
	success = result.status == R_CORE_ANAL_ARTIFACT_REPLACE_OK;
	free (replacements);

beach:
	r_th_lock_leave (core->lock);
	return success;
}

static RCoreOwnedArtifactSet *artifact_set_at(const RCore *core, size_t index) {
	if (!core || !core->priv) {
		return NULL;
	}
	RCorePriv *priv = core->priv;
	if (!priv->anal_artifacts || index >= r_list_length (priv->anal_artifacts->sets)) {
		return NULL;
	}
	return r_list_get_n (priv->anal_artifacts->sets, index);
}

R_API size_t r_core_anal_artifact_set_count(const RCore *core) {
	if (!core || !core->priv) {
		return 0;
	}
	RCorePriv *priv = core->priv;
	return priv->anal_artifacts? r_list_length (priv->anal_artifacts->sets): 0;
}

R_API bool r_core_anal_artifact_set_view(const RCore *core, size_t index,
		RCoreAnalArtifactSetView *view) {
	R_RETURN_VAL_IF_FAIL (view, false);
	RCoreOwnedArtifactSet *set = artifact_set_at (core, index);
	if (!set) {
		return false;
	}
	*view = (RCoreAnalArtifactSetView) {
		.provider_id = set->provider_id,
		.domain_id = set->domain_id,
		.scope_id = set->scope_id,
		.comment_count = r_list_length (set->comments),
		.flag_count = r_list_length (set->flags),
		.xref_count = r_list_length (set->xrefs),
	};
	return true;
}

R_API bool r_core_anal_artifact_comment_view(const RCore *core, size_t set_index,
		size_t index, RCoreAnalArtifactComment *comment) {
	R_RETURN_VAL_IF_FAIL (comment, false);
	RCoreOwnedArtifactSet *set = artifact_set_at (core, set_index);
	RCoreOwnedArtifactComment *owned = set? r_list_get_n (set->comments, index): NULL;
	if (!owned) {
		return false;
	}
	*comment = (RCoreAnalArtifactComment) {
		.addr = owned->addr,
		.prefix = owned->prefix,
		.text = owned->text,
	};
	return true;
}

R_API bool r_core_anal_artifact_flag_view(const RCore *core, size_t set_index,
		size_t index, RCoreAnalArtifactFlag *flag) {
	R_RETURN_VAL_IF_FAIL (flag, false);
	RCoreOwnedArtifactSet *set = artifact_set_at (core, set_index);
	RCoreOwnedArtifactFlag *owned = set? r_list_get_n (set->flags, index): NULL;
	if (!owned) {
		return false;
	}
	*flag = (RCoreAnalArtifactFlag) {
		.name = owned->name,
		.addr = owned->addr,
		.size = owned->size,
	};
	return true;
}

R_API bool r_core_anal_artifact_xref_view(const RCore *core, size_t set_index,
		size_t index, RAnalRef *xref) {
	R_RETURN_VAL_IF_FAIL (xref, false);
	RCoreOwnedArtifactSet *set = artifact_set_at (core, set_index);
	RCoreOwnedArtifactXref *owned = set? r_list_get_n (set->xrefs, index): NULL;
	if (!owned) {
		return false;
	}
	*xref = (RAnalRef) {
		.at = owned->from,
		.addr = owned->to,
		.type = owned->type,
	};
	return true;
}

static RCoreOwnedArtifactComment *owned_artifact_comment_clone(const RCoreOwnedArtifactComment *source) {
	RCoreOwnedArtifactComment *comment = R_NEW0 (RCoreOwnedArtifactComment);
	comment->addr = source->addr;
	comment->prefix = strdup (source->prefix);
	comment->text = strdup (source->text);
	if (!comment->prefix || !comment->text) {
		owned_artifact_comment_free (comment);
		return NULL;
	}
	return comment;
}

static RCoreOwnedArtifactFlag *owned_artifact_flag_clone(const RCoreOwnedArtifactFlag *source) {
	RCoreOwnedArtifactFlag *flag = R_NEW0 (RCoreOwnedArtifactFlag);
	flag->name = strdup (source->name);
	flag->addr = source->addr;
	flag->size = source->size;
	if (!flag->name) {
		owned_artifact_flag_free (flag);
		return NULL;
	}
	return flag;
}

static RCoreOwnedArtifactSet *owned_artifact_set_new(const char *provider_id, const char *domain_id, ut64 scope_id) {
	RCoreOwnedArtifactSet *set = R_NEW0 (RCoreOwnedArtifactSet);
	set->provider_id = strdup (provider_id);
	set->domain_id = strdup (domain_id);
	set->scope_id = scope_id;
	set->comments = r_list_newf (owned_artifact_comment_free);
	set->flags = r_list_newf (owned_artifact_flag_free);
	set->xrefs = r_list_newf (owned_artifact_xref_free);
	if (!set->provider_id || !set->domain_id || !set->comments || !set->flags || !set->xrefs) {
		owned_artifact_set_free (set);
		return NULL;
	}
	return set;
}

static RCoreOwnedArtifactSet *owned_artifact_set_clone(const RCoreOwnedArtifactSet *source) {
	RCoreOwnedArtifactSet *set = owned_artifact_set_new (
		source->provider_id, source->domain_id, source->scope_id);
	if (!set) {
		return NULL;
	}
	RListIter *iter;
	RCoreOwnedArtifactComment *source_comment;
	r_list_foreach (source->comments, iter, source_comment) {
		RCoreOwnedArtifactComment *comment = owned_artifact_comment_clone (source_comment);
		if (!comment || !r_list_append (set->comments, comment)) {
			owned_artifact_comment_free (comment);
			owned_artifact_set_free (set);
			return NULL;
		}
	}
	RCoreOwnedArtifactFlag *source_flag;
	r_list_foreach (source->flags, iter, source_flag) {
		RCoreOwnedArtifactFlag *flag = owned_artifact_flag_clone (source_flag);
		if (!flag || !r_list_append (set->flags, flag)) {
			owned_artifact_flag_free (flag);
			owned_artifact_set_free (set);
			return NULL;
		}
	}
	RCoreOwnedArtifactXref *source_xref;
	r_list_foreach (source->xrefs, iter, source_xref) {
		RCoreOwnedArtifactXref *xref = R_NEW (RCoreOwnedArtifactXref);
		*xref = *source_xref;
		if (!r_list_append (set->xrefs, xref)) {
			owned_artifact_xref_free (xref);
			owned_artifact_set_free (set);
			return NULL;
		}
	}
	return set;
}

static RCoreAnalArtifactStore *artifact_store_clone(const RCoreAnalArtifactStore *source) {
	RCoreAnalArtifactStore *store = r_core_anal_artifact_store_new ();
	if (!store) {
		return NULL;
	}
	store->revision = source->revision;
	RListIter *iter;
	RCoreOwnedArtifactSet *source_set;
	r_list_foreach (source->sets, iter, source_set) {
		RCoreOwnedArtifactSet *set = owned_artifact_set_clone (source_set);
		if (!set || !r_list_append (store->sets, set)) {
			owned_artifact_set_free (set);
			r_core_anal_artifact_store_free (store);
			return NULL;
		}
	}
	return store;
}

static bool artifact_key_matches(const RCoreOwnedArtifactSet *set, const char *provider_id,
		const char *domain_id, ut64 scope_id) {
	return set->scope_id == scope_id
		&& !strcmp (set->provider_id, provider_id)
		&& !strcmp (set->domain_id, domain_id);
}

static RCoreOwnedArtifactSet *artifact_store_find(const RCoreAnalArtifactStore *store,
		const char *provider_id, const char *domain_id, ut64 scope_id) {
	RListIter *iter;
	RCoreOwnedArtifactSet *set;
	r_list_foreach (store->sets, iter, set) {
		if (artifact_key_matches (set, provider_id, domain_id, scope_id)) {
			return set;
		}
	}
	return NULL;
}

static bool artifact_store_remove(RCoreAnalArtifactStore *store, const char *provider_id,
		const char *domain_id, ut64 scope_id) {
	RListIter *iter;
	RCoreOwnedArtifactSet *set;
	r_list_foreach (store->sets, iter, set) {
		if (artifact_key_matches (set, provider_id, domain_id, scope_id)) {
			r_list_delete (store->sets, iter);
			return true;
		}
	}
	return false;
}

static bool valid_artifact_id(const char *id) {
	if (R_STR_ISEMPTY (id) || strlen (id) > 128) {
		return false;
	}
	const unsigned char *cursor = (const unsigned char *)id;
	for (; *cursor; cursor++) {
		if (!(isalnum (*cursor) || *cursor == '.' || *cursor == '_' || *cursor == '-')) {
			return false;
		}
	}
	return true;
}

static bool valid_artifact_prefix(const char *prefix) {
	if (R_STR_ISEMPTY (prefix) || strlen (prefix) > 128 || strchr (prefix, '\n')) {
		return false;
	}
	return true;
}

static bool valid_artifact_text(const char *text) {
	return R_STR_ISNOTEMPTY (text) && strlen (text) <= 4096 && !strchr (text, '\n');
}

static RAnalRefType artifact_xref_normalize(RAnalRefType type) {
	if (R_ANAL_REF_TYPE_PERM (type)) {
		return type;
	}
	switch (R_ANAL_REF_TYPE_MASK (type)) {
	case R_ANAL_REF_TYPE_CODE:
	case R_ANAL_REF_TYPE_CALL:
	case R_ANAL_REF_TYPE_JUMP:
		return type | R_ANAL_REF_TYPE_EXEC;
	default:
		return type | R_ANAL_REF_TYPE_READ;
	}
}

static int artifact_xref_compare(const void *left_data, const void *right_data) {
	const RCoreOwnedArtifactXref *left = left_data;
	const RCoreOwnedArtifactXref *right = right_data;
	if (left->from != right->from) {
		return left->from < right->from? -1: 1;
	}
	if (left->to != right->to) {
		return left->to < right->to? -1: 1;
	}
	if (left->type != right->type) {
		return left->type < right->type? -1: 1;
	}
	return 0;
}

static bool artifact_replacement_is_valid(const RCoreAnalArtifactReplacement *replacement) {
	if (!valid_artifact_id (replacement->provider_id)
			|| !valid_artifact_id (replacement->domain_id)
			|| replacement->scope_id == UT64_MAX
			|| (replacement->comment_count && !replacement->comments)
			|| (replacement->flag_count && !replacement->flags)
			|| (replacement->xref_count && !replacement->xrefs)
			|| replacement->comment_count > 4096
			|| replacement->flag_count > 4096
			|| replacement->xref_count > 1 << 20) {
		return false;
	}
	size_t i;
	for (i = 0; i < replacement->comment_count; i++) {
		const RCoreAnalArtifactComment *comment = &replacement->comments[i];
		if (!valid_artifact_prefix (comment->prefix)
				|| !valid_artifact_text (comment->text)
				|| !r_str_startswith (comment->text, comment->prefix)) {
			return false;
		}
		size_t j;
		for (j = 0; j < i; j++) {
			const RCoreAnalArtifactComment *prior = &replacement->comments[j];
			if (prior->addr == comment->addr && !strcmp (prior->prefix, comment->prefix)
					&& strcmp (prior->text, comment->text)) {
				return false;
			}
		}
	}
	for (i = 0; i < replacement->flag_count; i++) {
		const RCoreAnalArtifactFlag *flag = &replacement->flags[i];
		if (R_STR_ISEMPTY (flag->name) || strlen (flag->name) > 1024
				|| flag->addr == UT64_MAX || flag->size > UT32_MAX) {
			return false;
		}
		size_t j;
		for (j = 0; j < i; j++) {
			const RCoreAnalArtifactFlag *prior = &replacement->flags[j];
			if (!strcmp (prior->name, flag->name)
					&& (prior->addr != flag->addr || prior->size != flag->size)) {
				return false;
			}
		}
	}
	for (i = 0; i < replacement->xref_count; i++) {
		const RAnalRef *xref = &replacement->xrefs[i];
		if (xref->at == UT64_MAX || xref->addr == UT64_MAX || xref->at == xref->addr) {
			return false;
		}
	}
	return true;
}

static RCoreOwnedArtifactSet *owned_artifact_set_from_replacement(
		const RCoreAnalArtifactReplacement *replacement) {
	RCoreOwnedArtifactSet *set = owned_artifact_set_new (
		replacement->provider_id, replacement->domain_id, replacement->scope_id);
	if (!set) {
		return NULL;
	}
	size_t i;
	for (i = 0; i < replacement->comment_count; i++) {
		const RCoreAnalArtifactComment *source = &replacement->comments[i];
		RListIter *existing_iter;
		RCoreOwnedArtifactComment *existing;
		bool duplicate = false;
		r_list_foreach (set->comments, existing_iter, existing) {
			if (existing->addr == source->addr && !strcmp (existing->prefix, source->prefix)) {
				duplicate = true;
				break;
			}
		}
		if (duplicate) {
			continue;
		}
		RCoreOwnedArtifactComment *comment = R_NEW0 (RCoreOwnedArtifactComment);
		comment->addr = source->addr;
		comment->prefix = strdup (source->prefix);
		comment->text = strdup (source->text);
		if (!comment->prefix || !comment->text || !r_list_append (set->comments, comment)) {
			owned_artifact_comment_free (comment);
			owned_artifact_set_free (set);
			return NULL;
		}
	}
	for (i = 0; i < replacement->flag_count; i++) {
		const RCoreAnalArtifactFlag *source = &replacement->flags[i];
		RListIter *existing_iter;
		RCoreOwnedArtifactFlag *existing;
		bool duplicate = false;
		r_list_foreach (set->flags, existing_iter, existing) {
			if (!strcmp (existing->name, source->name)) {
				duplicate = true;
				break;
			}
		}
		if (duplicate) {
			continue;
		}
		RCoreOwnedArtifactFlag *flag = R_NEW0 (RCoreOwnedArtifactFlag);
		flag->name = strdup (source->name);
		flag->addr = source->addr;
		flag->size = source->size;
		if (!flag->name || !r_list_append (set->flags, flag)) {
			owned_artifact_flag_free (flag);
			owned_artifact_set_free (set);
			return NULL;
		}
	}
	size_t xref_bytes;
	if (r_mul_overflow_size_t (replacement->xref_count,
			sizeof (RCoreOwnedArtifactXref), &xref_bytes)) {
		owned_artifact_set_free (set);
		return NULL;
	}
	RCoreOwnedArtifactXref *sorted_xrefs = replacement->xref_count
		? malloc (xref_bytes): NULL;
	if (replacement->xref_count && !sorted_xrefs) {
		owned_artifact_set_free (set);
		return NULL;
	}
	for (i = 0; i < replacement->xref_count; i++) {
		const RAnalRef *source = &replacement->xrefs[i];
		sorted_xrefs[i] = (RCoreOwnedArtifactXref) {
			.from = source->at,
			.to = source->addr,
			.type = artifact_xref_normalize (source->type),
		};
	}
	if (replacement->xref_count > 1) {
		qsort (sorted_xrefs, replacement->xref_count,
			sizeof (RCoreOwnedArtifactXref), artifact_xref_compare);
	}
	for (i = 0; i < replacement->xref_count; i++) {
		if (i && sorted_xrefs[i - 1].from == sorted_xrefs[i].from
				&& sorted_xrefs[i - 1].to == sorted_xrefs[i].to) {
			if (sorted_xrefs[i - 1].type != sorted_xrefs[i].type) {
				free (sorted_xrefs);
				owned_artifact_set_free (set);
				return NULL;
			}
			continue;
		}
		RCoreOwnedArtifactXref *xref = R_NEW (RCoreOwnedArtifactXref);
		*xref = sorted_xrefs[i];
		if (!r_list_append (set->xrefs, xref)) {
			owned_artifact_xref_free (xref);
			free (sorted_xrefs);
			owned_artifact_set_free (set);
			return NULL;
		}
	}
	free (sorted_xrefs);
	return set;
}

typedef struct {
	ut64 *items;
	size_t count;
	size_t capacity;
} ArtifactAddrSet;

typedef struct {
	char **items;
	size_t count;
	size_t capacity;
} ArtifactNameSet;

static void artifact_addr_set_fini(ArtifactAddrSet *set) {
	free (set->items);
	memset (set, 0, sizeof (*set));
}

static bool artifact_addr_set_add(ArtifactAddrSet *set, ut64 addr) {
	size_t i;
	for (i = 0; i < set->count; i++) {
		if (set->items[i] == addr) {
			return true;
		}
	}
	if (set->count == set->capacity) {
		size_t capacity = set->capacity? set->capacity * 2: 16;
		size_t size;
		if (capacity < set->capacity
				|| r_mul_overflow_size_t (capacity, sizeof (ut64), &size)) {
			return false;
		}
		ut64 *items = realloc (set->items, size);
		if (!items) {
			return false;
		}
		set->items = items;
		set->capacity = capacity;
	}
	set->items[set->count++] = addr;
	return true;
}

static void artifact_name_set_fini(ArtifactNameSet *set) {
	size_t i;
	for (i = 0; i < set->count; i++) {
		free (set->items[i]);
	}
	free (set->items);
	memset (set, 0, sizeof (*set));
}

static bool artifact_name_set_add(ArtifactNameSet *set, const char *name) {
	size_t i;
	for (i = 0; i < set->count; i++) {
		if (!strcmp (set->items[i], name)) {
			return true;
		}
	}
	if (set->count == set->capacity) {
		size_t capacity = set->capacity? set->capacity * 2: 16;
		size_t size;
		if (capacity < set->capacity
				|| r_mul_overflow_size_t (capacity, sizeof (char *), &size)) {
			return false;
		}
		char **items = realloc (set->items, size);
		if (!items) {
			return false;
		}
		set->items = items;
		set->capacity = capacity;
	}
	char *copy = strdup (name);
	if (!copy) {
		return false;
	}
	set->items[set->count++] = copy;
	return true;
}

static bool collect_set_keys(const RCoreOwnedArtifactSet *set, ArtifactAddrSet *addresses,
		ArtifactNameSet *names) {
	RListIter *iter;
	RCoreOwnedArtifactComment *comment;
	r_list_foreach (set->comments, iter, comment) {
		if (!artifact_addr_set_add (addresses, comment->addr)) {
			return false;
		}
	}
	RCoreOwnedArtifactFlag *flag;
	r_list_foreach (set->flags, iter, flag) {
		if (!artifact_name_set_add (names, flag->name)) {
			return false;
		}
	}
	return true;
}

static bool line_has_owned_prefix(const char *line, size_t length,
		const RCoreAnalArtifactStore *store, ut64 addr) {
	RListIter *set_iter;
	RCoreOwnedArtifactSet *set;
	r_list_foreach (store->sets, set_iter, set) {
		RListIter *comment_iter;
		RCoreOwnedArtifactComment *comment;
		r_list_foreach (set->comments, comment_iter, comment) {
			size_t prefix_length = strlen (comment->prefix);
			if (comment->addr == addr && length >= prefix_length
					&& !memcmp (line, comment->prefix, prefix_length)) {
				return true;
			}
		}
	}
	return false;
}

static bool line_equals_owned_comment(const char *line, size_t length,
		const RCoreAnalArtifactStore *store, ut64 addr) {
	RListIter *set_iter;
	RCoreOwnedArtifactSet *set;
	r_list_foreach (store->sets, set_iter, set) {
		RListIter *comment_iter;
		RCoreOwnedArtifactComment *comment;
		r_list_foreach (set->comments, comment_iter, comment) {
			const size_t text_length = strlen (comment->text);
			if (comment->addr == addr && length == text_length
					&& !memcmp (line, comment->text, text_length)) {
				return true;
			}
		}
	}
	return false;
}

static int owned_comment_compare(const void *a, const void *b) {
	const RCoreOwnedArtifactComment *left = a;
	const RCoreOwnedArtifactComment *right = b;
	int result = strcmp (left->prefix, right->prefix);
	return result? result: strcmp (left->text, right->text);
}

static RList *candidate_comments_at(const RCoreAnalArtifactStore *store, ut64 addr, bool *conflict) {
	RList *comments = r_list_new ();
	if (!comments) {
		return NULL;
	}
	RListIter *set_iter;
	RCoreOwnedArtifactSet *set;
	r_list_foreach (store->sets, set_iter, set) {
		RListIter *comment_iter;
		RCoreOwnedArtifactComment *comment;
		r_list_foreach (set->comments, comment_iter, comment) {
			if (comment->addr != addr) {
				continue;
			}
			RListIter *existing_iter;
			RCoreOwnedArtifactComment *existing;
			r_list_foreach (comments, existing_iter, existing) {
				if (!strcmp (existing->prefix, comment->prefix)) {
					if (strcmp (existing->text, comment->text)) {
						*conflict = true;
						r_list_free (comments);
						return NULL;
					}
					comment = NULL;
					break;
				}
			}
			if (comment && !r_list_append (comments, comment)) {
				r_list_free (comments);
				return NULL;
			}
		}
	}
	r_list_sort (comments, owned_comment_compare);
	return comments;
}

static char *render_comment_projection(const char *current, const RCoreAnalArtifactStore *old_store,
		const RCoreAnalArtifactStore *candidate, ut64 addr, bool *conflict) {
	RStrBuf *buffer = r_strbuf_new (NULL);
	if (!buffer) {
		return NULL;
	}
	bool first = true;
	const char *cursor = r_str_get (current);
	while (*cursor) {
		const char *end = strchr (cursor, '\n');
		size_t length = end? (size_t)(end - cursor): strlen (cursor);
		if (line_equals_owned_comment (cursor, length, old_store, addr)) {
			// Remove only the exact line previously owned by this store.
		} else if (line_has_owned_prefix (cursor, length, candidate, addr)) {
			*conflict = true;
			r_strbuf_free (buffer);
			return NULL;
		} else {
			if ((!first && !r_strbuf_append (buffer, "\n"))
					|| !r_strbuf_append_n (buffer, cursor, length)) {
				r_strbuf_free (buffer);
				return NULL;
			}
			first = false;
		}
		if (!end) {
			break;
		}
		cursor = end + 1;
	}
	RList *comments = candidate_comments_at (candidate, addr, conflict);
	if (!comments) {
		r_strbuf_free (buffer);
		return NULL;
	}
	RListIter *iter;
	RCoreOwnedArtifactComment *comment;
	r_list_foreach (comments, iter, comment) {
		if ((!first && !r_strbuf_append (buffer, "\n"))
				|| !r_strbuf_append (buffer, comment->text)) {
			r_list_free (comments);
			r_strbuf_free (buffer);
			return NULL;
		}
		first = false;
	}
	r_list_free (comments);
	return r_strbuf_drain (buffer);
}

static bool prepare_comment_projection(RAnal *anal, RAnalMetaStoreShadow *shadow,
		const RCoreAnalArtifactStore *old_store, const RCoreAnalArtifactStore *candidate,
		const ArtifactAddrSet *addresses, bool *conflict, bool *projection_changed) {
	const RSpace *space = NULL;
	size_t i;
	for (i = 0; i < addresses->count; i++) {
		ut64 addr = addresses->items[i];
		const char *current = r_meta_get_string_in_space (anal, R_META_TYPE_COMMENT, space, addr);
		char *rendered = render_comment_projection (current, old_store, candidate, addr, conflict);
		if (!rendered) {
			return false;
		}
		if (strcmp (r_str_get (current), rendered)) {
			*projection_changed = true;
		}
		bool ok = true;
		if (*rendered) {
			ok = r_meta_store_shadow_set_comment (shadow, space, addr, rendered);
		} else {
			r_meta_store_shadow_del_comment (shadow, space, addr);
		}
		free (rendered);
		if (!ok) {
			return false;
		}
	}
	return true;
}

static bool replacements_have_unique_keys(const RCoreAnalArtifactReplacement *replacements,
		size_t replacement_count, size_t *failed_index) {
	size_t i;
	for (i = 0; i < replacement_count; i++) {
		size_t j;
		for (j = 0; j < i; j++) {
			if (replacements[i].scope_id == replacements[j].scope_id
					&& !strcmp (replacements[i].provider_id, replacements[j].provider_id)
					&& !strcmp (replacements[i].domain_id, replacements[j].domain_id)) {
				*failed_index = i;
				return false;
			}
		}
	}
	return true;
}

static RCoreAnalArtifactStore *prepare_candidate_store(const RCoreAnalArtifactStore *old_store,
		const RCoreAnalArtifactReplacement *replacements, size_t replacement_count,
		ArtifactAddrSet *addresses, ArtifactNameSet *names, size_t *failed_index) {
	RCoreAnalArtifactStore *candidate = artifact_store_clone (old_store);
	if (!candidate) {
		return NULL;
	}
	size_t i;
	for (i = 0; i < replacement_count; i++) {
		const RCoreAnalArtifactReplacement *replacement = &replacements[i];
		RCoreOwnedArtifactSet *old_set = artifact_store_find (candidate,
			replacement->provider_id, replacement->domain_id, replacement->scope_id);
		if (old_set && !collect_set_keys (old_set, addresses, names)) {
			*failed_index = i;
			r_core_anal_artifact_store_free (candidate);
			return NULL;
		}
		artifact_store_remove (candidate, replacement->provider_id,
			replacement->domain_id, replacement->scope_id);
		RCoreOwnedArtifactSet *set = owned_artifact_set_from_replacement (replacement);
		if (!set || !collect_set_keys (set, addresses, names)) {
			*failed_index = i;
			owned_artifact_set_free (set);
			r_core_anal_artifact_store_free (candidate);
			return NULL;
		}
		if ((replacement->comment_count || replacement->flag_count || replacement->xref_count)
				&& !r_list_append (candidate->sets, set)) {
			*failed_index = i;
			owned_artifact_set_free (set);
			r_core_anal_artifact_store_free (candidate);
			return NULL;
		}
		if (!replacement->comment_count && !replacement->flag_count && !replacement->xref_count) {
			owned_artifact_set_free (set);
		}
	}
	return candidate;
}

static const RCoreOwnedArtifactFlag *artifact_flag_claim(const RCoreAnalArtifactStore *store,
		const char *name, bool *conflict) {
	const RCoreOwnedArtifactFlag *claim = NULL;
	RListIter *set_iter;
	RCoreOwnedArtifactSet *set;
	r_list_foreach (store->sets, set_iter, set) {
		RListIter *flag_iter;
		RCoreOwnedArtifactFlag *flag;
		r_list_foreach (set->flags, flag_iter, flag) {
			if (strcmp (flag->name, name)) {
				continue;
			}
			if (claim && (claim->addr != flag->addr || claim->size != flag->size)) {
				*conflict = true;
				return NULL;
			}
			claim = flag;
		}
	}
	return claim;
}

static bool flag_matches_claim(const RFlagItem *item, const RCoreOwnedArtifactFlag *claim) {
	return item && claim && item->addr == claim->addr && item->size == claim->size;
}

static bool prepare_flag_projection(RFlag *flags, RFlagStoreShadow *shadow,
		const RCoreAnalArtifactStore *old_store, const RCoreAnalArtifactStore *candidate,
		const ArtifactNameSet *names, bool *conflict) {
	size_t i;
	for (i = 0; i < names->count; i++) {
		const char *name = names->items[i];
		const RCoreOwnedArtifactFlag *old_claim = artifact_flag_claim (old_store, name, conflict);
		if (*conflict) {
			return false;
		}
		const RCoreOwnedArtifactFlag *new_claim = artifact_flag_claim (candidate, name, conflict);
		if (*conflict) {
			return false;
		}
		const RFlagItem *live = r_flag_store_shadow_get_exact (shadow, name);
		if (old_claim && !flag_matches_claim (live, old_claim)) {
			*conflict = true;
			return false;
		}
		if (!old_claim && live && new_claim) {
			*conflict = true;
			return false;
		}
		if (!new_claim) {
			if (old_claim && !r_flag_store_shadow_del_exact (shadow, name)) {
				return false;
			}
			continue;
		}
		const RSpace *space = live? live->space: r_flag_space_cur (flags);
		if (!r_flag_store_shadow_set_exact (shadow, name, new_claim->addr,
				(ut32)new_claim->size, space)) {
			return false;
		}
	}
	return true;
}

static bool owned_set_has_comment(const RCoreOwnedArtifactSet *set,
		const RCoreOwnedArtifactComment *needle) {
	RListIter *iter;
	RCoreOwnedArtifactComment *comment;
	r_list_foreach (set->comments, iter, comment) {
		if (comment->addr == needle->addr && !strcmp (comment->prefix, needle->prefix)
				&& !strcmp (comment->text, needle->text)) {
			return true;
		}
	}
	return false;
}

static bool owned_set_has_flag(const RCoreOwnedArtifactSet *set,
		const RCoreOwnedArtifactFlag *needle) {
	RListIter *iter;
	RCoreOwnedArtifactFlag *flag;
	r_list_foreach (set->flags, iter, flag) {
		if (!strcmp (flag->name, needle->name) && flag->addr == needle->addr
				&& flag->size == needle->size) {
			return true;
		}
	}
	return false;
}

static bool owned_set_has_xref(const RCoreOwnedArtifactSet *set,
		const RCoreOwnedArtifactXref *needle) {
	RListIter *iter;
	RCoreOwnedArtifactXref *xref;
	r_list_foreach (set->xrefs, iter, xref) {
		if (xref->from == needle->from && xref->to == needle->to && xref->type == needle->type) {
			return true;
		}
	}
	return false;
}

static bool owned_artifact_set_equal(const RCoreOwnedArtifactSet *left,
		const RCoreOwnedArtifactSet *right) {
	if (!left || !right) {
		const RCoreOwnedArtifactSet *set = left? left: right;
		return !set || (r_list_empty (set->comments) && r_list_empty (set->flags)
			&& r_list_empty (set->xrefs));
	}
	if (r_list_length (left->comments) != r_list_length (right->comments)
			|| r_list_length (left->flags) != r_list_length (right->flags)
			|| r_list_length (left->xrefs) != r_list_length (right->xrefs)) {
		return false;
	}
	RListIter *iter;
	RCoreOwnedArtifactComment *comment;
	r_list_foreach (left->comments, iter, comment) {
		if (!owned_set_has_comment (right, comment)) {
			return false;
		}
	}
	RCoreOwnedArtifactFlag *flag;
	r_list_foreach (left->flags, iter, flag) {
		if (!owned_set_has_flag (right, flag)) {
			return false;
		}
	}
	RCoreOwnedArtifactXref *xref;
	r_list_foreach (left->xrefs, iter, xref) {
		if (!owned_set_has_xref (right, xref)) {
			return false;
		}
	}
	return true;
}

static bool candidate_changes_artifacts(const RCoreAnalArtifactStore *old_store,
		const RCoreAnalArtifactStore *candidate,
		const RCoreAnalArtifactReplacement *replacements, size_t replacement_count) {
	size_t i;
	for (i = 0; i < replacement_count; i++) {
		const RCoreAnalArtifactReplacement *replacement = &replacements[i];
		RCoreOwnedArtifactSet *old_set = artifact_store_find (old_store,
			replacement->provider_id, replacement->domain_id, replacement->scope_id);
		RCoreOwnedArtifactSet *new_set = artifact_store_find (candidate,
			replacement->provider_id, replacement->domain_id, replacement->scope_id);
		if (!owned_artifact_set_equal (old_set, new_set)) {
			return true;
		}
	}
	return false;
}

typedef struct {
	RAnalOwnedXrefSet *sets;
	char **namespaces;
	size_t count;
} ArtifactXrefSets;

static void artifact_xref_sets_fini(ArtifactXrefSets *sets) {
	if (sets) {
		size_t i;
		for (i = 0; i < sets->count; i++) {
			free (sets->namespaces[i]);
		}
		free (sets->namespaces);
		free (sets->sets);
		memset (sets, 0, sizeof (*sets));
	}
}

static bool artifact_xref_sets_prepare(const RCoreAnalArtifactReplacement *replacements,
		size_t replacement_count, ArtifactXrefSets *result, size_t *failed_index) {
	size_t set_size;
	size_t namespace_size;
	if (r_mul_overflow_size_t (replacement_count, sizeof (RAnalOwnedXrefSet), &set_size)
			|| r_mul_overflow_size_t (replacement_count, sizeof (char *), &namespace_size)) {
		return false;
	}
	result->sets = calloc (1, set_size);
	result->namespaces = calloc (1, namespace_size);
	if (!result->sets || !result->namespaces) {
		artifact_xref_sets_fini (result);
		return false;
	}
	result->count = replacement_count;
	size_t i;
	for (i = 0; i < replacement_count; i++) {
		const RCoreAnalArtifactReplacement *replacement = &replacements[i];
		char *producer_namespace = r_str_newf ("%s/%s",
			replacement->provider_id, replacement->domain_id);
		if (!producer_namespace
				|| strlen (producer_namespace) > R_ANAL_OWNED_XREF_NAMESPACE_MAX) {
			free (producer_namespace);
			*failed_index = i;
			artifact_xref_sets_fini (result);
			return false;
		}
		result->namespaces[i] = producer_namespace;
		result->sets[i] = (RAnalOwnedXrefSet) {
			.producer_namespace = producer_namespace,
			.owner_addr = replacement->scope_id,
			.refs = replacement->xrefs,
			.ref_count = replacement->xref_count,
		};
	}
	return true;
}

typedef struct {
	ut64 revision;
	bool captured;
} ArtifactSnapshotRevision;

static bool capture_artifact_snapshot_revision(const RAnalFunctionSnapshot *snapshot, void *user) {
	ArtifactSnapshotRevision *result = user;
	RAnalFunctionSnapshotView view;
	if (!r_anal_function_snapshot_view (snapshot, &view)) {
		return false;
	}
	result->revision = view.revision_identity;
	result->captured = true;
	return true;
}

static bool artifact_replacement_epoch_matches(RCore *core, RAnal *anal,
		const RCoreAnalArtifactReplacement *replacement) {
	RAnalFunction *function = r_anal_get_function_at (anal, replacement->scope_id);
	if (!function || function->addr != replacement->scope_id
			|| r_anal_function_dirty_epoch (function) != replacement->expected_function_epoch
			|| anal->type_dirty_epoch != replacement->expected_type_epoch) {
		return false;
	}
	ArtifactSnapshotRevision revision = {0};
	return replacement->expected_snapshot_revision
		&& r_core_function_snapshot_at (core, replacement->scope_id,
			capture_artifact_snapshot_revision, &revision, NULL)
		&& revision.captured && revision.revision == replacement->expected_snapshot_revision;
}

static void publish_artifact_function_epochs(RAnal *anal,
		const RCoreAnalArtifactReplacement *replacements, size_t replacement_count) {
	size_t i;
	for (i = 0; i < replacement_count; i++) {
		RAnalFunction *function = r_anal_get_function_at (anal, replacements[i].scope_id);
		if (!function || function->addr != replacements[i].scope_id) {
			continue;
		}
		size_t j;
		bool already_published = false;
		for (j = 0; j < i; j++) {
			if (replacements[j].scope_id == replacements[i].scope_id) {
				already_published = true;
				break;
			}
		}
		if (!already_published) {
			r_anal_function_bump_dirty_epoch (function);
		}
	}
}

static RCoreAnalArtifactReplaceResult artifacts_replace_internal(RCore *core,
		const RCoreAnalArtifactReplacement *replacements, size_t replacement_count,
		bool require_source) {
	RCoreAnalArtifactReplaceResult result = {
		.status = R_CORE_ANAL_ARTIFACT_REPLACE_PREPARATION_FAILED,
		.failed_index = R_CORE_ANAL_ARTIFACT_INDEX_NONE,
	};
	if (!core || (!replacements && replacement_count)) {
		result.status = R_CORE_ANAL_ARTIFACT_REPLACE_INVALID_ARGUMENT;
		return result;
	}
	if (!replacement_count) {
		result.status = R_CORE_ANAL_ARTIFACT_REPLACE_OK;
		return result;
	}
	size_t i;
	for (i = 0; i < replacement_count; i++) {
		if (!artifact_replacement_is_valid (&replacements[i])) {
			result.status = R_CORE_ANAL_ARTIFACT_REPLACE_INVALID_ARGUMENT;
			result.failed_index = i;
			return result;
		}
	}
	if (!replacements_have_unique_keys (replacements, replacement_count, &result.failed_index)) {
		result.status = R_CORE_ANAL_ARTIFACT_REPLACE_INVALID_ARGUMENT;
		return result;
	}
	ArtifactXrefSets xref_sets = {0};
	if (!artifact_xref_sets_prepare (replacements, replacement_count, &xref_sets,
			&result.failed_index)) {
		result.status = result.failed_index == R_CORE_ANAL_ARTIFACT_INDEX_NONE
			? R_CORE_ANAL_ARTIFACT_REPLACE_PREPARATION_FAILED
			: R_CORE_ANAL_ARTIFACT_REPLACE_INVALID_ARGUMENT;
		return result;
	}
	RCorePriv *priv = core->priv;
	RAnal *anal = core->anal;
	RFlag *flags = core->flags;
	if (!priv || !priv->anal_artifacts || !anal || !flags) {
		result.status = R_CORE_ANAL_ARTIFACT_REPLACE_INVALID_ARGUMENT;
		artifact_xref_sets_fini (&xref_sets);
		return result;
	}
	ArtifactAddrSet addresses = {0};
	ArtifactNameSet names = {0};
	RCoreAnalArtifactStore *candidate = NULL;
	RAnalMetaStoreShadow *meta_shadow = NULL;
	RFlagStoreShadow *flag_shadow = NULL;
	RAnalOwnedXrefPrepared *xref_prepared = NULL;
	bool locked_core = false;
	bool locked_anal = false;
	bool locked_flags = false;
	r_th_lock_enter (core->lock);
	locked_core = true;
	r_th_lock_enter (anal->lock);
	locked_anal = true;
	r_th_lock_enter (flags->lock);
	locked_flags = true;
	if (require_source) {
		for (i = 0; i < replacement_count; i++) {
			if (!artifact_replacement_epoch_matches (core, anal, &replacements[i])) {
				result.status = R_CORE_ANAL_ARTIFACT_REPLACE_STALE_SOURCE;
				result.failed_index = i;
				goto cleanup;
			}
		}
	}
	candidate = prepare_candidate_store (priv->anal_artifacts, replacements,
		replacement_count, &addresses, &names, &result.failed_index);
	if (!candidate) {
		goto cleanup;
	}
	meta_shadow = r_meta_store_shadow_prepare (anal);
	flag_shadow = r_flag_store_shadow_prepare (flags);
	if (!meta_shadow || !flag_shadow) {
		goto cleanup;
	}
	bool conflict = false;
	bool comment_projection_changed = false;
	if (!prepare_comment_projection (anal, meta_shadow, priv->anal_artifacts,
			candidate, &addresses, &conflict, &comment_projection_changed)
			|| !prepare_flag_projection (flags, flag_shadow, priv->anal_artifacts,
				candidate, &names, &conflict)) {
		result.status = conflict? R_CORE_ANAL_ARTIFACT_REPLACE_CONFLICT
			: R_CORE_ANAL_ARTIFACT_REPLACE_PREPARATION_FAILED;
		goto cleanup;
	}
	RAnalOwnedXrefStatus xref_status = r_anal_xrefs_owned_prepare_many (
		anal, xref_sets.sets, xref_sets.count, &xref_prepared);
	if (xref_status != R_ANAL_OWNED_XREF_STATUS_OK) {
		result.status = xref_status == R_ANAL_OWNED_XREF_STATUS_INVALID
			? R_CORE_ANAL_ARTIFACT_REPLACE_CONFLICT
			: R_CORE_ANAL_ARTIFACT_REPLACE_PREPARATION_FAILED;
		goto cleanup;
	}
	bool changed = candidate_changes_artifacts (priv->anal_artifacts, candidate,
		replacements, replacement_count) || comment_projection_changed
		|| r_anal_xrefs_owned_changed (xref_prepared);
	if (!changed) {
		result.status = R_CORE_ANAL_ARTIFACT_REPLACE_OK;
		result.replaced = replacement_count;
		result.revision = priv->anal_artifacts->revision;
		goto cleanup;
	}
	r_meta_store_shadow_swap (anal, meta_shadow);
	r_anal_xrefs_owned_swap (anal, xref_prepared);
	r_flag_store_shadow_swap (flags, flag_shadow);
	RCoreAnalArtifactStore *old_store = priv->anal_artifacts;
	priv->anal_artifacts = candidate;
	candidate = old_store;
	priv->anal_artifacts->revision++;
	if (!priv->anal_artifacts->revision) {
		priv->anal_artifacts->revision++;
	}
	r_anal_xrefs_owned_publish (anal, xref_prepared);
	if (require_source) {
		publish_artifact_function_epochs (anal, replacements, replacement_count);
	}
	R_DIRTY_SET (anal);
	result.status = R_CORE_ANAL_ARTIFACT_REPLACE_OK;
	result.replaced = replacement_count;
	result.revision = priv->anal_artifacts->revision;

cleanup:
	if (locked_flags) {
		r_th_lock_leave (flags->lock);
	}
	if (locked_anal) {
		r_th_lock_leave (anal->lock);
	}
	if (locked_core) {
		r_th_lock_leave (core->lock);
	}
	r_anal_xrefs_owned_prepared_free (xref_prepared);
	r_flag_store_shadow_free (flag_shadow);
	r_meta_store_shadow_free (meta_shadow);
	r_core_anal_artifact_store_free (candidate);
	artifact_addr_set_fini (&addresses);
	artifact_name_set_fini (&names);
	artifact_xref_sets_fini (&xref_sets);
	return result;
}

R_API RCoreAnalArtifactReplaceResult r_core_anal_artifacts_replace(RCore *core,
		const RCoreAnalArtifactReplacement *replacements, size_t replacement_count) {
	return artifacts_replace_internal (core, replacements, replacement_count, true);
}

R_IPI bool r_core_anal_artifacts_drop_scope(RCore *core, ut64 scope_id) {
	R_RETURN_VAL_IF_FAIL (core && core->priv && core->anal && core->lock
		&& core->anal->lock && scope_id != UT64_MAX, false);
	bool success = false;
	r_th_lock_enter (core->lock);
	r_th_lock_enter (core->anal->lock);
	RCorePriv *priv = core->priv;
	RCoreAnalArtifactStore *store = priv->anal_artifacts;
	if (!store) {
		success = true;
		goto beach;
	}
	size_t count = 0;
	RListIter *iter;
	RCoreOwnedArtifactSet *set;
	r_list_foreach (store->sets, iter, set) {
		if (set->scope_id == scope_id) {
			count++;
		}
	}
	if (!count) {
		success = true;
		goto beach;
	}
	size_t replacement_bytes;
	if (r_mul_overflow_size_t (count, sizeof (RCoreAnalArtifactReplacement),
			&replacement_bytes)) {
		goto beach;
	}
	RCoreAnalArtifactReplacement *replacements = calloc (1, replacement_bytes);
	if (!replacements) {
		goto beach;
	}
	size_t index = 0;
	r_list_foreach (store->sets, iter, set) {
		if (set->scope_id != scope_id) {
			continue;
		}
		replacements[index++] = (RCoreAnalArtifactReplacement) {
			.provider_id = set->provider_id,
			.domain_id = set->domain_id,
			.scope_id = scope_id,
		};
	}
	RCoreAnalArtifactReplaceResult result = artifacts_replace_internal (
		core, replacements, count, false);
	success = result.status == R_CORE_ANAL_ARTIFACT_REPLACE_OK;
	free (replacements);

beach:
	r_th_lock_leave (core->anal->lock);
	r_th_lock_leave (core->lock);
	return success;
}
