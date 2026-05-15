/* radare - LGPL - Copyright 2011-2026 - pancake, Oddcoder */

#include <r_anal.h>
#define DB anal->sdb_cc

#define R_ANAL_DYNCC_MAX_MAPS 32
#define R_ANAL_DYNCC_NAME_SIZE 32
#define R_ANAL_DYNCC_GROUP_SIZE 256
#define R_ANAL_DYNCC_REGSET_SIZE 256
#define R_ANAL_DYNCC_MAX_ROLES 8
#define R_ANAL_DYNCC_TAIL (-1)
#define R_ANAL_DYNCC_CACHE_SIZE 8

typedef enum r_anal_dyn_cc_map_kind_t {
	R_ANAL_DYNCC_MAP_RANGE,
	R_ANAL_DYNCC_MAP_LIST,
	R_ANAL_DYNCC_MAP_GROUP,
	R_ANAL_DYNCC_MAP_CC,
} RAnalDynCCMapKind;

/* A slice references a span of the interned, immutable dyncc expression rather
 * than copying it. It stays valid for as long as that interned string lives,
 * which is the lifetime of anal->constpool. */
typedef struct r_anal_dyn_cc_slice_t {
	const char *p;
	ut16 len;
} RAnalDynCCSlice;

typedef struct r_anal_dyn_cc_map_t {
	bool has_args;
	int arg_base;
	int arg_count;
	int arg_delta;
	RAnalDynCCMapKind kind;
	char prefix;
	RAnalDynCCSlice base_reg; /* RANGE: explicit memory base register from m(reg) */
	int loc_base;
	int loc_count;
	int loc_delta;
	RAnalDynCCSlice text;     /* LIST: items inside (); GROUP: the whole {...}; CC: the &name */
	int reg_count;            /* LIST: number of comma-separated items */
} RAnalDynCCMap;

typedef struct r_anal_dyn_cc_role_t {
	RAnalDynCCSlice name;
	int arg;
	RAnalDynCCSlice loc;
} RAnalDynCCRole;

typedef struct r_anal_dyn_cc_t {
	RAnalDynCCMap args[R_ANAL_DYNCC_MAX_MAPS];
	int arg_map_count;
	RAnalDynCCMap rets[R_ANAL_DYNCC_MAX_MAPS];
	int ret_map_count;
	bool instance;
	int stack_pop;
	RAnalDynCCSlice clobbers;
	RAnalDynCCSlice preserves;
	RAnalDynCCRole roles[R_ANAL_DYNCC_MAX_ROLES];
	int role_count;
} RAnalDynCC;

/* Small round-robin cache of parsed dyncc expressions, keyed by interned
 * pointer identity. Avoids re-parsing the same expression on every accessor
 * call during analysis. Owned by RAnal, freed in r_anal_free / r_anal_cc_reset. */
typedef struct r_anal_dyn_cc_cache_t {
	const char *keys[R_ANAL_DYNCC_CACHE_SIZE];
	RAnalDynCC entries[R_ANAL_DYNCC_CACHE_SIZE];
	int next;
} RAnalDynCCCache;

static bool dyncc_parse_int(const char **sp, int *out) {
	const char *s = *sp;
	ut64 n = 0;
	if (!isdigit ((ut8)*s)) {
		return false;
	}
	while (isdigit ((ut8)*s)) {
		n = (n * 10) + (*s++ - '0');
		if (n > ST32_MAX) {
			return false;
		}
	}
	*out = (int)n;
	*sp = s;
	return true;
}

static bool dyncc_parse_optional_count(const char **sp, int *out) {
	if (!isdigit ((ut8)**sp)) {
		*out = R_ANAL_DYNCC_TAIL;
		return true;
	}
	return dyncc_parse_int (sp, out);
}

static bool dyncc_range_valid(int base, int count, int delta) {
	if (count < 0) {
		return true;
	}
	if (count == 0) {
		return true;
	}
	return delta > 0? base <= ST32_MAX - (count - 1): base >= count - 1;
}

static bool dyncc_parse_index_range(const char **sp, int *base, int *count, int *delta) {
	const char *s = *sp;
	if (!dyncc_parse_int (&s, base)) {
		return false;
	}
	if (*s != '+' && *s != '-') {
		*count = 1;
		*delta = 1;
		*sp = s;
		return true;
	}
	*delta = *s++ == '-'? -1: 1;
	if (!dyncc_parse_optional_count (&s, count)) {
		return false;
	}
	if (!dyncc_range_valid (*base, *count, *delta)) {
		return false;
	}
	*sp = s;
	return true;
}

static bool dyncc_parse_name(const char **sp, const char *end, RAnalDynCCSlice *out) {
	const char *s = *sp;
	const char *n = s;
	while (n < end && (isalnum ((ut8)*n) || *n == '_' || *n == '.' || *n == '-')) {
		n++;
	}
	size_t len = n - s;
	if (!len || len >= R_ANAL_DYNCC_NAME_SIZE) {
		return false;
	}
	out->p = s;
	out->len = (ut16)len;
	*sp = n;
	return true;
}

static bool dyncc_parse_list(const char **sp, const char *end, RAnalDynCCMap *map) {
	const char *s = *sp;
	if (*s++ != '(') {
		return false;
	}
	map->kind = R_ANAL_DYNCC_MAP_LIST;
	const char *content = s;
	while (s < end && *s != ')') {
		if (map->reg_count >= R_ANAL_CC_MAXARG) {
			return false;
		}
		const char *n = s;
		while (n < end && *n != ',' && *n != ')') {
			n++;
		}
		size_t len = n - s;
		if (!len || len >= R_ANAL_DYNCC_NAME_SIZE) {
			return false;
		}
		map->reg_count++;
		s = n;
		if (*s == ',') {
			s++;
		}
	}
	if (s >= end || *s != ')' || !map->reg_count) {
		return false;
	}
	map->text.p = content;
	map->text.len = (ut16)(s - content);
	*sp = s + 1;
	return true;
}

static bool dyncc_parse_group(const char **sp, const char *end, RAnalDynCCMap *map) {
	const char *s = *sp;
	if (*s++ != '{') {
		return false;
	}
	while (s < end && *s != '}') {
		if (*s == '{') {
			return false;
		}
		s++;
	}
	size_t len = s - *sp + 1;
	if (s >= end || *s != '}' || len <= 2 || len >= R_ANAL_DYNCC_GROUP_SIZE) {
		return false;
	}
	map->text.p = *sp;
	map->text.len = (ut16)len;
	map->kind = R_ANAL_DYNCC_MAP_GROUP;
	map->loc_count = 1;
	*sp = s + 1;
	return true;
}

static bool dyncc_parse_loc(const char **sp, const char *end, RAnalDynCCMap *map) {
	const char *s = *sp;
	if (s >= end) {
		return false;
	}
	if (*s == '&') {
		s++;
		map->kind = R_ANAL_DYNCC_MAP_CC;
		if (!dyncc_parse_name (&s, end, &map->text)) {
			return false;
		}
		*sp = s;
		return true;
	}
	if (*s == '(') {
		return dyncc_parse_list (sp, end, map);
	}
	if (*s == '{') {
		return dyncc_parse_group (sp, end, map);
	}
	if (!isalpha ((ut8)*s)) {
		return false;
	}
	map->kind = R_ANAL_DYNCC_MAP_RANGE;
	map->prefix = *s++;
	if (map->prefix == 'm' && s < end && *s == '(') {
		s++;
		const char *n = s;
		while (n < end && *n != ')') {
			n++;
		}
		size_t len = n - s;
		if (n >= end || !len || len >= R_ANAL_DYNCC_NAME_SIZE) {
			return false;
		}
		map->base_reg.p = s;
		map->base_reg.len = (ut16)len;
		s = n + 1;
	}
	if (!dyncc_parse_int (&s, &map->loc_base) || (*s != '+' && *s != '-')) {
		return false;
	}
	map->loc_delta = *s++ == '-'? -1: 1;
	if (!dyncc_parse_optional_count (&s, &map->loc_count)) {
		return false;
	}
	if (!dyncc_range_valid (map->loc_base, map->loc_count, map->loc_delta)) {
		return false;
	}
	*sp = s;
	return true;
}

static int dyncc_loc_count(const RAnalDynCCMap *map) {
	return map->kind == R_ANAL_DYNCC_MAP_LIST? map->reg_count: map->loc_count;
}

static const char *dyncc_scan_delim(const char *s, const char *end, char delim) {
	int depth = 0;
	for (; s < end; s++) {
		if (*s == '(' || *s == '{') {
			depth++;
		} else if (*s == ')' || *s == '}') {
			if (depth > 0) {
				depth--;
			}
		} else if (!depth && *s == delim) {
			return s;
		}
	}
	return end;
}

static bool dyncc_parse_map(const char *s, const char *end, bool args, int *next_arg, RAnalDynCCMap *map) {
	const char *eq = dyncc_scan_delim (s, end, '=');
	if (eq < end) {
		if (!args) {
			return false;
		}
		const char *ap = s;
		map->has_args = true;
		if (!dyncc_parse_index_range (&ap, &map->arg_base, &map->arg_count, &map->arg_delta) || ap != eq) {
			return false;
		}
		s = eq + 1;
	}
	const char *lp = s;
	if (!dyncc_parse_loc (&lp, end, map) || lp != end) {
		return false;
	}
	if (args && !map->has_args && map->kind != R_ANAL_DYNCC_MAP_CC) {
		map->has_args = true;
		map->arg_base = *next_arg;
		map->arg_delta = 1;
		map->arg_count = dyncc_loc_count (map);
		if (map->arg_count >= 0) {
			*next_arg += map->arg_count;
		}
	} else if (!args && !map->has_args && map->kind != R_ANAL_DYNCC_MAP_CC) {
		map->has_args = true;
		map->arg_base = *next_arg;
		map->arg_delta = 1;
		map->arg_count = dyncc_loc_count (map);
		if (map->arg_count == R_ANAL_DYNCC_TAIL) {
			return false;
		}
		*next_arg += map->arg_count;
	}
	if (map->has_args && map->arg_count == R_ANAL_DYNCC_TAIL && map->kind == R_ANAL_DYNCC_MAP_LIST) {
		return false;
	}
	int loc_count = dyncc_loc_count (map);
	if (map->kind != R_ANAL_DYNCC_MAP_CC && map->has_args && map->arg_count >= 0 && loc_count >= 0 && map->arg_count != loc_count) {
		return false;
	}
	return true;
}

static bool dyncc_parse_maps(const char *s, const char *end, bool args, RAnalDynCCMap *maps, int *count) {
	int next_arg = 0;
	while (s < end) {
		if (*count >= R_ANAL_DYNCC_MAX_MAPS) {
			return false;
		}
		const char *item_end = dyncc_scan_delim (s, end, ',');
		if (item_end == s) {
			return false;
		}
		RAnalDynCCMap map = {0};
		if (!dyncc_parse_map (s, item_end, args, &next_arg, &map)) {
			return false;
		}
		maps[(*count)++] = map;
		s = item_end;
		if (s < end && *s == ',') {
			s++;
		}
	}
	return true;
}

static bool dyncc_range_eq(const char *s, const char *end, const char *needle) {
	size_t len = strlen (needle);
	return end - s == len && !strncmp (s, needle, len);
}

static const char *dyncc_range_startswith(const char *s, const char *end, const char *prefix) {
	size_t len = strlen (prefix);
	return end - s >= len && !strncmp (s, prefix, len)? s + len: NULL;
}

static bool cc_parse_stack_pop_range(const char *s, const char *end, int *out) {
	if (!s || s >= end) {
		return false;
	}
	if (dyncc_range_eq (s, end, "caller")) {
		*out = 0;
		return true;
	}
	if (dyncc_range_eq (s, end, "callee")) {
		*out = R_ANAL_CC_STACK_POP_UNKNOWN;
		return true;
	}
	const char *p = dyncc_range_startswith (s, end, "pop=");
	if (!p) {
		p = s;
	}
	if (!dyncc_parse_int (&p, out)) {
		return false;
	}
	return p == end;
}

static bool cc_parse_stack_pop(const char *s, int *out) {
	return s? cc_parse_stack_pop_range (s, s + strlen (s), out): false;
}

static bool dyncc_set_regset(const char *s, const char *end, RAnalDynCCSlice *dst) {
	size_t len = end - s;
	if (!len || len >= R_ANAL_DYNCC_REGSET_SIZE) {
		return false;
	}
	dst->p = s;
	dst->len = (ut16)len;
	return true;
}

static bool dyncc_slice_eq(const RAnalDynCCSlice *slice, const char *s) {
	size_t len = strlen (s);
	return slice->len == len && !strncmp (slice->p, s, len);
}

static bool dyncc_is_builtin_role(const RAnalDynCCSlice *name) {
	return dyncc_slice_eq (name, "self")
		|| dyncc_slice_eq (name, "sret")
		|| dyncc_slice_eq (name, "vtt")
		|| dyncc_slice_eq (name, "error")
		|| dyncc_slice_eq (name, "context");
}

static bool dyncc_parse_role_name(const char *s, const char *end, RAnalDynCCSlice *name) {
	const char *role = dyncc_range_startswith (s, end, "role.");
	if (role) {
		s = role;
	} else {
		RAnalDynCCSlice tmp = {
			.p = s,
			.len = (ut16)(end - s)
		};
		if (!dyncc_is_builtin_role (&tmp)) {
			return false;
		}
	}
	const char *p = s;
	if (!dyncc_parse_name (&p, end, name) || p != end) {
		return false;
	}
	return true;
}

static int dyncc_find_role(const RAnalDynCC *d, const char *name, size_t name_len) {
	int i;
	for (i = 0; i < d->role_count; i++) {
		const RAnalDynCCRole *role = &d->roles[i];
		if (role->name.len == name_len && !strncmp (role->name.p, name, name_len)) {
			return i;
		}
	}
	return -1;
}

static bool dyncc_parse_role(const char *s, const char *end, RAnalDynCC *d) {
	const char *eq = dyncc_scan_delim (s, end, '=');
	if (eq == end || eq == s || eq + 1 == end) {
		return false;
	}
	RAnalDynCCSlice name = {0};
	if (!dyncc_parse_role_name (s, eq, &name)) {
		return false;
	}
	int slot = dyncc_find_role (d, name.p, name.len);
	if (slot < 0) {
		if (d->role_count >= R_ANAL_DYNCC_MAX_ROLES) {
			return false;
		}
		slot = d->role_count++;
	}
	RAnalDynCCRole *role = &d->roles[slot];
	memset (role, 0, sizeof (*role));
	role->name = name;
	role->arg = -1;
	const char *value = eq + 1;
	const char *p = value;
	int arg = -1;
	if (dyncc_parse_int (&p, &arg) && p == end) {
		role->arg = arg;
		return true;
	}
	size_t len = end - value;
	if (!len || len >= R_ANAL_DYNCC_GROUP_SIZE) {
		return false;
	}
	role->loc.p = value;
	role->loc.len = (ut16)len;
	return true;
}

static bool dyncc_parse_suffixes(const char *s, const char *end, RAnalDynCC *d) {
	while (s < end) {
		if (*s++ != '!') {
			return false;
		}
		const char *next = dyncc_scan_delim (s, end, '!');
		int pop;
		if (cc_parse_stack_pop_range (s, next, &pop)) {
			d->stack_pop = pop;
		} else {
			const char *regs = dyncc_range_startswith (s, next, "clobber=");
			if (regs) {
				if (!dyncc_set_regset (regs, next, &d->clobbers)) {
					return false;
				}
			} else if ((regs = dyncc_range_startswith (s, next, "preserve="))) {
				if (!dyncc_set_regset (regs, next, &d->preserves)) {
					return false;
				}
			} else if (!dyncc_parse_role (s, next, d)) {
				return false;
			}
		}
		s = next;
	}
	return true;
}

static bool dyncc_map_covers_arg0(const RAnalDynCCMap *map) {
	if (map->kind == R_ANAL_DYNCC_MAP_CC) {
		if (!map->has_args) {
			return true;
		}
		/* Fall through to the explicit logical-argument range check. */
	}
	if (!map->has_args) {
		return false;
	}
	if (map->arg_count == R_ANAL_DYNCC_TAIL) {
		return map->arg_delta > 0? map->arg_base <= 0: map->arg_base >= 0;
	}
	int i;
	for (i = 0; i < map->arg_count; i++) {
		if (map->arg_base + (i * map->arg_delta) == 0) {
			return true;
		}
	}
	return false;
}

static bool dyncc_has_arg0(const RAnalDynCC *d) {
	int i;
	for (i = 0; i < d->arg_map_count; i++) {
		if (dyncc_map_covers_arg0 (&d->args[i])) {
			return true;
		}
	}
	return false;
}

static bool dyncc_parse(const char *cc, RAnalDynCC *out) {
	if (!cc || strncmp (cc, "dyncc:", 6)) {
		return false;
	}
	RAnalDynCC d = {0};
	const char *args = cc + 6;
	const char *end = cc + strlen (cc);
	const char *kind = dyncc_scan_delim (args, end, ':');
	if (kind == end || (kind[1] != 'i' && kind[1] != 's') || kind[2] != ':') {
		return false;
	}
	const char *rets = kind + 3;
	const char *suffix = dyncc_scan_delim (rets, end, '!');
	const char *ret_end = suffix < end? suffix: end;
	d.instance = kind[1] == 'i';
	if (!dyncc_parse_maps (args, kind, true, d.args, &d.arg_map_count)) {
		return false;
	}
	if (!dyncc_parse_maps (rets, ret_end, false, d.rets, &d.ret_map_count)) {
		return false;
	}
	if (suffix < end && !dyncc_parse_suffixes (suffix, end, &d)) {
		return false;
	}
	if (d.instance && dyncc_find_role (&d, "self", 4) < 0 && !dyncc_has_arg0 (&d)) {
		return false;
	}
	*out = d;
	return true;
}

/* Intern a (ptr,len) span into anal->constpool and return the stable string. */
static const char *dyncc_intern(RAnal *anal, const char *p, size_t len) {
	if (!p || !len) {
		return NULL;
	}
	char tmp[R_ANAL_DYNCC_GROUP_SIZE];
	char *heap = NULL;
	if (len < sizeof (tmp)) {
		memcpy (tmp, p, len);
		tmp[len] = 0;
		p = tmp;
	} else {
		heap = r_str_ndup (p, len);
		if (!heap) {
			return NULL;
		}
		p = heap;
	}
	const char *ret = r_str_constpool_get (&anal->constpool, p);
	free (heap);
	return ret;
}

/* Parse a dyncc expression at most once. The returned pointer is owned by the
 * per-RAnal cache and is valid until the next eviction of that slot; callers
 * must use it before triggering another dyncc_get. */
static const RAnalDynCC *dyncc_get(RAnal *anal, const char *cc) {
	if (!cc || strncmp (cc, "dyncc:", 6)) {
		return NULL;
	}
	/* Intern first so parsed slices and cache keys reference immortal storage
	 * and identical expressions compare equal by pointer. */
	cc = r_str_constpool_get (&anal->constpool, cc);
	if (!cc) {
		return NULL;
	}
	RAnalDynCCCache *cache = anal->dyncc_cache;
	if (!cache) {
		cache = anal->dyncc_cache = R_NEW0 (RAnalDynCCCache);
		if (!cache) {
			return NULL;
		}
	}
	int i;
	for (i = 0; i < R_ANAL_DYNCC_CACHE_SIZE; i++) {
		if (cache->keys[i] == cc) {
			return &cache->entries[i];
		}
	}
	RAnalDynCC parsed;
	if (!dyncc_parse (cc, &parsed)) {
		return NULL;
	}
	const int slot = cache->next;
	cache->next = (cache->next + 1) % R_ANAL_DYNCC_CACHE_SIZE;
	cache->entries[slot] = parsed;
	cache->keys[slot] = cc;
	return &cache->entries[slot];
}

static bool dyncc_map_match(const RAnalDynCCMap *map, int n, int *rel) {
	if (!map->has_args || n < 0) {
		return false;
	}
	if (map->arg_count == R_ANAL_DYNCC_TAIL) {
		if (map->arg_delta > 0) {
			if (n < map->arg_base) {
				return false;
			}
			*rel = n - map->arg_base;
		} else {
			if (n > map->arg_base) {
				return false;
			}
			*rel = map->arg_base - n;
		}
		return true;
	}
	int i;
	for (i = 0; i < map->arg_count; i++) {
		if (map->arg_base + (i * map->arg_delta) == n) {
			*rel = i;
			return true;
		}
	}
	return false;
}

static bool dyncc_ref_arg_index(const RAnalDynCCMap *map, int n, int *refn, int *reflastn) {
	if (!map || map->kind != R_ANAL_DYNCC_MAP_CC || n < 0) {
		return false;
	}
	if (map->has_args) {
		int rel;
		if (!dyncc_map_match (map, n, &rel)) {
			return false;
		}
		*refn = rel;
		*reflastn = map->arg_count;
	} else {
		*refn = n;
		*reflastn = -1;
	}
	return true;
}

/* Locate the rel-th comma-separated item inside a parsed LIST slice. */
static bool dyncc_list_item(const RAnalDynCCMap *map, int rel, const char **out, size_t *out_len) {
	const char *s = map->text.p;
	const char *end = s + map->text.len;
	int i;
	for (i = 0; s <= end; i++) {
		const char *tok = s;
		while (s < end && *s != ',') {
			s++;
		}
		if (i == rel) {
			*out = tok;
			*out_len = s - tok;
			return true;
		}
		s++; /* skip the comma */
	}
	return false;
}

static const char *dyncc_map_loc(RAnal *anal, const RAnalDynCCMap *map, int rel) {
	if (rel < 0) {
		return NULL;
	}
	switch (map->kind) {
	case R_ANAL_DYNCC_MAP_LIST: {
		if (rel >= map->reg_count) {
			return NULL;
		}
		const char *tok = NULL;
		size_t tok_len = 0;
		if (!dyncc_list_item (map, rel, &tok, &tok_len)) {
			return NULL;
		}
		return dyncc_intern (anal, tok, tok_len);
	}
	case R_ANAL_DYNCC_MAP_GROUP:
		return rel == 0? dyncc_intern (anal, map->text.p, map->text.len): NULL;
	case R_ANAL_DYNCC_MAP_RANGE:
		if (map->loc_count >= 0 && rel >= map->loc_count) {
			return NULL;
		}
		if (map->prefix == 'm') {
			if (!map->base_reg.len) {
				return r_str_constpool_get (&anal->constpool, map->loc_delta > 0? "stack": "stack_rev");
			}
			r_strf_var (name, 80, "m(%.*s)%d", (int)map->base_reg.len, map->base_reg.p,
				map->loc_base + (rel * map->loc_delta));
			return r_str_constpool_get (&anal->constpool, name);
		}
		r_strf_var (name, 64, "%c%d", map->prefix, map->loc_base + (rel * map->loc_delta));
		return r_str_constpool_get (&anal->constpool, name);
	default:
		return NULL;
	}
}

static const char *dyncc_arg_home(RAnal *anal, const RAnalDynCC *d, int n, int home, int lastn) {
	int seen = 0;
	int i;
	for (i = 0; i < d->arg_map_count; i++) {
		const RAnalDynCCMap *map = &d->args[i];
		const char *loc = NULL;
		if (map->kind == R_ANAL_DYNCC_MAP_CC) {
			int refn, reflastn;
			if (dyncc_ref_arg_index (map, n, &refn, &reflastn)) {
				r_strf_var (refcc, R_ANAL_DYNCC_NAME_SIZE, "%.*s", (int)map->text.len, map->text.p);
				loc = r_anal_cc_arg (anal, refcc, refn, reflastn >= 0? reflastn: lastn);
			}
		} else {
			int rel;
			if (dyncc_map_match (map, n, &rel)) {
				loc = dyncc_map_loc (anal, map, rel);
			}
		}
		if (loc) {
			if (seen == home) {
				return loc;
			}
			seen++;
		}
	}
	return NULL;
}

static const RAnalDynCCRole *dyncc_role(const RAnalDynCC *d, const char *name) {
	int slot = dyncc_find_role (d, name, strlen (name));
	return slot >= 0? &d->roles[slot]: NULL;
}

static const char *dyncc_role_loc(RAnal *anal, const RAnalDynCC *d, const char *name) {
	const RAnalDynCCRole *role = dyncc_role (d, name);
	if (role) {
		return role->arg >= 0
			? dyncc_arg_home (anal, d, role->arg, 0, -1)
			: dyncc_intern (anal, role->loc.p, role->loc.len);
	}
	if (!strcmp (name, "self") && d->instance) {
		return dyncc_arg_home (anal, d, 0, 0, -1);
	}
	return NULL;
}

static const char *dyncc_ret(RAnal *anal, const RAnalDynCC *d, int n) {
	int i;
	for (i = 0; i < d->ret_map_count; i++) {
		const RAnalDynCCMap *map = &d->rets[i];
		if (map->kind == R_ANAL_DYNCC_MAP_CC) {
			r_strf_var (refcc, R_ANAL_DYNCC_NAME_SIZE, "%.*s", (int)map->text.len, map->text.p);
			const char *ret = r_anal_cc_ret (anal, refcc, n);
			if (ret) {
				return ret;
			}
			continue;
		}
		int rel;
		if (dyncc_map_match (map, n, &rel)) {
			return dyncc_map_loc (anal, map, rel);
		}
	}
	return NULL;
}

static int dyncc_max_arg(RAnal *anal, const RAnalDynCC *d) {
	int max = 0;
	int i;
	for (i = 0; i < d->arg_map_count; i++) {
		const RAnalDynCCMap *map = &d->args[i];
		if (map->kind == R_ANAL_DYNCC_MAP_CC && !map->has_args) {
			r_strf_var (refcc, R_ANAL_DYNCC_NAME_SIZE, "%.*s", (int)map->text.len, map->text.p);
			max = R_MAX (max, r_anal_cc_max_arg (anal, refcc));
		} else if (map->has_args) {
			if (map->arg_count == R_ANAL_DYNCC_TAIL) {
				max = R_MAX (max, map->arg_base);
			} else if (map->arg_count > 0) {
				int end = map->arg_base + ((map->arg_count - 1) * map->arg_delta);
				max = R_MAX (max, R_MAX (map->arg_base, end) + 1);
			}
		}
	}
	return max;
}

static bool dyncc_ref_exists(RAnal *anal, const RAnalDynCCSlice *name) {
	r_strf_var (refcc, R_ANAL_DYNCC_NAME_SIZE, "%.*s", (int)name->len, name->p);
	const char *x = sdb_const_get (DB, refcc, 0);
	return x && !strcmp (x, "cc");
}

static bool dyncc_refs_exist(RAnal *anal, const RAnalDynCC *d) {
	int i;
	for (i = 0; i < d->arg_map_count; i++) {
		if (d->args[i].kind == R_ANAL_DYNCC_MAP_CC && !dyncc_ref_exists (anal, &d->args[i].text)) {
			return false;
		}
	}
	for (i = 0; i < d->ret_map_count; i++) {
		if (d->rets[i].kind == R_ANAL_DYNCC_MAP_CC && !dyncc_ref_exists (anal, &d->rets[i].text)) {
			return false;
		}
	}
	for (i = 0; i < d->role_count; i++) {
		if (d->roles[i].arg >= 0 && !dyncc_arg_home (anal, d, d->roles[i].arg, 0, -1)) {
			return false;
		}
	}
	return true;
}

R_API void r_anal_cc_del(RAnal *anal, const char *name) {
	R_RETURN_IF_FAIL (anal && name);
	RAnalDynCC d;
	if (dyncc_parse (name, &d)) {
		return;
	}
	size_t i;
	RStrBuf sb;
	sdb_unset (DB, r_strbuf_initf (&sb, "%s", name), 0);
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.ret", name), 0);
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.retn", name), 0);
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.argn", name), 0);
	for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
		sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.arg%u", name, (unsigned int)i), 0);
		sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.ret%u", name, (unsigned int)i), 0);
	}
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.self", name), 0);
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.error", name), 0);
	r_strbuf_fini (&sb);
}

R_API bool r_anal_cc_set(RAnal *anal, const char *expr) {
	R_RETURN_VAL_IF_FAIL (anal && expr, false);
	char *e = strdup (expr);
	char *p = strchr (e, '(');
	if (!p) {
		free (e);
		return false;
	}
	*p++ = 0;
	char *args = strdup (p);
	r_str_trim (p);
	char *end = strchr (args, ')');
	if (!end) {
		free (args);
		free (e);
		return false;
	}
	*end++ = 0;
	r_str_trim (p);
	r_str_trim (e);
	char *ccname = strchr (e, ' ');
	if (ccname) {
		*ccname++ = 0;
		r_str_trim (ccname);
	} else {
		free (args);
		free (e);
		return false;
	}
	RAnalDynCC d;
	if (dyncc_parse (ccname, &d)) {
		free (args);
		free (e);
		return false;
	}
	sdb_set (DB, ccname, "cc", 0);
	r_strf_buffer (64);
	sdb_unset (DB, r_strf ("cc.%s.ret", ccname), 0);
	int i;
	for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
		sdb_unset (DB, r_strf ("cc.%s.ret%d", ccname, i), 0);
	}
	if (strchr (e, ',')) {
		RList *ccRets = r_str_split_list (e, ",", 0);
		RListIter *iter;
		char *ret;
		int n = 0;
		r_list_foreach (ccRets, iter, ret) {
			r_str_trim (ret);
			sdb_set (DB, r_strf ("cc.%s.ret%d", ccname, n), ret, 0);
			n++;
		}
		sdb_num_set (DB, r_strf ("cc.%s.retn", ccname), n, 0);
		r_list_free (ccRets);
	} else {
		sdb_set (DB, r_strf ("cc.%s.ret0", ccname), e, 0);
		sdb_unset (DB, r_strf ("cc.%s.retn", ccname), 0);
	}

	RList *ccArgs = r_str_split_list (args, ",", 0);
	RListIter *iter;
	const char *arg;
	int n = 0;
	r_list_foreach (ccArgs, iter, arg) {
		if (!strcmp (arg, "stack")) {
			sdb_set (DB, r_strf ("cc.%s.argn", ccname), arg, 0);
		} else {
			sdb_set (DB, r_strf ("cc.%s.arg%d", ccname, n), arg, 0);
			n++;
		}
	}
	r_list_free (ccArgs);
	free (e);
	free (args);
	return true;
}

R_API bool r_anal_cc_once(RAnal *anal) {
	R_CRITICAL_ENTER (anal);
	bool res = sdb_add (DB, "warn", "once", 0);
	R_CRITICAL_LEAVE (anal);
	return res;
}

R_API void r_anal_cc_reset(RAnal *anal) {
	R_CRITICAL_ENTER (anal);
	sdb_reset (DB);
	R_FREE (anal->dyncc_cache);
	R_CRITICAL_LEAVE (anal);
}

static void dyncc_json_roles(RAnal *anal, PJ *pj, const RAnalDynCC *d) {
	if (!d->instance && !d->role_count) {
		return;
	}
	pj_ko (pj, "roles");
	const char *self = dyncc_role_loc (anal, d, "self");
	if (self) {
		pj_ks (pj, "self", self);
	}
	int i;
	for (i = 0; i < d->role_count; i++) {
		const RAnalDynCCRole *role = &d->roles[i];
		if (dyncc_slice_eq (&role->name, "self")) {
			continue;
		}
		const char *loc = role->arg >= 0
			? dyncc_arg_home (anal, d, role->arg, 0, -1)
			: dyncc_intern (anal, role->loc.p, role->loc.len);
		if (loc) {
			r_strf_var (name, R_ANAL_DYNCC_NAME_SIZE, "%.*s", (int)role->name.len, role->name.p);
			pj_ks (pj, name, loc);
		}
	}
	pj_end (pj);
}

R_API void r_anal_cc_get_json(RAnal *anal, PJ *pj, const char *name) {
	R_RETURN_IF_FAIL (anal && pj && name);
	r_strf_buffer (64);
	int i;
	const RAnalDynCC *d = dyncc_get (anal, name);
	if (d) {
		const char *ret = dyncc_ret (anal, d, 0);
		if (ret) {
			pj_ks (pj, "ret", ret);
		}
		pj_ka (pj, "rets");
		for (i = 0; ; i++) {
			const char *r = dyncc_ret (anal, d, i);
			if (!r) {
				break;
			}
			pj_s (pj, r);
		}
		pj_end (pj);
		char *sig = r_anal_cc_get (anal, name);
		if (sig) {
			pj_ks (pj, "signature", sig);
			free (sig);
		}
		int max = dyncc_max_arg (anal, d);
		pj_ka (pj, "args");
		for (i = 0; i < max; i++) {
			pj_s (pj, dyncc_arg_home (anal, d, i, 0, -1));
		}
		pj_end (pj);
		pj_ka (pj, "arg_homes");
		for (i = 0; i < max; i++) {
			pj_a (pj);
			int home;
			for (home = 0; ; home++) {
				const char *arg = dyncc_arg_home (anal, d, i, home, -1);
				if (!arg) {
					break;
				}
				pj_s (pj, arg);
			}
			pj_end (pj);
		}
		pj_end (pj);
		const char *argn = dyncc_arg_home (anal, d, max, 0, -1);
		if (argn) {
			pj_ks (pj, "argn", argn);
		}
		dyncc_json_roles (anal, pj, d);
		return;
	}
	// get cc by name and print the expr
	const char *cc_type = sdb_const_get (DB, name, 0);
	if (!cc_type || strcmp (cc_type, "cc")) {
		return;
	}
	const char *ret = r_anal_cc_ret (anal, name, 0);
	if (!ret) {
		return;
	}
	pj_ks (pj, "ret", ret);
	pj_ka (pj, "rets");
	int rn;
	for (rn = 0; ; rn++) {
		const char *r = r_anal_cc_ret (anal, name, rn);
		if (!r) {
			break;
		}
		pj_s (pj, r);
	}
	pj_end (pj);
	char *sig = r_anal_cc_get (anal, name);
	pj_ks (pj, "signature", sig);
	free (sig);
	pj_ka (pj, "args");
	for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
		const char *k = r_strf ("cc.%s.arg%d", name, i);
		const char *arg = sdb_const_get (DB, k, 0);
		if (!arg) {
			break;
		}
		pj_s (pj, arg);
	}
	pj_end (pj);
	const char *argn = sdb_const_get (DB, r_strf ("cc.%s.argn", name), 0);
	if (argn) {
		pj_ks (pj, "argn", argn);
	}
	const char *error = r_anal_cc_error (anal, name);
	if (error) {
		pj_ks (pj, "error", error);
	}
}

R_API char *r_anal_cc_get(RAnal *anal, const char *name) {
	Sdb *db = anal->sdb_cc;
	R_RETURN_VAL_IF_FAIL (anal && name, NULL);
	int i;
	const RAnalDynCC *d = dyncc_get (anal, name);
	if (d) {
		RStrBuf *sb = r_strbuf_new (NULL);
		const char *ret = dyncc_ret (anal, d, 0);
		r_strbuf_append (sb, ret? ret: "void");
		for (i = 1; ; i++) {
			const char *rs = dyncc_ret (anal, d, i);
			if (!rs) {
				break;
			}
			r_strbuf_appendf (sb, ":%s", rs);
		}
		const char *self = dyncc_role_loc (anal, d, "self");
		r_strbuf_appendf (sb, " %s%s%s (", r_str_get (self), self? ".": "", name);
		int max = dyncc_max_arg (anal, d);
		bool is_first = true;
		for (i = 0; i < max; i++) {
			const char *arg = dyncc_arg_home (anal, d, i, 0, -1);
			if (!arg) {
				continue;
			}
			r_strbuf_appendf (sb, "%s%s", is_first? "": ", ", arg);
			is_first = false;
		}
		const char *argn = dyncc_arg_home (anal, d, max, 0, -1);
		if (argn) {
			r_strbuf_appendf (sb, "%s%s", is_first? "": ", ", argn);
		}
		r_strbuf_append (sb, ");");
		return r_strbuf_drain (sb);
	}
	// get cc by name and print the expr
	const char *cc = sdb_const_get (db, name, 0);
	if (cc && strcmp (cc, "cc")) {
		R_LOG_ERROR ("Invalid calling convention name (%s)", name);
		return NULL;
	}
	const char *ret = r_anal_cc_ret (anal, name, 0);
	if (!ret) {
		R_LOG_ERROR ("Cannot find return type for %s", name);
		return NULL;
	}

	RStrBuf *sb = r_strbuf_new (NULL);
	const char *self = r_anal_cc_self (anal, name);
	// Multi-return: print "r0:r1:r2 ..."
	r_strbuf_appendf (sb, "%s", ret);
	int rn;
	for (rn = 1; ; rn++) {
		const char *rs = r_anal_cc_ret (anal, name, rn);
		if (!rs) {
			break;
		}
		r_strbuf_appendf (sb, ":%s", rs);
	}
	r_strbuf_appendf (sb, " %s%s%s (", r_str_get (self), self? ".": "", name);
	bool isFirst = true;
	bool revarg = false;
	{
		r_strf_var (k, 128, "cc.%s.revarg", name);
		const char *s = sdb_const_get (db, k, 0);
		revarg = r_str_is_true (s);
	}
	for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
		r_strf_var (k, 128, "cc.%s.arg%d", name, i);
		const char *arg = sdb_const_get (db, k, 0);
		if (!arg) {
			break;
		}
		r_strbuf_appendf (sb, "%s%s", isFirst? "": ", ", arg);
		isFirst = false;
	}
	r_strf_var (rename, 128, "cc.%s.argn", name);
	const char *argn = sdb_const_get (db, rename, 0);
	if (argn) {
		r_strbuf_appendf (sb, "%s%s", isFirst? "": ", ", argn);
	}
	r_strbuf_append (sb, ")");

	const char *error = r_anal_cc_error (anal, name);
	if (error) {
		r_strbuf_appendf (sb, " %s", error);
	}

	r_strbuf_append (sb, ";");
	if (revarg) {
		r_strbuf_append (sb, " // revarg");
	}
	return r_strbuf_drain (sb);
}

R_API bool r_anal_cc_exist(RAnal *anal, const char *cc) {
	R_RETURN_VAL_IF_FAIL (anal && cc, false);
	if (!strcmp (cc, "dyncc")) {
		return true;
	}
	const RAnalDynCC *d = dyncc_get (anal, cc);
	if (d) {
		return dyncc_refs_exist (anal, d);
	}
	const char *x = sdb_const_get (DB, cc, 0);
	return (x != NULL) && !strcmp (x, "cc");
}

R_API const char *r_anal_cc_arg_home(RAnal *anal, const char *cc, int n, int home, int lastn) {
	R_RETURN_VAL_IF_FAIL (anal && n >= 0 && home >= 0, NULL);
	if (!cc) {
		return NULL;
	}
	const RAnalDynCC *d = dyncc_get (anal, cc);
	if (d) {
		return dyncc_arg_home (anal, d, n, home, lastn);
	}
	if (home > 0) {
		return NULL;
	}
	Sdb *db = DB;
	r_strf_buffer (64);
	if (lastn > 0) {
		char *revarg = r_strf ("cc.%s.revarg", cc);
		if (r_str_is_true (sdb_const_get (db, revarg, 0))) {
			if (n >= lastn) {
				return NULL;
			}
			n = lastn - n - 1;
		}
	}
	char *query = r_strf ("cc.%s.arg%d", cc, n);
	const char *ret = sdb_const_get (db, query, 0);
	if (!ret) {
		query = r_strf ("cc.%s.argn", cc);
		ret = sdb_const_get (db, query, 0);
	}
	return ret? r_str_constpool_get (&anal->constpool, ret): NULL;
}

R_API const char *r_anal_cc_arg(RAnal *anal, const char *cc, int n, int lastn) {
	return r_anal_cc_arg_home (anal, cc, n, 0, lastn);
}

R_API const char *r_anal_cc_role(RAnal *anal, const char *convention, const char *role) {
	R_RETURN_VAL_IF_FAIL (anal && convention && role, NULL);
	const RAnalDynCC *d = dyncc_get (anal, convention);
	if (d) {
		return dyncc_role_loc (anal, d, role);
	}
	RStrBuf sb;
	const char *key = r_strbuf_initf (&sb, "cc.%s.%s", convention, role);
	const char *value = sdb_const_get (DB, key, 0);
	const char *res = value? r_str_constpool_get (&anal->constpool, value): NULL;
	r_strbuf_fini (&sb);
	return res;
}

R_API const char *r_anal_cc_self(RAnal *anal, const char *convention) {
	return r_anal_cc_role (anal, convention, "self");
}

R_API void r_anal_cc_set_self(RAnal *anal, const char *convention, const char *self) {
	R_RETURN_IF_FAIL (anal && convention && self);
	RAnalDynCC d;
	if (dyncc_parse (convention, &d)) {
		return;
	}
	if (!r_anal_cc_exist (anal, convention)) {
		return;
	}
	RStrBuf sb;
	sdb_set (DB, r_strbuf_initf (&sb, "cc.%s.self", convention), self, 0);
	r_strbuf_fini (&sb);
}

R_API const char *r_anal_cc_error(RAnal *anal, const char *convention) {
	return r_anal_cc_role (anal, convention, "error");
}

R_API void r_anal_cc_set_error(RAnal *anal, const char *convention, const char *error) {
	R_RETURN_IF_FAIL (anal && convention && error);
	RAnalDynCC d;
	if (dyncc_parse (convention, &d)) {
		return;
	}
	if (!r_anal_cc_exist (anal, convention)) {
		return;
	}
	RStrBuf sb;
	sdb_set (DB, r_strbuf_initf (&sb, "cc.%s.error", convention), error, 0);
	r_strbuf_fini (&sb);
}

R_API int r_anal_cc_max_arg(RAnal *anal, const char *cc) {
	int i = 0;
	R_RETURN_VAL_IF_FAIL (anal && DB && cc, 0);

	const RAnalDynCC *d = dyncc_get (anal, cc);
	if (d) {
		return dyncc_max_arg (anal, d);
	}

	for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
		r_strf_var (query, 64, "cc.%s.arg%d", cc, i);
		const char *res = sdb_const_get (DB, query, 0);
		if (!res) {
			break;
		}
	}
	return i;
}

R_API int r_anal_cc_max_arg_clamped(RAnal *anal, const char *cc) {
	R_RETURN_VAL_IF_FAIL (anal && cc, 0);
	return R_MIN (r_anal_cc_max_arg (anal, cc), R_ANAL_CC_MAXARG);
}

R_API const char *r_anal_cc_ret(RAnal *anal, const char *convention, int n) {
	R_RETURN_VAL_IF_FAIL (anal && convention && n >= 0, NULL);
	const RAnalDynCC *d = dyncc_get (anal, convention);
	if (d) {
		return dyncc_ret (anal, d, n);
	}
	r_strf_buffer (64);
	if (n > 0) {
		int retn = sdb_num_get (DB, r_strf ("cc.%s.retn", convention), 0);
		if (n >= retn) {
			return NULL;
		}
	}
	const char *ret = sdb_const_get (DB, r_strf ("cc.%s.ret%d", convention, n), 0);
	if (ret) {
		return ret;
	}
	if (n == 0) {
		return sdb_const_get (DB, r_strf ("cc.%s.ret", convention), 0);
	}
	return NULL;
}

R_API int r_anal_cc_stack_pop(RAnal *anal, const char *convention) {
	R_RETURN_VAL_IF_FAIL (anal && convention, 0);
	const RAnalDynCC *d = dyncc_get (anal, convention);
	if (d) {
		return d->stack_pop;
	}
	r_strf_var (query, 64, "cc.%s.pop", convention);
	const char *pop = sdb_const_get (DB, query, 0);
	int ret = 0;
	return cc_parse_stack_pop (pop, &ret)? ret: 0;
}

static const char *cc_regset(RAnal *anal, const char *convention, const char *field) {
	const RAnalDynCC *d = dyncc_get (anal, convention);
	if (d) {
		const RAnalDynCCSlice *slice = !strcmp (field, "clobber")? &d->clobbers: &d->preserves;
		return dyncc_intern (anal, slice->p, slice->len);
	}
	r_strf_var (query, 64, "cc.%s.%s", convention, field);
	const char *ret = sdb_const_get (DB, query, 0);
	return ret? r_str_constpool_get (&anal->constpool, ret): NULL;
}

R_API const char *r_anal_cc_clobbers(RAnal *anal, const char *convention) {
	R_RETURN_VAL_IF_FAIL (anal && convention, NULL);
	return cc_regset (anal, convention, "clobber");
}

R_API const char *r_anal_cc_preserves(RAnal *anal, const char *convention) {
	R_RETURN_VAL_IF_FAIL (anal && convention, NULL);
	return cc_regset (anal, convention, "preserve");
}

static bool cc_piece_push(RAnal *anal, RVecAnalCCPiece *pieces, int off, int size, const char *loc, size_t loc_len) {
	if (!loc_len) {
		return false;
	}
	const char *name = dyncc_intern (anal, loc, loc_len);
	if (!name) {
		return false;
	}
	RAnalCCPiece piece = {
		.off = off,
		.size = size,
		.loc = name
	};
	RVecAnalCCPiece_push_back (pieces, &piece);
	return true;
}

static bool cc_piece_parse(RAnal *anal, RVecAnalCCPiece *pieces, const char *s, const char *end, int idx) {
	while (s < end && isspace ((ut8)*s)) {
		s++;
	}
	while (end > s && isspace ((ut8)end[-1])) {
		end--;
	}
	if (s >= end) {
		return false;
	}
	int off = idx;
	if (isdigit ((ut8)*s)) {
		const char *p = s;
		if (dyncc_parse_int (&p, &off) && p < end && *p == ':') {
			s = p + 1;
		}
	}
	int size = 0;
	const char *dot = end;
	while (dot > s && isdigit ((ut8)dot[-1])) {
		dot--;
	}
	if (dot > s && dot[-1] == '.') {
		const char *p = dot;
		if (dyncc_parse_int (&p, &size) && p == end) {
			end = dot - 1;
		}
	}
	return cc_piece_push (anal, pieces, off, size, s, end - s);
}

static const char *cc_group_next(const char *s, const char *end) {
	const char *p = s;
	for (; p < end; p++) {
		if (*p == ',') {
			return p;
		}
		if (*p == ':') {
			const char *n = s;
			while (n < p && isdigit ((ut8)*n)) {
				n++;
			}
			if (n != p) {
				return p;
			}
		}
	}
	return p;
}

R_API bool r_anal_cc_location_pieces(RAnal *anal, const char *loc, RVecAnalCCPiece *pieces) {
	R_RETURN_VAL_IF_FAIL (anal && loc && pieces, false);
	RVecAnalCCPiece_clear (pieces);
	size_t len = strlen (loc);
	if (len < 2 || loc[0] != '{' || loc[len - 1] != '}') {
		return cc_piece_push (anal, pieces, 0, 0, loc, len);
	}
	const char *s = loc + 1;
	const char *end = loc + len - 1;
	int idx = 0;
	while (s < end) {
		const char *next = cc_group_next (s, end);
		if (!cc_piece_parse (anal, pieces, s, next, idx++)) {
			RVecAnalCCPiece_clear (pieces);
			return false;
		}
		s = next + (next < end);
	}
	return RVecAnalCCPiece_length (pieces) > 0;
}

R_API bool r_anal_cc_location_uses(RAnal *anal, const char *loc, const char *reg) {
	R_RETURN_VAL_IF_FAIL (anal && loc && reg, false);
	if (*loc && *loc != '{') {
		return !strcmp (loc, reg);
	}
	RVecAnalCCPiece pieces;
	RVecAnalCCPiece_init (&pieces);
	bool ret = false;
	if (r_anal_cc_location_pieces (anal, loc, &pieces)) {
		RAnalCCPiece *piece;
		R_VEC_FOREACH (&pieces, piece) {
			if (!strcmp (piece->loc, reg)) {
				ret = true;
				break;
			}
		}
	}
	RVecAnalCCPiece_fini (&pieces);
	return ret;
}

R_API const char *r_anal_cc_location_first(RAnal *anal, const char *loc) {
	R_RETURN_VAL_IF_FAIL (anal && loc, NULL);
	if (*loc && *loc != '{') {
		return loc;
	}
	RVecAnalCCPiece pieces;
	RVecAnalCCPiece_init (&pieces);
	const char *ret = NULL;
	if (r_anal_cc_location_pieces (anal, loc, &pieces)) {
		RAnalCCPiece *piece = RVecAnalCCPiece_at (&pieces, 0);
		ret = piece? piece->loc: NULL;
	}
	RVecAnalCCPiece_fini (&pieces);
	return ret;
}

R_API bool r_anal_cc_location_in_regset(RAnal *anal, const char *loc, const char *regset, bool all) {
	R_RETURN_VAL_IF_FAIL (anal && loc, false);
	if (R_STR_ISEMPTY (regset)) {
		return false;
	}
	if (*loc && *loc != '{') {
		return r_anal_cc_regset_contains (regset, loc);
	}
	RVecAnalCCPiece pieces;
	RVecAnalCCPiece_init (&pieces);
	bool ret = all;
	if (r_anal_cc_location_pieces (anal, loc, &pieces)) {
		RAnalCCPiece *piece;
		R_VEC_FOREACH (&pieces, piece) {
			bool contains = r_anal_cc_regset_contains (regset, piece->loc);
			if (contains != all) {
				ret = contains;
				break;
			}
		}
	} else {
		ret = false;
	}
	RVecAnalCCPiece_fini (&pieces);
	return ret;
}

R_API bool r_anal_cc_regset_contains(const char *regset, const char *reg) {
	R_RETURN_VAL_IF_FAIL (regset && reg, false);
	const char *s = regset;
	if (*s == '(') {
		s++;
	}
	while (*s) {
		while (*s == ',' || isspace ((ut8)*s)) {
			s++;
		}
		const char *e = s;
		while (*e && *e != ',' && *e != ')') {
			e++;
		}
		const char *t = e;
		while (t > s && isspace ((ut8)t[-1])) {
			t--;
		}
		if (t > s && strlen (reg) == (size_t)(t - s) && !strncmp (s, reg, t - s)) {
			return true;
		}
		if (*e == ')') {
			break;
		}
		s = e;
	}
	return false;
}

R_API const char *r_anal_cc_default(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	return sdb_const_get (DB, "default.cc", 0);
}

R_API void r_anal_set_cc_default(RAnal *anal, const char *cc) {
	R_RETURN_IF_FAIL (anal && cc);
	sdb_set (DB, "default.cc", cc, 0);
}

R_API const char *r_anal_syscc_default(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	return sdb_const_get (DB, "default.syscc", 0);
}

R_API void r_anal_set_syscc_default(RAnal *anal, const char *cc) {
	R_RETURN_IF_FAIL (anal && cc);
	sdb_set (DB, "default.syscc", cc, 0);
}

R_API const char *r_anal_cc_func(RAnal *anal, const char *func_name) {
	R_RETURN_VAL_IF_FAIL (anal && func_name, NULL);
	r_strf_var (query, 64, "func.%s.cc", func_name);
	const char *cc = sdb_const_get (anal->sdb_types, query, 0);
	return cc ? cc : r_anal_cc_default (anal);
}
