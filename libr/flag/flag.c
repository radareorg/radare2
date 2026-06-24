/* radare - LGPL - Copyright 2007-2025 - pancake */

#include <r_flag.h>
#include <r_cons.h>
#include <r_lib.h>

R_LIB_VERSION (r_flag);

#define IS_FI_NOTIN_SPACE(f, i) (r_flag_space_cur (f) && (i)->space != r_flag_space_cur (f))
#define IS_FI_IN_SPACE(fi, sp) (!(sp) || (fi)->space == (sp))
#define STRDUP_OR_NULL(s) (!R_STR_ISEMPTY (s)? strdup (s): NULL)
#define FLAG_NAME_STACK_BUFSZ 1024

static bool flag_count_foreach(RFlagItem *fi, void *user);

typedef struct r_flag_filtered_name_t {
	const char *original;
	const char *name;
	char *heap;
	bool filtered;
	char stack[FLAG_NAME_STACK_BUFSZ];
} RFlagFilteredName;

static const char *str_callback(RNum *user, ut64 addr, bool *ok) {
	if (ok) {
		*ok = false;
	}
	if (user) {
		RFlag *f = (RFlag*)user;
		const RVecFlagItemPtr *list = r_flag_get_vec (f, addr);
		RFlagItem *item = r_flag_item_vec_last (list);
		if (item) {
			if (ok) {
				*ok = true;
			}
			return item->name;
		}
	}
	return NULL;
}

static void flag_skiplist_free(void *data) {
	if (data) {
		RFlagsAtOffset *item = (RFlagsAtOffset *)data;
		RVecFlagItemPtr_fini (&item->flags);
		free (data);
	}
}

static int flag_skiplist_cmp(const void *va, const void *vb) {
	const ut64 ao = ((RFlagsAtOffset *)va)->addr;
	const ut64 bo = ((RFlagsAtOffset *)vb)->addr;
	if (R_LIKELY (ao < bo)) {
		return -1;
	}
	if (R_LIKELY (ao > bo)) {
		return 1;
	}
	return 0;
}

static bool flag_vec_delete_item(RVecFlagItemPtr *flags, const RFlagItem *item) {
	size_t i = 0;
	RFlagItem **fi;
	R_VEC_FOREACH (flags, fi) {
		if (*fi == item) {
			RVecFlagItemPtr_remove (flags, i);
			return true;
		}
		i++;
	}
	return false;
}

static ut64 num_callback(RNum *user, const char *name, bool *ok) {
	RFlag *f = (RFlag *)user;
	if (ok) {
		*ok = false;
	}
	RFlagItem *fi = ht_pp_find (f->ht_name, name, NULL);
	if (fi) {
		// XXX this is not efficient
		const char *alias = r_flag_item_set_alias (f, fi, NULL);
		// NOTE: to avoid warning infinite loop here we avoid recursivity
		if (alias) {
			return 0LL;
		}
		if (ok) {
			*ok = true;
		}
		return fi->addr;
	}
	return 0LL;
}

static void free_item_realname(RFlagItem *item) {
	if (item->name != item->realname) {
		if (!item->realname_pooled) {
			free (item->realname);
		}
		item->realname = NULL;
	}
	item->realname_pooled = false;
}

#if 0
return the list of flag at the nearest position:
dir == -1 -> result <= addr
dir == 0 ->  result == addr
dir == 1 ->  result >= addr
#endif
static RFlagsAtOffset *r_flag_get_nearest_list(RFlag *f, ut64 addr, int dir) {
	RFlagsAtOffset key = { .addr = addr };
	RFlagsAtOffset *flags = (dir >= 0)
		? r_skiplist_get_geq (f->by_addr, &key)
		: r_skiplist_get_leq (f->by_addr, &key);
	return (dir == 0 && flags && flags->addr != addr)? NULL: flags;
}

static void remove_addrmap(RFlag *f, RFlagItem *item) {
	R_RETURN_IF_FAIL (f && item);
	RFlagsAtOffset *flags = r_flag_get_nearest_list (f, item->addr, 0);
	if (flags) {
		flag_vec_delete_item (&flags->flags, item);
		if (RVecFlagItemPtr_empty (&flags->flags)) {
			r_skiplist_delete (f->by_addr, flags);
		}
		R_DIRTY_SET (f);
	}
}

static RFlagsAtOffset *flags_at_addr(RFlag *f, ut64 addr) {
	if (f->mask) {
		addr &= f->mask;
	}
	RFlagsAtOffset *res = r_flag_get_nearest_list (f, addr, 0);
	if (res) {
		return res;
	}
	// there is no existing flagsAtOffset, we create one now
	res = R_NEW0 (RFlagsAtOffset);
	RVecFlagItemPtr_init (&res->flags);
	res->addr = addr;
	r_skiplist_insert (f->by_addr, res);
	return res;
}

static bool filter_item_name(RFlagFilteredName *filtered, const char * R_NONNULL name) {
	R_RETURN_VAL_IF_FAIL (filtered && name, false);
	filtered->original = name;
	filtered->name = NULL;
	filtered->heap = NULL;
	filtered->filtered = false;
	if (r_name_check (name)) {
		filtered->name = name;
		return true;
	}
	const size_t len = strlen (name);
	char *res;
	if (len < sizeof (filtered->stack)) {
		res = filtered->stack;
		memcpy (res, name, len + 1);
	} else {
		res = strdup (name);
		if (!res) {
			return false;
		}
		filtered->heap = res;
	}
	r_str_trim (res);
	r_name_filter (res, 0);
	filtered->name = res;
	filtered->filtered = true;
	return true;
}

static void filtered_item_name_fini(RFlagFilteredName *filtered) {
	free (filtered->heap);
}

static char *push_filtered_item_name(RFlag *f, const RFlagFilteredName *filtered) {
	R_RETURN_VAL_IF_FAIL (f && f->names && filtered && filtered->original, NULL);
	char *pooled = r_arena_push_str (f->names, filtered->original);
	if (pooled && filtered->filtered) {
		r_str_trim (pooled);
		r_name_filter (pooled, 0);
	}
	return pooled;
}

static void set_name(RFlagItem *item, char *pooled_name) {
	R_RETURN_IF_FAIL (item && pooled_name);
	free_item_realname (item);
	item->name = pooled_name;
	item->name_pooled = true;
	item->realname = pooled_name;
}

static bool update_flag_item_addr(RFlag *f, RFlagItem *fi, ut64 newaddr, bool is_new, bool force) {
	if (fi->addr != newaddr || force) {
		if (!is_new) {
			remove_addrmap (f, fi);
		}
		fi->addr = newaddr;
		RFlagsAtOffset *flagsAtOffset = flags_at_addr (f, newaddr);
		if (flagsAtOffset) {
			RFlagItem **slot = RVecFlagItemPtr_emplace_back (&flagsAtOffset->flags);
			if (slot) {
				*slot = fi;
				R_DIRTY_SET (f);
				return true;
			}
		}
	}
	return false;
}

static bool set_flag_item_name(RFlag *f, RFlagItem *item, const RFlagFilteredName *fname, bool force R_UNUSED) {
	R_RETURN_VAL_IF_FAIL (f && f->names && item && fname && fname->name, false);
	if (item->name && !strcmp (item->name, fname->name)) {
		return false;
	}
	RFlagItem *existing = ht_pp_find (f->ht_name, fname->name, NULL);
	if (existing && existing != item) {
		return false;
	}
	char *pooled = push_filtered_item_name (f, fname);
	if (!pooled) {
		return false;
	}
	bool res = (item->name)
		? ht_pp_update_key (f->ht_name, item->name, pooled)
		: ht_pp_insert (f->ht_name, pooled, item);
	if (res) {
		set_name (item, pooled);
		R_DIRTY_SET (f);
		return true;
	}
	return false;
}

static bool update_flag_item_name(RFlag *f, RFlagItem *item, const char *newname, bool force) {
	R_RETURN_VAL_IF_FAIL (f && item && newname, false);
	if (!force && item->name == newname) {
		return false;
	}
	RFlagFilteredName fname;
	if (!filter_item_name (&fname, newname)) {
		return false;
	}
	if (!r_name_check (fname.name)) {
		filtered_item_name_fini (&fname);
		return false;
	}
	bool res = set_flag_item_name (f, item, &fname, force);
	filtered_item_name_fini (&fname);
	return res;
}

static void ht_free_flag(HtPPKv *kv) {
	if (kv) {
		r_flag_item_free (kv->value);
	}
}

static HtPP *flag_ht_name_new(void) {
	HtPPOptions opt = {
		.cmp = (HtPPListComparator)strcmp,
		.hashfn = (HtPPHashFunction)sdb_hash,
		.dupkey = NULL,
		.dupvalue = NULL,
		.calcsizeK = (HtPPCalcSizeK)strlen,
		.calcsizeV = NULL,
		.freefn = ht_free_flag,
		.elem_size = sizeof (HtPPKv),
	};
	return ht_pp_new_opt (&opt);
}

static void ht_free_meta(HtUPKv *kv) {
	if (kv) {
		// free (kv->key);
		RFlagItemMeta *fim = (RFlagItemMeta *)kv->value;
		free (fim->comment);
		free (fim->color);
		free (fim);
	}
}

static bool unset_flags_space(RFlagItem *fi, void *user) {
	fi->space = NULL;
	return true;
}

static void count_flags_in_space(REvent *ev, int type, void *user, void *data) {
	RSpaces *sp = (RSpaces *)ev->user;
	RFlag *f = container_of (sp, RFlag, spaces);
	RSpaceEvent *spe = (RSpaceEvent *)data;
	r_flag_foreach_space (f, spe->data.count.space, flag_count_foreach, &spe->res);
}

static void unset_flagspace(REvent *ev, int type, void *user, void *data) {
	RSpaces *sp = (RSpaces *)ev->user;
	RFlag *f = container_of (sp, RFlag, spaces);
	const RSpaceEvent *spe = (const RSpaceEvent *)data;
	r_flag_foreach_space (f, spe->data.unset.space, unset_flags_space, NULL);
}

static void new_spaces(RFlag *f) {
	r_spaces_init (&f->spaces, "fs");
	r_event_hook (f->spaces.event, R_SPACE_EVENT_COUNT, count_flags_in_space, NULL);
	r_event_hook (f->spaces.event, R_SPACE_EVENT_UNSET, unset_flagspace, NULL);
}

R_API RFlag *r_flag_new(void) {
	RFlag *f = R_NEW0 (RFlag);
	f->num = r_num_new (&num_callback, &str_callback, f);
	if (!f->num) {
		r_flag_free (f);
		return NULL;
	}
	f->lock = r_th_lock_new (true);
	f->base = 0;
	RVecFlagZoneItem_init (&f->zones);
	f->tags = sdb_new0 ();
	f->names = r_arena_new ();
	if (!f->names) {
		r_flag_free (f);
		return NULL;
	}
	f->names->default_alignment = 1;
	f->ht_name = flag_ht_name_new ();
	f->ht_meta = ht_up_new (NULL, ht_free_meta, NULL);
	f->by_addr = r_skiplist_new (flag_skiplist_free, flag_skiplist_cmp);
	new_spaces (f);
	R_DIRTY_SET (f);
	return f;
}

static bool flag_ht_migrate(void *user, const void *k, const void *v) {
	HtPPKv kv = {0};
	kv.key = (void *)k;
	kv.key_len = (ut32)strlen ((const char *)k);
	kv.value = (void *)v;
	ht_pp_insert_kv ((HtPP *)user, &kv, false);
	return true;
}

R_API void r_flag_reserve(RFlag *f, ut64 count) {
	R_RETURN_IF_FAIL (f && f->ht_name);
	HtPP *old = f->ht_name;
	if ((ut64)old->count >= count) {
		return;
	}
	ut64 desired = (ut64)old->count + count;
	desired += (desired >> 3) + 16;
	if (desired <= (ut64)old->size || desired > UT32_MAX) {
		return;
	}
	HtPP *nh = ht_pp_new_size ((ut32)desired, NULL, ht_free_flag, NULL);
	if (!nh) {
		return;
	}
	nh->opt.dupkey = NULL;
	ht_pp_foreach (old, flag_ht_migrate, nh);
	old->opt.freefn = NULL;
	ht_pp_free (old);
	f->ht_name = nh;
}

R_API RFlagItem *r_flag_item_clone(RFlagItem *item) {
	R_RETURN_VAL_IF_FAIL (item, NULL);

	RFlagItem *n = R_NEW0 (RFlagItem);
	n->id = item->id;
	n->name = STRDUP_OR_NULL (item->name);
	n->realname = STRDUP_OR_NULL (item->realname);
	n->rawname = STRDUP_OR_NULL (item->rawname);
	n->addr = item->addr;
	n->size = item->size;
	n->space = item->space;
	n->demangled = item->demangled;
	return n;
}

R_API void r_flag_item_free(RFlagItem *fi) {
	if (R_LIKELY (fi)) {
		free_item_realname (fi);
		if (!fi->name_pooled) {
			free (fi->name);
		}
		if (!fi->rawname_pooled) {
			free (fi->rawname);
		}
		free (fi);
	}
}

R_API void r_flag_free(RFlag *f) {
	if (R_LIKELY (f)) {
		r_th_lock_free (f->lock);
		f->lock = NULL;
		r_skiplist_free (f->by_addr);
		ht_pp_free (f->ht_name);
		ht_up_free (f->ht_meta);
		sdb_free (f->tags);
		r_spaces_fini (&f->spaces);
		r_num_free (f->num);
		RVecFlagZoneItem_fini (&f->zones);
		r_arena_free (f->names);
		free (f);
	}
}

static bool print_flag_name(RFlagItem *fi, void *user) {
	RStrBuf *sb = (RStrBuf *)user;
	r_strbuf_appendf (sb, "%s\n", fi->name);
	return true;
}

struct print_flag_t {
	RFlag *f;
	PJ *pj;
	bool in_range;
	ut64 range_from;
	ut64 range_to;
	RSpace *fs;
	bool real;
	const char *pfx;
	RStrBuf *sb;
};

static bool print_flag_json(RFlagItem *fi, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	if (u->in_range && (fi->addr < u->range_from || fi->addr >= u->range_to)) {
		return true;
	}
	pj_o (u->pj);
	pj_ks (u->pj, "name", fi->name);
	if (fi->realname && fi->name != fi->realname) {
		pj_ks (u->pj, "realname", fi->realname);
	}
	pj_ki (u->pj, "size", fi->size);
	RFlagItemMeta *fim = r_flag_get_meta (u->f, fi->id);
	if (fim) {
		if (fim->comment) {
			pj_ks (u->pj, "comment", fim->comment);
		}
		if (fim->alias) {
			pj_ks (u->pj, "alias", fim->alias);
			ut64 addr = r_num_math (u->f->num, fim->alias);
			pj_kn (u->pj, "addr", addr);
		} else {
			pj_kn (u->pj, "addr", fi->addr);
		}
	} else {
		pj_kn (u->pj, "addr", fi->addr);
	}
	pj_end (u->pj);
	return true;
}

static bool print_flag_rad(RFlagItem *flag, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	char *comment_b64 = NULL, *tmp = NULL;
	if (u->in_range && (flag->addr < u->range_from || flag->addr >= u->range_to)) {
		return true;
	}
	if (!u->fs || flag->space != u->fs) {
		u->fs = flag->space;
		r_strbuf_appendf (u->sb, "fs %s\n", u->fs? u->fs->name: "*");
	}
	const char *cmt = r_flag_item_set_comment (u->f, flag, NULL);
	const char *alias = r_flag_item_set_alias (u->f, flag, NULL);
	if (R_STR_ISNOTEMPTY (cmt)) {
		comment_b64 = r_base64_encode_dyn ((const ut8*)cmt, -1);
		// prefix the armored string with "base64:"
		if (comment_b64) {
			tmp = r_str_newf ("base64:%s", comment_b64);
			free (comment_b64);
			comment_b64 = tmp;
		}
	}
	if (alias) {
		r_strbuf_appendf (u->sb, "'fa %s %s\n", flag->name, alias);
		if (comment_b64) {
			r_strbuf_appendf (u->sb, "'fC %s %s\n",
				flag->name, r_str_get (comment_b64));
		}
	} else {
		r_strbuf_appendf (u->sb, "'f %s %" PFMT64d " 0x%08" PFMT64x "%s%s %s\n",
			flag->name, flag->size, flag->addr,
			u->pfx? "+": "", r_str_get (u->pfx),
			r_str_get (comment_b64));
	}

	free (comment_b64);
	return true;
}

static bool print_flag_orig_name(RFlagItem *fi, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	if (u->in_range && (fi->addr < u->range_from || fi->addr >= u->range_to)) {
		return true;
	}
	const char *alias = r_flag_item_set_alias (u->f, fi, NULL);
	const char *name = u->real? fi->realname: (u->f->realnames? fi->realname: fi->name);
	if (alias) {
		r_strbuf_appendf (u->sb, "%s %"PFMT64d" %s\n", alias, fi->size, name);
	} else {
		r_strbuf_appendf (u->sb, "0x%08" PFMT64x " %" PFMT64d " %s\n", fi->addr, fi->size, name);
	}
	return true;
}

/* print with r_cons the flag items in the flag f, given as a parameter */
R_API char *r_flag_list(RFlag *f, int rad, const char * R_NULLABLE pfx) {
	R_RETURN_VAL_IF_FAIL (f, NULL);
	bool in_range = false;
	ut64 range_from = UT64_MAX;
	ut64 range_to = UT64_MAX;
	if (rad == 'i') {
		char *arg = R_STR_ISNOTEMPTY (pfx)? r_str_trim_dup (pfx + 1): strdup ("");
		char *sp = strchr (arg,  ' ');
		if (sp) {
			*sp++ = 0;
			range_from = r_num_math (f->num, arg);
			range_to = r_num_math (f->num, sp);
		} else {
			const int bsize = 4096;
			range_from = r_num_math (f->num, arg);
			range_to = range_from + bsize;
		}
		in_range = true;
		free (arg);
		rad = pfx[0];
		pfx = NULL;
	}
	if (pfx && !*pfx) {
		pfx = NULL;
	}
	char *res = NULL;
	switch (rad) {
	case 'q':
		{
			RStrBuf *sb = r_strbuf_new ("");
			r_flag_foreach_space (f, r_flag_space_cur (f), print_flag_name, sb);
			res = r_strbuf_drain (sb);
		}
		break;
	case 'j': {
		PJ *pj = pj_new ();
		struct print_flag_t u = {
			.f = f,
			.pj = pj,
			.in_range = in_range,
			.range_from = range_from,
			.range_to = range_to,
			.real = false
		};
		pj_a (pj);
		r_flag_foreach_space (f, r_flag_space_cur (f), print_flag_json, &u);
		pj_end (pj);
		res = pj_drain (pj);
		break;
	}
	case 1:
	case '*': {
		struct print_flag_t u = {
			.f = f,
			.in_range = in_range,
			.range_from = range_from,
			.range_to = range_to,
			.fs = NULL,
			.pfx = pfx,
			.sb = r_strbuf_new ("")
		};
		r_flag_foreach_space (f, r_flag_space_cur (f), print_flag_rad, &u);
		res = r_strbuf_drain (u.sb);
		break;
	}
	default:
	case 'n':
		if (!pfx || pfx[0] != 'j') {// show original name
			struct print_flag_t u = {
				.f = f,
				.in_range = in_range,
				.range_from = range_from,
				.range_to = range_to,
				.real = (rad == 'n'),
				.sb = r_strbuf_new ("")
			};
			r_flag_foreach_space (f, r_flag_space_cur (f), print_flag_orig_name, &u);
			res = r_strbuf_drain (u.sb);
		} else {
			PJ *pj = pj_new ();
			struct print_flag_t u = {
				.f = f,
				.pj = pj,
				.in_range = in_range,
				.range_from = range_from,
				.range_to = range_to,
				.real = true
			};
			pj_a (pj);
			r_flag_foreach_space (f, r_flag_space_cur (f), print_flag_json, &u);
			pj_end (pj);
			res = pj_drain (pj);
		}
		break;
	}
	return res? res: strdup ("");
}

static RFlagItem *evalFlag(RFlag *f, RFlagItem *fi) {
	R_RETURN_VAL_IF_FAIL (f && fi, NULL);
	const char *alias = r_flag_item_set_alias (f, fi, NULL);
	if (alias) {
		fi->addr = r_num_math (f->num, alias);
	}
	return fi;
}

/* return true if flag.* exist at addr. Otherwise, false is returned.
 * For example (f, "sym", 3, 0x1000)*/
R_API bool r_flag_exist_at(RFlag *f, const char *flag_prefix, ut16 fp_size, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (f && flag_prefix, false);
	if (f->mask) {
		addr &= f->mask;
	}
	const RVecFlagItemPtr *list = r_flag_get_vec (f, addr);
	RFlagItem **iter;
	RFlagItem *fi;
	r_flag_item_vec_foreach (list, iter, fi) {
		if (fi->name && !strncmp (fi->name, flag_prefix, fp_size)) {
			return true;
		}
	}
	return false;
}

/* return the flag item with name "name" in the RFlag "f", if it exists. */
/* Otherwise, NULL is returned. */
R_API RFlagItem *r_flag_get(RFlag *f, const char *name) {
	R_RETURN_VAL_IF_FAIL (f, NULL);
	RFlagItem *r = ht_pp_find (f->ht_name, name, NULL);
	return r? evalFlag (f, r): NULL;
}

/* return the first flag item that can be found at addr, or NULL otherwise */
R_API RFlagItem *r_flag_get_in(RFlag *f, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (f, NULL);
	if (f->mask) {
		addr &= f->mask;
	}
	const RVecFlagItemPtr *list = r_flag_get_vec (f, addr);
	RFlagItem *item = r_flag_item_vec_last (list);
	return item? evalFlag (f, item): NULL;
}

/* Return the first flag matching an address ordered by the operands */
/* Pass in the name of each space, in order, followed by a NULL */
R_API RFlagItem *r_flag_get_by_spaces(RFlag *f, bool prionospace, ut64 addr, ...) {
	R_RETURN_VAL_IF_FAIL (f, NULL);
	if (f->mask) {
		addr &= f->mask;
	}

	const RVecFlagItemPtr *list = r_flag_get_vec (f, addr);
	RFlagItem *ret = NULL;
	va_list ap, aq;

	va_start (ap, addr);
	// some quick checks for common cases
	if (!list || RVecFlagItemPtr_empty (list)) {
		goto beach;
	}
	if (RVecFlagItemPtr_length (list) == 1) {
		ret = r_flag_item_vec_last (list);
		goto beach;
	}

	// count spaces in the vaarg
	va_copy (aq, ap);
	const char *spacename = va_arg (aq, const char *);

	size_t n_spaces = 0;
	while (spacename) {
		n_spaces++;
		spacename = va_arg (aq, const char *);
	}
	va_end (aq);

	// get RSpaces from the names
	size_t i = 0;
	RSpace **spaces = R_NEWS (RSpace *, n_spaces);
	if (!spaces) {
		goto beach;
	}
	spacename = va_arg (ap, const char *);
	while (spacename) {
		RSpace *space = r_flag_space_get (f, spacename);
		if (space) {
			spaces[i++] = space;
		}
		spacename = va_arg (ap, const char *);
	}
	n_spaces = i;

	ut64 min_space_i = n_spaces + 1;
	RFlagItem **iter;
	RFlagItem *fi;
	r_flag_item_vec_foreach (list, iter, fi) {
		// get the "priority" of the flag flagspace and
		// check if better than what we found so far
		if (prionospace && !fi->space) {
			ret = fi;
			break;
		}
		for (i = 0; i < n_spaces; i++) {
			if (fi->space == spaces[i]) {
				break;
			}
			if (i >= min_space_i) {
				break;
			}
		}

		if (i < min_space_i) {
			min_space_i = i;
			ret = fi;
		}
		if (!min_space_i) {
			// this is the best flag we can find, let's stop immediately
			break;
		}
	}
	free (spaces);
beach:
	va_end (ap);
	return ret? evalFlag (f, ret): NULL;
}

static int flagItemPriority(const RFlagItem *item) {
	R_RETURN_VAL_IF_FAIL (item, 0);
	const char *n = item->name;
	if (!n) {
		return 100;
	}
	if (r_str_startswith (n, "method.")) {
		return 1;
	}
	if (r_str_startswith (n, "class.")) {
		return 2;
	}
	if (r_str_startswith (n, "sym.func.")) {
		// lower prio than "sym."
		return 5;
	}
	if (r_str_startswith (n, "sym.")) {
		return 3;
	}
	if (r_str_startswith (n, "fn.")) {
		return 4;
	}
	if (r_str_startswith (n, "func.")) {
		return 5;
	}
	if (r_str_startswith (n, "fcn.")) {
		return 6;
	}
	// Also filter out section names
	if (r_str_startswith (item->name, "section.")) {
		return 10;
	}
	return 6;
}

static bool isreg(RFlagItem *item) {
	if (!strchr (item->name, '.')) {
		if (item->space && r_str_startswith (item->name, "regis")) {
			return true;
		}
	}
	return false;
}

static inline bool is_better_flag(RFlag *f, RFlagItem *best, RFlagItem *cand, int *best_prio_out) {
	if (!cand) {
		return false;
	}
	if (isreg (cand)) {
		return false;
	}
	if (IS_FI_NOTIN_SPACE (f, cand)) {
		return false;
	}
	const int p = flagItemPriority (cand);
	if (!best || p < *best_prio_out) {
		*best_prio_out = p;
		return true;
	}
	return false;
}

/* returns the last flag item or NULL before or at the given addr. */
R_API RFlagItem *r_flag_get_at(RFlag *f, ut64 addr, bool closest) {
	R_RETURN_VAL_IF_FAIL (f, NULL);
	R_CRITICAL_ENTER (f);
	if (f->mask) {
		addr &= f->mask;
	}

	RFlagItem *nice = NULL;
	int nice_priority = INT_MAX;
	const RFlagsAtOffset *flags_at = r_flag_get_nearest_list (f, addr, -1);
	if (!flags_at) {
		R_CRITICAL_LEAVE (f);
		return NULL;
	}
	if (flags_at->addr == addr) {
		RFlagItem **iter;
		R_VEC_FOREACH (&flags_at->flags, iter) {
			RFlagItem *item = *iter;
			if (is_better_flag (f, nice, item, &nice_priority)) {
				nice = item;
				if (!nice_priority) {
					break;
				}
			}
		}
		if (nice) {
			RFlagItem *fi = evalFlag (f, nice);
			R_CRITICAL_LEAVE (f);
			return fi;
		}
	}

	if (!closest) {
		R_CRITICAL_LEAVE (f);
		return NULL;
	}
	while (!nice && flags_at) {
		RFlagItem **iter;
		R_VEC_FOREACH (&flags_at->flags, iter) {
			RFlagItem *item = *iter;
			if (isreg (item) || IS_FI_NOTIN_SPACE (f, item)) {
				continue;
			}
			if (item->addr == addr) {
				R_LOG_DEBUG ("The impossible happened");
				RFlagItem *fi = evalFlag (f, item);
				R_CRITICAL_LEAVE (f);
				return fi;
			}
			nice = item;
			break;
		}
		flags_at = (!nice && flags_at->addr) ?
			r_flag_get_nearest_list (f, flags_at->addr- 1, -1): NULL;
	}
	RFlagItem *fi = nice? evalFlag (f, nice): NULL;
	R_CRITICAL_LEAVE (f);
	return fi;
}

R_API RVecFlagItemPtr *r_flag_all_list(RFlag *f, bool by_space) {
	R_RETURN_VAL_IF_FAIL (f, NULL);
	RVecFlagItemPtr *ret = RVecFlagItemPtr_new ();
	if (!ret) {
		return NULL;
	}

	RSpace *cur = by_space? r_flag_space_cur (f): NULL;
	RSkipListNode *it;
	RFlagsAtOffset *flags_at;
	r_skiplist_foreach (f->by_addr, it, flags_at) {
		RFlagItem **iter;
		R_VEC_FOREACH (&flags_at->flags, iter) {
			RFlagItem *fi = *iter;
			if (IS_FI_IN_SPACE (fi, cur)) {
				RVecFlagItemPtr_push_back (ret, &fi);
			}
		}
	}
	return ret;
}

/* return the list of flag items that are associated with a given offset */
R_API const RVecFlagItemPtr* /*<RFlagItem*>*/ r_flag_get_vec(RFlag *f, ut64 addr) {
	if (f->mask) {
		addr &= f->mask;
	}
	const RFlagsAtOffset *item = r_flag_get_nearest_list (f, addr, 0);
	return item? &item->flags: NULL;
}

R_API char *r_flag_get_liststr(RFlag *f, ut64 addr) {
	if (f->mask) {
		addr &= f->mask;
	}
	const RVecFlagItemPtr *list = r_flag_get_vec (f, addr);
	RStrBuf *sb = r_strbuf_new ("");
	RFlagItem **iter;
	RFlagItem *fi;
	r_flag_item_vec_foreach (list, iter, fi) {
		r_strbuf_appendf (sb, "%s%s",
			fi->realname, iter + 1 != R_VEC_END_ITER (list)? ",": "");
	}
	if (r_strbuf_is_empty (sb)) {
		r_strbuf_free (sb);
		return NULL;
	}
	return r_strbuf_drain (sb);
}

// Set a new flag named `name` at addr. If there's already a flag with
// the same name, slightly change the name by appending ".%d" as suffix
R_API RFlagItem *r_flag_set_next(RFlag *f, const char *name, ut64 addr, ut32 size) {
	R_RETURN_VAL_IF_FAIL (f && name, NULL);
	if (f->mask) {
		addr &= f->mask;
	}
	if (!r_flag_get (f, name)) {
		return r_flag_set (f, name, addr, size);
	}
	int i, newNameSize = strlen (name);
	char *newName = malloc (newNameSize + 16);
	if (!newName) {
		return NULL;
	}
	strcpy (newName, name);
	for (i = 0; ; i++) {
		snprintf (newName + newNameSize, 15, ".%d", i);
		if (!r_flag_get (f, newName)) {
			RFlagItem *fi = r_flag_set (f, newName, addr, size);
			if (fi) {
				free (newName);
				R_DIRTY_SET (f);
				return fi;
			}
		}
	}
	return NULL;
}

R_API RFlagItem *r_flag_set_inspace(RFlag *f, const char *space, const char *name, ut64 addr, ut32 size) {
	if (space) {
		r_flag_space_push (f, space);
	}
	RFlagItem *fi = r_flag_set (f, name, addr, size);
	if (space) {
		r_flag_space_pop (f);
	}
	R_DIRTY_SET (f);
	return fi;
}

/* create or modify an existing flag item with the given name and parameters.
** The realname of the item will be the same as the name. NULL is returned in case of errors */
R_API RFlagItem *r_flag_set(RFlag *f, const char *name, ut64 addr, ut32 size) {
	R_RETURN_VAL_IF_FAIL (f && name && *name, NULL);
	if (f->mask) {
		addr &= f->mask;
	}
	bool is_new = false;
	RFlagFilteredName itemname;
	if (!filter_item_name (&itemname, name)) {
		return NULL;
	}
	// this should never happen because the name is filtered before..
	if (!r_name_check (itemname.name)) {
		R_LOG_ERROR ("Invalid flag name '%s'", name);
		filtered_item_name_fini (&itemname);
		return NULL;
	}

	RFlagItem *item = r_flag_get (f, itemname.name);
	if (item && item->addr == addr) {
		item->size = size;
		filtered_item_name_fini (&itemname);
		return item;
	}

	if (!item) {
		item = R_NEW0 (RFlagItem);
		is_new = true;
		f->lastid++;
	}
	item->id = f->lastid;
	// decide flagspace: current by default, or best prefix match if autospace
	item->space = r_flag_space_cur (f);
	if (f->autospace && R_STR_ISNOTEMPTY (name)) {
		size_t best_len = 0;
		RSpace *best_sp = NULL;
		RSpaceIter *it;
		RSpace *sp;
		r_spaces_foreach (&f->spaces, it, sp) {
			if (!sp || !sp->prefixes) {
				continue;
			}
			RListIter *pi;
			char *pfx;
			r_list_foreach (sp->prefixes, pi, pfx) {
				if (R_STR_ISEMPTY (pfx)) {
					continue;
				}
				if (r_str_startswith (name, pfx)) {
					size_t lp = strlen (pfx);
					if (lp > best_len) {
						best_len = lp;
						best_sp = sp;
					}
				}
			}
		}
		if (best_sp) {
			item->space = best_sp;
		}
	}
	item->size = size;

	update_flag_item_addr (f, item, addr + f->base, is_new, true);
	set_flag_item_name (f, item, &itemname, true);
	filtered_item_name_fini (&itemname);
	return item;
}

static void purgeifempty(RFlag *f, RFlagItem *fi, RFlagItemMeta *fim) {
	RFlagItemMeta empty = {0};
	if (!memcmp (&empty, fim, sizeof (empty))) {
		ht_up_delete (f->ht_meta, fi->id);
	}
}

/* add/replace/remove the alias of a flag item */
R_API const char *r_flag_item_set_alias(RFlag *f, RFlagItem *fi, const char *alias) {
	R_RETURN_VAL_IF_FAIL (fi, NULL);
	RFlagItemMeta *fim;
	if (alias) {
		if (*alias) {
			fim = r_flag_get_meta2 (f, fi->id);
			free (fim->alias);
			fim->alias = strdup (alias);
		} else {
			fim = r_flag_get_meta (f, fi->id);
			if (fim && fim->alias) {
				R_FREE (fim->alias);
				purgeifempty (f, fi, fim);
			}
			return NULL;
		}
	} else {
		fim = r_flag_get_meta (f, fi->id);
	}
	// TODO: remove the meta if empty
	return fim? fim->alias: NULL;
}

/* add/replace/remove the comment of a flag item */
R_API const char *r_flag_item_set_comment(RFlag *f, RFlagItem *fi, const char *comment) {
	R_RETURN_VAL_IF_FAIL (f && fi, NULL);
	if (comment) {
		if (*comment) {
			RFlagItemMeta *fim = r_flag_get_meta2 (f, fi->id);
			free (fim->comment);
			fim->comment = strdup (comment);
		} else {
			RFlagItemMeta *fim = r_flag_get_meta (f, fi->id);
			if (fim) {
				R_FREE (fim->comment);
				purgeifempty (f, fi, fim);
			}
		}
	} else {
		RFlagItemMeta *fim = r_flag_get_meta (f, fi->id);
		return fim? fim->comment: NULL;
	}
	return NULL;
}

/* add/replace/remove the realname of a flag item */
R_API const char *r_flag_item_set_realname(RFlag *f, RFlagItem *item, const char *realname) {
	R_RETURN_VAL_IF_FAIL (item, NULL);
	if (item->realname && realname && !strcmp (item->realname, realname)) {
		return item->realname;
	}
	free_item_realname (item);
	if (R_STR_ISEMPTY (realname)) {
		item->realname = NULL;
	} else if (f && f->names) {
		item->realname = r_arena_push_str (f->names, realname);
		item->realname_pooled = item->realname != NULL;
	} else {
		item->realname = strdup (realname);
	}
	return item->realname;
}

/* add/replace/remove the rawname of a flag item */
R_API const char *r_flag_item_set_rawname(RFlag *f, RFlagItem *item, const char * R_NULLABLE rawname) {
	R_RETURN_VAL_IF_FAIL (item, NULL);
	if (item->rawname && rawname && !strcmp (item->rawname, rawname)) {
		return item->rawname;
	}
	if (!item->rawname_pooled) {
		free (item->rawname);
	}
	item->rawname = NULL;
	item->rawname_pooled = false;
	if (R_STR_ISEMPTY (rawname)) {
		return NULL;
	}
	if (f && f->names) {
		item->rawname = r_arena_push_str (f->names, rawname);
		item->rawname_pooled = item->rawname != NULL;
	} else {
		item->rawname = strdup (rawname);
	}
	return item->rawname;
}

/* add/replace/remove the color of a flag item */
R_API const char *r_flag_item_set_color(RFlag *f, RFlagItem *fi, const char * R_NULLABLE color) {
	R_RETURN_VAL_IF_FAIL (f && fi, NULL);
	RFlagItemMeta *fim;
	if (color) {
		fim = r_flag_get_meta2 (f, fi->id);
		if (fim) {
			if (*color) {
				free (fim->color);
				fim->color = strdup (color);
				return fim->color;
			}
			R_FREE (fim->color);
			purgeifempty (f, fi, fim);
			return NULL;
		}
	} else {
		fim = r_flag_get_meta (f, fi->id);
		if (fim) {
			return fim->color;
		}
	}
	return NULL;
}

/* change the name of a flag item, if the new name is available.
** true is returned if everything works well, false otherwise */
R_API bool r_flag_rename(RFlag *f, RFlagItem *item, const char *name) {
	R_RETURN_VAL_IF_FAIL (f && item && name && *name, false);
	return update_flag_item_name (f, item, name, false);
}

R_API const char *r_flag_item_set_type(RFlag *f, RFlagItem *fi, const char * R_NULLABLE type) {
	R_RETURN_VAL_IF_FAIL (fi && type, NULL);
	RFlagItemMeta *fim = r_flag_get_meta2 (f, fi->id);
	free (fim->type);
	fim->type = strdup (type);
	return fim->type;
}

R_API RFlagItemMeta * R_NULLABLE r_flag_get_meta(RFlag *f, ut32 id) {
	R_RETURN_VAL_IF_FAIL (f, NULL);
	return (RFlagItemMeta *)ht_up_find (f->ht_meta, id, NULL);
}

R_API RFlagItemMeta *r_flag_get_meta2(RFlag *f, ut32 id) {
	RFlagItemMeta *fim = r_flag_get_meta (f, id);
	if (!fim) {
		fim = R_NEW0 (RFlagItemMeta);
		ht_up_insert (f->ht_meta, id, fim);
	}
	return fim;
}

R_API void r_flag_del_meta(RFlag *f, ut32 id) {
	ht_up_delete (f->ht_meta, id);
}

/* unset the given flag item.
 * returns true if the item is successfully unset, false otherwise.
 *
 * NOTE: the item is freed. */
R_API bool r_flag_unset(RFlag *f, RFlagItem *item) {
	R_RETURN_VAL_IF_FAIL (f && item, false);
	r_flag_del_meta (f, item->id);
	remove_addrmap (f, item);
	ht_pp_delete (f->ht_name, item->name);
	R_DIRTY_SET (f);
	return true;
}

/* unset the first flag item found at addr
 * return true if such a flag is found and unset, false otherwise. */
R_API bool r_flag_unset_addr(RFlag *f, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (f, false);
	RFlagItem *item = r_flag_get_in (f, addr);
	if (item && r_flag_unset (f, item)) {
		return true;
	}
	return false;
}

struct unset_foreach_t {
	RFlag *f;
	int n;
};

static bool unset_foreach(RFlagItem *fi, void *user) {
	struct unset_foreach_t *u = (struct unset_foreach_t *)user;
	if (IS_FI_NOTIN_SPACE (u->f, fi)) {
		return true;
	}
	r_flag_unset (u->f, fi);
	u->n++;
	return true;
}

/* unset all the flag items that satisfy the given glob.
 * return the number of unset items. -1 on error */
// XXX This is O(n^n) because unset_globa iterates all flags and unset too.
R_API int r_flag_unset_glob(RFlag *f, const char *glob) {
	R_RETURN_VAL_IF_FAIL (f, -1);

	struct unset_foreach_t u = { .f = f, .n = 0 };
	r_flag_foreach_glob (f, glob, unset_foreach, &u);
	R_DIRTY_SET (f);
	return u.n;
}

/* unset the flag item with the given name.
 * returns true if the item is found and unset, false otherwise. */
R_API bool r_flag_unset_name(RFlag *f, const char *name) {
	R_RETURN_VAL_IF_FAIL (f, false);
	RFlagItem *item = ht_pp_find (f->ht_name, name, NULL);
	if (item && r_flag_unset (f, item)) {
		R_DIRTY_SET (f);
		return true;
	}
	return false;
}

/* unset all flag items in the RFlag f */
R_API void r_flag_unset_all(RFlag *f) {
	R_RETURN_IF_FAIL (f);
	ht_pp_free (f->ht_name);
	f->ht_name = flag_ht_name_new ();
	r_arena_reset (f->names);
	r_skiplist_purge (f->by_addr);
	r_spaces_fini (&f->spaces);
	new_spaces (f);
	R_DIRTY_SET (f);
}

struct flag_relocate_t {
	RFlag *f;
	ut64 addr;
	ut64 addr_mask;
	ut64 neg_mask;
	ut64 to;
	int n;
};

static bool flag_relocate_foreach(RFlagItem *fi, void *user) {
	struct flag_relocate_t *u = (struct flag_relocate_t *)user;
	ut64 fn = fi->addr & u->neg_mask;
	ut64 on = u->addr & u->neg_mask;
	if (fn == on) {
		ut64 fm = fi->addr & u->addr_mask;
		ut64 om = u->to & u->addr_mask;
		update_flag_item_addr (u->f, fi, (u->to & u->neg_mask) + fm + om, false, false);
		u->n++;
	}
	return true;
}

R_API int r_flag_relocate(RFlag *f, ut64 addr, ut64 addr_mask, ut64 to) {
	R_RETURN_VAL_IF_FAIL (f, -1);
	struct flag_relocate_t u = {
		.f = f,
		.addr = addr,
		.addr_mask = addr_mask,
		.neg_mask = ~(addr_mask),
		.to = to,
		.n = 0
	};
	r_flag_foreach (f, flag_relocate_foreach, &u);
	return u.n;
}

R_API bool r_flag_move(RFlag *f, ut64 at, ut64 to) {
	R_RETURN_VAL_IF_FAIL (f, false);
	RFlagItem *item = r_flag_get_in (f, at);
	if (item) {
		r_flag_set (f, item->name, to, item->size);
		return true;
	}
	return false;
}

// BIND
R_API void r_flag_bind(RFlag *f, RFlagBind *fb) {
	R_RETURN_IF_FAIL (f && fb);
	fb->f = f;
	fb->exist_at = r_flag_exist_at;
	fb->get = r_flag_get;
	fb->get_at = r_flag_get_at;
	fb->get_vec = r_flag_get_vec;
	fb->set = r_flag_set;
	fb->unset = r_flag_unset;
	fb->unset_name = r_flag_unset_name;
	fb->unset_addr = r_flag_unset_addr;
	fb->set_fs = r_flag_space_set;
	fb->push_fs = r_flag_space_push;
	fb->pop_fs = r_flag_space_pop;
}

static bool flag_count_foreach(RFlagItem *fi, void *user) {
	int *count = (int *)user;
	(*count)++;
	return true;
}

R_API int r_flag_count(RFlag *f, const char * R_NULLABLE glob) {
	R_RETURN_VAL_IF_FAIL (f, -1);
	int count = 0;
	r_flag_foreach_glob (f, glob, flag_count_foreach, &count);
	return count;
}

#define FOREACH_BODY(condition) \
	RSkipListNode *it, *tmp; \
	RFlagsAtOffset *flags_at; \
	RVecFlagItemPtr items; \
	RVecFlagItemPtr_init (&items); \
	r_skiplist_foreach_safe (f->by_addr, it, tmp, flags_at) { \
		if (flags_at) { \
			RVecFlagItemPtr_clear (&items); \
			RVecFlagItemPtr_append (&items, &flags_at->flags, NULL); \
			RFlagItem **it2; \
			R_VEC_FOREACH (&items, it2) { \
				RFlagItem *fi = *it2; \
				if (condition) { \
					if (!cb (fi, user)) { \
						RVecFlagItemPtr_fini (&items); \
						return; \
					} \
				} \
			} \
		} \
	} \
	RVecFlagItemPtr_fini (&items);

R_API void r_flag_foreach(RFlag *f, RFlagItemCb cb, void *user) {
	FOREACH_BODY (true);
}

R_API void r_flag_foreach_prefix(RFlag *f, const char *pfx, int pfx_len, RFlagItemCb cb, void *user) {
	pfx_len = pfx_len < 0? strlen (pfx): pfx_len;
	FOREACH_BODY (!strncmp (fi->name, pfx, pfx_len));
}

R_API void r_flag_foreach_range(RFlag *f, ut64 from, ut64 to, RFlagItemCb cb, void *user) {
	FOREACH_BODY (fi->addr >= from && fi->addr < to);
}

R_API void r_flag_foreach_glob(RFlag *f, const char *glob, RFlagItemCb cb, void *user) {
	FOREACH_BODY (!glob || r_str_glob (fi->name, glob));
}

R_API void r_flag_foreach_space_glob(RFlag *f, const char *glob, const RSpace *space, RFlagItemCb cb, void *user) {
	FOREACH_BODY (IS_FI_IN_SPACE (fi, space) && (!glob || r_str_glob (fi->name, glob)));
}

R_API void r_flag_foreach_space(RFlag *f, const RSpace *space, RFlagItemCb cb, void *user) {
	FOREACH_BODY (IS_FI_IN_SPACE (fi, space));
}

typedef bool (*RFlagItemMatchCb)(const RFlagItem *fi, const void *user);

static bool flag_match_space(const RFlagItem *fi, const void *user) {
	const RSpace *sp = (const RSpace *)user;
	return fi->space == sp;
}

static bool flag_match_prefix(const RFlagItem *fi, const void *user) {
	const char *pfx = (const char *)user;
	return fi->name && r_str_startswith (fi->name, pfx);
}

static RFlagItem *flag_closest_match(RFlag *f, ut64 addr, ut64 radius, RFlagItemMatchCb match, const void *user) {
	const RFlagsAtOffset *exact, *left, *right;

	R_RETURN_VAL_IF_FAIL (f && match, NULL);
	if (f->mask) {
		addr &= f->mask;
	}

	R_CRITICAL_ENTER (f);

	exact = r_flag_get_nearest_list (f, addr, 0);
	if (exact) {
		RFlagItem **it;
		R_VEC_FOREACH (&exact->flags, it) {
			RFlagItem *fi = *it;
			if (match (fi, user)) {
				RFlagItem *ret = evalFlag (f, fi);
				R_CRITICAL_LEAVE (f);
				return ret;
			}
		}
	}

	left = r_flag_get_nearest_list (f, addr, -1);
	if (left && left->addr == addr) {
		if (addr) {
			left = r_flag_get_nearest_list (f, addr - 1, -1);
		} else {
			left = NULL;
		}
	}
	right = r_flag_get_nearest_list (f, addr, +1);
	if (right && right->addr == addr) {
		if (addr != UT64_MAX) {
			right = r_flag_get_nearest_list (f, addr + 1, +1);
		} else {
			right = NULL;
		}
	}

	for (;;) {
		const RFlagsAtOffset *node;
		ut64 ld = left ? (addr - left->addr) : UT64_MAX;
		ut64 rd = right ? (right->addr - addr) : UT64_MAX;
		bool go_left = false;

		if (left && right) {
			go_left = ld <= rd;
		} else if (left) {
			go_left = true;
		} else if (!right) {
			break;
		}
		node = go_left ? left : right;
		if ((go_left ? ld : rd) > radius) {
			break;
		}
		RFlagItem **it;
		R_VEC_FOREACH (&node->flags, it) {
			RFlagItem *fi = *it;
			if (match (fi, user)) {
				RFlagItem *ret = evalFlag (f, fi);
				R_CRITICAL_LEAVE (f);
				return ret;
			}
		}
		if (go_left) {
			left = node->addr ? r_flag_get_nearest_list (f, node->addr - 1, -1) : NULL;
		} else {
			right = (node->addr != UT64_MAX) ? r_flag_get_nearest_list (f, node->addr + 1, +1) : NULL;
		}
	}

	R_CRITICAL_LEAVE (f);
	return NULL;
}

R_API RFlagItem *r_flag_closest_in_space(RFlag *f, const char *space, ut64 addr, ut64 radius) {
	RSpace *sp = NULL;

	R_RETURN_VAL_IF_FAIL (f, NULL);
	if (space && *space) {
		sp = r_flag_space_get (f, space);
		if (!sp) {
			return NULL;
		}
	} else {
		sp = r_flag_space_cur (f);
		if (!sp) {
			return NULL;
		}
	}
	return flag_closest_match (f, addr, radius, flag_match_space, sp);
}

R_API RFlagItem *r_flag_closest_with_prefix(RFlag *f, const char *pfx, ut64 addr, ut64 radius) {
	R_RETURN_VAL_IF_FAIL (f && pfx, NULL);
	return flag_closest_match (f, addr, radius, flag_match_prefix, pfx);
}
