/* radare - LGPL - Copyright 2007-2025 - pancake, ret2libc */

#include <r_flag.h>
#include <r_cons.h>

R_LIB_VERSION (r_flag);

#define IS_FI_NOTIN_SPACE(f, i) (r_flag_space_cur (f) && (i)->space != r_flag_space_cur (f))
#define IS_FI_IN_SPACE(fi, sp) (!(sp) || (fi)->space == (sp))
#define STRDUP_OR_NULL(s) (!R_STR_ISEMPTY (s)? strdup (s): NULL)

static const char *str_callback(RNum *user, ut64 addr, bool *ok) {
	if (ok) {
		*ok = false;
	}
	if (user) {
		RFlag *f = (RFlag*)user;
		const RList *list = r_flag_get_list (f, addr);
		if (list && !r_list_empty (list)) {
			RFlagItem *item = r_list_last (list);
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
		r_list_free (item->flags);
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
		free (item->realname);
	}
}

static void free_item_name(RFlagItem *item) {
	if (item->name != item->realname) {
		free (item->name);
	}
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
		r_list_delete_data (flags->flags, item);
		if (r_list_empty (flags->flags)) {
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
	res = R_NEW (RFlagsAtOffset);
	res->flags = r_list_new ();
	if (!res->flags) {
		free (res);
		return NULL;
	}

	res->addr = addr;
	r_skiplist_insert (f->by_addr, res);
	return res;
}

static char *filter_item_name(const char * R_NONNULL name) {
	R_RETURN_VAL_IF_FAIL (name, NULL);
	char *res = strdup (name);
	if (R_LIKELY (res)) {
		r_str_trim (res);
		r_name_filter (res, 0);
	}
	return res;
}

static void set_name(RFlagItem *item, char *name) {
	R_RETURN_IF_FAIL (item && name);
	free_item_name (item);
	item->name = name;
	free_item_realname (item);
	item->realname = item->name;
}

static bool update_flag_item_addr(RFlag *f, RFlagItem *fi, ut64 newaddr, bool is_new, bool force) {
	if (fi->addr != newaddr || force) {
		if (!is_new) {
			remove_addrmap (f, fi);
		}
		fi->addr = newaddr;
		RFlagsAtOffset *flagsAtOffset = flags_at_addr (f, newaddr);
		if (flagsAtOffset) {
			r_list_append (flagsAtOffset->flags, fi);
			R_DIRTY_SET (f);
			return true;
		}
	}
	return false;
}

static bool update_flag_item_name(RFlag *f, RFlagItem *item, const char *newname, bool force) {
	R_RETURN_VAL_IF_FAIL (f && item && newname, false);
	if (!force && (item->name == newname || (item->name && !strcmp (item->name, newname)))) {
		return false;
	}
	char *fname = filter_item_name (newname);
	if (fname) {
		bool res = (item->name)
			? ht_pp_update_key (f->ht_name, item->name, fname)
			: ht_pp_insert (f->ht_name, fname, item);
		if (res) {
			set_name (item, fname);
			R_DIRTY_SET (f);
			return true;
		}
		free (fname);
	}
	return false;
}

static void ht_free_flag(HtPPKv *kv) {
	if (kv) {
		free (kv->key);
		r_flag_item_free (kv->value);
	}
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

static bool count_flags(RFlagItem *fi, void *user) {
	int *count = (int *)user;
	(*count)++;
	return true;
}

static bool unset_flags_space(RFlagItem *fi, void *user) {
	fi->space = NULL;
	return true;
}

static void count_flags_in_space(REvent *ev, int type, void *user, void *data) {
	RSpaces *sp = (RSpaces *)ev->user;
	RFlag *f = container_of (sp, RFlag, spaces);
	RSpaceEvent *spe = (RSpaceEvent *)data;
	r_flag_foreach_space (f, spe->data.count.space, count_flags, &spe->res);
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
	f->zones = r_list_newf (r_flag_zone_item_free);
	f->tags = sdb_new0 ();
	f->ht_name = ht_pp_new (NULL, ht_free_flag, NULL);
	f->ht_meta = ht_up_new (NULL, ht_free_meta, NULL);
	f->by_addr = r_skiplist_new (flag_skiplist_free, flag_skiplist_cmp);
	new_spaces (f);
	R_DIRTY_SET (f);
	return f;
}

R_API RFlagItem *r_flag_item_clone(RFlagItem *item) {
	R_RETURN_VAL_IF_FAIL (item, NULL);

	RFlagItem *n = R_NEW0 (RFlagItem);
	n->id = item->id;
	n->name = STRDUP_OR_NULL (item->name);
	n->realname = STRDUP_OR_NULL (item->realname);
	n->addr = item->addr;
	n->size = item->size;
	n->space = item->space;
	return n;
}

R_API void r_flag_item_free(RFlagItem *fi) {
	if (R_LIKELY (fi)) {
		/* release only one of the two pointers if they are the same */
		free_item_name (fi);
		free (fi->realname);
		free (fi);
	}
}

R_API void r_flag_free(RFlag *f) {
	if (R_LIKELY (f)) {
		r_th_lock_free (f->lock);
		f->lock = NULL;
		r_skiplist_free (f->by_addr);
		ht_pp_free (f->ht_name);
		sdb_free (f->tags);
		r_spaces_fini (&f->spaces);
		r_num_free (f->num);
		r_list_free (f->zones);
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
	return res;
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
	RListIter *iter = NULL;
	RFlagItem *item = NULL;
	if (f->mask) {
		addr &= f->mask;
	}
	const RList *list = r_flag_get_list (f, addr);
	if (list) {
		r_list_foreach (list, iter, item) {
			if (item->name && !strncmp (item->name, flag_prefix, fp_size)) {
				return true;
			}
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
	const RList *list = r_flag_get_list (f, addr);
	return list? evalFlag (f, r_list_last (list)): NULL;
}

/* Return the first flag matching an address ordered by the operands */
/* Pass in the name of each space, in order, followed by a NULL */
R_API RFlagItem *r_flag_get_by_spaces(RFlag *f, bool prionospace, ut64 addr, ...) {
	R_RETURN_VAL_IF_FAIL (f, NULL);
	if (f->mask) {
		addr &= f->mask;
	}

	const RList *list = r_flag_get_list (f, addr);
	RFlagItem *ret = NULL;
	RListIter *iter;
	RFlagItem *fi;
	va_list ap, aq;

	va_start (ap, addr);
	// some quick checks for common cases
	if (r_list_empty (list)) {
		goto beach;
	}
	if (r_list_length (list) == 1) {
		ret = r_list_last (list);
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
	RSpace **spaces = R_NEWS (RSpace *, n_spaces + 1);
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
	r_list_foreach (list, iter, fi) {
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

static bool isFunctionFlag(const char *n) {
	if (r_str_startswith (n, "method.") || r_str_startswith (n, "sym.")) {
		return true;
	}
	if (*n == 'f') {
		return (r_str_startswith (n, "fn.")
			|| r_str_startswith (n, "func.")
			|| r_str_startswith (n, "fcn.0"));
	}
	return false;
}

static bool isreg(RFlagItem *item) {
	if (!strchr (item->name, '.')) {
		if (item->space && r_str_startswith (item->name, "regis")) {
			return true;
		}
	}
	return false;
}
/* returns the last flag item defined before or at the given addr.
 * NULL is returned if such a item is not found. */
R_API RFlagItem *r_flag_get_at(RFlag *f, ut64 addr, bool closest) {
	R_RETURN_VAL_IF_FAIL (f, NULL);
	R_CRITICAL_ENTER (f);
	if (f->mask) {
		addr &= f->mask;
	}

	RFlagItem *nice = NULL;
	RListIter *iter;
	const RFlagsAtOffset *flags_at = r_flag_get_nearest_list (f, addr, -1);
	if (!flags_at) {
		R_CRITICAL_LEAVE (f);
		return NULL;
	}
	if (flags_at->addr == addr) {
		RFlagItem *item;
		r_list_foreach (flags_at->flags, iter, item) {
			if (isreg (item)) {
				continue;
			}
			if (IS_FI_NOTIN_SPACE (f, item)) {
				continue;
			}
			if (nice) {
				if (isFunctionFlag (nice->name)) {
					nice = item;
				}
			} else {
				nice = item;
			}
		}
		if (nice) {
			R_CRITICAL_LEAVE (f);
			return evalFlag (f, nice);
		}
	}

	if (!closest) {
		R_CRITICAL_LEAVE (f);
		return NULL;
	}
	while (!nice && flags_at) {
		RFlagItem *item;
		r_list_foreach (flags_at->flags, iter, item) {
			if (isreg (item)) {
				continue;
			}
			if (IS_FI_NOTIN_SPACE (f, item)) {
				continue;
			}
			if (item->addr == addr) {
				R_LOG_DEBUG ("The impossible happened");
				return evalFlag (f, item);
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

static bool append_to_list(RFlagItem *fi, void *user) {
	RList *ret = (RList *)user;
	r_list_append (ret, fi);
	return true;
}

R_API RList *r_flag_all_list(RFlag *f, bool by_space) {
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}

	RSpace *cur = by_space? r_flag_space_cur (f): NULL;
	r_flag_foreach_space (f, cur, append_to_list, ret);
	return ret;
}

/* return the list of flag items that are associated with a given offset */
R_API const RList* /*<RFlagItem*>*/ r_flag_get_list(RFlag *f, ut64 addr) {
	if (f->mask) {
		addr &= f->mask;
	}
	const RFlagsAtOffset *item = r_flag_get_nearest_list (f, addr, 0);
	return item ? item->flags : NULL;
}

R_API char *r_flag_get_liststr(RFlag *f, ut64 addr) {
	RFlagItem *fi;
	RListIter *iter;
	if (f->mask) {
		addr &= f->mask;
	}
	const RList *list = r_flag_get_list (f, addr);
	char *p = NULL;
	r_list_foreach (list, iter, fi) {
		p = r_str_appendf (p, "%s%s",
			fi->realname, iter->n? ",": "");
	}
	return p;
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
 * The realname of the item will be the same as the name.
 * NULL is returned in case of any errors during the process. */
R_API RFlagItem *r_flag_set(RFlag *f, const char *name, ut64 addr, ut32 size) {
	R_RETURN_VAL_IF_FAIL (f && name && *name, NULL);
	if (f->mask) {
		addr &= f->mask;
	}

	bool is_new = false;
	char *itemname = filter_item_name (name);
	if (!itemname) {
		return NULL;
	}
	// this should never happen because the name is filtered before..
	if (!r_name_check (itemname)) {
		R_LOG_ERROR ("Invalid flag name '%s'", name);
		return NULL;
	}

	RFlagItem *item = r_flag_get (f, itemname);
	free (itemname);
	if (item && item->addr == addr) {
		item->size = size;
		return item;
	}

	if (!item) {
		item = R_NEW0 (RFlagItem);
		is_new = true;
		f->lastid++;
	}
	item->id = f->lastid;
	item->space = r_flag_space_cur (f);
	item->size = size;

	update_flag_item_addr (f, item, addr + f->base, is_new, true);
	update_flag_item_name (f, item, name, true);
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
	free_item_realname (item);
	item->realname = R_STR_ISEMPTY (realname)? NULL: strdup (realname);
	return item->realname;
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
 * true is returned if everything works well, false otherwise */
R_API int r_flag_rename(RFlag *f, RFlagItem *item, const char *name) {
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
	R_DIRTY_SET (f);
	return item && r_flag_unset (f, item);
}

/* unset all flag items in the RFlag f */
R_API void r_flag_unset_all(RFlag *f) {
	R_RETURN_IF_FAIL (f);
	ht_pp_free (f->ht_name);
	f->ht_name = ht_pp_new (NULL, ht_free_flag, NULL);
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
	fb->get_list = r_flag_get_list;
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
	RListIter *it2, *tmp2;	  \
	RFlagItem *fi; \
	r_skiplist_foreach_safe (f->by_addr, it, tmp, flags_at) { \
		if (flags_at) { \
			r_list_foreach_safe (flags_at->flags, it2, tmp2, fi) {	\
				if (condition) { \
					if (!cb (fi, user)) { \
						return; \
					} \
				} \
			} \
		} \
	}

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
