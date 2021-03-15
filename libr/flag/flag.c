/* radare - LGPL - Copyright 2007-2021 - pancake, ret2libc */

#include <r_flag.h>
#include <r_util.h>
#include <r_cons.h>
#include <stdio.h>

R_LIB_VERSION(r_flag);

#define IS_FI_NOTIN_SPACE(f, i) (r_flag_space_cur (f) && (i)->space != r_flag_space_cur (f))
#define IS_FI_IN_SPACE(fi, sp) (!(sp) || (fi)->space == (sp))
#define STRDUP_OR_NULL(s) (!R_STR_ISEMPTY (s)? strdup (s): NULL)

static const char *str_callback(RNum *user, ut64 off, int *ok) {
	RFlag *f = (RFlag*)user;
	if (ok) {
		*ok = 0;
	}
	if (f) {
		const RList *list = r_flag_get_list (f, off);
		RFlagItem *item = r_list_get_top (list);
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
	RFlagsAtOffset *item = (RFlagsAtOffset *)data;
	r_list_free (item->flags);
	free (data);
}

static int flag_skiplist_cmp(const void *va, const void *vb) {
	const RFlagsAtOffset *a = (RFlagsAtOffset *)va, *b = (RFlagsAtOffset *)vb;
	if (a->off == b->off) {
		return 0;
	}
	return a->off < b->off? -1: 1;
}

static ut64 num_callback(RNum *user, const char *name, int *ok) {
	RFlag *f = (RFlag *)user;
	if (ok) {
		*ok = 0;
	}
	RFlagItem *item = ht_pp_find (f->ht_name, name, NULL);
	if (item) {
		// NOTE: to avoid warning infinite loop here we avoid recursivity
		if (item->alias) {
			return 0LL;
		}
		if (ok) {
			*ok = 1;
		}
		return item->offset;
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

/* return the list of flag at the nearest position.
   dir == -1 -> result <= off
   dir == 0 ->  result == off
   dir == 1 ->  result >= off*/
static RFlagsAtOffset *r_flag_get_nearest_list(RFlag *f, ut64 off, int dir) {
	RFlagsAtOffset key = { .off = off };
	RFlagsAtOffset *flags = (dir >= 0)
		? r_skiplist_get_geq (f->by_off, &key)
		: r_skiplist_get_leq (f->by_off, &key);
	return (dir == 0 && flags && flags->off != off)? NULL: flags;
}

static void remove_offsetmap(RFlag *f, RFlagItem *item) {
	r_return_if_fail (f && item);
	RFlagsAtOffset *flags = r_flag_get_nearest_list (f, item->offset, 0);
	if (flags) {
		r_list_delete_data (flags->flags, item);
		if (r_list_empty (flags->flags)) {
			r_skiplist_delete (f->by_off, flags);
		}
	}
}

static RFlagsAtOffset *flags_at_offset(RFlag *f, ut64 off) {
	if (f->mask) {
		off &= f->mask;
	}
	RFlagsAtOffset *res = r_flag_get_nearest_list (f, off, 0);
	if (res) {
		return res;
	}

	// there is no existing flagsAtOffset, we create one now
	res = R_NEW (RFlagsAtOffset);
	if (!res) {
		return NULL;
	}

	res->flags = r_list_new ();
	if (!res->flags) {
		free (res);
		return NULL;
	}

	res->off = off;
	r_skiplist_insert (f->by_off, res);
	return res;
}

static char *filter_item_name(const char *name) {
	char *res = strdup (name);
	if (!res) {
		return NULL;
	}

	r_str_trim (res);
	r_name_filter (res, 0);
	return res;
}

static void set_name(RFlagItem *item, char *name) {
	free_item_name (item);
	item->name = name;
	free_item_realname (item);
	item->realname = item->name;
}

static bool update_flag_item_offset(RFlag *f, RFlagItem *item, ut64 newoff, bool is_new, bool force) {
	if (item->offset != newoff || force) {
		if (!is_new) {
			remove_offsetmap (f, item);
		}
		item->offset = newoff;

		RFlagsAtOffset *flagsAtOffset = flags_at_offset (f, newoff);
		if (!flagsAtOffset) {
			return false;
		}

		r_list_append (flagsAtOffset->flags, item);
		return true;
	}

	return false;
}

static bool update_flag_item_name(RFlag *f, RFlagItem *item, const char *newname, bool force) {
	if (!f || !item || !newname) {
		return false;
	}
	if (!force && (item->name == newname || (item->name && !strcmp (item->name, newname)))) {
		return false;
	}
	char *fname = filter_item_name (newname);
	if (!fname) {
		return false;
	}
	bool res = (item->name)
		? ht_pp_update_key (f->ht_name, item->name, fname)
		: ht_pp_insert (f->ht_name, fname, item);
	if (res) {
		set_name (item, fname);
		return true;
	}
	free (fname);
	return false;
}

static void ht_free_flag(HtPPKv *kv) {
	free (kv->key);
	r_flag_item_free (kv->value);
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
	if (!f) {
		return NULL;
	}
	f->num = r_num_new (&num_callback, &str_callback, f);
	if (!f->num) {
		r_flag_free (f);
		return NULL;
	}
	f->base = 0;
	f->cb_printf = (PrintfCallback)printf;
	f->zones = r_list_newf (r_flag_zone_item_free);
	f->tags = sdb_new0 ();
	f->ht_name = ht_pp_new (NULL, ht_free_flag, NULL);
	f->by_off = r_skiplist_new (flag_skiplist_free, flag_skiplist_cmp);
	new_spaces(f);
	return f;
}

R_API RFlagItem *r_flag_item_clone(RFlagItem *item) {
	r_return_val_if_fail (item, NULL);

	RFlagItem *n = R_NEW0 (RFlagItem);
	if (!n) {
		return NULL;
	}
	n->color = STRDUP_OR_NULL (item->color);
	n->comment = STRDUP_OR_NULL (item->comment);
	n->alias = STRDUP_OR_NULL (item->alias);
	n->name = STRDUP_OR_NULL (item->name);
	n->realname = STRDUP_OR_NULL (item->realname);
	n->offset = item->offset;
	n->size = item->size;
	n->space = item->space;
	return n;
}

R_API void r_flag_item_free(RFlagItem *item) {
	if (!item) {
		return;
	}
	free (item->color);
	free (item->comment);
	free (item->alias);
	/* release only one of the two pointers if they are the same */
	free_item_name (item);
	free (item->realname);
	free (item);
}

R_API RFlag *r_flag_free(RFlag *f) {
	r_return_val_if_fail (f, NULL);
	r_skiplist_free (f->by_off);
	ht_pp_free (f->ht_name);
	sdb_free (f->tags);
	r_spaces_fini (&f->spaces);
	r_num_free (f->num);
	r_list_free (f->zones);
	free (f);
	return NULL;
}

static bool print_flag_name(RFlagItem *fi, void *user) {
	RFlag *flag = (RFlag *)user;
	flag->cb_printf ("%s\n", fi->name);
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
};

static bool print_flag_json(RFlagItem *flag, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	if (u->in_range && (flag->offset < u->range_from || flag->offset >= u->range_to)) {
		return true;
	}
	pj_o (u->pj);
	pj_ks (u->pj, "name", flag->name);
	if (flag->name != flag->realname) {
		pj_ks (u->pj, "realname", flag->realname);
	}
	pj_ki (u->pj, "size", flag->size);
	if (flag->alias) {
		pj_ks (u->pj, "alias", flag->alias);
	} else {
		pj_kn (u->pj, "offset", flag->offset);
	}
	if (flag->comment) {
		pj_ks (u->pj, "comment", flag->comment);
	}
	pj_end (u->pj);
	return true;
}

static bool print_flag_rad(RFlagItem *flag, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	char *comment_b64 = NULL, *tmp = NULL;
	if (u->in_range && (flag->offset < u->range_from || flag->offset >= u->range_to)) {
		return true;
	}
	if (!u->fs || flag->space != u->fs) {
		u->fs = flag->space;
		u->f->cb_printf ("fs %s\n", u->fs? u->fs->name: "*");
	}
	if (flag->comment && *flag->comment) {
		comment_b64 = r_base64_encode_dyn (flag->comment, -1);
		// prefix the armored string with "base64:"
		if (comment_b64) {
			tmp = r_str_newf ("base64:%s", comment_b64);
			free (comment_b64);
			comment_b64 = tmp;
		}
	}
	if (flag->alias) {
		u->f->cb_printf ("fa %s %s\n", flag->name, flag->alias);
		if (comment_b64) {
			u->f->cb_printf ("\"fC %s %s\"\n",
				flag->name, r_str_get (comment_b64));
		}
	} else {
		u->f->cb_printf ("f %s %" PFMT64d " 0x%08" PFMT64x "%s%s %s\n",
			flag->name, flag->size, flag->offset,
			u->pfx? "+": "", r_str_get (u->pfx),
			r_str_get (comment_b64));
	}

	free (comment_b64);
	return true;
}

static bool print_flag_orig_name(RFlagItem *flag, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	if (u->in_range && (flag->offset < u->range_from || flag->offset >= u->range_to)) {
		return true;
	}
	if (flag->alias) {
		const char *n = u->real? flag->realname: flag->name;
		u->f->cb_printf ("%s %"PFMT64d" %s\n", flag->alias, flag->size, n);
	} else {
		const char *n = u->real? flag->realname: (u->f->realnames? flag->realname: flag->name);
		u->f->cb_printf ("0x%08" PFMT64x " %" PFMT64d " %s\n", flag->offset, flag->size, n);
	}
	return true;
}

/* print with r_cons the flag items in the flag f, given as a parameter */
R_API void r_flag_list(RFlag *f, int rad, const char *pfx) {
	r_return_if_fail (f);
	bool in_range = false;
	ut64 range_from = UT64_MAX;
	ut64 range_to = UT64_MAX;
	if (rad == 'i') {
		char *sp, *arg = strdup (pfx + 1);
		sp = strchr (arg,  ' ');
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

	switch (rad) {
	case 'q':
		r_flag_foreach_space (f, r_flag_space_cur (f), print_flag_name, f);
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
		f->cb_printf ("%s\n", pj_string (pj));
		pj_free (pj);
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
			.pfx = pfx
		};
		r_flag_foreach_space (f, r_flag_space_cur (f), print_flag_rad, &u);
		break;
	}
	default:
	case 'n': {
		if (!pfx || pfx[0] != 'j') {// show original name
			struct print_flag_t u = {
				.f = f,
				.in_range = in_range,
				.range_from = range_from,
				.range_to = range_to,
				.real = (rad == 'n')
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
			f->cb_printf ("%s\n", pj_string (pj));
			pj_free (pj);
		}
		break;
	}
	}
}

static RFlagItem *evalFlag(RFlag *f, RFlagItem *item) {
	r_return_val_if_fail (f && item, NULL);
	if (item->alias) {
		item->offset = r_num_math (f->num, item->alias);
	}
	return item;
}

/* return true if flag.* exist at offset. Otherwise, false is returned.
 * For example (f, "sym", 3, 0x1000)*/
R_API bool r_flag_exist_at(RFlag *f, const char *flag_prefix, ut16 fp_size, ut64 off) {
	r_return_val_if_fail (f && flag_prefix, NULL);
	RListIter *iter = NULL;
	RFlagItem *item = NULL;
	if (f->mask) {
		off &= f->mask;
	}
	const RList *list = r_flag_get_list (f, off);
	if (list) {
		r_list_foreach (list, iter, item) {
			if (item->name && !strncmp (item->name, flag_prefix, fp_size)) {
				return true;
			}
		}
	}
	return false;
}

/* return the flag item with name "name" in the RFlag "f", if it exists.
 * Otherwise, NULL is returned. */
R_API RFlagItem *r_flag_get(RFlag *f, const char *name) {
	r_return_val_if_fail (f, NULL);
	RFlagItem *r = ht_pp_find (f->ht_name, name, NULL);
	return r? evalFlag (f, r): NULL;
}

/* return the first flag item that can be found at offset "off", or NULL otherwise */
R_API RFlagItem *r_flag_get_i(RFlag *f, ut64 off) {
	r_return_val_if_fail (f, NULL);
	if (f->mask) {
		off &= f->mask;
	}
	const RList *list = r_flag_get_list (f, off);
	return list? evalFlag (f, r_list_get_top (list)): NULL;
}

/* return the first flag that matches an offset ordered by the order of
 * operands to the function.
 * Pass in the name of each space, in order, followed by a NULL */
R_API RFlagItem *r_flag_get_by_spaces(RFlag *f, ut64 off, ...) {
	r_return_val_if_fail (f, NULL);
	if (f->mask) {
		off &= f->mask;
	}

	const RList *list = r_flag_get_list (f, off);
	RFlagItem *ret = NULL;
	const char *spacename;
	RSpace **spaces;
	RListIter *iter;
	RFlagItem *flg;
	va_list ap, aq;
	size_t n_spaces = 0, i;

	va_start (ap, off);
	// some quick checks for common cases
	if (r_list_empty (list)) {
		goto beach;
	}
	if (r_list_length (list) == 1) {
		ret = r_list_get_top (list);
		goto beach;
	}

	// count spaces in the vaarg
	va_copy (aq, ap);
	spacename = va_arg (aq, const char *);
	while (spacename) {
		n_spaces++;
		spacename = va_arg (aq, const char *);
	}
	va_end (aq);

	// get RSpaces from the names
	i = 0;
	spaces = R_NEWS (RSpace *, n_spaces);
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
	r_list_foreach (list, iter, flg) {
		// get the "priority" of the flag flagspace and
		// check if better than what we found so far
		for (i = 0; i < n_spaces; i++) {
			if (flg->space == spaces[i]) {
				break;
			}
			if (i >= min_space_i) {
				break;
			}
		}

		if (i < min_space_i) {
			min_space_i = i;
			ret = flg;
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
	return (!strncmp (n, "sym.func.", 9)
	|| !strncmp (n, "method.", 7)
	|| !strncmp (n, "sym.", 4)
	|| !strncmp (n, "func.", 5)
	|| !strncmp (n, "fcn.0", 5));
}

/* returns the last flag item defined before or at the given offset.
 * NULL is returned if such a item is not found. */
R_API RFlagItem *r_flag_get_at(RFlag *f, ut64 off, bool closest) {
	r_return_val_if_fail (f, NULL);
	if (f->mask) {
		off &= f->mask;
	}

	RFlagItem *nice = NULL;
	RListIter *iter;
	const RFlagsAtOffset *flags_at = r_flag_get_nearest_list (f, off, -1);
	if (!flags_at) {
		return NULL;
	}
	if (flags_at->off == off) {
		RFlagItem *item;
		r_list_foreach (flags_at->flags, iter, item) {
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
			return evalFlag (f, nice);
		}
	}

	if (!closest) {
		return NULL;
	}
	while (!nice && flags_at) {
		RFlagItem *item;
		r_list_foreach (flags_at->flags, iter, item) {
			if (IS_FI_NOTIN_SPACE (f, item)) {
				continue;
			}
			if (item->offset == off) {
				eprintf ("XXX Should never happend\n");
				return evalFlag (f, item);
			}
			nice = item;
			break;
		}
		if (!nice && flags_at->off) {
			flags_at = r_flag_get_nearest_list (f, flags_at->off - 1, -1);
		} else {
			flags_at = NULL;
		}
	}
	return nice? evalFlag (f, nice): NULL;
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
R_API const RList* /*<RFlagItem*>*/ r_flag_get_list(RFlag *f, ut64 off) {
	if (f->mask) {
		off &= f->mask;
	}
	const RFlagsAtOffset *item = r_flag_get_nearest_list (f, off, 0);
	return item ? item->flags : NULL;
}

R_API char *r_flag_get_liststr(RFlag *f, ut64 off) {
	RFlagItem *fi;
	RListIter *iter;
	if (f->mask) {
		off &= f->mask;
	}
	const RList *list = r_flag_get_list (f, off);
	char *p = NULL;
	r_list_foreach (list, iter, fi) {
		p = r_str_appendf (p, "%s%s",
			fi->realname, iter->n? ",": "");
	}
	return p;
}

// Set a new flag named `name` at offset `off`. If there's already a flag with
// the same name, slightly change the name by appending ".%d" as suffix
R_API RFlagItem *r_flag_set_next(RFlag *f, const char *name, ut64 off, ut32 size) {
	r_return_val_if_fail (f && name, NULL);
	if (f->mask) {
		off &= f->mask;
	}
	if (!r_flag_get (f, name)) {
		return r_flag_set (f, name, off, size);
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
			RFlagItem *fi = r_flag_set (f, newName, off, size);
			if (fi) {
				free (newName);
				return fi;
			}
		}
	}
	return NULL;
}

/* create or modify an existing flag item with the given name and parameters.
 * The realname of the item will be the same as the name.
 * NULL is returned in case of any errors during the process. */
R_API RFlagItem *r_flag_set(RFlag *f, const char *name, ut64 off, ut32 size) {
	r_return_val_if_fail (f && name && *name, NULL);
	if (f->mask) {
		off &= f->mask;
	}

	bool is_new = false;
	char *itemname = filter_item_name (name);
	if (!itemname) {
		return NULL;
	}
	// this should never happen because the name is filtered before..
	if (!r_name_check (itemname)) {
		eprintf ("Invalid flag name '%s'\n", name);
		return NULL;
	}

	RFlagItem *item = r_flag_get (f, itemname);
	free (itemname);
	if (item && item->offset == off) {
		item->size = size;
		return item;
	}

	if (!item) {
		item = R_NEW0 (RFlagItem);
		if (!item) {
			goto err;
		}
		is_new = true;
	}

	item->space = r_flag_space_cur (f);
	item->size = size;

	update_flag_item_offset (f, item, off + f->base, is_new, true);
	update_flag_item_name (f, item, name, true);
	return item;
err:
	r_flag_item_free (item);
	return NULL;
}

/* add/replace/remove the alias of a flag item */
R_API void r_flag_item_set_alias(RFlagItem *item, const char *alias) {
	r_return_if_fail (item);
	free (item->alias);
	item->alias = R_STR_ISEMPTY (alias)? NULL: strdup (alias);
}

/* add/replace/remove the comment of a flag item */
R_API void r_flag_item_set_comment(RFlagItem *item, const char *comment) {
	r_return_if_fail (item);
	free (item->comment);
	item->comment = R_STR_ISEMPTY (comment)? NULL: strdup (comment);
}

/* add/replace/remove the realname of a flag item */
R_API void r_flag_item_set_realname(RFlagItem *item, const char *realname) {
	r_return_if_fail (item);
	free_item_realname (item);
	item->realname = R_STR_ISEMPTY (realname)? NULL: strdup (realname);
}

/* add/replace/remove the color of a flag item */
R_API const char *r_flag_item_set_color(RFlagItem *item, const char *color) {
	r_return_val_if_fail (item, NULL);
	free (item->color);
	item->color = (color && *color) ? strdup (color) : NULL;
	return item->color;
}

/* change the name of a flag item, if the new name is available.
 * true is returned if everything works well, false otherwise */
R_API int r_flag_rename(RFlag *f, RFlagItem *item, const char *name) {
	r_return_val_if_fail (f && item && name && *name, false);
	return update_flag_item_name (f, item, name, false);
}

/* unset the given flag item.
 * returns true if the item is successfully unset, false otherwise.
 *
 * NOTE: the item is freed. */
R_API bool r_flag_unset(RFlag *f, RFlagItem *item) {
	r_return_val_if_fail (f && item, false);
	remove_offsetmap (f, item);
	ht_pp_delete (f->ht_name, item->name);
	return true;
}

/* unset the first flag item found at offset off.
 * return true if such a flag is found and unset, false otherwise. */
R_API bool r_flag_unset_off(RFlag *f, ut64 off) {
	r_return_val_if_fail (f, false);
	RFlagItem *item = r_flag_get_i (f, off);
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
	r_return_val_if_fail (f, -1);

	struct unset_foreach_t u = { .f = f, .n = 0 };
	r_flag_foreach_glob (f, glob, unset_foreach, &u);
	return u.n;
}

/* unset the flag item with the given name.
 * returns true if the item is found and unset, false otherwise. */
R_API bool r_flag_unset_name(RFlag *f, const char *name) {
	r_return_val_if_fail (f, false);
	RFlagItem *item = ht_pp_find (f->ht_name, name, NULL);
	return item && r_flag_unset (f, item);
}

/* unset all flag items in the RFlag f */
R_API void r_flag_unset_all(RFlag *f) {
	r_return_if_fail (f);
	ht_pp_free (f->ht_name);
	f->ht_name = ht_pp_new (NULL, ht_free_flag, NULL);
	r_skiplist_purge (f->by_off);
	r_spaces_fini (&f->spaces);
	new_spaces (f);
}

struct flag_relocate_t {
	RFlag *f;
	ut64 off;
	ut64 off_mask;
	ut64 neg_mask;
	ut64 to;
	int n;
};

static bool flag_relocate_foreach(RFlagItem *fi, void *user) {
	struct flag_relocate_t *u = (struct flag_relocate_t *)user;
	ut64 fn = fi->offset & u->neg_mask;
	ut64 on = u->off & u->neg_mask;
	if (fn == on) {
		ut64 fm = fi->offset & u->off_mask;
		ut64 om = u->to & u->off_mask;
		update_flag_item_offset (u->f, fi, (u->to & u->neg_mask) + fm + om, false, false);
		u->n++;
	}
	return true;
}

R_API int r_flag_relocate(RFlag *f, ut64 off, ut64 off_mask, ut64 to) {
	r_return_val_if_fail (f, -1);
	struct flag_relocate_t u = {
		.f = f,
		.off = off,
		.off_mask = off_mask,
		.neg_mask = ~(off_mask),
		.to = to,
		.n = 0
	};

	r_flag_foreach (f, flag_relocate_foreach, &u);
	return u.n;
}

R_API bool r_flag_move(RFlag *f, ut64 at, ut64 to) {
	r_return_val_if_fail (f, false);
	RFlagItem *item = r_flag_get_i (f, at);
	if (item) {
		r_flag_set (f, item->name, to, item->size);
		return true;
	}
	return false;
}

// BIND
R_API void r_flag_bind(RFlag *f, RFlagBind *fb) {
	r_return_if_fail (f && fb);
	fb->f = f;
	fb->exist_at = r_flag_exist_at;
	fb->get = r_flag_get;
	fb->get_at = r_flag_get_at;
	fb->get_list = r_flag_get_list;
	fb->set = r_flag_set;
	fb->unset = r_flag_unset;
	fb->unset_name = r_flag_unset_name;
	fb->unset_off = r_flag_unset_off;
	fb->set_fs = r_flag_space_set;
	fb->push_fs = r_flag_space_push;
	fb->pop_fs = r_flag_space_pop;
}

static bool flag_count_foreach(RFlagItem *fi, void *user) {
	int *count = (int *)user;
	(*count)++;
	return true;
}

R_API int r_flag_count(RFlag *f, const char *glob) {
	int count = 0;
	r_return_val_if_fail (f, -1);
	r_flag_foreach_glob (f, glob, flag_count_foreach, &count);
	return count;
}

#define FOREACH_BODY(condition) \
	RSkipListNode *it, *tmp; \
	RFlagsAtOffset *flags_at; \
	RListIter *it2, *tmp2;	  \
	RFlagItem *fi; \
	r_skiplist_foreach_safe (f->by_off, it, tmp, flags_at) { \
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
	FOREACH_BODY (fi->offset >= from && fi->offset < to);
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
