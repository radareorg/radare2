/* radare - LGPL - Copyright 2007-2017 - pancake */

#include <r_flag.h>
#include <r_util.h>
#include <r_cons.h>
#include <stdio.h>

R_LIB_VERSION(r_flag);

#define STROFF(x) sdb_fmt (2, "flg.%"PFMT64x, x)

#define ISNULLSTR(x) (!(x) || !*(x))
#define IS_IN_SPACE(f, i) ((f)->space_idx != -1 && (i)->space != (f)->space_idx)

static const char *str_callback(RNum *user, ut64 off, int *ok) {
	RList *list;
	RFlag *f = (RFlag*)user;
	RFlagItem *item;
	if (ok) {
		*ok = 0;
	}
	if (f) {
		list = ht_find (f->ht_off, STROFF (off), NULL);
		item = r_list_get_top (list);
		if (item) {
			if (ok) {
				*ok = true;
			}
			return item->name;
		}
	}
	return NULL;
}

static void flag_free_kv(HtKv *kv) {
	free (kv->key);
	//we do not free kv->value since there is a reference in other list
	free (kv);
}

static void item_list_kv_free(HtKv *kv) {
	free (kv->key);
	r_list_free (kv->value);
	free (kv);
}

static ut64 num_callback(RNum *user, const char *name, int *ok) {
	RFlag *f = (RFlag*)user;
	RFlagItem *item;
	if (ok) {
		*ok = 0;
	}
	item = ht_find (f->ht_name, name, NULL);
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

static void remove_offsetmap(RFlag *f, RFlagItem *item) {
	RList *fs_off = ht_find (f->ht_off, STROFF (item->offset), NULL);
	if (fs_off) {
		r_list_delete_data (fs_off, item);
		if (r_list_empty (fs_off)) {
			ht_delete (f->ht_off, STROFF (item->offset));
		}
	}
}

static int set_name(RFlagItem *item, const char *name) {
	if (item->name != item->realname) {
		free (item->name);
	}
	item->name = strdup (name);
	if (!item->name) {
		return false;
	}
	r_str_chop (item->name);
	r_name_filter (item->name, 0); // TODO: name_filter should be chopping already
	free (item->realname);
	item->realname = strdup (item->name);
	return true;
}

R_API RFlag * r_flag_new() {
	int i;
	RFlag *f = R_NEW0 (RFlag);
	if (!f) return NULL;
	f->num = r_num_new (&num_callback, &str_callback, f);
	if (!f->num) {
		r_flag_free (f);
		return NULL;
	}
	f->base = 0;
	f->cb_printf = (PrintfCallback)printf;
#if R_FLAG_ZONE_USE_SDB
	f->zones = sdb_new0 ();
#else
	f->zones = NULL;
#endif
	f->flags = r_list_new ();
	if (!f->flags) {
		r_flag_free (f);
		return NULL;
	}
	f->flags->free = (RListFree) r_flag_item_free;
	f->space_idx = -1;
	f->spacestack = r_list_newf (NULL);
	if (!f->spacestack) {
		r_flag_free (f);
		return NULL;
	}
	f->ht_name = ht_new (NULL, flag_free_kv, NULL);
	f->ht_off = ht_new (NULL, item_list_kv_free, NULL);
#if R_FLAG_ZONE_USE_SDB
	sdb_free (f->zones);
#else
	r_list_free (f->zones);
#endif
	for (i = 0; i < R_FLAG_SPACES_MAX; i++) {
		f->spaces[i] = NULL;
	}
	return f;
}

R_API void r_flag_item_free(RFlagItem *item) {
	if (item) {
		free (item->color);
		free (item->comment);
		free (item->alias);
		/* release only one of the two pointers if they are the same */
		if (item->name != item->realname) {
			free (item->name); 
		}
		free (item->realname);
		R_FREE (item);
	}
}

R_API RFlag *r_flag_free(RFlag *f) {
	int i;
	for (i = 0; i < R_FLAG_SPACES_MAX; i++) {
		free (f->spaces[i]);
	}
	ht_free (f->ht_off);
	ht_free (f->ht_name);
	r_list_free (f->flags);
	r_list_free (f->spacestack);
	r_num_free (f->num);
	free (f);
	return NULL;
}

/* print with r_cons the flag items in the flag f, given as a parameter */
R_API void r_flag_list(RFlag *f, int rad, const char *pfx) {
	bool in_range = false;
	ut64 range_from = UT64_MAX;
	ut64 range_to = UT64_MAX;
	int fs = -1;
	RListIter *iter;
	RFlagItem *flag;
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
	case 'j': {
		int first = 1;
		f->cb_printf ("[");
		r_list_foreach (f->flags, iter, flag) {
			if (IS_IN_SPACE (f, flag)) {
				continue;
			}
			if (in_range && (flag->offset < range_from || flag->offset >= range_to)) {
				continue;
			}
			f->cb_printf ("%s{\"name\":\"%s\",\"size\":%"PFMT64d",",
				first?"":",", flag->name, flag->size);
			if (flag->alias) {
				f->cb_printf ("\"alias\":\"%s\"", flag->alias);
			} else {
				f->cb_printf ("\"offset\":%"PFMT64d, flag->offset);
			}
			if (flag->comment)
				f->cb_printf (",\"comment\":\"}");
			else f->cb_printf ("}");
			first = 0;
		}
		f->cb_printf ("]\n");
		}
		break;
	case 1:
	case '*':
		r_list_foreach (f->flags, iter, flag) {
			if (IS_IN_SPACE (f, flag)) {
				continue;
			}
			if (in_range && (flag->offset < range_from || flag->offset >= range_to)) {
				continue;
			}
			if (fs == -1 || flag->space != fs) {
				const char *flagspace;
				fs = flag->space;
				flagspace = r_flag_space_get_i (f, fs);
				if (!flagspace || !*flagspace)
					flagspace = "*";
				f->cb_printf ("fs %s\n", flagspace);
			}
			if (flag->alias) {
				f->cb_printf ("fa %s %s\n", flag->name, flag->alias);
				if (flag->comment && *flag->comment)
					f->cb_printf ("\"fC %s %s\"\n",
						flag->name, flag->comment);
			} else {
				f->cb_printf ("f %s %"PFMT64d" 0x%08"PFMT64x"%s%s %s\n",
					flag->name, flag->size, flag->offset,
					pfx?"+":"", pfx?pfx:"",
					flag->comment? flag->comment:"");
			}
		}
		break;
	case 'n': // show original name
		r_list_foreach (f->flags, iter, flag) {
			if (IS_IN_SPACE (f, flag)) {
				continue;
			}
			if (in_range && (flag->offset < range_from || flag->offset >= range_to)) {
				continue;
			}
			if (flag->alias) {
				f->cb_printf ("%s %"PFMT64d" %s\n",
						flag->alias, flag->size, flag->realname);
			} else {
				f->cb_printf ("0x%08"PFMT64x" %"PFMT64d" %s\n",
						flag->offset, flag->size, flag->realname);
			}
		}
		break;
	default:
		r_list_foreach (f->flags, iter, flag) {
			if (IS_IN_SPACE (f, flag)) {
				continue;
			}
			if (in_range && (flag->offset < range_from || flag->offset >= range_to)) {
				continue;
			}
			if (flag->alias) {
				f->cb_printf ("%s %"PFMT64d" %s\n",
					flag->alias, flag->size, flag->name);
			} else {
				f->cb_printf ("0x%08"PFMT64x" %"PFMT64d" %s\n",
					flag->offset, flag->size, flag->name);
			}
		}
		break;
	}
}

static RFlagItem *evalFlag(RFlag *f, RFlagItem *item) {
	if (item && item->alias) {
		item->offset = r_num_math (f->num, item->alias);
	}
	return item;
}

/* return true if flag.* exist at offset. Otherwise, false is returned.
 * For example (f, "sym", 3, 0x1000)*/
R_API bool r_flag_exist_at(RFlag *f, const char *flag_prefix, ut16 fp_size, ut64 off) {
	RListIter *iter = NULL;
	RFlagItem *item = NULL;
	if (!f) {
		return false;
	}
	RList *list = ht_find (f->ht_off, STROFF (off), NULL);
	if (!list) {
		return false;
	}
	r_list_foreach (list, iter, item) {
		if (item->name && !strncmp (item->name, flag_prefix, fp_size)) {
			return true;
		}
	}
	return false;
}

/* return the flag item with name "name" in the RFlag "f", if it exists.
 * Otherwise, NULL is returned. */
R_API RFlagItem *r_flag_get(RFlag *f, const char *name) {
	RFlagItem *r;
	if (!f) {
		return NULL;
	}
	r = ht_find (f->ht_name, name, NULL);
	return evalFlag (f, r);
}

/* return the first flag item that can be found at offset "off", or NULL otherwise */
R_API RFlagItem *r_flag_get_i(RFlag *f, ut64 off) {
	RList *list;
	if (!f) {
		return NULL;
	}
	list = ht_find (f->ht_off, STROFF (off), NULL);
	return list ? evalFlag (f, r_list_get_top (list)) : NULL;
}

/* return the first flag item at offset "off" that doesn't start with "loc.",
 * "fcn.", "section." or NULL if such a flag doesn't exist.
 *
 * XXX: this function is buggy and it's not really clear what's the purpose */
R_API RFlagItem *r_flag_get_i2(RFlag *f, ut64 off) {
	RFlagItem *oitem = NULL, *item = NULL;
	RListIter *iter;
	RList *list = ht_find (f->ht_off, STROFF (off), NULL);
	if (!list) {
		return NULL;
	}
	r_list_foreach (list, iter, item) {
		if (!item->name) {
			continue;
		}
		/* catch sym. first */
		if (!strncmp (item->name, "loc.", 4)) {
			continue;
		}
		if (!strncmp (item->name, "fcn.", 4)) {
			continue;
		}
		if (!strncmp (item->name, "section.", 8)) {
			continue;
		}
		if (!strncmp (item->name, "section_end.", 12)) {
			continue;
		}
		if (r_str_nlen (item->name, 5) > 4 &&
		    item->name[3] == '.') {
			oitem = item;
			break;
		}
		oitem = item;
		if (strlen (item->name) < 5 || item->name[3]!='.') continue;
		oitem = item;
	}
	return evalFlag (f, oitem);
}

/* returns the last flag item defined before or at the given offset.
 * NULL is returned if such a item is not found. */
R_API RFlagItem *r_flag_get_at(RFlag *f, ut64 off, bool closest) {
	RFlagItem *item, *nice = NULL;
	RListIter *iter;

	r_list_foreach (f->flags, iter, item) {
		if (f->space_strict && IS_IN_SPACE (f, item)) {
			continue;
		}
		if (item->offset == off) {
			return evalFlag (f, item);
		}
		if (closest && off > item->offset) {
			if (!nice || nice->offset < item->offset) {
				nice = item;
			}
		}
	}
	return evalFlag (f, nice);
}

/* return the list of flag items that are associated with a given offset */
R_API const RList* /*<RFlagItem*>*/ r_flag_get_list(RFlag *f, ut64 off) {
	return ht_find (f->ht_off, STROFF (off), NULL);
}

R_API char *r_flag_get_liststr(RFlag *f, ut64 off) {
	RFlagItem *fi;
	RListIter *iter;
	const RList *list = r_flag_get_list (f, off);
	char *p = NULL;
	r_list_foreach (list, iter, fi) {
		p = r_str_appendf (p, "%s%s",
			fi->realname, iter->n ? "," : ":");
	}
	return p;
}

R_API RFlagItem *r_flag_set_next(RFlag *f, const char *name, ut64 off, ut32 size) {
	if (!r_flag_get (f, name)) {
		return r_flag_set (f, name, off, size);
	}
	int i, newNameSize = strlen (name);
	char *newName = malloc (newNameSize + 16);
	strcpy (newName, name);
	for (i = 0; ; i++) {
		snprintf (newName + newNameSize, 15, ".%d", i);
		if (!r_flag_get (f, newName)) {
			RFlagItem *fi = r_flag_set (f, newName, off, size);
			free (newName);
			return fi;
		}
	}
	return NULL;
}

/* create or modify an existing flag item with the given name and parameters.
 * The realname of the item will be the same as the name.
 * NULL is returned in case of any errors during the process. */
R_API RFlagItem *r_flag_set(RFlag *f, const char *name, ut64 off, ut32 size) {
	RFlagItem *item = NULL;
	RList *list;

	/* contract fail */
	if (!name || !*name) {
		return NULL;
	}

	item = r_flag_get (f, name);
	if (item) {
		if (item->offset == off) {
			item->size = size;
			return item;
		}
		remove_offsetmap (f, item);
	} else {
		item = R_NEW0 (RFlagItem);
		if (!item) {
			return NULL;
		}
		if (!set_name (item, name)) {
			eprintf ("Invalid flag name '%s'.\n", name);
			free (item);
			return NULL;
		}
		//item share ownership prone to uaf, that is why only
		//f->flags has set up free pointer
		ht_insert (f->ht_name, item->name, item);
		r_list_append (f->flags, item);
	}

	item->space = f->space_idx;
	item->offset = off + f->base;
	item->size = size;

	list = ht_find (f->ht_off, STROFF (off), NULL);
	if (!list) {
		list = r_list_new ();
		ht_insert (f->ht_off, STROFF (off), list);
	}
	r_list_append (list, item);
	return item;
}

/* add/replace/remove the alias of a flag item */
R_API void r_flag_item_set_alias(RFlagItem *item, const char *alias) {
	if (item) {
		free (item->alias);
		item->alias = ISNULLSTR (alias)? NULL: strdup (alias);
	}
}

/* add/replace/remove the comment of a flag item */
R_API void r_flag_item_set_comment(RFlagItem *item, const char *comment) {
	if (item) {
		free (item->comment);
		item->comment = ISNULLSTR (comment) ? NULL : strdup (comment);
	}
}

/* add/replace/remove the realname of a flag item */
R_API void r_flag_item_set_realname(RFlagItem *item, const char *realname) {
	if (item) {
		if (item->realname != item->name) {
			free (item->realname);
		}
		item->realname = ISNULLSTR (realname) ? NULL : strdup (realname);
	}
}

/* change the name of a flag item, if the new name is available.
 * true is returned if everything works well, false otherwise */
R_API int r_flag_rename(RFlag *f, RFlagItem *item, const char *name) {
	if (!f || !item || !name || !*name) {
		return false;
	}
#if 0
	ut64 off = item->offset;
	int size = item->size;
	r_flag_unset (f, item);
	r_flag_set (f, name, off, size);
	return true;
#else
	ht_delete (f->ht_name, item->name);
	if (!set_name (item, name)) {
		return false;
	}
	ht_insert (f->ht_name, item->name, item);
#endif
	return true;
}

/* unset the given flag item.
 * returns true if the item is successfully unset, false otherwise.
 *
 * NOTE: the item is not freed. */
R_API int r_flag_unset(RFlag *f, RFlagItem *item) {
	RListFree orig = f->flags->free;
	remove_offsetmap (f, item);
	ht_delete (f->ht_name, item->name);
	f->flags->free = NULL;
	r_list_delete_data (f->flags, item);
	f->flags->free = orig;
	return true;
}

/* unset the first flag item found at offset off.
 * return true if such a flag is found and unset, false otherwise. */
R_API int r_flag_unset_off(RFlag *f, ut64 off) {
	RFlagItem *item = r_flag_get_i (f, off);
	if (item && r_flag_unset (f, item)) {
		R_FREE (item);
		return true;
	}
	return false;
}

/* unset all the flag items that satisfy the given glob.
 * return the number of unset items. */
R_API int r_flag_unset_glob(RFlag *f, const char *glob) {
	RListIter it, *iter;
	RFlagItem *flag;
	int n = 0;

	r_list_foreach (f->flags, iter, flag) {
		if (IS_IN_SPACE (f, flag)) continue;
		if (!glob || r_str_glob (flag->name, glob)) {
			it.n = iter->n;
			r_flag_unset (f, flag);
			free (flag);
			iter = &it;
			n++;
		}
	}
	return n;
}

/* unset the flag item with the given name.
 * returns true if the item is found and unset, false otherwise. */
R_API int r_flag_unset_name(RFlag *f, const char *name) {
	RFlagItem *item = ht_find (f->ht_name, name, NULL);
	if (item && r_flag_unset (f, item)) {
		R_FREE (item);
		return true;
	}
	return false;
}

/* unset all flag items in the RFlag f */
R_API void r_flag_unset_all(RFlag *f) {
	f->space_idx = -1;
	r_list_free (f->flags);
	f->flags = r_list_newf ((RListFree)r_flag_item_free);
	if (!f->flags) {
		return;
	}
	ht_free (f->ht_name);
	//don't set free since f->flags will free up items when needed avoiding uaf
	f->ht_name = ht_new (NULL, flag_free_kv, NULL);
	ht_free (f->ht_off);
	f->ht_off = ht_new (NULL, item_list_kv_free, NULL);
	r_flag_space_unset (f, NULL);
}

R_API int r_flag_relocate(RFlag *f, ut64 off, ut64 off_mask, ut64 to) {
	ut64 neg_mask = ~(off_mask);
	RFlagItem *item;
	RListIter *iter;
	int n = 0;

	r_list_foreach (f->flags, iter, item) {
		ut64 fn = item->offset & neg_mask;
		ut64 on = off & neg_mask;
		if (fn == on) {
			ut64 fm = item->offset & off_mask;
			ut64 om = to & off_mask;
			item->offset = (to&neg_mask) + fm + om;
			n++;
		}
	}
	return n;
}

R_API int r_flag_move(RFlag *f, ut64 at, ut64 to) {
	RFlagItem *item = r_flag_get_i (f, at);
	if (item) {
		r_flag_set (f, item->name, to, item->size);
		return true;
	}
	return false;
}

#ifdef MYTEST
int main () {
	RFlagItem *i;
	RFlag *f = r_flag_new ();
	r_flag_set (f, "rip", 0xfff333999000LL, 1);
	r_flag_set (f, "rip", 0xfff333999002LL, 1);
	r_flag_unset (f, "rip", NULL);
	r_flag_set (f, "rip", 3, 4);
	r_flag_set (f, "rip", 4, 4);
	r_flag_set (f, "corwp", 300, 4);
	r_flag_set (f, "barp", 300, 4);
	r_flag_set (f, "rip", 3, 4);
	r_flag_set (f, "rip", 4, 4);

	i = r_flag_get (f, "rip");
	if (i) printf ("nRIP: %p %llx\n", i, i->offset);
	else printf ("nRIP: null\n");

	i = r_flag_get_i (f, 0xfff333999000LL);
	if (i) printf ("iRIP: %p %llx\n", i, i->offset);
	else printf ("iRIP: null\n");
}
#endif

R_API const char *r_flag_color(RFlag *f, RFlagItem *it, const char *color) {
	if (!f || !it) return NULL;
	if (!color) return it->color;
	free (it->color);
	it->color = *color ? strdup (color) : NULL;
	return it->color;
}

// BIND
R_API int r_flag_bind(RFlag *f, RFlagBind *fb) {
	fb->f = f;
	fb->exist_at = r_flag_exist_at;
	fb->get = r_flag_get;
	fb->get_at = r_flag_get_at;
	fb->set = r_flag_set;
	fb->set_fs = r_flag_space_set;
	return 0;
}

R_API int r_flag_count(RFlag *f, const char *glob) {
	int count = 0;
	RFlagItem *flag;
	RListIter *iter;
	r_list_foreach (f->flags, iter, flag) {
		if (r_str_glob (flag->name, glob))
			count ++;
	}
	return count;
}
