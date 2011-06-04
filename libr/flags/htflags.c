/* radare - LGPL - Copyright 2007-2011 pancake<nopcode.org> */

#include <r_flags.h>
#include <r_util.h>
#include <r_cons.h>
#include <stdio.h>

R_API RFlag * r_flag_new() {
	int i;
	RFlag *f = R_NEW (RFlag);
	if (!f) return NULL;
	f->flags = r_list_new ();
	f->flags->free = free;
	f->space_idx = -1;
	f->space_idx2 = -1;
	f->ht_name = r_hashtable64_new ();
	f->ht_off = r_hashtable64_new ();
	for (i=0; i<R_FLAG_SPACES_MAX; i++)
		f->spaces[i] = NULL;
	return f;
}

R_API RFlag * r_flag_free(RFlag *f) {
	RFlagItem *item;
	RListIter *iter;
	r_list_foreach (f->flags, iter, item) {
		RList *list = r_hashtable64_lookup (f->ht_name, item->namehash);
		r_list_free (list);
		list = r_hashtable64_lookup (f->ht_off, item->offset);
		r_list_free (list);
	}
	r_hashtable64_free (f->ht_off);
	r_hashtable64_free (f->ht_name);
	r_list_free (f->flags);
	free (f);
	return NULL;
}


R_API void r_flag_list(RFlag *f, int rad) {
	int fs = -1;
	RListIter *iter;
	RFlagItem *flag;

	r_list_foreach_prev (f->flags, iter, flag) {
		if ((f->space_idx != -1) && (flag->space != f->space_idx))
			continue;
		if (rad) {
			if (fs == -1 || flag->space != fs) {
				fs = flag->space;
				r_cons_printf ("fs %s\n", r_flag_space_get_i (f, fs));
			}
			r_cons_printf ("f %s %"PFMT64d" 0x%08"PFMT64x"\n",
				flag->name, flag->size, flag->offset);
		} else r_cons_printf("0x%08"PFMT64x" %"PFMT64d" %s\n",
				flag->offset, flag->size, flag->name);
	}
}

R_API RFlagItem *r_flag_get(RFlag *f, const char *name) {
	RList *list = r_hashtable64_lookup (f->ht_name, r_str_hash64 (name));
	if (list) {
		RFlagItem *item = r_list_get_top (list);
		return item;
	}
	return NULL;
}

R_API RFlagItem *r_flag_get_i(RFlag *f, ut64 off) {
	RList *list = r_hashtable64_lookup (f->ht_off, off);
	if (list) {
		RFlagItem *item = r_list_get_top (list);
		return item;
	}
	return NULL;
}

R_API int r_flag_set(RFlag *f, const char *name, ut64 off, ut32 size, int dup) {
	RList *list2, *list;
	dup = 0; // XXX: force nondup
	if (dup) {
		RFlagItem *item = R_NEW0 (RFlagItem);
		item->space = f->space_idx;
		r_list_append (f->flags, item);

		r_flag_item_set_name (item, name);
		item->offset = off;
		item->size = size;

		list = r_hashtable64_lookup (f->ht_name, item->namehash);
		if (!list) {
			list = r_list_new ();
			r_hashtable64_insert (f->ht_name, item->namehash, list);
		}
		r_list_append (list, item);

		list2 = r_hashtable64_lookup (f->ht_off, off);
		if (list2 == NULL) {
			list2 = r_list_new ();
			r_hashtable64_insert (f->ht_name, off, list2);
		}
		r_list_append (list2, item);
	} else {
		RListIter *iter2 = NULL;
		RFlagItem *item2 = NULL, *item = r_flag_get (f, name);
		if (item) {
			RList *list2, *lol;
			if (item->offset == off)
				return R_TRUE;
			/* remove old entry */
			list2 = r_hashtable64_lookup (f->ht_off, item->offset);
			if (list2)
			r_list_foreach (list2, iter2, item2) {
				if (item->namehash != item2->namehash)
					continue;
				/* append new entry in new place */
				lol = r_hashtable64_lookup (f->ht_off, off);
				if (lol == NULL) {
					lol = r_list_new ();
					r_hashtable64_insert (f->ht_off, off, lol);
				} else eprintf ("reusing lol table\n");
				r_list_append (lol, item);
//printf ("BUGBUG: %s\n", item->name);
#if 1
				//list2->free = NULL;
				// XXX: MUST FIX DOUBLE EIP FLAG IN DEBUGGER
				// XXX: This produces a segfault in the future XXX //
				//r_list_split_iter (list2, iter2);
				if ( 1||r_list_empty (list2)) {
					//r_list_free (list2);
					r_hashtable64_remove (f->ht_off, item->offset);
				}
#endif
				break;
			}
			/* update new entry */
			item->offset = off;
			item->size = size;
		} else {
			item = R_NEW0 (RFlagItem);
			item->space = f->space_idx;

			r_list_append (f->flags, item);

			r_flag_item_set_name (item, name);
			item->offset = off;
			item->size = size;

			list = r_hashtable64_lookup (f->ht_name, item->namehash);
			if (!list) list = r_list_new ();
			r_list_append (list, item);
			r_hashtable64_insert (f->ht_name, item->namehash, list);

			list2 = r_hashtable64_lookup (f->ht_off, off);
			if (list2 == NULL)
				list2 = r_list_new ();
			r_list_append (list2, item);
			r_hashtable64_insert (f->ht_off, off, list2);
		}
	}
	return R_FALSE;
}

R_API void r_flag_item_set_name(RFlagItem *item, const char *name) {
	int len;
	strncpy (item->name, name, R_FLAG_NAME_SIZE);
	len = R_MIN (R_FLAG_NAME_SIZE, strlen (r_str_chop (item->name)) + 1);
	memmove (item->name, r_str_chop (item->name), len);
	item->name[R_FLAG_NAME_SIZE-1]='\0';
	item->namehash = r_str_hash64 (item->name);
}

R_API int r_flag_rename(RFlag *f, RFlagItem *item, const char *name) {
	ut64 hash = r_str_hash64 (item->name);
	RList *list = r_hashtable64_lookup (f->ht_name, hash);
	if (list) {
		RFlagItem *item = r_list_get_top (list);
		if (r_list_empty (list)) {
			r_list_free (list);
			r_hashtable64_remove (f->ht_name, hash);
		}
		r_list_delete_data (list, item);
		r_flag_item_set_name (item, name);
		list = r_hashtable64_lookup (f->ht_name, item->namehash);
		if (!list) {
			list = r_list_new ();
			r_hashtable64_insert (f->ht_name, item->namehash, list);
		}
		r_list_append (list, item);
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_flag_unset_i(RFlag *f, ut64 off, RFlagItem *p) {
	RFlagItem *item = r_flag_get_i (f, off);
eprintf ("TODO: r_flag_unset_i\n");
	if (item) {
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_flag_unset_glob(RFlag *f, const char *glob) {
	int n = 0;
	RListIter it, *iter;
	RFlagItem *flag;
	r_list_foreach (f->flags, iter, flag) {
		if ((f->space_idx != -1) && (flag->space != f->space_idx))
			continue;
		if (r_str_glob (flag->name, glob)) {
			it.n = iter->n;
			r_flag_unset (f, flag->name, flag);
			iter = &it;
			n++;
		}
	}
	return n;
}

static void unflag(RFlag *f, ut64 namehash) {
	RFlagItem *item;
	RListIter *iter;
	r_list_foreach (f->flags, iter, item) {
		if (item->namehash == namehash) {
			r_list_delete (f->flags, iter);
			break;
		}
	}
}

R_API int r_flag_unset(RFlag *f, const char *name, RFlagItem *p) {
	ut64 off;
	RListIter *iter2;
	RFlagItem *item2, *item = p;
	ut64 hash = r_str_hash64 (name);
	RList *list2, *list = r_hashtable64_lookup (f->ht_name, hash);
// list = name hash
// list2 = off hash
	if (list && list->head) {
		if (!item) item = r_list_pop (list);
		if (!item) return R_FALSE;
		off = item->offset;

		list2 = r_hashtable64_lookup (f->ht_off, off);
		if (list2) {
			/* delete flag by name */
			r_list_foreach (list2, iter2, item2) {
				if (hash == item2->namehash) {
					r_list_delete (list2, iter2);
					break;
				}
			}
			if (list2 && r_list_empty (list2)) {
				r_list_free (list2);
				r_hashtable64_remove (f->ht_off, off);
			}
		}
		/* delete from f->flags list */
		unflag (f, hash);
		if (list && r_list_empty (list)) {
			r_list_free (list);
			r_hashtable64_remove (f->ht_name, hash);
		}
		return R_TRUE;
	}
	return R_FALSE;
}
