/* radare - LGPL - Copyright 2007-2014 - pancake */

#include <r_flags.h>
#include <r_util.h>
#include <r_cons.h>
#include <stdio.h>

R_LIB_VERSION(r_flag);

static ut64 num_callback (RNum *user, const char *name, int *ok) {
	RFlag *f = (RFlag*)user;
	RList *list;

	if (ok) *ok = 0;
	
	list = r_hashtable64_lookup (f->ht_name, r_str_hash64 (name));
	if (list) {
		RFlagItem *item = r_list_get_top (list);
		// NOTE: to avoid warning infinite loop here we avoid recursivity
		if (item->alias)
			return 0LL;
		if (ok) *ok = 1;
		return item->offset;
	}
	return 0LL;
}

R_API RFlag * r_flag_new() {
	int i;
	RFlag *f = R_NEW (RFlag);
	if (!f) return NULL;
	f->num = r_num_new (&num_callback, f);
	f->base = 0;
	f->flags = r_list_new ();
	f->flags->free = (RListFree) r_flag_item_free;
	f->space_idx = -1;
	f->space_idx2 = -1;
	f->ht_name = r_hashtable64_new ();
	f->ht_off = r_hashtable64_new ();
	for (i=0; i<R_FLAG_SPACES_MAX; i++)
		f->spaces[i] = NULL;
	return f;
}

R_API void r_flag_item_free (RFlagItem *item) {
	free (item->cmd);
	free (item->color);
	free (item->comment);
	free (item->alias);
	item->cmd = item->comment = NULL;
	free (item);
}

R_API RFlag *r_flag_free(RFlag *f) {
	int i;
#if 0
	RFlagItem *item;
	RListIter *iter;
	r_list_foreach (f->flags, iter, item) {
		RList *list = r_hashtable64_lookup (f->ht_name, item->namehash);
		// XXX r_list_free (list);
		list = r_hashtable64_lookup (f->ht_off, item->offset);
		// XXX: segfault sometimes wtf -- r_list_free (list);
	}
#endif
	for (i=0; i<R_FLAG_SPACES_MAX; i++)
		free (f->spaces[i]);
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

	switch (rad) {
	case 'j': {
		int first = 1;
		r_cons_printf ("[");
		r_list_foreach_prev (f->flags, iter, flag) {
			if ((f->space_idx != -1) && (flag->space != f->space_idx))
				continue;
			r_cons_printf ("%s{\"name\":\"%s\",\"size\":\"%"PFMT64d"\",",
				first?"":",", flag->name, flag->size);
			if (flag->alias) {
				r_cons_printf ("\"alias\":\"%s\"", flag->alias);
			} else {
				r_cons_printf ("\"offset\":%"PFMT64d, flag->offset);
			}
			if (flag->comment)
				r_cons_printf (",\"comment\":\"}");
			else r_cons_printf ("}");
			first = 0;
		}
		r_cons_printf ("]\n");
		}
		break;
	case 1:
	case '*':
		 r_list_foreach_prev (f->flags, iter, flag) {
			 if ((f->space_idx != -1) && (flag->space != f->space_idx))
				 continue;
			 if (fs == -1 || flag->space != fs) {
				 const char *flagspace;
				 fs = flag->space;
				 flagspace = r_flag_space_get_i (f, fs);
				 if (!flagspace || !*flagspace)
					 flagspace = "*";
				 r_cons_printf ("fs %s\n", flagspace);
			 }
			 if (flag->alias) {
				 r_cons_printf ("fa %s %s\n", flag->name, flag->alias);
				 if (flag->comment && *flag->comment) 
					 r_cons_printf ("\"fC %s %s\"\n", flag->name, flag->comment);
			 } else {
				 r_cons_printf ("f %s %"PFMT64d" 0x%08"PFMT64x" %s\n",
					 flag->name, flag->size, flag->offset,
					 flag->comment? flag->comment:"");
			 }
		 }
		 break;
	case 'n': // show original name
		 r_list_foreach_prev (f->flags, iter, flag) {
			 if ((f->space_idx != -1) && (flag->space != f->space_idx))
				 continue;
			 if (flag->alias) {
				 r_cons_printf ("%s %"PFMT64d" %s\n",
					 flag->alias, flag->size, flag->realname);
			 } else {
				 r_cons_printf ("0x%08"PFMT64x" %"PFMT64d" %s\n",
					 flag->offset, flag->size, flag->realname);
			 }
		 }
		 break;
	default:
		 r_list_foreach_prev (f->flags, iter, flag) {
			 if ((f->space_idx != -1) && (flag->space != f->space_idx))
				 continue;
			 if (flag->alias) {
				 r_cons_printf ("%s %"PFMT64d" %s\n",
					 flag->alias, flag->size, flag->name);
			 } else {
				 r_cons_printf ("0x%08"PFMT64x" %"PFMT64d" %s\n",
					 flag->offset, flag->size, flag->name);
			 }
		 }
		 break;
	}
}

static RFlagItem *evalFlag (RFlag *f, RFlagItem *item) {
	if (item) {
		if (item->alias) {
			ut64 res = r_num_math (f->num, item->alias);
			item->offset = res;
		}
	}
	return item;
}

R_API RFlagItem *r_flag_get(RFlag *f, const char *name) {
	RList *list = r_hashtable64_lookup (f->ht_name, r_str_hash64 (name));
	if (list) {
		RFlagItem *item = r_list_get_top (list);
		return evalFlag (f, item);
	}
	return NULL;
}


R_API RFlagItem *r_flag_get_i2(RFlag *f, ut64 off) {
// TODO: this is buggy, do not use, must rewrite in sdb
	RFlagItem *oitem = NULL;
	RFlagItem *item = NULL;
	RList *list = r_hashtable64_lookup (f->ht_off, off);
	if (list) {
		RListIter *iter;
		r_list_foreach (list, iter, item) {
			// XXX: hack, because some times the hashtable is poluted by ghost values
			if (item->offset != off)
				continue;
			if (!strchr (item->name, '.'))
				oitem = item;
			if (strlen (item->name) < 5 || item->name[3]!='.')
				continue;
			oitem = item;
		}
	}
	return oitem;
}

R_API const RList* /*<RFlagItem*>*/ r_flag_get_list(RFlag *f, ut64 off) {
	return r_hashtable64_lookup (f->ht_off, off);
}

#define R_FLAG_TEST 0
R_API RFlagItem *r_flag_get_i(RFlag *f, ut64 off) {
	RList *list = r_hashtable64_lookup (f->ht_off, off);
	if (list) {
		RFlagItem *item = r_list_get_top (list);
#if R_FLAG_TEST
		return item;
#else
		// XXX: hack, because some times the hashtable is poluted by ghost values
		if (item->offset == off)
			return item;
#endif
	}
	return NULL;
}

R_API RFlagItem *r_flag_set(RFlag *f, const char *name, ut64 off, ut32 size, int dup) {
	RFlagItem *item = NULL;
	RListIter *iter2 = NULL;
	RFlagItem *item2 = NULL;
	RList *list2, *list;

	dup = 0; // XXX: force nondup

	/* contract fail */
	if (!name || !*name)
		return NULL;
	if (dup) {
// XXX: doesnt works well 
		item = R_NEW0 (RFlagItem);
		if (!r_flag_item_set_name (item, name, NULL)) {
			eprintf ("Invalid flag name '%s'.\n", name);
			free (item);
			return NULL;
		}
		item->space = f->space_idx;
		r_list_append (f->flags, item);

		item->offset = off + f->base;
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
		item = r_flag_get (f, name);
		if (item) {
			RList *list2, *lol;
			if (item->offset == off)
				return item;
			/* remove old entry */
			list2 = r_hashtable64_lookup (f->ht_off, item->offset);
			if (list2)
			/* No _safe loop necessary because we break immediately after the delete. */
			r_list_foreach (list2, iter2, item2) {
				if (item->namehash != item2->namehash)
					continue;
				if (item2->offset == item->offset) {
					// r_list_delete (list2, iter2);
					// delete without freeing contents
					r_list_split_iter (list2, iter2);
					free (iter2);
					if (r_list_empty (list2)) {
						r_list_free (list2);
						r_hashtable64_remove (f->ht_off, item2->offset);
						r_hashtable64_insert (f->ht_off, item2->offset, NULL);
					}
					break;
				}
			}

			lol = r_hashtable64_lookup (f->ht_off, off);
			if (lol == NULL) {
				lol = r_list_new ();
				r_hashtable64_insert (f->ht_off, off, lol);
			}
			r_list_append (lol, item);
			/* update new entry */
			item->offset = off;
			item->size = size;
		} else {
			item = R_NEW0 (RFlagItem);
			if (!r_flag_item_set_name (item, name, NULL)) {
				eprintf ("Invalid flag name '%s'.\n", name);
				free (item);
				return NULL;
			}
			item->space = f->space_idx;
			r_list_append (f->flags, item);
			item->offset = off + f->base;
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
				r_hashtable64_insert (f->ht_off, off, list2);
			}
			r_list_append (list2, item);
		}
	}
	return item;
}

#define ISNULLSTR(x) (!x||!*x)
R_API void r_flag_item_set_alias(RFlagItem *item, const char *alias) {
	if (item) {
		free (item->alias);
		item->alias = ISNULLSTR(alias)? NULL: strdup (alias);
	}
}

R_API void r_flag_item_set_comment(RFlagItem *item, const char *comment) {
	if (item) {
		free (item->comment);
		item->comment = ISNULLSTR(comment)? NULL: strdup (comment);
	}
}

R_API int r_flag_item_set_name(RFlagItem *item, const char *name, const char *realname) {
	int len;
	if (!item)
		return R_FALSE;
	if (!realname)
		realname = name;
	if (!r_name_check (name))
		return R_FALSE;
	/* original name. maybe do some char mangling : printable*/
	/* filtered name : typable */
	strncpy (item->realname, realname, R_FLAG_NAME_SIZE);
	strncpy (item->name, name, R_FLAG_NAME_SIZE);
	len = R_MIN (R_FLAG_NAME_SIZE, strlen (r_str_chop (item->name)) + 1);
	memmove (item->name, r_str_chop (item->name), len);
	r_name_filter (item->name, 0);
	item->name[R_FLAG_NAME_SIZE-1]='\0';
	item->namehash = r_str_hash64 (item->realname);
	return R_TRUE;
}

R_API int r_flag_rename(RFlag *f, RFlagItem *item, const char *name) {
	ut64 hash;
	RList *list;
	if (!f || !item || !name || !*name) {
		eprintf ("r_flag_rename: contract fail\n");
		return R_FALSE;
	}
	hash = r_str_hash64 (item->name);
	list = r_hashtable64_lookup (f->ht_name, hash);
	if (list) {
		RFlagItem *item = r_list_get_top (list);
		if (r_list_empty (list)) {
			//r_list_free (list);
			r_hashtable64_remove (f->ht_name, hash);
		} else {
			r_hashtable64_remove (f->ht_name, hash);
			r_list_delete_data (list, item);
		}
		if (!r_flag_item_set_name (item, name, NULL)) {
			r_list_append (list, item);
			return R_FALSE;
		}
		list = r_hashtable64_lookup (f->ht_name, item->namehash);
		if (!list) {
			list = r_list_new ();
			r_hashtable64_insert (f->ht_name, item->namehash, list);
		}
		r_list_append (list, item);
	}
	return R_TRUE;
}

R_API int r_flag_unset_i(RFlag *f, ut64 off, RFlagItem *p) {
	RFlagItem *flag = r_flag_get_i (f, off);
	if (flag) {
		r_flag_unset (f, flag->name, NULL); //, flag);
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
	/* No _safe loop necessary because we return immediately after the delete. */
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
			/* No _safe loop necessary because we break immediately after the delete. */
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

R_API RFlagItem *r_flag_get_at(RFlag *f, ut64 off) {
	RFlagItem *item, *nice = NULL;
	RListIter *iter;

	r_list_foreach (f->flags, iter, item) {
		if (item->offset == off)
			return item;
		if (off > item->offset) {
			if (nice)  {
				if (nice->offset < item->offset)
					nice = item;
			} else nice = item;
		}
	}
	return nice;
}

R_API int r_flag_relocate (RFlag *f, ut64 off, ut64 off_mask, ut64 to) {
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

R_API int r_flag_move (RFlag *f, ut64 at, ut64 to) {
	RFlagItem *item = r_flag_get_i (f, at);
	if (item) {
		r_flag_set (f, item->name, to, item->size, 0);
		return R_TRUE;
	}
	return R_FALSE;
}

#ifdef MYTEST
int main () {
	RFlagItem *i;
	RFlag *f = r_flag_new ();
	r_flag_set (f, "rip", 0xfff333999000LL, 1, 0);
	r_flag_set (f, "rip", 0xfff333999002LL, 1, 0);
	r_flag_unset (f, "rip", NULL);
	r_flag_set (f, "rip", 3, 4, 0);
	r_flag_set (f, "rip", 4, 4, 0);
	r_flag_set (f, "corwp", 300, 4, 0);
	r_flag_set (f, "barp", 300, 4, 0);
	r_flag_set (f, "rip", 3, 4, 0);
	r_flag_set (f, "rip", 4, 4, 0);

	i = r_flag_get (f, "rip");
	if (i) printf ("nRIP: %p %llx\n", i, i->offset);
	else printf ("nRIP: null\n");

	i = r_flag_get_i (f, 0xfff333999000LL);
	if (i) printf ("iRIP: %p %llx\n", i, i->offset);
	else printf ("iRIP: null\n");
}
#endif

R_API const char *r_flag_color(RFlag *f, RFlagItem *it, const char *color) {
	if (!f || !it)
		return NULL;
	if (!color)
		return it->color;
	free (it->color);
	if (*color)
		it->color = strdup (color);
	else it->color = NULL;
	return it->color;
}

// BIND

R_API int r_flag_bind (RFlag *f, RFlagBind *fb) {
	fb->f = f;
	fb->get = r_flag_get;
	fb->set = r_flag_set;
	fb->set_fs = r_flag_space_set;
	return 0;
}
