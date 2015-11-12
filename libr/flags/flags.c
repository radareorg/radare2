/* radare - LGPL - Copyright 2007-2015 - pancake */

#include <r_flags.h>
#include <r_util.h>
#include <r_cons.h>
#include <stdio.h>

R_LIB_VERSION(r_flag);

#define USE_SDB 0
#if USE_SDB
Sdb *db = NULL;
#endif

/* aim to fix a bug in hashtable64 , collisions happen */
#define XORKEY 0x12345678
#define XOROFF(x) (x^XORKEY)
// offset needs to be xored to avoid some collisions !!! must switch to sdb
//#define XOROFF(x) x

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
#if USE_SDB
	db = sdb_new0 ();
#endif
	f->num = r_num_new (&num_callback, f);
	f->base = 0;
	f->flags = r_list_new ();
	f->flags->free = (RListFree) r_flag_item_free;
	f->space_idx = -1;
	f->space_idx2 = -1;
	f->spacestack = r_list_newf (NULL);
	f->ht_name = r_hashtable64_new ();
	f->ht_off = r_hashtable64_new ();
	for (i=0; i<R_FLAG_SPACES_MAX; i++)
		f->spaces[i] = NULL;
	return f;
}

R_API void r_flag_item_free (RFlagItem *item) {
#if USE_SDB
	sdb_free (db);
	db = NULL;
#endif
	free (item->cmd);
	free (item->color);
	free (item->comment);
	free (item->alias);
	item->cmd = item->comment = NULL;
	/* release only one of the two pointers if they are the same */
	if (item->name != item->realname)
		free (item->name);
	free (item->realname);
	free (item);
}

R_API RFlag *r_flag_free(RFlag *f) {
	int i;
	for (i=0; i<R_FLAG_SPACES_MAX; i++)
		free (f->spaces[i]);
	r_hashtable64_free (f->ht_off);
	r_hashtable64_free (f->ht_name);
	r_list_free (f->flags);
	r_list_free (f->spacestack);
	free (f);
	return NULL;
}

R_API void r_flag_list(RFlag *f, int rad, const char *pfx) {
	int fs = -1;
	RListIter *iter;
	RFlagItem *flag;

	if (pfx && !*pfx)
		pfx = NULL;
	switch (rad) {
	case 'j': {
		int first = 1;
		r_cons_printf ("[");
		r_list_foreach (f->flags, iter, flag) {
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
		 r_list_foreach (f->flags, iter, flag) {
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
					 r_cons_printf ("\"fC %s %s\"\n",
						flag->name, flag->comment);
			 } else {
				 r_cons_printf ("f %s %"PFMT64d" 0x%08"PFMT64x"%s%s %s\n",
					 flag->name, flag->size, flag->offset,
					 pfx?"+":"", pfx?pfx:"",
					 flag->comment? flag->comment:"");
			 }
		 }
		 break;
	case 'n': // show original name
		 r_list_foreach (f->flags, iter, flag) {
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
		 r_list_foreach (f->flags, iter, flag) {
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
	if (item && item->alias) {
		item->offset = r_num_math (f->num, item->alias);
	}
	return item;
}

R_API RFlagItem *r_flag_get(RFlag *f, const char *name) {
	RList *list = r_hashtable64_lookup (f->ht_name, r_str_hash64 (name));
	if (list) return evalFlag (f, r_list_get_top (list));
	return NULL;
}

R_API RFlagItem *r_flag_get_i2(RFlag *f, ut64 off) {
// TODO: this is buggy, do not use, must rewrite in sdb
	RFlagItem *oitem = NULL;
	RFlagItem *item = NULL;
#if USE_SDB
	char buf[128];
	if (!f) return NULL;
	char * foo = sdb_get (db, sdb_itoa (off, buf, 16), 0);
	return r_flag_get (f, foo);
#else
	RListIter *iter;
	RList *list = r_hashtable64_lookup (f->ht_off, XOROFF (off));
	if (!list) return NULL;
	r_list_foreach (list, iter, item) {
		// XXX: hack, because some times the hashtable is poluted by ghost values
		if (item->offset != off)
			continue;
		/* catch sym. first */
		if (!strncmp (item->name, "loc.", 4)) {
			continue;
		}
		if (!strncmp (item->name, "fcn.", 4)) {
			continue;
		}
		if (r_str_nlen(item->name, 5) > 4 && item->name[3] == '.') {
			oitem = item;
			break;
		}
		oitem = item;
		if (strlen (item->name) < 5 || item->name[3]!='.')
			continue;
		oitem = item;
	}
	return oitem;
#endif
}

R_API const RList* /*<RFlagItem*>*/ r_flag_get_list(RFlag *f, ut64 off) {
	return r_hashtable64_lookup (f->ht_off, XOROFF(off));
}

R_API char *r_flag_get_liststr(RFlag *f, ut64 off) {
	RFlagItem *fi;
	RListIter *iter;
	const RList *list = r_flag_get_list (f, off);
	char *p = NULL;
	r_list_foreach (list, iter, fi) {
		p = r_str_concatf (p, "%s%s",
			fi->realname, iter->n?",":":");
	}
	return p;
}

#define R_FLAG_TEST 0
R_API RFlagItem *r_flag_get_i(RFlag *f, ut64 off) {
	RList *list;
	if (!f) return NULL;
	list = r_hashtable64_lookup (f->ht_off, XOROFF(off));
//if (off == 0x4005c4) { eprintf ("FLAG GET IT %llx = %p\n", off, list); }
	if (list) {
		RFlagItem *item = r_list_get_top (list);
#if R_FLAG_TEST
		return item;
#else
		// XXX: hack, because some times the hashtable is poluted by ghost values
		if (item && item->offset == off)
			return item;
#endif
	}
	return NULL;
}

R_API RFlagItem *r_flag_set(RFlag *f, const char *name, ut64 off, ut32 size, int dup) {
	RFlagItem *item = NULL;
#if 1
	RListIter *iter2 = NULL;
	RListIter *iter22 = NULL;
	RFlagItem *item2 = NULL;
#endif
	RList *list2, *list;

#if USE_SDB
{
char buf[128];
sdb_num_set (db, name, off, 0);
sdb_set (db, sdb_itoa (off, buf, 16), name, 0);
}
#endif

//if (strstr(name, "str")) eprintf ("%d %s=0x%"PFMT64x"\n", dup, name, off);
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

		list2 = r_hashtable64_lookup (f->ht_off, XOROFF(off));
		if (list2 == NULL) {
			list2 = r_list_new ();
			r_hashtable64_insert (f->ht_name, off, list2);
		}
		r_list_append (list2, item);
	} else {
		item = r_flag_get (f, name);
		if (item) {
			if (item->offset == off) {
				item->size = size;
				return item;
			}
			/* remove old entry */
#if 1
			RList *list2 = r_hashtable64_lookup (f->ht_off, XOROFF(item->offset));
			if (list2) {
				/* No _safe loop necessary because we break immediately after the delete. */
				r_list_foreach_safe (list2, iter2, iter22, item2) {
					if (item->namehash != item2->namehash)
						continue;
					if (item->offset == item2->offset) {
						// r_list_delete (list2, iter2);
						// delete without freeing contents
						//list2->free = NULL;
						r_list_split_iter (list2, iter2);
						if (r_list_empty (list2)) {
							r_hashtable64_remove (f->ht_off, item2->offset);
							r_hashtable64_insert (f->ht_off, item2->offset, NULL);
							//r_list_free (list2);
							//list2 = NULL;
						}
						break;
					}
				}
			}
#endif
			/* update new entry */
			item->offset = off;
			item->size = size;

#if 1
			RList *lol = r_hashtable64_lookup (f->ht_off, XOROFF(off));
			if (!lol) {
				lol = r_list_new ();
				r_hashtable64_remove (f->ht_off, XOROFF(off));
				r_hashtable64_insert (f->ht_off, XOROFF(off), lol);
			}
			if (lol) {
				r_list_append (lol, item);
			}
#endif
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

			list2 = r_hashtable64_lookup (f->ht_off, XOROFF(off));
			if (list2 == NULL) {
				list2 = r_list_new ();
				r_hashtable64_insert (f->ht_off, XOROFF(off), list2);
//if (off == 0x4005c4) { eprintf ("FLAG SET IT %llx = %p\n", off, list2); }
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
		item->alias = ISNULLSTR (alias)? NULL: strdup (alias);
	}
}

R_API void r_flag_item_set_comment(RFlagItem *item, const char *comment) {
	if (item) {
		free (item->comment);
		item->comment = ISNULLSTR (comment)? NULL: strdup (comment);
	}
}

R_API int r_flag_item_set_name(RFlagItem *item, const char *name, const char *realname) {
	if (!item || !r_name_check (name))
		return false;
	if (!realname) realname = name;

	/* realname is the original name of the flag */
	item->realname = strdup (realname);
	item->namehash = r_str_hash64 (item->realname);

	/* the name contains only printable chars that doesn't conflict with r2 shell */
	item->name = strdup (name);
	r_str_chop (item->name);
	r_name_filter (item->name, 0); // TODO: name_filter should be chopping already

	/* avoid unnecessary dupped memory */
	if (!strcmp (item->name, item->realname)) {
		free (item->name);
		item->name = item->realname;
	}
	return true;
}

R_API int r_flag_rename(RFlag *f, RFlagItem *item, const char *name) {
	ut64 hash;
	RList *list;
	if (!f || !item || !name || !*name) {
		eprintf ("r_flag_rename: contract fail\n");
		return false;
	}
	hash = r_str_hash64 (item->realname);
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
			return false;
		}
		list = r_hashtable64_lookup (f->ht_name, item->namehash);
		if (!list) {
			list = r_list_new ();
			r_hashtable64_insert (f->ht_name, item->namehash, list);
		}
		r_list_append (list, item);
	}
	return true;
}

R_API int r_flag_unset_i(RFlag *f, ut64 off, RFlagItem *p) {
	RFlagItem *flag = r_flag_get_i (f, off);
	if (flag) {
		r_flag_unset (f, flag->name, NULL);
		return true;
	}
	return false;
}

R_API int r_flag_unset_glob(RFlag *f, const char *glob) {
	int n = 0;
	RListIter it, *iter;
	RFlagItem *flag;
	r_list_foreach (f->flags, iter, flag) {
		if ((f->space_idx != -1) && (flag->space != f->space_idx))
			continue;
		if (!glob || r_str_glob (flag->name, glob)) {
			it.n = iter->n;
			r_flag_unset (f, flag->name, flag);
			iter = &it;
			n++;
		}
	}
	return n;
}

R_API void r_flag_unset_all (RFlag *f) {
	f->space_idx = -1;
	f->space_idx2 = -1;

	// --- seems buggy and slow r_flag_unset_glob (f, NULL);
	r_list_free (f->flags);
	f->flags = r_list_new ();
	f->flags->free = (RListFree) r_flag_item_free;

	r_hashtable64_free (f->ht_name);
	f->ht_name = r_hashtable64_new ();
	r_hashtable64_free (f->ht_off);
	f->ht_off = r_hashtable64_new ();

	r_flag_space_unset (f, NULL);
}

static void unflag(RFlag *f, RFlagItem *me) {
	RListFree lf = f->flags->free;
	f->flags->free = NULL;
	memset (me, 0, sizeof (RFlagItem));
	r_list_delete_data (f->flags, me);
	f->flags->free = lf;
}

R_API int r_flag_unset(RFlag *f, const char *name, RFlagItem *p) {
	ut64 off;
	RFlagItem *item = p;
	ut64 hash = r_str_hash64 (name);
	RList *list2, *list = r_hashtable64_lookup (f->ht_name, hash);
	// list = name hash
	// list2 = off hash
	if (list && list->head) {
		if (!item) item = r_list_pop (list); // removes element from list
		if (!item) {
			return false;
		}
		off = item->offset;

		list2 = r_hashtable64_lookup (f->ht_off, XOROFF (off));
		if (list2) {
			/* delete flag by name */
			r_list_delete_data (list2, item);
			if (list2 && r_list_empty (list2)) {
				r_list_free (list2);
				r_hashtable64_remove (f->ht_off, XOROFF(off));
			}
			if (list && r_list_empty (list)) {
				r_list_free (list);
				r_hashtable64_remove (f->ht_name, hash);
			}
		}
		/* delete from f->flags list */
		unflag (f, item);
		return true;
	}
	return false;
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
		return true;
	}
	return false;
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
	fb->get_at = r_flag_get_at;
	fb->set = r_flag_set;
	fb->set_fs = r_flag_space_set;
	return 0;
}
