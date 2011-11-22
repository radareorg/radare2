/* radare - LGPL - Copyright 2007-2011 pancake<nopcode.org> */

#include <r_flags.h>
#include <r_util.h>
#include <r_cons.h>
#include <stdio.h>

// TODO: remove r_cons dependency here..
// remove btree here.. we want something funnier like.. RMixed :D

/* compare names */
static int ncmp(const void *a, const void *b) {
	RFlagItem *fa = (RFlagItem *)a;
	RFlagItem *fb = (RFlagItem *)b;
	return strcmp (fa->name, fb->name);
}

/* compare offsets */
static int cmp(const void *a, const void *b) {
	RFlagItem *fa = (RFlagItem *)a;
	RFlagItem *fb = (RFlagItem *)b;
	if (fa->offset > fb->offset) return 1;
	else if (fa->offset < fb->offset) return -1;
	return 0;
}

R_API int r_flag_sort(RFlag *f, int namesort) {
	int ret = R_FALSE;
	int changes;
	RFlagItem *flag, *fi = NULL;
	RListIter *iter, *it_elem;
	RList *tmp = r_list_new ();
	// find bigger ones after this
	do {
		changes = 0;
		fi = NULL;
		r_list_foreach (f->flags, iter, flag) {
			if (fi == NULL) {
				fi = flag;
				it_elem = iter;
				changes = 1;
			} else if (((namesort)? ncmp (fi, flag): cmp (fi, flag)) <= 0) {
				fi = flag;
				it_elem = iter;
				changes = 1;
			}
		}
		if (fi && changes) {
			ret = R_TRUE;
			r_list_split_iter (f->flags, it_elem);
			free (it_elem);
			r_list_append (tmp, fi);
		}
	} while (changes);

	free (f->flags);
	f->flags = tmp;
	f->flags->free = free;
	return ret;
}

R_API RFlag * r_flag_free(RFlag *f) {
	r_list_free (f->flags);
	free (f);
	return NULL;
}

R_API RFlag * r_flag_new() {
	int i;
	RFlag *f = R_NEW (RFlag);
	if (!f) return NULL;
	f->flags = r_list_new ();
	f->flags->free = free;
	f->space_idx = -1;
	f->space_idx2 = -1;
#if USE_BTREE
	btree_init (&f->tree);
	btree_init (&f->ntree);
#endif
	for (i=0; i<R_FLAG_SPACES_MAX; i++)
		f->spaces[i] = NULL;
	return f;
}

// Deprecated??
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
	RFlagItem *flag;
	RListIter *iter;
	if (strnull (name) || (name[0]>='0' && name[0]<='9'))
		return NULL;
	ut64 hash = r_str_hash64 (name);
	r_list_foreach_prev (f->flags, iter, flag) {
		//if (!strcmp (name, flag->name))
		if (hash == flag->namehash)
			return flag;
	}
	return NULL;
}

R_API RFlagItem *r_flag_get_at(RFlag *f, ut64 off) {
	RFlagItem *item, *nice = NULL;
	RListIter *iter;

	r_list_foreach (f->flags, iter, item) {
		if (item->offset > off) {
			if (nice)  {
				if (item->offset < nice->offset)
					nice = item;
			}else nice = item;
		}
	}
	return nice;
}

R_API RFlagItem *r_flag_get_i(RFlag *f, ut64 off) {
	RFlagItem *i;
#if USE_BTREE
	RFlagItem tmp = { .offset = off };
	i = btree_get (f->tree, &tmp, cmp);
	return i;
#else
	/* slow workaround */
	RListIter *iter;
	r_list_foreach_prev (f->flags, iter, i) {
		if (off == i->offset)
			return i;
	}
	return NULL;
#endif
}

R_API int r_flag_unset_i(RFlag *f, ut64 addr, RFlagItem *p) {
	RFlagItem *item;
	RListIter *iter;

	r_list_foreach (f->flags, iter, item) {
		if (item->offset == addr) {
			r_list_delete (f->flags, iter);
			return R_TRUE;
		}
	}
	return R_FALSE;
#if USE_BTREE
	/* XXX */
	btree_del (f->tree, item, cmp, NULL);
	btree_del (f->ntree, item, ncmp, NULL);
#endif
	return 0;
}

R_API int r_flag_unset(RFlag *f, const char *name, RFlagItem *p) {
	RFlagItem *item;
	RListIter *iter;

	if (*name == '*') {
		r_list_destroy (f->flags);
	} else {
		item = r_flag_get (f, name);
		// XXX: This is slow.. because get+unlink is traversing the linked list twice
		// XXX: we must use a hashtable here
		/* MARK: entrypoint to remove flags */
		if (item) {
#if USE_BTREE
			btree_del (f->tree, item, cmp, NULL);
			btree_del (f->ntree, item, ncmp, NULL);
#endif
			r_list_unlink (f->flags, item);
		}
	}
	return 0;
}

R_API int r_flag_set(RFlag *fo, const char *name, ut64 addr, ut32 size, int dup) {
	RFlagItem *flag = NULL;
#if !USE_BTREE
	RListIter *iter;
#endif
	if (!dup && !r_flag_name_check (name)) {
		eprintf ("r_flag_set: invalid flag name '%s'.\n", name);
		return R_FALSE;
	}
#if USE_BTREE
	{
/* XXX : This is not working properly!! */
		RFlagItem tmp;
		tmp.namehash = r_str_hash64 (name);
//eprintf("NAME(%s) HASH(%x)\n", name, tmp.namehash);
		flag = btree_get (fo->ntree, &tmp, ncmp);
		if (flag) {
			if (dup) {
				/* ignore dupped name+offset */
				if (flag->offset == addr)
					return 1;
			} else {
				flag->offset = addr;
				flag->size = size; // XXX
				flag->format = 0; // XXX
//eprintf("update '%s'\n", f->name);
				return R_TRUE;
			}
		}
//		if (flag)
//			return R_TRUE;
//		else eprintf("NOT REGISTERED(%s)\n", name);
	}
#else
	RFlagItem *f; // Move to !BTREE section?
	ut64 hash = r_str_hash64 (name);

// THIS IS ULTRASLOW!
// XXX: use hashtable here or gtfo
	r_list_foreach (fo->flags, iter, f) {
		//if (!strcmp(f->name, name)) {
		if (hash == f->namehash) {
			if (dup) {
				/* ignore dupped name+offset */
				if (f->offset == addr)
					return 1;
			} else {
				flag = f;
				f->offset = addr;
				f->size = size; // XXX
				f->format = 0; // XXX
				return R_TRUE;
			}
		}
	}
#endif
	if (flag == NULL) {
		/* MARK: entrypoint for flag addition */
		flag = R_NEW (RFlagItem);
		memset (flag,'\0', sizeof (RFlagItem));
		flag->offset = addr;
		r_flag_item_set_name (flag, name);
#if USE_BTREE
		btree_add (&fo->tree, flag, cmp);
		btree_add (&fo->ntree, flag, ncmp);
#endif
		r_list_append (fo->flags, flag);
		if (flag==NULL)
			return R_TRUE;
	}

	flag->offset = addr;
	flag->space = fo->space_idx;
	flag->size = size; // XXX
	flag->format = 0; // XXX
	flag->cmd = NULL;

	return R_FALSE;
}

//R_API void r_flag_item_rename(RFlagItem *item, const char *name) {
//}
R_API void r_flag_item_set_name(RFlagItem *item, const char *name) {
	int len;
	strncpy (item->name, name, R_FLAG_NAME_SIZE);
	len = R_MIN (R_FLAG_NAME_SIZE, strlen (r_str_chop (item->name)) + 1);
	memmove (item->name, r_str_chop (item->name), len);
	item->name[R_FLAG_NAME_SIZE-1]='\0';
	item->namehash = r_str_hash64 (item->name);
}
