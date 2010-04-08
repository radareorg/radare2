/* radare - LGPL - Copyright 2007-2010 pancake<nopcode.org> */

#include <r_flags.h>
#include <r_util.h>
#include <r_cons.h>
#include <stdio.h>

#if USE_BTREE
/* compare names */
static int ncmp(const void *a, const void *b) {
	RFlagItem *fa = (RFlagItem *)a;
	RFlagItem *fb = (RFlagItem *)b;
	int ret = 0;
	/* we cannot use a simple substraction coz ut64 > s32 :) */
	if (fa->namehash > fb->namehash) ret = 1;
	else if (fa->namehash < fb->namehash) ret = -1;
	return ret;
}

/* compare offsets */
static int cmp(const void *a, const void *b) {
	RFlagItem *fa = (RFlagItem *)a;
	RFlagItem *fb = (RFlagItem *)b;
	int ret = 0;
	/* we cannot use a simple substraction coz ut64 > s32 :) */
	if (fa->offset > fb->offset) ret = 1;
	else if (fa->offset < fb->offset) ret = -1;
	return ret;
}
#endif

R_API int r_flag_init(RFlag *f) {
	int i;
	INIT_LIST_HEAD(&f->flags);
	f->space_idx = -1;
	f->space_idx2 = -1;
#if USE_BTREE
	btree_init(&f->tree);
	btree_init(&f->ntree);
#endif
	for (i=0;i<R_FLAG_SPACES_MAX;i++)
		f->space[i] = NULL;
	return 0;
}

R_API void r_flag_sort(RFlag *flag) {
	// TODO: Implement sorted linked list
	eprintf ("TODO: r_flag_sort\n");
}

R_API RFlag * r_flag_new() {
	RFlag *f = R_NEW (RFlag);
	r_flag_init (f);
	return f;
}

R_API RFlagItem *r_flag_list(RFlag *f, int rad) {
	int fs = -1;
	struct list_head *pos;
	list_for_each_prev (pos, &f->flags) {
		RFlagItem *flag = list_entry (pos, RFlagItem, list);
		if ((f->space_idx != -1) && (flag->space != f->space_idx))
			continue;
		if (rad) {
			if (fs == -1 || flag->space != fs) {
				fs = flag->space;
				r_cons_printf ("fs %s\n", r_flag_space_get (f, fs));
			}
			r_cons_printf ("f %s %lld 0x%08llx\n",
				flag->name, flag->size, flag->offset);
		} else r_cons_printf("0x%08llx %lld %s\n",
				flag->offset, flag->size, flag->name);
	}
	return NULL;
}

R_API RFlagItem *r_flag_get(RFlag *f, const char *name) {
#if USE_BTREE
	RFlagItem tmp;
#else
	RFlagItem *flag;
	struct list_head *pos;
#endif
	if (name==NULL || name[0]=='\0' || (name[0]>='0'&& name[0]<='9'))
		return NULL;
#if USE_BTREE
	tmp.namehash = r_str_hash (name);
//eprintf("GET_I (0x%08llx) = %p\n", off, flag);
	return btree_get (f->ntree, &tmp, ncmp);
#else
	list_for_each_prev (pos, &f->flags) {
		flag = list_entry (pos, RFlagItem, list);
		if (!strcmp (name, flag->name))
			return flag;
	}
#endif
	return NULL;
}

R_API RFlagItem *r_flag_get_i(RFlag *f, ut64 off) {
#if USE_BTREE
	RFlagItem *i;
	RFlagItem tmp = { .offset = off };
	i = btree_get (f->tree, &tmp, cmp);
//eprintf("GET_N (0x%08llx) = %p\n", off, i);
	return i;
#else
	/* slow workaround */
	struct list_head *pos;
	list_for_each_prev (pos, &f->flags) {
		RFlagItem *flag = list_entry (pos, RFlagItem, list);
		if (off == flag->offset)
			return flag;
	}
	return NULL;
#endif
}

R_API int r_flag_unset(RFlag *f, const char *name) {
	RFlagItem *item = r_flag_get (f, name);
	/* MARK: entrypoint to remove flags */
	if (item) {
#if USE_BTREE
		btree_del (f->tree, item, cmp, NULL);
		btree_del (f->ntree, item, ncmp, NULL);
#endif
		list_del (&item->list);
	}
	return 0;
}

R_API int r_flag_set(RFlag *fo, const char *name, ut64 addr, ut32 size, int dup) {
	const char *ptr;
	RFlagItem *flag = NULL;
#if !USE_BTREE
	struct list_head *pos;
#endif
	if (!dup) {
		/* show flags as radare commands */
		if (!r_flag_name_check (name)) {
			eprintf ("invalid flag name '%s'.\n", name);
			return R_FALSE;
		}
		for (ptr = name + 1; *ptr != '\0'; ptr = ptr +1) {
			if (!IS_PRINTABLE (*ptr)) {
				eprintf ("invalid flag name\n");
				return R_FALSE;
			}
		}
	}
#if USE_BTREE
	{
/* XXX : This is not working properly!! */
		RFlagItem tmp;
		tmp.namehash = r_str_hash (name);
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
	list_for_each (pos, &fo->flags) {
		RFlagItem *f = (RFlagItem *)
			list_entry(pos, RFlagItem, list);
		if (!strcmp(f->name, name)) {
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
		strncpy (flag->name, name, R_FLAG_NAME_SIZE);
		strncpy (flag->name, r_str_chop (flag->name), R_FLAG_NAME_SIZE);
		flag->name[R_FLAG_NAME_SIZE-1]='\0';
		flag->namehash = r_str_hash (flag->name);
#if USE_BTREE
		btree_add (&fo->tree, flag, cmp);
		btree_add (&fo->ntree, flag, ncmp);
#endif
		list_add_tail (&(flag->list), &fo->flags);
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
