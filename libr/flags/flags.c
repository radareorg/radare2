/* radare - LGPL - Copyright 2007-2010 pancake<nopcode.org> */

#include <r_flags.h>
#include <r_util.h>
#include <stdio.h>

#if USE_BTREE
/* compare names */
static int ncmp(const void *a, const void *b)
{
	struct r_flag_item_t *fa = (struct r_flag_item_t *)a;
	struct r_flag_item_t *fb = (struct r_flag_item_t *)b;
	int ret = 0;
	/* we cannot use a simple substraction coz ut64 > s32 :) */
	if (fa->namehash > fb->namehash) ret = 1;
	else if (fa->namehash < fb->namehash) ret = -1;
	return ret;
}

/* compare offsets */
static int cmp(const void *a, const void *b)
{
	struct r_flag_item_t *fa = (struct r_flag_item_t *)a;
	struct r_flag_item_t *fb = (struct r_flag_item_t *)b;
	int ret = 0;
	/* we cannot use a simple substraction coz ut64 > s32 :) */
	if (fa->offset > fb->offset) ret = 1;
	else if (fa->offset < fb->offset) ret = -1;
	return ret;
}
#endif

R_API int r_flag_init(struct r_flag_t *f)
{
	int i;
	INIT_LIST_HEAD(&f->flags);
	f->space_idx = -1;
	f->space_idx2 = -1;
	f->base = 0LL;
#if USE_BTREE
	btree_init(&f->tree);
	btree_init(&f->ntree);
#endif
	for(i=0;i<R_FLAG_SPACES_MAX;i++)
		f->space[i] = NULL;
	return 0;
}

R_API struct r_flag_t * r_flag_new()
{
	struct r_flag_t *f = MALLOC_STRUCT (struct r_flag_t);
	r_flag_init (f);
	return f;
}

R_API int r_flag_set_base(struct r_flag_t *f, ut64 new_base)
{
	f->base = new_base;
	return 0;
}

R_API struct r_flag_item_t *r_flag_list(struct r_flag_t *f, int rad)
{
	struct list_head *pos;
	list_for_each_prev(pos, &f->flags) {
		struct r_flag_item_t *flag = list_entry(pos, struct r_flag_item_t, list);
		if (rad) r_cons_printf("f %s %lld @ 0x%08llx\n",
			flag->name, flag->size, flag->offset);
		else r_cons_printf("0x%08llx %lld %s\n",
			flag->offset, flag->size, flag->name);
	}
	return NULL;
}

R_API struct r_flag_item_t *r_flag_get(struct r_flag_t *f, const char *name)
{
#if USE_BTREE
	struct r_flag_item_t *i;
	struct r_flag_item_t tmp;
#else
	struct list_head *pos;
#endif
	if (name==NULL || name[0]=='\0' || (name[0]>='0'&& name[0]<='9'))
		return NULL;
#if USE_BTREE
	tmp.namehash = r_str_hash(name);
	i = btree_get(f->ntree, &tmp, ncmp);
//eprintf("GET_I (0x%08llx) = %p\n", off, i);
	return i;
#else
	list_for_each_prev(pos, &f->flags) {
		struct r_flag_item_t *flag = list_entry(pos, struct r_flag_item_t, list);
		if (!strcmp(name, flag->name))
			return flag;
	}
#endif
	return NULL;
}

R_API struct r_flag_item_t *r_flag_get_i(struct r_flag_t *f, ut64 off)
{
#if USE_BTREE
	struct r_flag_item_t *i;
	struct r_flag_item_t tmp = { .offset = off };
	i = btree_get(f->tree, &tmp, cmp);
//eprintf("GET_N (0x%08llx) = %p\n", off, i);
	return i;
#else
	/* slow workaround */
	struct list_head *pos;
	list_for_each_prev(pos, &f->flags) {
		struct r_flag_item_t *flag = list_entry(pos, struct r_flag_item_t, list);
		if (off == flag->offset)
			return flag;
	}
	return NULL;
#endif
}

R_API int r_flag_unset(struct r_flag_t *f, const char *name)
{
	struct r_flag_item_t *item;
	item = r_flag_get(f, name);
	/* MARK: entrypoint to remove flags */
	if (item) {
#if USE_BTREE
		btree_del(f->tree, item, cmp, NULL);
		btree_del(f->ntree, item, ncmp, NULL);
#endif
		list_del(&item->list);
	}
	return 0;
}

R_API int r_flag_set(struct r_flag_t *fo, const char *name, ut64 addr, ut32 size, int dup)
{
	const char *ptr;
	struct r_flag_item_t *flag = NULL;
#if !USE_BTREE
	struct list_head *pos;
#endif

	if (!dup) {
		/* show flags as radare commands */
		if (!r_flag_name_check(name)) {
			fprintf(stderr, "invalid flag name '%s'.\n", name);
			return R_FALSE;
		}

		for (ptr = name + 1; *ptr != '\0'; ptr = ptr +1) {
			if (!IS_PRINTABLE(*ptr)) {
				fprintf(stderr, "invalid flag name\n");
				return R_FALSE;
			}
		}
	}

#if USE_BTREE
	{
/* XXX : This is not working properly!! */
		struct r_flag_item_t tmp;
		tmp.namehash = r_str_hash(name);
//eprintf("NAME(%s) HASH(%x)\n", name, tmp.namehash);
		flag = btree_get(fo->ntree, &tmp, ncmp);
		if (flag) {
			if (dup) {
				/* ignore dupped name+offset */
				if (flag->offset == addr)
					return 1;
			} else {
				flag->offset = addr + fo->base;
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
	list_for_each(pos, &fo->flags) {
		struct r_flag_item_t *f = (struct r_flag_item_t *)
			list_entry(pos, struct r_flag_item_t, list);
		if (!strcmp(f->name, name)) {
			if (dup) {
				/* ignore dupped name+offset */
				if (f->offset == addr)
					return 1;
			} else {
				flag = f;
				f->offset = addr + fo->base;
				f->size = size; // XXX
				f->format = 0; // XXX
//eprintf("update '%s'\n", f->name);
				return R_TRUE;
			}
		}
	}
#endif

	if (flag == NULL) {
		/* MARK: entrypoint for flag addition */
		flag = malloc(sizeof(struct r_flag_item_t));
		memset(flag,'\0', sizeof(struct r_flag_item_t));
		flag->offset = addr + fo->base;
		strncpy(flag->name, name, R_FLAG_NAME_SIZE);
		strncpy(flag->name, r_str_chop(flag->name), R_FLAG_NAME_SIZE);
		flag->name[R_FLAG_NAME_SIZE-1]='\0';
		flag->namehash = r_str_hash(flag->name);
#if USE_BTREE
		btree_add(&fo->tree, flag, cmp);
		btree_add(&fo->ntree, flag, ncmp);
#endif
		list_add_tail(&(flag->list), &fo->flags);
		if (flag==NULL)
			return R_TRUE;
	}

//eprintf("NAME(%s) HASH(%x)\n", flag->name, flag->namehash);
	flag->offset = addr + fo->base;
	flag->space = fo->space_idx;
	flag->size = size; // XXX
	flag->format = 0; // XXX
	flag->cmd = NULL;

	return R_FALSE;
}
