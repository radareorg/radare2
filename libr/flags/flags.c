/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_flags.h>
#include <r_cons.h> // TODO: drop dependency
#include <stdio.h>

#define IS_PRINTABLE(x) (x>=' '&&x<='~')

int r_flag_init(struct r_flag_t *f)
{
	int i;
	INIT_LIST_HEAD(&f->flags);
	f->space_idx = -1;
	f->space_idx2 = -1;
	f->base = 0LL;
	for(i=0;i<R_FLAG_SPACES;i++)
		f->space[i] = NULL;
	return 0;
}


int r_flag_set_base(struct r_flag_t *f, u64 new_base)
{
	f->base = new_base;
	return 0;
}


const const char *r_flag_space_get(struct r_flag_t *f, int idx)
{
	if (idx==-1)
		return "";
	if (idx>255||f->space[idx]=='\0')
		return "";
	return f->space[idx];
}

struct r_flag_item_t *r_flag_list(struct r_flag_t *f, int rad)
{
	struct list_head *pos;
	list_for_each_prev(pos, &f->flags) {
		struct r_flag_item_t *flag = list_entry(pos, struct r_flag_item_t, list);
		if (rad) printf("f %s %d @ 0x%08llx\n", flag->name,
			flag->size, flag->offset);
		else printf("0x%08llx %d %s\n",
			flag->offset, flag->size, flag->name);
	}
	return NULL;
}

struct r_flag_item_t *r_flag_get(struct r_flag_t *f, const char *name)
{
	struct list_head *pos;
	if (name==NULL || name[0]=='\0' || (name[0]>='0'&& name[0]<='9'))
		return NULL;
	list_for_each_prev(pos, &f->flags) {
		struct r_flag_item_t *flag = list_entry(pos, struct r_flag_item_t, list);
		if (!strcmp(name, flag->name))
			return flag;
	}
	return NULL;
}

int r_flag_unset(struct r_flag_t *f, const char *name)
{
	struct r_flag_item_t *item;
	item = r_flag_get(f, name);
	if (item)
		list_del(&item->list);
	return 0;
}

int r_flag_set(struct r_flag_t *fo, const char *name, u64 addr, u32 size, int dup)
{
	const char *ptr;
	struct r_flag_item_t *flag = NULL;
	struct list_head *pos;

	if (!dup) {
		/* show flags as radare commands */
		if (!r_flag_name_check(name)) {
			fprintf(stderr, "invalid flag name '%s'.\n", name);
			return 2;
		}

		for (ptr = name + 1; *ptr != '\0'; ptr = ptr +1) {
			if (!IS_PRINTABLE(*ptr)) {
				fprintf(stderr, "invalid flag name\n");
				return 2;
			}
		}
	}

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
				f->size = 1; // XXX
				f->format = 0; // XXX
				return 1;
			}
		}
	}

	if (flag == NULL) {
		flag = malloc(sizeof(struct r_flag_item_t));
		memset(flag,'\0', sizeof(struct r_flag_item_t));
		list_add_tail(&(flag->list), &fo->flags);
		if (flag==NULL)
			return 1;
	}

	strncpy(flag->name, name, R_FLAG_NAME_SIZE);
	flag->name[R_FLAG_NAME_SIZE-1]='\0';
	flag->offset = addr + fo->base;
	flag->space = fo->space_idx;
	flag->size = 1; // XXX
	flag->format = 0; // XXX
	flag->cmd = NULL;

	return 0;
}
