/* radare - LGPL - Copyright 2007-2013 - pancake */
// TODO: RRef - reference counting

#include <stdio.h>

#define _R_LIST_C_
#include "r_util.h"

inline RListIter *r_list_iter_new () {
	return malloc (sizeof (RListIter));
}

void r_list_iter_free (RListIter *list) {
	/* do nothing? */
}

RListIter *r_list_iter_get_next(RListIter *list) {
	return list->n;
}

void *r_list_iter_get_data(RListIter *list) {
	if (list == NULL) return NULL;
	return list->data;
}

RListIter *r_list_iterator (RList *list) {
	return list? list->head: NULL;
}

RListIter *r_list_push (RList *list, void *item) {
	return r_list_append (list, item);
}

RListIter *r_list_get_next (RListIter *list) {
	return list->n;
}

R_API void r_list_init(RList *list) {
	list->head = NULL;
	list->tail = NULL;
	list->free = NULL;
}

R_API int r_list_length(RList *list) {
	int count = 0;
	RListIter *iter = r_list_iterator (list);
	while (iter) {
		count ++;
		iter = iter->n;
	}
	return count;
}

/* remove all elements of a list */
R_API void r_list_purge (RList *list) {
	RListIter *it;
	if (list) {
		it = list->head;
		while (it) {
			RListIter *next = it->n;
			r_list_delete (list, it);
			it = next;
		}
		list->head = list->tail = NULL;
	}
}

/* free the list */
R_API void r_list_free (RList *list) {
	if (list) {
		r_list_purge (list);
		free (list);
	}
}

R_API boolt r_list_delete_data (RList *list, void *ptr) {
	void *p;
	RListIter *iter;
	r_list_foreach (list, iter, p) {
		if (ptr == p) {
			r_list_delete (list, iter);
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API void r_list_delete (RList *list, RListIter *iter) {
	r_list_split_iter (list, iter);
	if (list->free && iter->data)
		list->free (iter->data);
	iter->data = NULL;
	free (iter);
}

R_API void r_list_split (RList *list, void *ptr) {
	RListIter *iter = r_list_iterator (list);
	while (iter) {
		void *item = iter->data;
		if (ptr == item) {
			r_list_split_iter (list, iter);
			free (iter);
			break;
		}
		iter = iter->n;
	}
}

R_API void r_list_split_iter (RList *list, RListIter *iter) {
	if (list->head == iter) list->head = iter->n;
	if (list->tail == iter) list->tail = iter->p;
	if (iter->p) iter->p->n = iter->n;
	if (iter->n) iter->n->p = iter->p;
}

//Warning: free functions must be compatible
R_API void r_list_join (RList *list1, RList *list2) {
	if (list1->tail == NULL) {
		list1->tail = list2->head;
	} else if (list2->head != NULL) {
		list1->tail->n = list2->head;
		list2->head->p = list1->tail;
	}
}

R_API RList *r_list_new() {
	RList *list = R_NEW0(RList);
	r_list_init (list);
	return list;
}

R_API RList *r_list_newf(RListFree f) {
	RList *l = r_list_new ();
	if (l) l->free = f;
	return l;
}

R_API RListIter *r_list_item_new (void *data) {
	RListIter *new = R_NEW (RListIter);
	new->data = data;
	return new;
}

R_API RListIter *r_list_append(RList *list, void *data) {
	RListIter *new = NULL;
	if (list && data) {
		new = R_NEW (RListIter);
		if (list->tail)
			list->tail->n = new;
		new->data = data;
		new->p = list->tail;
		new->n = NULL;
		list->tail = new;
		if (list->head == NULL)
			list->head = new;
	}
	return new;
}

R_API RListIter *r_list_prepend(RList *list, void *data) {
	RListIter *new = R_NEW (RListIter);
	if (list->head)
		list->head->p = new;
	new->data = data;
	new->n = list->head;
	new->p = NULL;
	list->head = new;
	if (list->tail == NULL)
		list->tail = new;
	return new;
}

R_API void *r_list_pop(RList *list) {
	void *data = NULL;
	RListIter *iter;
	if (list->tail) {
		iter = list->tail;
		if (list->head == list->tail) {
			list->head = list->tail = NULL;
		} else {
			list->tail = iter->p;
			list->tail->n = NULL;
		}
		data = iter->data;
		free (iter);
	}
	return data;
}

R_API int r_list_del_n(RList *list, int n) {
	RListIter *it;
	int i;

	if (!list)
		return R_FALSE;
	for (it = list->head, i = 0; it && it->data; it = it->n, i++)
		if (i == n) {
			if (it->p == NULL && it->n == NULL) {
				list->head = list->tail = NULL;
			} else if (it->p == NULL) {
				it->n->p = NULL;
				list->head = it->n;
			} else if (it->n == NULL) {
				it->p->n = NULL;
				list->tail = it->p;
			} else {
				it->p->n = it->n;
				it->n->p = it->p;
			}
			free (it);
			return R_TRUE;
		}
	return R_FALSE;
}

R_API void *r_list_get_top(RList *list) {
	if (list && list->tail)
		return list->tail->data;
	return NULL;
}
R_API void *r_list_get_bottom(RList *list) {
	if (list && list->head)
		return list->head->data;
	return NULL;
}

R_API void r_list_reverse(RList *list) {
	RListIter *it, *tmp;
	if (list) {
		for (it = list->head; it && it->data; it = it->p) {
			tmp = it->p;
			it->p = it->n;
			it->n = tmp;
		}
		tmp = list->head;
		list->head = list->tail;
		list->tail = tmp;
	}
}

R_API RList *r_list_clone (RList *list) {
	RList *l = NULL;
	RListIter *iter;
	void *data;

	if (list) {
		l = r_list_new ();
		l->free = NULL;
		r_list_foreach (list, iter, data)
			r_list_append (l, data);
	}
	return l;
}

R_API void r_list_sort(RList *list, RListComparator cmp) {
	RListIter *it;
	RListIter *it2;
	for (it = list->head; it && it->data; it = it->n) {
		for (it2 = it->n; it2 && it2->data; it2 = it2->n) {
			if (cmp (it->data, it2->data)>0) {
				void *t = it->data;
				it->data = it2->data;
				it2->data = t;
			}
		}
	}
}

R_API RListIter *r_list_add_sorted(RList *list, void *data, RListComparator cmp) {
	RListIter *it, *new = NULL;
	if (list && data && cmp) {
		for (it = list->head; it && it->data && cmp (data, it->data)>0; it = it->n) ;
		if (it) {
			new = R_NEW (RListIter);
			new->n = it;
			new->p = it->p;
			new->data = data;
			new->n->p = new;
			if (new->p == NULL)
				list->head = new;
			else new->p->n = new;
		} else {
			r_list_append (list, data);
		}
		return new;
	}
	return NULL;
}

R_API int r_list_set_n(RList *list, int n, void *p) {
	RListIter *it;
	int i;
	if (list)
	for (it = list->head, i = 0; it && it->data; it = it->n, i++) {
		if (i == n) {
			it->data = p;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API void *r_list_get_n(RList *list, int n) {
	RListIter *it;
	int i;
	if (list)
		for (it = list->head, i = 0; it && it->data; it = it->n, i++)
			if (i == n)
				return it->data;
	return NULL;
}

R_API void *r_list_get_by_int(RList *list, int off, int n) {
	ut8 *p;
	RListIter *iter;
	r_list_foreach (list, iter, p) {
		if (!memcmp (&n, p+off, sizeof (int)))
			return p;
	}
	return NULL;
}

R_API void *r_list_get_by_int64(RList *list, int off, ut64 n) {
	ut8 *p;
	RListIter *iter;
	r_list_foreach (list, iter, p) {
		if (!memcmp (&n, p+off, sizeof (ut64)))
			return p;
	}
	return NULL;
}

R_API void *r_list_get_by_string(RList *list, int off, const char *str) {
	char *p;
	RListIter *iter;
	r_list_foreach (list, iter, p) {
		const char *ptr = p+off;
		if (!strcmp (str, ptr))
			return p;
	}
	return NULL;
}

R_API RListIter *r_list_contains (RList *list, void *p) {
	void *q;
	RListIter *iter;
	r_list_foreach (list, iter, q) {
		if (p == q)
			return iter;
	}
	return NULL;
}

R_API RListIter *r_list_find (RList *list, void *p, RListComparator cmp) {
	void *q;
	RListIter *iter;
	r_list_foreach (list, iter, q) {
		if (cmp (p, q) == 0)
			return iter;
	}
	return NULL;
}

#if TEST

// TODO: move into t/list.c
int main () {
	RListIter *iter, *it;
	RList *l = r_list_new ();

	r_list_append (l, "foo");
	r_list_append (l, "bar");
	r_list_append (l, "cow");
	r_list_prepend (l, "HEAD");
	r_list_prepend (l, "HEAD 00");
	it = r_list_append (l, "LAST");

	{
		char *str;
		r_list_foreach(l, iter, str) {
			printf("-- %s\n", str);
		}
		printf("--**--\n");
		r_list_foreach_prev(l, iter, str) {
			printf("-- %s\n", str);
		}
	}

	iter = r_list_iterator (l);
	while (r_list_iter_next (iter)) {
		const char *str = r_list_iter_get (iter);
		printf ("-> %s\n", str);
	}
	eprintf ("--sort--\n");
	r_list_sort (l, (RListComparator)strcmp);
	iter = r_list_iterator (l);
	while (r_list_iter_next (iter)) {
		const char *str = r_list_iter_get (iter);
		printf ("-> %s\n", str);
	}

	r_list_delete (l, it);

	char *foo = (char*) r_list_get_n (l, 2);
	printf (" - n=2 => %s\n", foo);
	iter = r_list_iterator (l);
	while (r_list_iter_next (iter)) {
		RListIter *cur = iter;
		char *str = r_list_iter_get (iter);
		if (!strcmp (str, "bar"))
			r_list_delete (l, cur);
	}

	iter = r_list_iterator (l);
	while (r_list_iter_next (iter)) {
		char *str = r_list_iter_get (iter);
		//XXX r_list_delete (l, iter);
		printf (" - %s\n", str);
	}

	r_list_free (l);

	/* ------------- */
	l = r_list_new ();
	l->free = free;

	r_list_append (l, strdup ("one"));
	r_list_append (l, strdup ("two"));
	r_list_append (l, strdup ("tri"));
	it = r_list_append (l, strdup ("LAST"));

	r_list_delete (l, it);

	{
		RListIter* i = r_list_iterator (l);
		for (; i; i = i->n) {
			char *str = i->data;
			printf (" * %s\n", str);
		}
	}

	r_list_free (l);

	l = r_list_new ();
	l->free = free;

	r_list_append (l, strdup ("one"));
	r_list_append (l, strdup ("two"));
	r_list_append (l, strdup ("tri"));

	{
		char *str;
		r_list_foreach (l, it, str)
			printf (" - %s\n", str);

		RList *list;
		list = r_list_clone (l);

		r_list_foreach (list, it, str)
			printf (" - %s\n", str);

		r_list_reverse (l);

		r_list_foreach (l, it, str)
			printf (" * %s\n", str);
	}

	r_list_free (l);
	//r_list_free (l);

	return 0;
}
#endif
