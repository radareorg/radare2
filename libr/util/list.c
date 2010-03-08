#include "r_util.h"

R_API void r_list_init(RList *list) {
	list->head = NULL;
	list->tail = NULL;
	list->free = NULL;
}

R_API void r_list_unlink (RList *list, void *ptr) {
	RListIter *iter = r_list_iterator (list);
	while (iter) {
		void *item = iter->data;
		if (ptr == item) {
			r_list_delete (list, iter);
			break;
		}
		iter = iter->n;
	}
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
	if (list->head == iter)
		list->head = iter->n;
	if (list->tail == iter)
		list->tail = iter->p;
	if (iter->p)
		iter->p->n = iter->n;
	if (iter->n)
		iter->n->p = iter->p;
}

R_API void r_list_delete (RList *list, RListIter *iter) {
	r_list_split_iter (list, iter);
	if (list->free && iter->data) {
		list->free (iter->data);
		iter->data = NULL;
	}
	free (iter);
}

R_API RList *r_list_new() {
	RList *list = MALLOC_STRUCT (RList);
	r_list_init (list);
	return list;
}

R_API void r_list_destroy (RList *list) {
	RListIter *it = list->head;
	while (it) {
		RListIter *next = it->n;
		r_list_delete (list, it);
		it = next;
	}
	list->head = list->tail = NULL;
}

R_API RListIter *r_list_item_new (void *data) {
	RListIter *new = MALLOC_STRUCT (RListIter);
	new->data = data;
	return new;
}

R_API RListIter *r_list_append(RList *list, void *data) {
	RListIter *new = NULL;
	if (data) {
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
	RListIter *new = MALLOC_STRUCT (RListIter);
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

#if TEST
int main () {
	RListIter *iter, *it;
	RList *l = r_list_new ();

	r_list_append (l, "foo");
	r_list_append (l, "bar");
	r_list_append (l, "cow");
	r_list_prepend (l, "HEAD");
	r_list_prepend (l, "HEAD 00");
	it = r_list_append (l, "LAST");

	r_list_delete (l, it);

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

	return 0;
}
#endif
