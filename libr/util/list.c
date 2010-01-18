#include "r_util.h"

R_API void r_list_init(rList *list) {
	list->head = NULL;
	list->tail = NULL;
	list->free = NULL;
}

R_API void r_list_delete (rList *list, rListIter *item) {
	if (list->head == item)
		list->head = item->next;
	if (list->tail == item)
		list->tail = item->prev;
	if (item->prev)
		item->prev->next = item->next;
	if (item->next)
		item->next->prev = item->prev;
	if (list->free && item->data) {
		list->free (item->data);
		item->data = NULL;
	}
	free (item);
}

R_API rList *r_list_new() {
	rList *list = MALLOC_STRUCT (rList);
	r_list_init (list);
	return list;
}

R_API void r_list_destroy (rList *list) {
	/* TODO: free elements */
	if (list->free) {
		rListIter *it = list->head;
		while (it) {
			rListIter *next = it->next;
			r_list_delete (list, it);
			it = next;
		}
	}
	list->head = list->tail = NULL;
	//free (list);
}

R_API rListIter *r_list_item_new (void *data) {
	rListIter *new = MALLOC_STRUCT (rListIter);
	new->data = data;
	return new;
}

R_API rListIter *r_list_append(rList *list, void *data) {
	rListIter *new = MALLOC_STRUCT (rListIter);
	if (list->tail)
		list->tail->next = new;
	new->data = data;
	new->prev = list->tail;
	new->next = NULL;
	list->tail = new;
	if (list->head == NULL)
		list->head = new;
	return new;
}

R_API rListIter *r_list_prepend(rList *list, void *data) {
	rListIter *new = MALLOC_STRUCT (rListIter);
	if (list->head)
		list->head->prev = new;
	new->data = data;
	new->next = list->head;
	new->prev = NULL;
	list->head = new;
	if (list->tail == NULL)
		list->tail = new;
	return new;
}

#if TEST
int main () {
	rListIter *iter, *it;
	rList *l = r_list_new ();

	r_list_append (l, "foo");
	r_list_append (l, "bar");
	r_list_append (l, "cow");
	r_list_prepend (l, "HEAD");
	r_list_prepend (l, "HEAD 00");
	it = r_list_append (l, "LAST");

	r_list_delete (l, it);

	iter = r_list_iterator (l);
	while (r_list_iter_next (iter)) {
		rListIter *cur = iter;
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

	r_list_destroy (l);
	r_list_free (l);

	/* ------------- */
	l = r_list_new ();

	r_list_append (l, strdup ("one"));
	r_list_append (l, strdup ("two"));
	r_list_append (l, strdup ("tri"));
	it = r_list_append (l, strdup ("LAST"));

	r_list_delete (l, it);

	{
		rListIter* i = r_list_iterator (l);
		for (; i; i = i->next) {
			char *str = i->data;
			printf (" * %s\n", str);
		}
	}

	l->free = free;
	r_list_destroy (l);

	return 0;
}
#endif
