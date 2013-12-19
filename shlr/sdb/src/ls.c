/* sdb - LGPLv3 - Copyright 2007-2013 - pancake */

#include <string.h>
#include "ls.h"

R_API SdbList *ls_new() {
	SdbList *list = R_NEW (SdbList);
	list->head = NULL;
	list->tail = NULL;
	list->free = free; // HACK
	list->length = 0;
	return list;
}

R_API void ls_delete (SdbList *list, SdbListIter *iter) {
	if (iter==NULL) {
		printf ("ls_delete: null iter?\n");
		return;
	}
	ls_split_iter (list, iter);
	if (list->free && iter->data) {
		list->free (iter->data);
		iter->data = NULL;
	}
	free (iter);
	list->length--;
}

R_API void ls_split_iter (SdbList *list, SdbListIter *iter) {
	if (list->head == iter) list->head = iter->n;
	if (list->tail == iter) list->tail = iter->p;
	if (iter->p) iter->p->n = iter->n;
	if (iter->n) iter->n->p = iter->p;
}

R_API void ls_destroy (SdbList *list) {
	SdbListIter *it;
	if (list) {
		it = list->head;
		while (it) {
			SdbListIter *next = it->n;
			ls_delete (list, it);
			it = next;
		//	free (it);
		}
		list->head = list->tail = NULL;
		list->length = 0;
	}
	//free (list);
}

R_API void ls_free (SdbList *list) {
	if (!list) return;
	list->free = NULL;
	ls_destroy (list);
	free (list);
}

// XXX: Too slow?
R_API SdbListIter *ls_append(SdbList *list, void *data) {
	SdbListIter *it = R_NEW (SdbListIter);
	if (list->tail)
		list->tail->n = it;
	it->data = data;
	it->p = list->tail;
	it->n = NULL;
	list->tail = it;
	if (list->head == NULL)
		list->head = it;
	list->length++;
	return it;
}

R_API SdbListIter *ls_prepend(SdbList *list, void *data) {
	SdbListIter *new = R_NEW (SdbListIter);
	if (list->head)
		list->head->p = new;
	new->data = data;
	new->n = list->head;
	new->p = NULL;
	list->head = new;
	if (list->tail == NULL)
		list->tail = new;
	list->length++;
	return new;
}
