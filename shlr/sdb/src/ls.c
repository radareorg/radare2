/* sdb - LGPLv3 - Copyright 2007-2014 - pancake */

#include <string.h>
#include "ls.h"

SDB_API SdbList *ls_new() {
	SdbList *list = R_NEW (SdbList);
	if (!list)
		return NULL;
	list->head = NULL;
	list->tail = NULL;
	list->free = free; // HACK
	list->length = 0;
	return list;
}

SDB_API void ls_delete (SdbList *list, SdbListIter *iter) {
	if (!list || !iter) return;
	ls_split_iter (list, iter);
	if (list->free && iter->data) {
		list->free (iter->data);
		iter->data = NULL;
	}
	free (iter);
	list->length--;
}

SDB_API void ls_split_iter (SdbList *list, SdbListIter *iter) {
	if (!list || !iter) return;
	if (list->head == iter) list->head = iter->n;
	if (list->tail == iter) list->tail = iter->p;
	if (iter->p) iter->p->n = iter->n;
	if (iter->n) iter->n->p = iter->p;
}

SDB_API void ls_destroy (SdbList *list) {
	SdbListIter *it;
	if (!list) return;
	it = list->head;
	while (it) {
		SdbListIter *next = it->n;
		ls_delete (list, it);
		it = next;
	}
	list->head = list->tail = NULL;
	list->length = 0;
}

SDB_API void ls_free (SdbList *list) {
	if (!list) return;
	ls_destroy (list);
	list->free = NULL;
	free (list);
}

SDB_API SdbListIter *ls_append(SdbList *list, void *data) {
	SdbListIter *it;
	if (!list)
		return NULL;
	it = R_NEW (SdbListIter);
	if (!it)
		return NULL;
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

SDB_API SdbListIter *ls_prepend(SdbList *list, void *data) {
	SdbListIter *it = R_NEW (SdbListIter);
	if (!it) return NULL;
	if (list->head)
		list->head->p = it;
	it->data = data;
	it->n = list->head;
	it->p = NULL;
	list->head = it;
	if (list->tail == NULL)
		list->tail = it;
	list->length++;
	return it;
}
