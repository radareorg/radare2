/* sdb - MIT - Copyright 2007-2016 - pancake, alvaro */

#include <string.h>
#include "ls.h"

#define LS_MERGE_DEPTH 50

SDB_API SdbList *ls_newf(SdbListFree freefn) {
	SdbList *list = ls_new ();
	if (list) {
		list->free = freefn;
	}
	return list;
}

SDB_API SdbList *ls_new() {
	SdbList *list = R_NEW0 (SdbList);
	if (!list) {
		return NULL;
	}
	return list;
}

static void ls_insertion_sort(SdbList *list, SdbListComparator cmp) {
	SdbListIter *it, *it2;
	for (it = list->head; it && it->data; it = it->n) {
		for (it2 = it->n; it2 && it2->data; it2 = it2->n) {
			if (cmp (it->data, it2->data) > 0) {
				void *t = it->data;
				it->data = it2->data;
				it2->data = t;
			}
		}
	}
}

static SdbListIter *_merge(SdbListIter *first, SdbListIter *second, SdbListComparator cmp) {
	if (!first) { 
		return second;
	}
	if (!second) {
		return first;
	}
	if (cmp (first->data, second->data) > 0) {
		second->n = _merge (first, second->n, cmp);
		second->n->p = second;
		second->p = NULL;
		return second;
	} 
	first->n = _merge (first->n, second, cmp);
	first->n->p = first;
	first->p = NULL;
	return first;
}

static SdbListIter * _sdb_list_split(SdbListIter *head) {
	SdbListIter *tmp;
	SdbListIter *fast;
	SdbListIter *slow;
	if (!head || !head->n) {
		return head;
	} 
	slow = head;
	fast = head;
	while (fast && fast->n && fast->n->n) {
		fast = fast->n->n;
		slow = slow->n;
	}
	tmp = slow->n;
	slow->n = NULL;
	return tmp;
}

static SdbListIter * _merge_sort(SdbListIter *head, SdbListComparator cmp, int depth) {
	SdbListIter *second;
	if (!head || !head->n) {
		return head;
	}
	if (depth == LS_MERGE_DEPTH) {
		SdbListIter *it, *it2;
		for (it = head; it && it->data; it = it->n) {
			for (it2 = it->n; it2 && it2->data; it2 = it2->n) {
				if (cmp (it->data, it2->data) > 0) {
					void *t = it->data;
					it->data = it2->data;
					it2->data = t;
				}
			}
		}
		return head;
	}
	second = _sdb_list_split (head);
	head = _merge_sort (head, cmp, depth++);
	second = _merge_sort (second, cmp, depth++);
	return _merge (head, second, cmp);
}

static void ls_merge_sort(SdbList *list, SdbListComparator cmp) {
	if (list && list->head && cmp) {
		SdbListIter *iter;
		list->head = _merge_sort (list->head, cmp, 0);
		//update tail reference
		iter = list->head;
		while (iter && iter->n) {
			iter = iter->n;
		}
		list->tail = iter;
	}
}

SDB_API bool ls_sort(SdbList *list, SdbListComparator cmp) {
	if (!cmp || list->sorted == cmp) {
		return false;
	}
	if (list->length > 43) {
		ls_merge_sort (list, cmp);
	} else {
		ls_insertion_sort (list, cmp);
	}
	list->sorted = cmp;
	return true;
}

SDB_API void ls_delete(SdbList *list, SdbListIter *iter) {
	if (!list || !iter) {
		return;
	}
	ls_split_iter (list, iter);
	if (list->free && iter->data) {
		list->free (iter->data);
		iter->data = NULL;
	}
	free (iter);
}

SDB_API bool ls_delete_data(SdbList *list, void *ptr) {
	void *kvp;
	SdbListIter *iter;
	ls_foreach (list, iter, kvp) {
		if (ptr == kvp) {
			ls_delete (list, iter);
			return true;
		}
	}
	return false;
}

SDB_API void ls_split_iter(SdbList *list, SdbListIter *iter) {
	if (!list || !iter) {
		return;
	}
	if (list->head == iter) {
		list->head = iter->n;
	}
	if (list->tail == iter) {
		list->tail = iter->p;
	}
	if (iter->p) {
		iter->p->n = iter->n;
	}
	if (iter->n) {
		iter->n->p = iter->p;
	}
	list->length--;
}

SDB_API void ls_destroy(SdbList *list) {
	SdbListIter *it;
	if (!list) {
		return;
	}
	it = list->head;
	while (it) {
		SdbListIter *next = it->n;
		ls_delete (list, it);
		it = next;
	}
	list->head = list->tail = NULL;
	list->length = 0;
}

SDB_API void ls_free(SdbList *list) {
	if (!list) {
		return;
	}
	ls_destroy (list);
	list->free = NULL;
	free (list);
}

SDB_API SdbListIter *ls_append(SdbList *list, void *data) {
	SdbListIter *it;
	if (!list) {
		return NULL;
	}
	it = R_NEW (SdbListIter);
	if (!it) {
		return NULL;
	}	
	if (list->tail) {
		list->tail->n = it;
	}
	it->data = data;
	it->p = list->tail;
	it->n = NULL;
	list->tail = it;
	if (!list->head) {
		list->head = it;
	}
	list->length++;
	list->sorted = NULL;
	return it;
}

SDB_API SdbListIter *ls_prepend(SdbList *list, void *data) {
	SdbListIter *it = R_NEW (SdbListIter);
	if (!it) {
		return NULL;
	}
	if (list->head) {
		list->head->p = it;
	}
	it->data = data;
	it->n = list->head;
	it->p = NULL;
	list->head = it;
	if (!list->tail) {
		list->tail = it;
	}
	list->length++;
	list->sorted = NULL;
	return it;
}

SDB_API void *ls_pop(SdbList *list) {
	void *data = NULL;
	SdbListIter *iter;
	if (list) {
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
			list->length--;
		}
		list->sorted = NULL;
		return data;
	}
	return NULL;
}
