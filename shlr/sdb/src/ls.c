/* sdb - MIT - Copyright 2007-2017 - pancake, alvaro */

#include <string.h>
#include "ls.h"

SDB_API SdbList *ls_newf(SdbListFree freefn) {
	SdbList *list = ls_new ();
	if (list) {
		list->free = freefn;
	}
	return list;
}

SDB_API SdbList *ls_new(void) {
	SdbList *list = R_NEW0 (SdbList);
	if (!list) {
		return NULL;
	}
	return list;
}

static void ls_insertion_sort_iter(SdbListIter *iter, SdbListComparator cmp) {
	SdbListIter *it, *it2;
	for (it = iter; it && it->data; it = it->n) {
		for (it2 = it->n; it2 && it2->data; it2 = it2->n) {
			if (cmp (it->data, it2->data) > 0) {
				void *t = it->data;
				it->data = it2->data;
				it2->data = t;
			}
		}
	}
}

static void ls_insertion_sort(SdbList *list, SdbListComparator cmp) {
	ls_insertion_sort_iter (list->head, cmp);
}

static SdbListIter *_merge(SdbListIter *first, SdbListIter *second, SdbListComparator cmp) {
	SdbListIter *next = NULL, *result = NULL, *head = NULL;
	while (first || second) {
		if (!second) {
			next = first;
			first = first->n;
		} else if (!first) {
			next = second;
			second = second->n;
		} else if (cmp (first->data, second->data) <= 0) {
			next = first;
			first = first->n;
		} else {
			next = second;
			second = second->n;
		}
		if (!head) {
			result = next;
			head = result;
			head->p = NULL;
		} else {
			result->n = next;
			next->p = result;
			result = result->n;
		}
	}
	head->p = NULL;
	next->n = NULL;
	return head;
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

static SdbListIter * _merge_sort(SdbListIter *head, SdbListComparator cmp) {
	SdbListIter *second;
	if (!head || !head->n) {
		return head;
	}
	second = _sdb_list_split (head);
	head = _merge_sort (head, cmp);
	second = _merge_sort (second, cmp);
	return _merge (head, second, cmp);
}

SDB_API bool ls_merge_sort(SdbList *list, SdbListComparator cmp) {
	if (!cmp) {
		return false;
	}
	if (list && list->head && cmp) {
		SdbListIter *iter;
		list->head = _merge_sort (list->head, cmp);
		//update tail reference
		iter = list->head;
		while (iter && iter->n) {
			iter = iter->n;
		}
		list->tail = iter;
		list->sorted = true;
	}
	return true;
}

SDB_API bool ls_sort(SdbList *list, SdbListComparator cmp) {
	if (!cmp || list->cmp == cmp) {
		return false;
	}
	if (list->length > 43) {
		ls_merge_sort (list, cmp);
	} else {
		ls_insertion_sort (list, cmp);
	}
	list->cmp = cmp;
	list->sorted = true;
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
	list->sorted = false;
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
	list->sorted = false;
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
		return data;
	}
	return NULL;
}

SDB_API SdbList *ls_clone(SdbList *list) {
	if (!list) {
		return NULL;
	}
	SdbList *r = ls_new (); // ownership of elements stays in original list
	if (!r) {
		return NULL;
	}
	void *v;
	SdbListIter *iter;
	ls_foreach (list, iter, v) {
		ls_append (r, v);
	}
	return r;
}

SDB_API int ls_join(SdbList *list1, SdbList *list2) {
	if (!list1 || !list2) {
		return 0;
	}
	if (!(list2->length)) {
		return 0;
	}
	if (!(list1->length)) {
		list1->head = list2->head;
		list1->tail = list2->tail;
	} else {
		list1->tail->n = list2->head;
		list2->head->p = list1->tail;
		list1->tail = list2->tail;
		list1->tail->n = NULL;
	}
	list1->length += list2->length;
	list2->head = list2->tail = NULL;
	list1->sorted = false;
	return 1;
}


SDB_API SdbListIter *ls_insert(SdbList *list, int n, void *data) {
	SdbListIter *it, *item;
	int i;
	if (list) {
		if (!list->head || !n) {
			return ls_prepend (list, data);
		}
		for (it = list->head, i = 0; it && it->data; it = it->n, i++) {
			if (i == n) {
				item = R_NEW0 (SdbListIter);
				if (!item) {
					return NULL;
				}
				item->data = data;
				item->n = it;
				item->p = it->p;
				if (it->p) {
					it->p->n = item;
				}
				it->p = item;
				list->length++;
				list->sorted = false;
				return item;
			}
		}
	}
	return ls_append (list, data);
}


SDB_API void *ls_pop_head(SdbList *list) {
	void *data = NULL;
	SdbListIter *iter;
	if (list) {
		if (list->head) {
			iter = list->head;
			if (list->head == list->tail) {
				list->head = list->tail = NULL;
			} else {
				list->head = iter->n;
				list->head->p = NULL;
			}
			data = iter->data;
			free (iter);
		}
		list->length--;
		return data;
	}
	return NULL;
}


SDB_API int ls_del_n(SdbList *list, int n) {
	SdbListIter *it;
	int i;
	if (!list) {
		return false;
	}
	for (it = list->head, i = 0; it && it->data; it = it->n, i++)
		if (i == n) {
			if (!it->p && !it->n) {
				list->head = list->tail = NULL;
			} else if (!it->p) {
				it->n->p = NULL;
				list->head = it->n;
			} else if (!it->n) {
				it->p->n = NULL;
				list->tail = it->p;
			} else {
				it->p->n = it->n;
				it->n->p = it->p;
			}
			free (it);
			list->length--;
			return true;
		}
	return false;
}
