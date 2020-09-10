/* radare - LGPL - Copyright 2007-2019 - pancake, alvarofe */
// TODO: RRef - reference counting

#include <stdio.h>

#define _R_LIST_C_
#include "r_util.h"

inline RListIter *r_list_iter_new(void) {
	return calloc (1, sizeof (RListIter));
}

R_API void r_list_iter_free(RListIter *list) {
	/* do nothing? */
}

R_API RListIter *r_list_iter_get_next(RListIter *list) {
	r_return_val_if_fail (list, NULL);
	return list->n;
}

R_API void *r_list_iter_get_data(RListIter *list) {
	r_return_val_if_fail (list, NULL);
	return list->data;
}

R_API RListIter *r_list_iterator(const RList *list) {
	r_return_val_if_fail (list, NULL);
	return list->head;
}

R_API RListIter *r_list_push(RList *list, void *item) {
	return r_list_append (list, item);
}

R_API RListIter *r_list_get_next(RListIter *list) {
	r_return_val_if_fail (list, NULL);
	return list->n;
}

//  rename to head/last
R_API void *r_list_first(const RList *list) {
	r_return_val_if_fail (list, NULL);
	return list->head ? list->head->data : NULL;
}

R_API void *r_list_last(const RList *list) {
	r_return_val_if_fail (list, NULL);
	return list->tail ? list->tail->data : NULL;
}

R_API void r_list_init(RList *list) {
	list->head = NULL;
	list->tail = NULL;
	list->free = NULL;
	list->length = 0;
	list->sorted = false;
}

R_API int r_list_length(const RList *list) {
	r_return_val_if_fail (list, 0);
	return list->length;
}

/* remove all elements of a list */
R_API void r_list_purge(RList *list) {
	r_return_if_fail (list);

	RListIter *it = list->head;
	while (it) {
		RListIter *next = it->n;
		r_list_delete (list, it);
		it = next;
	}
	list->length = 0;
	list->head = list->tail = NULL;
}

/* free the list */
R_API void r_list_free(RList *list) {
	if (list) {
		r_list_purge (list);
		free (list);
	}
}

R_API bool r_list_delete_data(RList *list, void *ptr) {
	void *p;
	RListIter *iter;

	r_return_val_if_fail (list, false);

	r_list_foreach (list, iter, p) {
		if (ptr == p) {
			r_list_delete (list, iter);
			return true;
		}
	}
	return false;
}

R_API void r_list_delete(RList *list, RListIter *iter) {
	r_return_if_fail (list && iter);
	r_list_split_iter (list, iter);
	if (list->free && iter->data) {
		list->free (iter->data);
	}
	iter->data = NULL;
	free (iter);
}

R_API void r_list_split(RList *list, void *ptr) {
	r_return_if_fail (list);

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

R_API void r_list_split_iter(RList *list, RListIter *iter) {
	r_return_if_fail (list);

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

//Warning: free functions must be compatible
R_API int r_list_join(RList *list1, RList *list2) {
	r_return_val_if_fail (list1 && list2, 0);

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
		list1->sorted = false;
	}
	list1->length += list2->length;
	list2->length = 0;
	list2->head = list2->tail = NULL;
	return 1;
}

R_API RList *r_list_new(void) {
	RList *list = R_NEW0 (RList);
	if (!list) {
		return NULL;
	}
	r_list_init (list);
	return list;
}

R_API RList *r_list_newf(RListFree f) {
	RList *l = r_list_new ();
	if (l) {
		l->free = f;
	}
	return l;
}

R_API RListIter *r_list_item_new(void *data) {
	RListIter *item = R_NEW0 (RListIter);
	if (item) {
		item->data = data;
	}
	return item;
}

R_API RListIter *r_list_append(RList *list, void *data) {
	RListIter *item = NULL;

	r_return_val_if_fail (list, NULL);

	item = R_NEW (RListIter);
	if (!item) {
		return item;
	}
	if (list->tail) {
		list->tail->n = item;
	}
	item->data = data;
	item->p = list->tail;
	item->n = NULL;
	list->tail = item;
	if (!list->head) {
		list->head = item;
	}
	list->length++;
	list->sorted = false;
	return item;
}

R_API RListIter *r_list_prepend(RList *list, void *data) {
	r_return_val_if_fail (list, NULL);

	RListIter *item = R_NEW0 (RListIter);
	if (!item) {
		return NULL;
	}
	if (list->head) {
		list->head->p = item;
	}
	item->data = data;
	item->n = list->head;
	item->p = NULL;
	list->head = item;
	if (!list->tail) {
		list->tail = item;
	}
	list->length++;
	list->sorted = true;
	return item;
}

R_API RListIter *r_list_insert(RList *list, int n, void *data) {
	RListIter *it, *item;
	int i;

	r_return_val_if_fail (list, NULL);

	if (!list->head || !n) {
		return r_list_prepend (list, data);
	}
	for (it = list->head, i = 0; it && it->data; it = it->n, i++) {
		if (i == n) {
			item = R_NEW (RListIter);
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
			list->sorted = true;
			return item;
		}
	}
	return r_list_append (list, data);
}

R_API void *r_list_pop(RList *list) {
	void *data = NULL;
	RListIter *iter;

	r_return_val_if_fail (list, NULL);

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
	list->length--;
	return data;
}

R_API void *r_list_pop_head(RList *list) {
	void *data = NULL;

	r_return_val_if_fail (list, NULL);

	if (list->head) {
		RListIter *iter = list->head;
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

R_API int r_list_del_n(RList *list, int n) {
	RListIter *it;
	int i;

	r_return_val_if_fail (list, false);

	for (it = list->head, i = 0; it && it->data; it = it->n, i++) {
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
	}
	return false;
}

R_API void *r_list_get_top(const RList *list) {
	r_return_val_if_fail (list, NULL);

	return list->tail ? list->tail->data : NULL;
}

R_API void *r_list_get_bottom(const RList *list) {
	r_return_val_if_fail (list, NULL);

	return list->head ? list->head->data : NULL;
}

R_API void r_list_reverse(RList *list) {
	RListIter *it, *tmp;

	r_return_if_fail (list);

	for (it = list->head; it && it->data; it = it->p) {
		tmp = it->p;
		it->p = it->n;
		it->n = tmp;
	}
	tmp = list->head;
	list->head = list->tail;
	list->tail = tmp;
}

R_API RList *r_list_clone(const RList *list) {
	RListIter *iter;
	void *data;

	r_return_val_if_fail (list, NULL);

	RList *l = r_list_new ();
	if (!l) {
		return NULL;
	}
	l->free = NULL;
	r_list_foreach (list, iter, data) {
		r_list_append (l, data);
	}
	l->sorted = list->sorted;
	return l;
}

R_API RListIter *r_list_add_sorted(RList *list, void *data, RListComparator cmp) {
	RListIter *it, *item = NULL;

	r_return_val_if_fail (list && data && cmp, NULL);

	for (it = list->head; it && it->data && cmp (data, it->data) > 0; it = it->n) {
		;
	}
	if (it) {
		item = R_NEW0 (RListIter);
		if (!item) {
			return NULL;
		}
		item->n = it;
		item->p = it->p;
		item->data = data;
		item->n->p = item;
		if (!item->p) {
			list->head = item;
		} else {
			item->p->n = item;
		}
		list->length++;
	} else {
		r_list_append (list, data);
	}
	list->sorted = true;
	return item;
}

R_API int r_list_set_n(RList *list, int n, void *p) {
	RListIter *it;
	int i;

	r_return_val_if_fail (list, false);
	for (it = list->head, i = 0; it ; it = it->n, i++) {
		if (i == n) {
			if (list->free) {
				list->free (it->data);
			}
			it->data = p;
			list->sorted = false;
			return true;
		}
	}
	return false;
}

R_API void *r_list_get_n(const RList *list, int n) {
	RListIter *it;
	int i;

	r_return_val_if_fail (list, NULL);

	for (it = list->head, i = 0; it && it->data; it = it->n, i++) {
		if (i == n) {
			return it->data;
		}
	}
	return NULL;
}

R_API RListIter *r_list_contains(const RList *list, const void *p) {
	void *q;
	RListIter *iter;

	r_return_val_if_fail (list, NULL);

	r_list_foreach (list, iter, q) {
		if (p == q) {
			return iter;
		}
	}
	return NULL;
}

R_API RListIter *r_list_find(const RList *list, const void *p, RListComparator cmp) {
	void *q;
	RListIter *iter;

	r_return_val_if_fail (list, NULL);

	r_list_foreach (list, iter, q) {
		if (!cmp (p, q)) {
			return iter;
		}
	}
	return NULL;
}

static RListIter *_merge(RListIter *first, RListIter *second, RListComparator cmp) {
	RListIter *next = NULL, *result = NULL, *head = NULL;
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

static RListIter * _r_list_half_split(RListIter *head) {
	RListIter *tmp;
	RListIter *fast;
	RListIter *slow;
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

static RListIter * _merge_sort(RListIter *head, RListComparator cmp) {
	RListIter *second;
	if (!head || !head->n) {
		return head;
	}
	second = _r_list_half_split (head);
	head = _merge_sort (head, cmp);
	second = _merge_sort (second, cmp);
	return _merge (head, second, cmp);
}

R_API void r_list_merge_sort(RList *list, RListComparator cmp) {
	r_return_if_fail (list);

	if (!list->sorted && list->head && cmp) {
		RListIter *iter;
		list->head = _merge_sort (list->head, cmp);
		//update tail reference
		iter = list->head;
		while (iter && iter->n) {
			iter = iter->n;
		}
		list->tail = iter;
	}
	list->sorted = true;
}

R_API void r_list_insertion_sort(RList *list, RListComparator cmp) {
	r_return_if_fail (list);

	if (!list->sorted) {
		RListIter *it;
		RListIter *it2;
		if (cmp) {
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
		list->sorted = true;
	}
}

//chose wisely based on length
R_API void r_list_sort(RList *list, RListComparator cmp) {
	r_return_if_fail (list);
	if (list->length > 43) {
		r_list_merge_sort (list, cmp);
	} else {
		r_list_insertion_sort (list, cmp);
	}
}

R_API RList *r_list_uniq(const RList *list, RListComparator cmp) {
	RListIter *iter, *iter2;
	void *item, *item2;

	r_return_val_if_fail (list && cmp, NULL);

	RList *nl = r_list_newf (NULL);
	if (!nl) {
		return NULL;
	}
	r_list_foreach (list, iter, item) {
		bool found = false;
		r_list_foreach (nl, iter2, item2) {
			if (cmp (item, item2) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			r_list_append (nl, item);
		}
	}
	return nl;
}
R_API char *r_list_to_str(RList *list, char ch) {
	RListIter *iter;
	RStrBuf *buf = r_strbuf_new ("");
	if (!buf) {
		return NULL;
	}
	char *item;
	r_list_foreach (list, iter, item) {
		r_strbuf_appendf (buf, "%s%c", item, ch);
	}
	return r_strbuf_drain (buf);
}
