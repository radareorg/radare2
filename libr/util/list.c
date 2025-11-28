/* radare - LGPL - Copyright 2007-2025 - pancake, alvarofe */

#define _R_LIST_C_
#include "r_util.h"
#include <sdb/set.h>

#define MERGE_LIMIT 24

R_API size_t r_list_iter_length(RListIter *iter) {
	size_t count = 0;
	while (iter->n) {
		count++;
		iter = iter->n;
	}
	return count;
}

inline RListIter *r_list_iter_new(void) {
	return calloc (1, sizeof (RListIter));
}

R_API void r_list_iter_free(RListIter *list) {
	/* do nothing? */
}

R_API RListIter *r_list_iter_get_next(RListIter *list) {
	R_RETURN_VAL_IF_FAIL (list, NULL);
	return list->n;
}

R_API RListIter *r_list_iter_get_prev(RListIter *list) {
	R_RETURN_VAL_IF_FAIL (list, NULL);
	return list->p;
}

R_API void *r_list_iter_get_data(RListIter *list) {
	R_RETURN_VAL_IF_FAIL (list, NULL);
	return list->data;
}

R_API RListIter *r_list_iterator(const RList *list) {
	R_RETURN_VAL_IF_FAIL (list, NULL);
	return list->head;
}

R_API RListIter *r_list_push(RList *list, void *item) {
	return r_list_append (list, item);
}

R_API RListIter *r_list_get_next(RListIter *list) {
	R_RETURN_VAL_IF_FAIL (list, NULL);
	return list->n;
}

//  rename to head/last
R_API void *r_list_first(const RList *list) {
	R_RETURN_VAL_IF_FAIL (list, NULL);
	return list->head ? list->head->data : NULL;
}

R_API void *r_list_last(const RList *list) {
	R_RETURN_VAL_IF_FAIL (list, NULL);
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
	R_RETURN_VAL_IF_FAIL (list, 0);
	return list->length;
}

/* remove all elements of a list */
R_API void r_list_purge(RList *list) {
	if (!list) {
		return;
	}
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

	R_RETURN_VAL_IF_FAIL (list, false);

	r_list_foreach (list, iter, p) {
		if (ptr == p) {
			r_list_delete (list, iter);
			return true;
		}
	}
	return false;
}

R_API void r_list_delete(RList *list, RListIter *iter) {
	R_RETURN_IF_FAIL (list && iter);
	r_list_split_iter (list, iter);
	if (list->free && iter->data) {
		list->free (iter->data);
	}
	iter->data = NULL;
	free (iter);
}

R_API void r_list_split(RList *list, void *ptr) {
	R_RETURN_IF_FAIL (list);

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
	R_RETURN_IF_FAIL (list);

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
	R_RETURN_VAL_IF_FAIL (list1 && list2, 0);

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

R_API RList * R_NONNULL r_list_new(void) {
	RList *list = R_NEW0 (RList);
	r_list_init (list);
	return list;
}

R_API RList * R_NONNULL r_list_newf(RListFree f) {
	RList *l = r_list_new ();
	if (l) {
		l->free = f;
	}
	return l;
}

R_API RListIter * R_NONNULL r_list_item_new(void *data) {
	RListIter *item = R_NEW0 (RListIter);
	item->data = data;
	return item;
}

R_API RListIter * R_NONNULL r_list_append(RList *list, void *data) {
	R_RETURN_VAL_IF_FAIL (list, NULL);

	RListIter *item = r_list_item_new (data);
	if (list->tail) {
		list->tail->n = item;
	}
	item->p = list->tail;
	list->tail = item;
	if (!list->head) {
		list->head = item;
	}
	list->length++;
	list->sorted = false;
	return item;
}

R_API RListIter *r_list_prepend(RList *list, void *data) {
	R_RETURN_VAL_IF_FAIL (list, NULL);

	RListIter *item = r_list_item_new (data);
	if (!item) {
		return NULL;
	}
	if (list->head) {
		list->head->p = item;
	}
	item->n = list->head;
	list->head = item;
	if (!list->tail) {
		list->tail = item;
	}
	list->length++;
	list->sorted = false;
	return item;
}

R_API RListIter *r_list_insert(RList *list, ut32 n, void *data) {
	R_RETURN_VAL_IF_FAIL (list, NULL);

	if (!list->head || !n) {
		return r_list_prepend (list, data);
	}

	RListIter *it;
	ut32 i;
	for (it = list->head, i = 0; it && it->data; it = it->n, i++) {
		if (i == n) {
			RListIter *item = r_list_item_new (data);
			if (!item) {
				return NULL;
			}
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
	return r_list_append (list, data);
}

R_API void *r_list_pop(RList *list) {
	void *data = NULL;
	RListIter *iter;

	R_RETURN_VAL_IF_FAIL (list, NULL);

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

R_API void *r_list_pop_head(RList *list) {
	void *data = NULL;

	R_RETURN_VAL_IF_FAIL (list, NULL);

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
		list->length--;
	}
	return data;
}

R_API int r_list_del_n(RList *list, int n) {
	RListIter *it;
	int i;

	R_RETURN_VAL_IF_FAIL (list, false);

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

// Moves an iter to the top(tail) of the list
// There is an underlying assumption here, that iter is an RListIter of this RList
R_API void r_list_iter_to_top(RList *list, RListIter *iter) {
	R_RETURN_IF_FAIL (list && iter);
	if (list->tail == iter) {
		return;
	}
	iter->n->p = iter->p;
	if (list->head == iter) {
		list->head = iter->n;
	} else {
		iter->p->n = iter->n;
	}
	iter->p = list->tail;
	list->tail->n = iter;
	iter->n = NULL;
	list->tail = iter;
	list->sorted = false;
}

R_API void r_list_reverse(RList *list) {
	RListIter *it, *tmp;

	R_RETURN_IF_FAIL (list);

	for (it = list->head; it && it->data; it = it->p) {
		tmp = it->p;
		it->p = it->n;
		it->n = tmp;
	}
	tmp = list->head;
	list->head = list->tail;
	list->tail = tmp;
}

R_API RList *r_list_clone(const RList *list, RListClone clone) {
	R_RETURN_VAL_IF_FAIL (list, NULL);

	RListIter *iter;
	void *data;

	RList *l = r_list_new ();
	if (clone) {
		l->free = list->free;
		r_list_foreach (list, iter, data) {
			r_list_append (l, clone (data));
		}
	} else {
		l->free = NULL;
		r_list_foreach (list, iter, data) {
			r_list_append (l, data);
		}
	}
	l->sorted = list->sorted;
	return l;
}

R_API RListIter *r_list_add_sorted(RList *list, void *data, RListComparator cmp) {
	R_RETURN_VAL_IF_FAIL (list && data && cmp, NULL);
	RListIter *it;
	RListIter *item = NULL;

	for (it = list->head; it && it->data && cmp (data, it->data) > 0; it = it->n) {
		;
	}
	if (it) {
		item = R_NEW0 (RListIter);
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
	R_RETURN_VAL_IF_FAIL (list, false);
	RListIter *it;
	int i;

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

R_API RListIter *r_list_get_nth(const RList *list, int n) {
	R_RETURN_VAL_IF_FAIL (list, NULL);
	RListIter *it;
	int i;
	for (it = list->head, i = 0; it && it->data; it = it->n, i++) {
		if (i == n) {
			return it;
		}
	}
	return NULL;
}

R_API void *r_list_get_n(const RList *list, int n) {
	RListIter *it = r_list_get_nth (list, n);
	return it? it->data: NULL;
}

R_API RListIter *r_list_contains(const RList *list, const void *p) {
	R_RETURN_VAL_IF_FAIL (list, NULL);

	void *q;
	RListIter *iter;
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

	R_RETURN_VAL_IF_FAIL (list, NULL);

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
	if (head) {
		head->p = NULL;
	}
	if (next) {
		next->n = NULL;
	}
	return head;
}

static RListIter *_merge_with_user(RListIter *first, RListIter *second, RListComparatorWithUser cmp, void *user) {
	RListIter *next = NULL, *result = NULL, *head = NULL;
	while (first || second) {
		if (!second) {
			next = first;
			first = first->n;
		} else if (!first) {
			next = second;
			second = second->n;
		} else if (cmp (first->data, second->data, user) <= 0) {
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
	if (head) {
		head->p = NULL;
	}
	if (next) {
		next->n = NULL;
	}
	return head;
}

static RListIter *_r_list_half_split(RListIter *head) {
	RListIter *tmp;
	RListIter *fast;
	RListIter *slow;
	if (!head || !head->n) {
		return head;
	}
	slow = head;
	fast = head;
	int count = 0;
	while (fast && fast->n && fast->n->n) {
		fast = fast->n->n;
		slow = slow->n;
		count++;
	}
	if (count < MERGE_LIMIT) {
		return NULL;
	}
	tmp = slow->n;
	slow->n = NULL;
	return tmp;
}

static void list_insertion_sort_iter(RListIter *iter, RListComparator cmp) {
	RListIter *it, *it2;
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

static void list_insertion_sort_iter_with_user(RListIter *iter, RListComparatorWithUser cmp, void *user) {
	RListIter *it, *it2;
	for (it = iter; it && it->data; it = it->n) {
		for (it2 = it->n; it2 && it2->data; it2 = it2->n) {
			if (cmp (it->data, it2->data, user) > 0) {
				void *t = it->data;
				it->data = it2->data;
				it2->data = t;
			}
		}
	}
}

static RListIter *_merge_sort(RListIter *head, RListComparator cmp) {
	RListIter *second;
	if (!head || !head->n) {
		return head;
	}
	second = _r_list_half_split (head);
	if (second) {
		head = _merge_sort (head, cmp);
		second = _merge_sort (second, cmp);
		return _merge (head, second, cmp);
	}
	list_insertion_sort_iter (head, cmp);
	return head;
}

static RListIter *_merge_sort_with_user(RListIter *head, RListComparatorWithUser cmp, void *user) {
	RListIter *second;
	if (!head || !head->n) {
		return head;
	}
	second = _r_list_half_split (head);
	if (second) {
		head = _merge_sort_with_user (head, cmp, user);
		second = _merge_sort_with_user (second, cmp, user);
		return _merge_with_user (head, second, cmp, user);
	}
	list_insertion_sort_iter_with_user (head, cmp, user);
	return head;
}

R_API void r_list_merge_sort(RList *list, RListComparator cmp) {
	R_RETURN_IF_FAIL (list);

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

R_API void r_list_merge_sort_with_user(RList *list, RListComparatorWithUser cmp, void *user) {
	R_RETURN_IF_FAIL (list);

	if (!list->sorted && list->head && cmp) {
		RListIter *iter;
		list->head = _merge_sort_with_user (list->head, cmp, user);
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
	R_RETURN_IF_FAIL (list);

	if (!list->sorted) {
		RListIter *it;
		for (it = list->head; it && it->data; it = it->n) {
			RListIter *it2;
			for (it2 = it->n; it2 && it2->data; it2 = it2->n) {
				if (cmp (it->data, it2->data) > 0) {
					void *t = it->data;
					it->data = it2->data;
					it2->data = t;
				}
			}
		}
		list->sorted = true;
	}
}

R_API void r_list_insertion_sort_with_user(RList *list, RListComparatorWithUser cmp, void *user) {
	R_RETURN_IF_FAIL (list);

	if (!list->sorted) {
		RListIter *it;
		RListIter *it2;
		if (cmp) {
			for (it = list->head; it && it->data; it = it->n) {
				for (it2 = it->n; it2 && it2->data; it2 = it2->n) {
					if (cmp (it->data, it2->data, user) > 0) {
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

// choose wisely based on length
R_API void r_list_sort(RList *list, RListComparator cmp) {
	R_RETURN_IF_FAIL (list);
	if (list->length > MERGE_LIMIT) {
		r_list_merge_sort (list, cmp);
	} else {
		r_list_insertion_sort (list, cmp);
	}
}

R_API void r_list_sort_with_user(RList *list, RListComparatorWithUser cmp, void *user) {
	R_RETURN_IF_FAIL (list);
	if (list->length > MERGE_LIMIT) {
		r_list_merge_sort_with_user (list, cmp, user);
	} else {
		r_list_insertion_sort_with_user (list, cmp, user);
	}
}

R_API RList *r_list_uniq(const RList *list, RListComparatorItem cmp) {
	RListIter *iter, *iter2;
	void *item;

	R_RETURN_VAL_IF_FAIL (list && cmp, 0);
	RList *rlist = r_list_newf (list->free);
	SetU *s = set_u_new ();
	r_list_foreach_safe (list, iter, iter2, item) {
		ut64 v = cmp (item);
		if (!set_u_contains (s, v)) {
			set_u_add (s, v);
			r_list_append (rlist, item);
		}
	}
	set_u_free (s);
	return rlist;
}

R_API int r_list_uniq_inplace(RList *list, RListComparatorItem cmp) {
	RListIter *iter, *iter2;
	void *item;
	int deleted = 0;

	R_RETURN_VAL_IF_FAIL (list && cmp, 0);
	SetU *s = set_u_new ();
	r_list_foreach_safe (list, iter, iter2, item) {
		ut64 v = cmp (item);
		if (set_u_contains (s, v)) {
			r_list_delete (list, iter);
			deleted ++;
		} else {
			set_u_add (s, v);
		}
	}
	set_u_free (s);
	return deleted;
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
