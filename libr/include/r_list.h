#ifndef R2_LIST_H
#define R2_LIST_H

#include <r_types.h>
#include <r_flist.h>
#include <sdb.h>
#ifdef __cplusplus
extern "C" {
#endif

#ifndef _INCLUDE_R_LIST_HEAD_H_
#define _INCLUDE_R_LIST_HEAD_H_
typedef void (*RListFree)(void *ptr);

typedef struct r_list_iter_t {
	void *data;
	struct r_list_iter_t *n, *p;
} RListIter;

typedef struct r_list_t {
	RListIter *head;
	RListIter *tail;
	RListFree free;
	int length;
	bool sorted;
} RList;

typedef struct r_list_range_t {
	HtPP *h;
	RList *l;
} RListRange;

// RListComparator should return -1, 0, 1 to indicate "a<b", "a==b", "a>b".
typedef int (*RListComparator)(const void *a, const void *b);

#define ROFList_Parent RList
typedef struct r_oflist_t {
	ROFList_Parent super; // super class
	RFList *array;	// statical readonly cache of linked list as a pointer array
} ROFList;
#endif

#ifdef R_API
#define r_list_foreach(list, it, pos)\
	if (list)\
		for (it = list->head; it && (pos = it->data, 1); it = it->n)
#define r_list_foreach_iter(list, it)\
	if (list)\
		for (it = list->head; it; it = it->n)
/* Safe when calling r_list_delete() while iterating over the list. */
#define r_list_foreach_safe(list, it, tmp, pos)\
	if (list)\
		for (it = list->head; it && (pos = it->data, tmp = it->n, 1); it = tmp)
#define r_list_foreach_prev(list, it, pos)\
	if (list)\
		for (it = list->tail; it && (pos = it->data, 1); it = it->p)
#define r_list_foreach_prev_safe(list, it, tmp, pos) \
	for (it = list->tail; it && (pos = it->data, tmp = it->p, 1); it = tmp)
#ifndef _R_LIST_C_
#define r_list_push(x, y) r_list_append ((x), (y))
#define r_list_iterator(x) (x)? (x)->head: NULL
// #define r_list_empty(x) (!x || (!(x->head) && !(x->tail)))
#define r_list_empty(x) (!(x) || !(x)->length)
#define r_list_head(x) ((x)? (x)->head: NULL)
#define r_list_tail(x) ((x)? (x)->tail: NULL)

#define r_list_iter_get(x) (x)->data; (x)=(x)->n
#define r_list_iter_next(x) ((x)? 1: 0)

#define r_list_iter_cur(x) (x)->p
#define r_list_iter_free(x) (x)
#endif
R_API RList *r_list_new(void);
R_API RList *r_list_newf(RListFree f);
R_API RListIter *r_list_iter_get_next(RListIter *list);
R_API int r_list_set_n(RList *list, int n, void *p);
R_API void *r_list_iter_get_data(RListIter *list);
R_API RListIter *r_list_append(RList *list, void *data);
R_API RListIter *r_list_prepend(RList *list, void *data);
R_API RListIter *r_list_insert(RList *list, int n, void *data);
R_API int r_list_length(const RList *list);
R_API void *r_list_first(const RList *list);
R_API void *r_list_last(const RList *list);
R_API RListIter *r_list_add_sorted(RList *list, void *data, RListComparator cmp);
R_API void r_list_sort(RList *list, RListComparator cmp);
R_API void r_list_merge_sort(RList *list, RListComparator cmp);
R_API void r_list_insertion_sort(RList *list, RListComparator cmp);
R_API RList *r_list_uniq(const RList *list, RListComparator cmp);
R_API void r_list_init(RList *list);
R_API void r_list_delete(RList *list, RListIter *iter);
R_API bool r_list_delete_data(RList *list, void *ptr);
R_API void r_list_iter_init(RListIter *iter, RList *list);
R_API void r_list_purge(RList *list);
R_API void r_list_free(RList *list);
R_API RListIter *r_list_item_new(void *data);
R_API void r_list_split(RList *list, void *ptr);
R_API void r_list_split_iter(RList *list, RListIter *iter);
R_API int r_list_join(RList *list1, RList *list2);
R_API void *r_list_get_n(const RList *list, int n);
R_API int r_list_del_n(RList *list, int n);
R_API void *r_list_get_top(const RList *list);
R_API void *r_list_get_bottom(const RList *list);
R_API void *r_list_pop(RList *list);
R_API void *r_list_pop_head(RList *list);
R_API void r_list_reverse(RList *list);
R_API RList *r_list_clone(const RList *list);
R_API char *r_list_to_str(RList *list, char ch);

/* hashlike api */
R_API RListIter *r_list_contains(const RList *list, const void *p);
R_API RListIter *r_list_find(const RList *list, const void *p, RListComparator cmp);

/* rlistflist */
// TODO: rename to init or so.. #define r_oflist_new() R_NEW(ROFList);memset
#define r_oflist_length(x, y) r_list_length (x, y)
#define r_oflist_destroy(x) r_oflist_deserialize (x)
#define r_oflist_free(x) r_oflist_deserialize (x), r_list_free (x)
#define r_oflist_append(x, y) r_oflist_deserialize (x), r_list_append (x, y)
#define r_oflist_prepend(x, y) r_oflist_deserialize (x), r_list_prepend (x, y)
#define r_oflist_delete(x, y) r_oflist_deserialize (x), r_list_delete (x, y)
#define r_oflist_array(x) x->array? x->array: (x->array = r_oflist_serialize (x)), x->array
#define r_oflist_deserialize(x)\
	free (x->array - 1), x->array = 0
#define r_oflist_serialize(x)\
	x->array = r_flist_new (r_list_length (x)), { \
		int idx = 0;\
		void *ptr;\
		RListIter *iter;\
		r_list_foreach (x, iter, ptr) r_flist_set (x->array, idx++, ptr);\
	}\
	x->array;
#endif

#ifdef __cplusplus
}
#endif

#endif
