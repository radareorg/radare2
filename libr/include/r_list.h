#ifndef R2_LIST_H
#define R2_LIST_H

#include <r_types.h>
#include <r_flist.h>

#ifdef __cplusplus
extern "C" {
#endif

// TODO: implement r_list_foreach_prev

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
} RList;

typedef int (*RListComparator)(void *a, void *b);

#define ROFList_Parent RList
typedef struct r_oflist_t {
	ROFList_Parent super; // super class
	RFList *array; // statical readonly cache of linked list as a pointer array
} ROFList;
#endif

#ifdef R_API
//#define R_LIST_NEW(x,y) x=r_list_new();x->free=(RListFree)y
#define r_list_foreach(list, it, pos) \
	if (list) for (it = list->head; it && (pos = it->data); it = it->n)
/* Safe when calling r_list_delete() while iterating over the list. */
#define r_list_foreach_safe(list, it, tmp, pos) \
	if (list) for (it = list->head; it && (pos = it->data) && ((tmp = it->n) || 1); it = tmp)
#define r_list_foreach_prev(list, it, pos) \
	if (list) for (it = list->tail; it && (pos = it->data); it = it->p)
#ifndef _R_LIST_C_
#define r_list_push(x,y) r_list_append(x,y)
#define r_list_iterator(x) (x)?(x)->head:NULL
#define r_list_empty(x) (x==NULL || (x->head==NULL && x->tail==NULL))
#define r_list_head(x) x->head
#define r_list_tail(x) x->tail

#define r_list_iter_get(x) x->data; x=x->n
#define r_list_iter_next(x) (x?1:0)

#define r_list_iter_cur(x) x->p
#define r_list_iter_free(x) x
#endif
R_API RList *r_list_new();
R_API RList *r_list_newf(RListFree f);
//R_API void r_list_iter_free (RListIter *x);
R_API RListIter *r_list_iter_get_next(RListIter *list);
R_API int r_list_set_n(RList *list, int n, void *p);
R_API void *r_list_iter_get_data(RListIter *list);
R_API RListIter *r_list_append(RList *list, void *data);
R_API RListIter *r_list_prepend(RList *list, void *data);
R_API int r_list_length(RList *list);
R_API RListIter *r_list_add_sorted(RList *list, void *data, RListComparator cmp);
R_API void r_list_sort(RList *list, RListComparator cmp);

R_API void r_list_init(RList *list);
R_API void r_list_delete (RList *list, RListIter *iter);
R_API boolt r_list_delete_data (RList *list, void *ptr);
R_API void r_list_iter_init (RListIter *iter, RList *list);
R_API void r_list_purge (RList *list);
R_API void r_list_free (RList *list);
R_API RListIter *r_list_item_new (void *data);
R_API void r_list_split (RList *list, void *ptr);
R_API void r_list_split_iter (RList *list, RListIter *iter);
R_API void r_list_join (RList *list1, RList *list2);
R_API void *r_list_get_n (RList *list, int n);
R_API int r_list_del_n (RList *list, int n);
R_API void *r_list_get_top (RList *list);
R_API void *r_list_get_bottom (RList *list);
R_API void *r_list_pop (RList *list);
R_API void r_list_reverse (RList *list);
R_API RList *r_list_clone (RList *list);

/* hashlike api */
R_API void *r_list_get_by_int(RList *list, int off, int n);
R_API void *r_list_get_by_int64(RList *list, int off, ut64 n);
R_API void *r_list_get_by_string(RList *list, int off, const char *str);
R_API RListIter *r_list_contains (RList *list, void *p);
R_API RListIter *r_list_find (RList *list, void *p, RListComparator cmp);

/* rlistflist */
// TODO: rename to init or so.. #define r_oflist_new() R_NEW(ROFList);memset
#define r_oflist_length(x,y) r_list_length(x,y)
#define r_oflist_destroy(x) r_oflist_deserialize(x)
#define r_oflist_free(x) r_oflist_deserialize(x), r_list_free(x)
#define r_oflist_append(x,y) r_oflist_deserialize(x), r_list_append(x,y)
#define r_oflist_prepend(x,y) r_oflist_deserialize(x), r_list_prepend(x,y)
#define r_oflist_delete(x,y) r_oflist_deserialize(x), r_list_delete(x,y)
#define r_oflist_array(x) x->array?x->array:(x->array=r_oflist_serialize(x)),x->array
#define r_oflist_deserialize(x) \
	free(x->array-1),x->array=0
#define r_oflist_serialize(x) \
	x->array = r_flist_new(r_list_length(x)), { \
		int idx = 0; \
		void *ptr; \
		RListIter *iter; \
		r_list_foreach (x, iter, ptr) \
			r_flist_set (x->array, idx++, ptr); \
	} x->array;
#endif

#ifdef __cplusplus
}
#endif

#endif
