#ifndef _INCLUDE_LS_H_
#define _INCLUDE_LS_H_

#include <stdio.h>
#include "types.h"

#ifndef R_API
#define R_API
#endif
// TODO: implement ls_foreach_prev

typedef void (*SdbListFree)(void *ptr);

typedef struct ls_iter_t {
	void *data;
	struct ls_iter_t *n, *p;
} SdbListIter;

typedef struct ls_t {
	unsigned int length;
	struct ls_iter_t *head;
	struct ls_iter_t *tail;
	SdbListFree free;
} SdbList;

typedef int (*SdbListComparator)(void *a, void *b);

#ifdef R_API
#define ls_foreach(list, it, pos) \
	for (it = list->head; it && (pos = it->data); it = it->n)
#define ls_foreach_prev(list, it, pos) \
	for (it = list->tail; it && (pos = it->data); it = it->p)
#define ls_iterator(x) (x)?(x)->head:NULL
#define ls_empty(x) (x==NULL || (x->head==NULL && x->tail==NULL))
#define ls_head(x) x->head
#define ls_tail(x) x->tail
#define ls_unref(x) x
#define ls_iter_get(x) x->data; x=x->n
#define ls_iter_next(x) (x?1:0)
#define ls_iter_cur(x) x->p
#define ls_iter_unref(x) x
R_API SdbList *ls_new(void);
R_API SdbListIter *ls_append(SdbList *list, void *data);
R_API SdbListIter *ls_prepend(SdbList *list, void *data);
R_API int ls_length(SdbList *list);
R_API void ls_add_sorted(SdbList *list, void *data, SdbListComparator cmp);
R_API void ls_sort(SdbList *list, SdbListComparator cmp);

R_API void ls_delete (SdbList *list, SdbListIter *iter);
R_API boolt ls_delete_data (SdbList *list, void *ptr);
R_API void ls_iter_init (SdbListIter *iter, SdbList *list);
R_API void ls_destroy (SdbList *list);
R_API void ls_free (SdbList *list);
R_API SdbListIter *ls_item_new (void *data);
R_API void ls_unlink (SdbList *list, void *ptr);
R_API void ls_split (SdbList *list, void *ptr);
R_API void ls_split_iter (SdbList *list, SdbListIter *iter);
R_API void *ls_get_n (SdbList *list, int n);
R_API int ls_del_n (SdbList *list, int n);
R_API void *ls_get_top (SdbList *list);
#define ls_push(x,y) ls_append(x,y)
R_API void *ls_pop (SdbList *list);
R_API void ls_reverse (SdbList *list);
R_API SdbList *ls_clone (SdbList *list);

#endif
#endif
