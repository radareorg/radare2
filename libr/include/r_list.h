#ifndef _INCLUDE_R_LIST_H_
#define _INCLUDE_R_LIST_H_

typedef void (*RListFree)(void *ptr);

typedef struct r_list_iter_t {
	void *data;
	struct r_list_iter_t *next, *prev;
} RListIter;

typedef struct r_list_t {
	struct r_list_iter_t *head;
	struct r_list_iter_t *tail;
	RListFree free;
} RList;

#define r_list_iterator(x) x->head
#define r_list_iter_free(x) free(x)
#define r_list_item_free(x) free(x)
#define r_list_free(x) free(x)
#define r_list_empty(x) (x->head==NULL && x->tail==NULL)
#define r_list_head(x) x->head
#define r_list_tail(x) x->tail
#define r_list_iter_get(x) x->data; x=x->next
#define r_list_iter_next(x) (x?1:0)

#ifdef R_API
R_API void r_list_init(RList *list);
R_API void r_list_delete (RList *list, RListIter *item);
R_API RList *r_list_new();
R_API void r_list_iter_init (RListIter *iter, RList *list);
R_API void r_list_destroy (RList *list);
R_API RListIter *r_list_item_new (void *data);
R_API RListIter *r_list_append(RList *list, void *data);
R_API RListIter *r_list_prepend(RList *list, void *data);
R_API void r_list_unlink (RList *list, void *ptr);
#endif

#endif
