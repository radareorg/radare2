#ifndef _INCLUDE_R_LIST_H_
#define _INCLUDE_R_LIST_H_

typedef void (*rListFree)(void *ptr);

typedef struct r_list_item_t {
	void *data;
	struct r_list_item_t *next, *prev;
} rListItem;

typedef struct r_list_iter_t {
	struct r_list_item_t *cur;
} rListIter;

typedef struct r_list_t {
	struct r_list_item_t *head;
	struct r_list_item_t *tail;
	rListFree free;
} rList;

#define r_list_iterator(x) r_list_iter_new(x)
#define r_list_iter_free(x) free(x)
#define r_list_item_free(x) free(x)
#define r_list_free(x) free(x)

#ifdef R_API
R_API void r_list_init(rList *list);
R_API void r_list_delete (rList *list, rListItem *item);
R_API rList *r_list_new();
R_API void r_list_iter_init (rListIter *iter, rList *list);
R_API rListIter *r_list_iter_new(rList *list);
R_API int r_list_empty(rList *list);
R_API void *r_list_iter_get(rListIter *iter);
R_API void r_list_destroy (rList *list);
R_API rListItem *r_list_item_new (void *data);
R_API rListItem *r_list_append(rList *list, void *data);
R_API rListItem *r_list_head(rList *list);
R_API rListItem *r_list_tail(rList *list);
R_API rListItem *r_list_prepend(rList *list, void *data);
R_API int r_list_iter_next(rListIter *iter);
#endif

#endif
