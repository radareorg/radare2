// (c) 2016 Jeffrey Crowell
// BSD 3 Clause License
// radare2

// Skiplists are a probabilistic datastructure than can be used as a k-v store
// with average case O(lg n) lookup time, and worst case O(n).

// https://en.wikipedia.org/wiki/Skip_list

#ifndef R2_SKIP_LIST_H
#define R2_SKIP_LIST_H

#include <r_list.h>

typedef struct r_skiplist_node_t {
	void *data;	// pointer to the value
	struct r_skiplist_node_t **forward; // forward pointer
} RSkipListNode;

typedef struct r_skiplist_t {
	RSkipListNode *head;	// list header
	int list_level; // current level of the list.
	int size;
	RListFree freefn;
	RListComparator compare;
} RSkipList;

R_API RSkipList* r_skiplist_new(RListFree freefn, RListComparator comparefn);
R_API void r_skiplist_free(RSkipList *list);
R_API void r_skiplist_purge(RSkipList *list);
R_API RSkipListNode* r_skiplist_insert(RSkipList* list, void* data);
R_API bool r_skiplist_insert_autofree(RSkipList* list, void* data);
R_API bool r_skiplist_delete(RSkipList* list, void* data);
R_API bool r_skiplist_delete_node(RSkipList *list, RSkipListNode *node);
R_API RSkipListNode* r_skiplist_find(RSkipList* list, void* data);
R_API RSkipListNode* r_skiplist_find_geq(RSkipList* list, void* data);
R_API RSkipListNode* r_skiplist_find_leq(RSkipList* list, void* data);
R_API void r_skiplist_join(RSkipList *l1, RSkipList *l2);
R_API void *r_skiplist_get_first(RSkipList *list);
R_API void *r_skiplist_get_n(RSkipList *list, int n);
R_API void* r_skiplist_get_geq(RSkipList* list, void* data);
R_API void* r_skiplist_get_leq(RSkipList* list, void* data);
R_API bool r_skiplist_empty(RSkipList *list);
R_API RList *r_skiplist_to_list(RSkipList *list);

#define r_skiplist_islast(list, el) (el->forward[0] == list->head)

#define r_skiplist_length(list) (list->size)

#define r_skiplist_foreach(list, it, pos)\
	if (list)\
		for (it = list->head->forward[0]; it != list->head && ((pos = it->data) || 1); it = it->forward[0])

#define r_skiplist_foreach_safe(list, it, tmp, pos)\
	if (list)\
		for (it = list->head->forward[0]; it != list->head && ((pos = it->data) || 1) && ((tmp = it->forward[0]) || 1); it = tmp)

#endif // R2_SKIP_LIST_H
