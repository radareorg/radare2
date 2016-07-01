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
	int levels;
} RSkipListNode;

typedef struct r_skiplist_t {
	RSkipListNode *head;	// list header
	int list_level; // current level of the list.
	ut32 count;
	RListFree freefn;
	RListComparator compare;
} RSkipList;

R_API RSkipList* r_skiplist_new(RListFree freefn, RListComparator comparefn);
R_API void r_skiplist_free(RSkipList *list);
R_API void r_skiplist_purge(RSkipList *list);
R_API RSkipListNode* r_skiplist_insert(RSkipList* list, void* data);
R_API bool r_skiplist_delete(RSkipList* list, void* data);
R_API RSkipListNode* r_skiplist_find(RSkipList* list, void* data);

#endif // R2_SKIP_LIST_H
