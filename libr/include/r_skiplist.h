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
	struct r_skiplist_node_t *forward[1]; // forward pointer
} r_skiplist_node;

typedef struct r_skiplist_t {
	r_skiplist_node *head;	// list header
	int list_level; // current level of the list.
	RListFree freefn;
	RListComparator compare;
} r_skiplist;

typedef r_skiplist RSkipList;

R_API r_skiplist* r_skiplist_new(RListFree freefn, RListComparator comparefn);
R_API r_skiplist_node* r_skiplist_insert(r_skiplist* list, void* data);
R_API void r_skiplist_delete(r_skiplist* list, void* data);
R_API r_skiplist_node* r_skiplist_find(r_skiplist* list, void* data);

#endif // R2_SKIP_LIST_H
