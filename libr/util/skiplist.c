// (c) 2016 Jeffrey Crowell, Riccardo Schirone(ret2libc)
// BSD 3 Clause License
// radare2

// Skiplists are a probabilistic datastructure than can be used as a k-v store
// with average case O(lg n) lookup time, and worst case O(n).

// https://en.wikipedia.org/wiki/Skip_list

#include <r_skiplist.h>

#define SKIPLIST_MAX_DEPTH 31

static RSkipListNode *r_skiplist_node_new(void *data, int level) {
	RSkipListNode *res = R_NEW0 (RSkipListNode);
	if (!res) {
		return NULL;
	}
	res->forward = R_NEWS0 (RSkipListNode *, level + 1);
	if (!res->forward)  {
		free (res);
		return NULL;
	}
	res->data = data;
	return res;
}

static void r_skiplist_node_free(RSkipList *list, RSkipListNode *node) {
	if (node) {
		if (list->freefn && node->data) {
			list->freefn (node->data);
		}
		free (node->forward);
		free (node);
	}
}

static void init_head(RSkipListNode *head) {
	int i;
	for (i = 0; i <= SKIPLIST_MAX_DEPTH; i++) {
		head->forward[i] = head;
	}
}

// Find the insertion/deletion point for the element `data` in the list.
// The array `updates`, if provided, is filled with the nodes that need to be
// updated for each layer.
//
// NOTE: `updates` should be big enough to contain `list->list_level + 1`
//       elements, when provided.
static RSkipListNode *find_insertpoint(RSkipList *list, void *data, RSkipListNode **updates, bool by_data) {
	RSkipListNode *x = list->head;
	int i;

	for (i = list->list_level; i >= 0; i--) {
		if (by_data) {
			while (x->forward[i] != list->head
				&& list->compare (x->forward[i]->data, data) < 0) {
				x = x->forward[i];
			}
		} else {
			while (x->forward[i] != list->head && x->forward[i] != data) {
				x = x->forward[i];
			}
		}
		if (updates) {
			updates[i] = x;
		}
	}
	x = x->forward[0];
	return x;
}

static bool delete_element(RSkipList* list, void* data, bool by_data) {
	int i;
	RSkipListNode *update[SKIPLIST_MAX_DEPTH + 1], *x;

	// locate delete points in the lists of all levels
	x = find_insertpoint (list, data, update, by_data);
	// do nothing if the element is not present in the list
	if (x == list->head || list->compare(x->data, data) != 0) {
		return false;
	}

	// update forward links for all `update` points,
	// by removing the element from the list in each level
	for (i = 0; i <= list->list_level; i++) {
		if (update[i]->forward[i] != x) {
			break;
		}
		update[i]->forward[i] = x->forward[i];
	}
	r_skiplist_node_free (list, x);

	// update the level of the list
	while ((list->list_level > 0) &&
		(list->head->forward[list->list_level] == list->head)) {
		list->list_level--;
	}
	list->size--;
	return true;
}

// Takes in a pointer to the function to free a list element, and a pointer to
// a function that returns 0 on equality between two elements, and -1 or 1
// when unequal (for sorting).
// Returns a new heap-allocated skiplist.
R_API RSkipList* r_skiplist_new(RListFree freefn, RListComparator comparefn) {
	RSkipList *list = R_NEW0 (RSkipList);
	if (!list) {
		return NULL;
	}

	list->head = r_skiplist_node_new (NULL, SKIPLIST_MAX_DEPTH);
	if (!list->head) {
		free (list);
		return NULL;
	}

	init_head (list->head);
	list->list_level = 0;
	list->size = 0;
	list->freefn = freefn;
	list->compare = comparefn;
	return list;
}

// Remove all elements from the list
R_API void r_skiplist_purge(RSkipList *list) {
	RSkipListNode *n;
	if (!list) {
		return;
	}
	n = list->head->forward[0];
	while (n != list->head) {
		RSkipListNode *x = n;
		n = n->forward[0];
		r_skiplist_node_free (list, x);
	}
	init_head (list->head);
	list->size = 0;
	list->list_level = 0;
}

// Free the entire list and it's element (if freefn is specified)
R_API void r_skiplist_free(RSkipList *list) {
	if (!list) {
		return;
	}
	r_skiplist_purge (list);
	r_skiplist_node_free (list, list->head);
	free (list);
}

// Inserts an element to the skiplist, and returns a pointer to the element's
// node.
R_API RSkipListNode* r_skiplist_insert(RSkipList* list, void* data) {
	RSkipListNode *update[SKIPLIST_MAX_DEPTH + 1];
	RSkipListNode *x;
	int i, x_level, new_level;

	// locate insertion points in the lists of all levels
	x = find_insertpoint (list, data, update, true);
	// check whether the element is already in the list
	if (x != list->head && !list->compare(x->data, data)) {
		return x;
	}

	// randomly choose the number of levels the new node will be put in
	for (x_level = 0; rand () < RAND_MAX / 2 && x_level < SKIPLIST_MAX_DEPTH; x_level++) {
		;
	}

	// update the `update` array with default values when the current node
	// has a level greater than the current one
	new_level = list->list_level;
	if (x_level > list->list_level) {
		for (i = list->list_level + 1; i <= x_level; i++) {
			update[i] = list->head;
		}
		new_level = x_level;
	}

	x = r_skiplist_node_new (data, x_level);
	if (!x) {
		return NULL;
	}

	// update forward links for all `update` points,
	// by inserting the new element in the list in each level
	for (i = 0; i <= x_level; i++) {
		x->forward[i] = update[i]->forward[i];
		update[i]->forward[i] = x;
	}

	list->list_level = new_level;
	list->size++;
	return x;
}

R_API bool r_skiplist_insert_autofree(RSkipList* list, void* data) {
	RSkipListNode* node = r_skiplist_insert (list, data);
	if (node && data != node->data) { // duplicate
		if (list->freefn) {
			list->freefn (data);
		}
		return false;
	}
	return true;
}

// Delete node with data as it's payload.
R_API bool r_skiplist_delete(RSkipList* list, void* data) {
	return delete_element (list, data, true);
}

// Delete the given RSkipListNode from the skiplist
R_API bool r_skiplist_delete_node(RSkipList *list, RSkipListNode *node) {
	return delete_element (list, node, false);
}

R_API RSkipListNode* r_skiplist_find(RSkipList* list, void* data) {
	RSkipListNode* x = find_insertpoint (list, data, NULL, true);
	if (x != list->head && list->compare (x->data, data) == 0) {
		return x;
	}
	return NULL;
}

R_API RSkipListNode* r_skiplist_find_geq(RSkipList* list, void* data) {
	RSkipListNode* x = find_insertpoint (list, data, NULL, true);
	return x != list->head ? x : NULL;
}

R_API RSkipListNode* r_skiplist_find_leq(RSkipList* list, void* data) {
	RSkipListNode *x = list->head;
	int i;

	for (i = list->list_level; i >= 0; i--) {
		while (x->forward[i] != list->head 
			&& list->compare (x->forward[i]->data, data) <= 0) {
			x = x->forward[i];
		}
	}
	return x != list->head ? x : NULL;
}

// Move all the elements of `l2` in `l1`.
R_API void r_skiplist_join(RSkipList *l1, RSkipList *l2) {
	RSkipListNode *it;
	void *data;

	r_skiplist_foreach (l2, it, data) {
		r_skiplist_insert (l1, data);
	}

	r_skiplist_purge (l2);
}

// Returns the first data element in the list, if present, NULL otherwise
R_API void *r_skiplist_get_first(RSkipList *list) {
	if (!list) {
		return NULL;
	}
	RSkipListNode *res = list->head->forward[0];
	return res == list->head ? NULL : res->data;
}

// Returns the nth data element in the list, if present, NULL otherwise
R_API void *r_skiplist_get_n(RSkipList *list, int n) {
	int count = 0;
	RSkipListNode *node;
	void *data;
	if (!list || n < 0) {
		return NULL;
	}
	r_skiplist_foreach (list, node, data) {
		if (count == n) {
			return data;
		}
		++count;
	}
	return NULL;
}


R_API void* r_skiplist_get_geq(RSkipList* list, void* data) {
	RSkipListNode *x = r_skiplist_find_geq (list, data);
	return x ? x->data : NULL;
}

R_API void* r_skiplist_get_leq(RSkipList* list, void* data) {
	RSkipListNode *x = r_skiplist_find_leq (list, data);
	return x ? x->data : NULL;
}

// Return true if the list is empty
R_API bool r_skiplist_empty(RSkipList *list) {
	return list->size == 0;
}

// Return a new allocated RList representing the given `list`
//
// NOTE: the data will be shared between the two lists. The user of this
//       function should choose which list will "own" the data pointers.
R_API RList *r_skiplist_to_list(RSkipList *list) {
	RList *res = r_list_new ();
	RSkipListNode *n;
	void *data;

	r_skiplist_foreach (list, n, data) {
		r_list_append (res, data);
	}

	return res;
}
