// (c) 2016 Jeffrey Crowell
// BSD 3 Clause License
// radare2

// Skiplists are a probabilistic datastructure than can be used as a k-v store
// with average case O(lg n) lookup time, and worst case O(n).

// https://en.wikipedia.org/wiki/Skip_list

#include <r_skiplist.h>

const int kSkipListDepth = 15; // max depth

RSkipListNode *r_skiplist_node_new (void *data) {
	RSkipListNode *res = R_NEW (RSkipListNode);
	if (!res) return NULL;
	res->forward = R_NEWS (RSkipListNode *, kSkipListDepth);
	if (!res->forward) goto err_forward;
	res->data = data;
	return res;

err_forward:
	free (res);
	return NULL;
}

void r_skiplist_node_free (RSkipList *list, RSkipListNode *node) {
	if (list->freefn && node->data) {
		list->freefn (node->data);
	}
	free (node->forward);
	free (node);
}

void init_head (RSkipList *list) {
	int i;
	for (i = 0; i <= kSkipListDepth; i++) {
		list->head->forward[i] = list->head;
	}
}

// Takes in a pointer to the function to free a list element, and a pointer to
// a function that retruns 0 on equality between two elements, and -1 or 1
// when unequal (for sorting).
// Returns a new heap-allocated skiplist.
R_API RSkipList* r_skiplist_new(RListFree freefn, RListComparator comparefn) {
	RSkipList *list = R_NEW0 (RSkipList);
	if (!list) return NULL;

	list->head = r_skiplist_node_new (NULL);
	if (!list->head) goto err_head;

	init_head (list);
	list->list_level = 0;
	list->size = 0;
	list->freefn = freefn;
	list->compare = comparefn;
	return list;

err_head:
	free (list);
	return NULL;
}

// Remove all elements from the list
R_API void r_skiplist_purge(RSkipList *list) {
	RSkipListNode *n;
	if (!list) return;

	n = list->head->forward[0];
	while (n != list->head) {
		RSkipListNode *x = n;
		n = n->forward[0];

		r_skiplist_node_free (list, x);
	}
	init_head (list);
	list->size = 0;
	list->list_level = 0;
}

// Free the entire list and it's element (if freefn is specified)
R_API void r_skiplist_free(RSkipList *list) {
	if (!list) return;
	r_skiplist_purge (list);
	r_skiplist_node_free (list, list->head);
	free (list);
}

// Inserts an element to the skiplist, and returns a pointer to the element's
// node.
R_API RSkipListNode* r_skiplist_insert(RSkipList* list, void* data) {
	RSkipListNode *update[kSkipListDepth+1];
	RSkipListNode *x;
	int i, x_level;

	x = list->head;
	for (i = list->list_level; i >= 0; i--) {
		while (x->forward[i] != list->head
			&& list->compare (x->forward[i]->data, data) < 0) {
			x = x->forward[i];
		}
		update[i] = x;
	}
	x = x->forward[0];
	if (x->forward[0] != list->head && list->compare(x->data, data) == 0) {
		return x;
	}

	for (x_level = 0; rand() < RAND_MAX/2 && x_level < kSkipListDepth; x_level++);

	if (x_level > list->list_level) {
		for (i = list->list_level + 1; i <= x_level; i++) {
			update[i] = list->head;
		}
		list->list_level = x_level;
	}

	x = r_skiplist_node_new (data);
	if (!x) {
		eprintf ("can't even malloc!");
		return NULL;
	}

	// update forward links
	for (i = 0; i <= x_level; i++) {
		x->forward[i] = update[i]->forward[i];
		update[i]->forward[i] = x;
	}
	list->size++;
	return x;
}

R_API void r_skiplist_delete(RSkipList* list, void* data) {
	int i;
	RSkipListNode *update[kSkipListDepth + 1], *node;

	// Delete node with data as it's payload.
	node = list->head;
	for (i = list->list_level; i >=0; i--) {
		while (node->forward[i] != list->head &&
			list->compare (node->forward[i]->data, data) < 1) {
			node = node->forward[i];
		}
		update[i] = node;
	}
	node = node->forward[0];
	if (node == list->head || !list->compare(node->data, data)) {
		return;
	}

	// Update the fwd pointers.
	for (i = 0; i <= list->list_level; i++) {
		if (update[i]->forward[i] != node) {
			break;
		}
		update[i]->forward[i] = node->forward[i];
	}
	r_skiplist_node_free (list, node);

	// Update the level.
	while ((list->list_level > 0) &&
		(list->head->forward[list->list_level] == list->head)) {
		list->list_level--;
	}
	list->size--;
}

R_API RSkipListNode* r_skiplist_find(RSkipList* list, void* data) {
	int i;
	RSkipListNode* x = list->head;
	for (i = list->list_level; i >= 0; i--) {
		while (x->forward[i] != list->head &&
			list->compare (x->forward[i]->data, data) < 0) {
			x = x->forward[i];
		}
	}
	x = x->forward[0];
	if (x != list->head && list->compare (x->data, data) == 0) {
		return x;
	}
	return NULL;
}
