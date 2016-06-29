// (c) 2016 Jeffrey Crowell
// BSD 3 Clause License
// radare2

// Skiplists are a probabilistic datastructure than can be used as a k-v store
// with average case O(lg n) lookup time, and worst case O(n).

// https://en.wikipedia.org/wiki/Skip_list

#include <r_skiplist.h>

const int kSkipListDepth = 15; // max depth

// Takes in a pointer to the function to free a list element, and a pointer to
// a function that retruns 0 on equality between two elements, and -1 or 1
// when unequal (for sorting).
// Returns a new heap-allocated skiplist.
R_API r_skiplist* r_skiplist_new(RListFree freefn, RListComparator comparefn) {
	int i;
	r_skiplist* list = calloc (1, sizeof (r_skiplist));
	if ((list->head =
				calloc (1,
				sizeof (r_skiplist_node) +
				kSkipListDepth * sizeof (r_skiplist_node*))) == NULL) {
		eprintf ("can't init skiplist...");
		return NULL;
	}
	for (i = 0; i <= kSkipListDepth; i++) {
		list->head->forward[i] = list->head;
	}
	list->list_level = 0;
	return list;
}

// Inserts an element to the skiplist, and returns a pointer to the element's
// node.
R_API r_skiplist_node* r_skiplist_insert(r_skiplist* list, void* data) {
	int i, new_level;
	r_skiplist_node* update [kSkipListDepth + 1];
	r_skiplist_node* nnode;

	// Find the spot for it.
	nnode = list->head;
	for (i = list->list_level; i >= 0; i--) {
		while ((nnode->forward[i] != list->head) &&
				(list->compare (nnode->forward[i]->data, data) < 1)) {
			nnode = nnode->forward[i];
		}
		update[i] = nnode;
	}
	nnode = nnode->forward[0];
	if (nnode != list->head && list->compare (nnode->data, data) == 0) {
		return nnode;
	}

	// Determine the level "randomly".
	// Skiplists are a probabilistic datastructure.
	for (new_level = 0; rand() % 2 && new_level < kSkipListDepth; new_level++);

	if (new_level < list->list_level) {
		for (i = list->list_level + 1; i <= new_level; i++) {
			update[i] = list->head;
		}
	}

	// Okie, now make the node actually...
	if ((nnode = calloc (1,
					sizeof (r_skiplist_node) +
					new_level * sizeof (r_skiplist_node*))) == NULL) {
		eprintf ("can't calloc new node for skiplist");
		return NULL;
	}
	nnode->data = data;

	// update fwd links.
	for (i = 0; i <= new_level; i++) {
		nnode->forward[i] = update[i]->forward[i];
	}
	return nnode;
}

R_API void r_skiplist_delete(r_skiplist* list, void* data) {
	int i;
	r_skiplist_node *update[kSkipListDepth + 1], *node;

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
		} else {
			update[i]->forward[i] = node->forward[i];
		}
	}
	free (node);

	// Update the level.
	while ((list->list_level > 0) &&
			(list->head->forward[list->list_level] == list->head)) {
		list->list_level--;
	}
}

R_API r_skiplist_node* r_skiplist_find(r_skiplist* list, void* data) {
	int i;
	r_skiplist_node* node = list->head;
	for (i = list->list_level; i >= 0; i--) {
		while (node->forward[i] != list->head &&
				list->compare (node->forward[i]->data, data) < 0) {
			node = node->forward[i];
		}
	}
	node = node->forward[0];
	if (node != list->head && list->compare (node->data, data)) {
		return node;
	}
	return NULL;
}
