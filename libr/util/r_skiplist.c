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
R_API RSkipList* r_skiplist_new(RListFree freefn, RListComparator comparefn) {
	int i;
	RSkipList *list = R_NEW0 (RSkipList);
	if (!list) return NULL;

	list->head = NULL;
	list->list_level = 1;
	list->freefn = freefn;
	list->compare = comparefn;
	list->count = 0;
	return list;
}

// Remove all elements from the list
R_API void r_skiplist_purge(RSkipList *list) {
	if (!list) return;
	// TODO: implement me
}

// Free the entire list and it's element (if freefn is specified)
R_API void r_skiplist_free(RSkipList *list) {
	if (!list) return;
	r_skiplist_purge (list);
	free (list);
}

RSkipListNode* r_skiplist_node_new (void *data, int level) {
	RSkipListNode* node = calloc (1, sizeof (RSkipList));
	node->levels = level;
	node->forward = calloc (level, sizeof (RSkipListNode*));
	node->data = data;
	return node;
}

void r_skiplist_node_free (RSkipListNode* node) {
	int i;
	for (i = 0; i < node->levels; i++) {
		free (node->forward[node->levels - i - 1]);
	}
	free (node);
	node = NULL;
}

// Inserts an element to the skiplist, and returns a pointer to the element's
// node.
R_API RSkipListNode* r_skiplist_insert(RSkipList* list, void* data) {
	int i, rnd, level = 0;
	RSkipListNode* node;
	RSkipListNode* current;
	if (list->count == 0) {
		// This is the first element in the list.
		node = r_skiplist_node_new (data, kSkipListDepth);
		list->head = node;
		list->count++;
		return node;
	}
	for (rnd = rand() % RAND_MAX; (rnd &1) == 1; rnd >>=1) {
		if (level < kSkipListDepth) {
			level++;
			if (level == list->list_level) {
				list->list_level++;
				break;
			}
		}
	}
	node = r_skiplist_node_new (data, level + 1);
	current = list->head;
	for (i = list->list_level - 1; i >=0; i--) {
		for (;current->forward[i]; current = current->forward[i]) {
			if (list->compare(current->forward[i]->data, data) > 1) {
				break;
			}
		}
		if (i <= level) {
			node->forward[i] = current->forward[i];
			current->forward[i] = node;
			list->count++;
		}
	}
	return node;
}

R_API bool r_skiplist_delete(RSkipList* list, void* data) {
	RSkipListNode* current = list->head;
	int i;
	for (i = list->list_level - 1; i >=0; i--) {
		for (; current->forward[i]; current = current->forward[i]) {
			if (list->compare (current->forward[i]->data, data) == 0) {
				RSkipListNode* tmp = current->forward[i];
				current->forward[i] = current->forward[i]->forward[i];
				r_skiplist_node_free (tmp);
				list->count--;
				return true;
			} else if (list->compare (current->forward[i]->data, data) > 1) {
				break;
			}
		}
	}
	return false;
}

R_API RSkipListNode* r_skiplist_find(RSkipList* list, void* data) {
	RSkipListNode* current = list->head;
	int i;
	for (i = list->list_level - 1; i >=0; i--) {
		for (; current->forward[i]; current = current->forward[i]) {
			if (list->compare (current->forward[i]->data, data) > 0) {
				break;
			} else if (list->compare (current->forward[i]->data, data) == 0) {
				return current->forward[i];
			}
		}
	}
	// Maybe it's the first element?
	if (list->compare (list->head->data, data) == 0) {
		return list->head;
	}
	return NULL;
}
