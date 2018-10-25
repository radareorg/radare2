/* radare - BSD 3 Clause License - Copyright 2017 - MaskRay */

#ifndef R2_RBTREE_H
#define R2_RBTREE_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#include "r_list.h"

#ifndef container_of
# ifdef _MSC_VER
#  define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
# else
#  define container_of(ptr, type, member) ((type *)((char *)(__typeof__(((type *)0)->member) *){ptr} - offsetof(type, member)))
# endif
#endif

// max height <= 2 * floor(log2(n + 1))
// We use `int` for size, so <= 2 * 31
#define R_RBTREE_MAX_HEIGHT 62

// Singleton can be zero initialized
typedef struct r_rb_node_t {
	struct r_rb_node_t *child[2];
	bool red;
} RBNode;

typedef RBNode* RBTree;

typedef int (*RBComparator)(const void *incoming, const RBNode *in_tree);
typedef void (*RBNodeFree)(RBNode *);
typedef void (*RBNodeSum)(RBNode *);

typedef struct r_rb_iter_t {
	int len;
	RBNode *path[R_RBTREE_MAX_HEIGHT];
} RBIter;

// Routines for augmented red-black trees. The user should provide an aggregation (monoid sum) callback `sum`
// to calculate extra information such as size, sum, ...
R_API bool r_rbtree_aug_delete(RBNode **root, void *data, RBComparator cmp, RBNodeFree freefn, RBNodeSum sum);
R_API void r_rbtree_aug_insert(RBNode **root, void *data, RBNode *node, RBComparator cmp, RBNodeSum sum);
R_API bool r_rbtree_aug_update_sum(RBNode *root, void *data, RBNode *node, RBComparator cmp, RBNodeSum sum);

R_API bool r_rbtree_delete(RBNode **root, void *data, RBComparator cmp, RBNodeFree freefn);
R_API RBNode *r_rbtree_find(RBNode *root, void *data, RBComparator cmp);
R_API void r_rbtree_free(RBNode *root, RBNodeFree freefn);
R_API void r_rbtree_insert(RBNode **root, void *data, RBNode *node, RBComparator cmp);
// Return the smallest node that is greater than or equal to `data`
R_API RBNode *r_rbtree_lower_bound(RBNode *root, void *data, RBComparator cmp);
// Return the smallest node that is greater than `data`
R_API RBNode *r_rbtree_upper_bound(RBNode *root, void *data, RBComparator cmp);

// Create a forward iterator starting from the leftmost node
R_API RBIter r_rbtree_first(RBNode *root);
// Create a backward iterator starting from the rightmost node
R_API RBIter r_rbtree_last(RBNode *root);
// Iterate [lower_bound, end) forward, used with r_rbtree_iter_next
R_API RBIter r_rbtree_lower_bound_backward(RBNode *root, void *data, RBComparator cmp);
// Iterate [begin, lower_bound) backward, used with r_rbtree_iter_prev
R_API RBIter r_rbtree_lower_bound_forward(RBNode *root, void *data, RBComparator cmp);
// Iterate [upper_bound, end) forward, used with r_rbtree_iter_next
R_API RBIter r_rbtree_upper_bound_backward(RBNode *root, void *data, RBComparator cmp);
// Iterate [begin, upper_bound) backward, used with r_rbtree_iter_prev
R_API RBIter r_rbtree_upper_bound_forward(RBNode *root, void *data, RBComparator cmp);

// struct Node { int key; RBNode rb; };
// r_rbtree_iter_get (it, struct Node, rb)
#define r_rbtree_iter_get(it, struc, rb) container_of ((it)->path[(it)->len-1]), struc, rb)
// If the iterator has more elements to iterate
#define r_rbtree_iter_has(it) (it).len
// Move forward
R_API void r_rbtree_iter_next(RBIter *it);
// Move backward
R_API void r_rbtree_iter_prev(RBIter *it);

// Iterate all elements of the forward iterator
#define r_rbtree_iter_while(it, data, struc, rb) \
	for (; (it).len && (data = container_of ((it).path[(it).len-1], struc, rb)); r_rbtree_iter_next (&(it)))

// Iterate all elements of the backward iterator
#define r_rbtree_iter_while_prev(it, data, struc, rb) \
	for (; (it).len && (data = container_of ((it).path[(it).len-1], struc, rb)); r_rbtree_iter_prev (&(it)))

#define r_rbtree_foreach(root, it, data, struc, rb) \
	for ((it) = r_rbtree_first (root); (it).len && (data = container_of ((it).path[(it).len-1], struc, rb)); r_rbtree_iter_next (&(it)))

#define r_rbtree_foreach_prev(root, it, data, struc, rb) \
	for ((it) = r_rbtree_last (root); (it).len && (data = container_of ((it).path[(it).len-1], struc, rb)); r_rbtree_iter_prev (&(it)))

#endif
