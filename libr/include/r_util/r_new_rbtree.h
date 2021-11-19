/*
BSD 2-Clause License

Copyright (c) 2018, lynnl

Cleaned up and refactored for r2 in 2021: condret

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef RBTREE_H
#define RBTREE_H

#include <r_util.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_crbtree_node {
	struct r_crbtree_node *link[2];
	struct r_crbtree_node *parent;
	ut32 red;
	void *data;
} RRBNode;

typedef int (*RRBComparator) (void *incoming, void *in, void *user);
typedef void (*RRBFree) (void *data);

typedef struct r_crbtree_t {
	RRBNode *root;
	size_t size;
	RRBFree free;
} RRBTree;

R_API RRBTree *r_crbtree_new(RRBFree freefn);
R_API void r_crbtree_clear(RRBTree *tree);
R_API void r_crbtree_free(RRBTree *tree);
R_API RRBNode *r_crbtree_find_node(RRBTree *tree, void *data, RRBComparator cmp, void *user);
R_API void *r_crbtree_find(RRBTree *tree, void *data, RRBComparator cmp, void *user);
R_API bool r_crbtree_insert(RRBTree *tree, void *data, RRBComparator cmp, void *user);
R_API void *r_crbtree_take(RRBTree *tree, void *data, RRBComparator cmp, void *user);
R_API bool r_crbtree_delete(RRBTree *tree, void *data, RRBComparator cmp, void *user);
R_API RRBNode *r_crbtree_first_node(RRBTree *tree);
R_API RRBNode *r_crbtree_last_node(RRBTree *tree);
R_API RRBNode *r_rbnode_next(RRBNode *node);
R_API RRBNode *r_rbnode_prev(RRBNode *node);

#define r_crbtree_foreach(tree, iter, stuff) \
	for (iter = tree? r_crbtree_first_node (tree): NULL, stuff = iter? iter->data: NULL; iter; iter = r_rbnode_next (iter), stuff = iter? iter->data: NULL)

#ifdef __cplusplus
}
#endif

#endif /* RBTREE_H */
