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

typedef struct r_rbtree_node {
	struct r_rbtree_node *link[2];
	struct r_rbtree_node *parent;
	ut32 red;
	void *data;
} RRBNode;

typedef int (*RRBComparator) (void *incoming, void *in, void *user);
typedef void (*RRBFree) (void *data);

typedef struct r_rbtree_t {
	RRBNode *root;
	size_t size;
	RRBFree free;
} RRBTree;

R_API RBTree *r_rbtree_new(RRBFree freefn);
R_API void r_rbtree_clear(RRBTree *tree);
R_API void r_rbtree_free(RRBTree *tree);
R_API RRBNode *r_rbtree_find_node(RRBTree *tree, void *data, RRBComparator cmp, void *user);
R_API void *r_rbtree_find(RRBTree *tree, void *data, RRBComparator cmp, void *user);
R_API bool r_rbtree_insert(RRBTree *tree, void *data, RRBComparator cmp, void *user);
R_API bool r_rbtree_delete(RRBTree *tree, void *data, RRBComparator cmp, void *user);
R_API RRBNode *r_rbtree_first_node(RRBTree *tree);
R_API RRBNode *r_rbtree_last_node(RRBTree *tree);
R_API RRBNode *r_rbnode_next(RRBNode *node);
R_API RRBNode *r_rbnode_prev(RRBNode *node);

#ifdef __cplusplus
}
#endif

#endif /* RBTREE_H */
