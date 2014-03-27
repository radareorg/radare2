#ifndef R2_BTREE_H
#define R2_BTREE_H

#include "r_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct btree_node {
	void *data;
	int hits; // profiling
	struct btree_node *left;
	struct btree_node *right;
};

#define BTREE_CMP(x) int (* x )(const void *, const void *)
#define BTREE_DEL(x) int (* x )(void *)

#ifdef R_API
R_API void btree_init(struct btree_node **T);
R_API struct btree_node *btree_remove(struct btree_node *p, BTREE_DEL(del));
R_API void *btree_search(struct btree_node *proot, void *x, BTREE_CMP(cmp), int parent);
R_API int btree_del(struct btree_node *proot, void *x, BTREE_CMP(cmp), BTREE_DEL(del));
R_API void *btree_get(struct btree_node *proot, void *x, BTREE_CMP(cmp));
R_API void btree_insert(struct btree_node **T, struct btree_node *p, BTREE_CMP(cmp));
R_API void btree_add(struct btree_node **T, void *e, BTREE_CMP(cmp));
R_API void btree_cleartree(struct btree_node *proot, BTREE_DEL(del));
#endif

#ifdef __cplusplus
}
#endif

#endif
