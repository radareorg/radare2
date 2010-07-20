#ifndef _INCLUDE_R_FLAGS_H_
#define _INCLUDE_R_FLAGS_H_

#define USE_BTREE 0

#if USE_BTREE
#include <btree.h>
#endif

#include <r_types.h>
#include "list.h"

#define R_FLAG_NAME_SIZE 128
#define R_FLAG_BUF_SIZE 128
#define R_FLAG_SPACES_MAX 128 

typedef struct r_flag_item_t {
	char name[R_FLAG_NAME_SIZE];
	ut64 namehash;
	ut64 offset;
	ut64 size;
	int format; // ??? 
	int space;
	char *cmd;
	unsigned char data[R_FLAG_BUF_SIZE]; // only take a minor part of the data
	struct list_head list;
} RFlagItem;

typedef struct r_flag_t {
	int space_idx;
	int space_idx2;
	const char *space[R_FLAG_SPACES_MAX];
#if USE_BTREE
	struct btree_node *tree; /* index by offset */
	struct btree_node *ntree; /* index by name */
#endif
	struct list_head flags;
} RFlag;

#ifdef R_API
R_API struct r_flag_t * r_flag_new();
R_API RFlag * r_flag_free(RFlag *f);
R_API void r_flag_list(struct r_flag_t *f, int rad);
R_API RFlagItem *r_flag_get(RFlag *f, const char *name);
R_API RFlagItem *r_flag_get_i(RFlag *f, ut64 off);
R_API int r_flag_unset(struct r_flag_t *f, const char *name);
R_API int r_flag_unset_i(struct r_flag_t *f, ut64 addr);
R_API int r_flag_set(struct r_flag_t *fo, const char *name, ut64 addr, ut32 size, int dup);
R_API int r_flag_sort(RFlag *f, int namesort);
R_API int r_flag_name_check(const char *name);
R_API int r_flag_name_filter(char *name);
R_API void r_flag_item_rename(RFlagItem *item, const char *name);

/* spaces */
R_API const char *r_flag_space_get(RFlag *f, int idx);
R_API void r_flag_space_set(RFlag *f, const char *name);
R_API void r_flag_space_list(RFlag *f);
#endif

#endif
