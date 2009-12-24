#ifndef _INCLUDE_R_FLAGS_H_
#define _INCLUDE_R_FLAGS_H_

#define USE_BTREE 1

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
	int namehash;
	ut64 offset;
	ut64 size;
	int format; // ??? 
	int space;
	const char *cmd;
	unsigned char data[R_FLAG_BUF_SIZE]; // only take a minor part of the data
	struct list_head list;
} rFlagItem;

typedef struct r_flag_t {
	int space_idx;
	int space_idx2;
	ut64 base;
	const char *space[R_FLAG_SPACES_MAX];
#if USE_BTREE
	struct btree_node *tree; /* index by offset */
	struct btree_node *ntree; /* index by name */
#endif
	struct list_head flags;
} rFlag;

#ifdef R_API
R_API int r_flag_init(struct r_flag_t *f);
R_API int r_flag_set_base(struct r_flag_t *f, ut64 base);
R_API struct r_flag_item_t *r_flag_list(struct r_flag_t *f, int rad);
R_API struct r_flag_item_t *r_flag_get(struct r_flag_t *f, const char *name);
R_API struct r_flag_item_t *r_flag_get_i(struct r_flag_t *f, ut64 off);
R_API int r_flag_unset(struct r_flag_t *f, const char *name);
R_API int r_flag_set(struct r_flag_t *fo, const char *name, ut64 addr, ut32 size, int dup);
R_API int r_flag_name_check(const char *name);
R_API int r_flag_name_filter(char *name);

/* spaces */
R_API const const char *r_flag_space_get(struct r_flag_t *f, int idx);
R_API void r_flag_space_set(struct r_flag_t *f, const char *name);
R_API void r_flag_space_list(struct r_flag_t *f);
#endif

#endif
