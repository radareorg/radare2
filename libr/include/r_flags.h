#ifndef _INCLUDE_R_FLAGS_H_
#define _INCLUDE_R_FLAGS_H_

#include <r_types.h>
#include "list.h"

#define R_FLAG_NAME_SIZE 128
#define R_FLAG_BUF_SIZE 128
#define R_FLAG_SPACES_MAX 128 

struct r_flag_item_t {
	char name[R_FLAG_NAME_SIZE];
	u64 offset;
	u64 size;
	int format; // ??? 
	int space;
	const char *cmd;
	unsigned char data[R_FLAG_BUF_SIZE]; // only take a minor part of the data
	struct list_head list;
};

struct r_flag_t {
	int space_idx;
	int space_idx2;
	u64 base;
	const char *space[R_FLAG_SPACES_MAX];
	struct list_head flags;
};

R_API int r_flag_init(struct r_flag_t *f);
R_API int r_flag_set_base(struct r_flag_t *f, u64 base);
R_API struct r_flag_item_t *r_flag_list(struct r_flag_t *f, int rad);
R_API struct r_flag_item_t *r_flag_get(struct r_flag_t *f, const char *name);
R_API struct r_flag_item_t *r_flag_get_i(struct r_flag_t *f, u64 off);
R_API int r_flag_unset(struct r_flag_t *f, const char *name);
R_API int r_flag_set(struct r_flag_t *fo, const char *name, u64 addr, u32 size, int dup);
R_API int r_flag_name_check(const char *name);
R_API int r_flag_name_filter(char *name);

/* spaces */
R_API const const char *r_flag_space_get(struct r_flag_t *f, int idx);
R_API void r_flag_space_set(struct r_flag_t *f, const char *name);
R_API void r_flag_space_list(struct r_flag_t *f);

#endif
