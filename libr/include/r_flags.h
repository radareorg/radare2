#ifndef _INCLUDE_R_FLAGS_H_
#define _INCLUDE_R_FLAGS_H_

#define USE_BTREE 0
/* FUCK YEAH */
#define USE_HT 1

#if USE_BTREE
#include <btree.h>
#endif

#include <r_types.h>
#include <r_util.h>
#include <r_list.h>

#define R_FLAG_NAME_SIZE 256
#define R_FLAG_BUF_SIZE 256
#define R_FLAG_SPACES_MAX 256

typedef struct r_flag_item_t {
	char name[R_FLAG_NAME_SIZE];
	ut64 namehash;
	ut64 offset;
	ut64 size;
	int format; // ???
	int space;
	char *cmd;
	char *comment;
	unsigned char data[R_FLAG_BUF_SIZE]; // only take a minor part of the data
} RFlagItem;

typedef struct r_flag_t {
	st64 base;
	int space_idx;
	int space_idx2;
	char *spaces[R_FLAG_SPACES_MAX];
#if USE_HT
	RHashTable64 *ht_off;
	RHashTable64 *ht_name;
#endif
#if USE_BTREE
	struct btree_node *tree; /* index by offset */
	struct btree_node *ntree; /* index by name */
#endif
	RList *flags;
} RFlag;

#ifdef R_API
R_API RFlag * r_flag_new();
R_API RFlag * r_flag_free(RFlag *f);
R_API void r_flag_list(RFlag *f, int rad);
R_API RFlagItem *r_flag_get(RFlag *f, const char *name);
R_API RFlagItem *r_flag_get_i(RFlag *f, ut64 off);
R_API int r_flag_unset(RFlag *f, const char *name, RFlagItem *p);
R_API int r_flag_unset_i(RFlag *f, ut64 addr, RFlagItem *p);
R_API int r_flag_set(RFlag *fo, const char *name, ut64 addr, ut32 size, int dup);
R_API int r_flag_sort(RFlag *f, int namesort);
R_API int r_flag_item_set_name(RFlagItem *item, const char *name);
R_API void r_flag_item_free (RFlagItem *item);
R_API void r_flag_item_set_comment(RFlagItem *item, const char *comment);
R_API int r_flag_unset_glob(RFlag *f, const char *name);
R_API int r_flag_rename(RFlag *f, RFlagItem *item, const char *name);
R_API RFlagItem *r_flag_get_at(RFlag *f, ut64 off);

/* spaces */
R_API int r_flag_space_get(RFlag *f, const char *name);
R_API const char *r_flag_space_get_i(RFlag *f, int idx);
R_API void r_flag_space_set(RFlag *f, const char *name);
R_API int r_flag_space_list(RFlag *f, int mode);
R_API int r_flag_space_rename (RFlag *f, const char *oname, const char *nname);
#endif

#endif
