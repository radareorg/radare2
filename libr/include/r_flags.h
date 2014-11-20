#ifndef R2_FLAGS_H
#define R2_FLAGS_H

#define USE_BTREE 0
/* FUCK YEAH */
#define USE_HT 1

#if USE_BTREE
#include <btree.h>
#endif

#include <r_types.h>
#include <r_util.h>
#include <r_list.h>

#ifdef __cplusplus
extern "C" {
#endif

// TODO: rename to r_flags_XXX api
R_LIB_VERSION_HEADER(r_flag);

#define R_FLAG_NAME_SIZE 256
#define R_FLAG_BUF_SIZE 256
#define R_FLAG_SPACES_MAX 256

typedef struct r_flag_item_t {
	char name[R_FLAG_NAME_SIZE];
	char realname[R_FLAG_NAME_SIZE];
	ut64 namehash;
	ut64 offset;
	ut64 size;
	int format; // ???
	int space;
	char *cmd;
	char *color;
	char *comment;
	char *alias;
	unsigned char data[R_FLAG_BUF_SIZE]; // only take a minor part of the data
} RFlagItem;

typedef struct r_flag_t {
	st64 base;
	int space_idx;
	int space_idx2;
	char *spaces[R_FLAG_SPACES_MAX];
	RNum *num;
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

/* compile time dependency */

#include <r_flags.h> // compile time line, no linkage needed
typedef RFlagItem* (*RFlagGet)(RFlag *f, const char *name);
typedef RFlagItem* (*RFlagSet)(RFlag *f, const char *name, ut64 addr, ut32 size, int dup);
typedef int (*RFlagSetSpace)(RFlag *f, const char *name);

typedef struct r_flag_bind_t {
	int init;
	RFlag *f;
	RFlagGet get;
	RFlagSet set;
	RFlagSetSpace set_fs;
} RFlagBind;

#define r_flag_bind_init(x) memset(&x,0,sizeof(x))
R_API int r_flag_bind(RFlag *io, RFlagBind *bnd);

#ifdef R_API
R_API RFlag * r_flag_new();
R_API RFlag * r_flag_free(RFlag *f);
R_API void r_flag_list(RFlag *f, int rad);
R_API RFlagItem *r_flag_get(RFlag *f, const char *name);
R_API RFlagItem *r_flag_get_i(RFlag *f, ut64 off);
R_API RFlagItem *r_flag_get_i2(RFlag *f, ut64 off);
R_API const RList* /*<RFlagItem*>*/ r_flag_get_list(RFlag *f, ut64 off);
R_API int r_flag_unset(RFlag *f, const char *name, RFlagItem *p);
R_API int r_flag_unset_i(RFlag *f, ut64 addr, RFlagItem *p);
R_API RFlagItem *r_flag_set(RFlag *fo, const char *name, ut64 addr, ut32 size, int dup);
R_API int r_flag_sort(RFlag *f, int namesort);
R_API int r_flag_item_set_name(RFlagItem *item, const char *name, const char *realname);
R_API void r_flag_item_set_alias(RFlagItem *item, const char *alias);
R_API void r_flag_item_free (RFlagItem *item);
R_API void r_flag_item_set_comment(RFlagItem *item, const char *comment);
R_API int r_flag_unset_glob(RFlag *f, const char *name);
R_API int r_flag_rename(RFlag *f, RFlagItem *item, const char *name);
R_API RFlagItem *r_flag_get_at(RFlag *f, ut64 off);
R_API int r_flag_relocate (RFlag *f, ut64 off, ut64 off_mask, ut64 to);
R_API int r_flag_move (RFlag *f, ut64 at, ut64 to);
R_API const char *r_flag_color(RFlag *f, RFlagItem *it, const char *color);

/* spaces */
R_API int r_flag_space_get(RFlag *f, const char *name);
R_API const char *r_flag_space_get_i(RFlag *f, int idx);
R_API int r_flag_space_set(RFlag *f, const char *name);
R_API int r_flag_space_list(RFlag *f, int mode);
R_API int r_flag_space_rename (RFlag *f, const char *oname, const char *nname);
#endif

#ifdef __cplusplus
}
#endif

#endif
