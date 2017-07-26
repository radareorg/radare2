#ifndef R2_FLAGS_H
#define R2_FLAGS_H

#include <r_types.h>
#include <r_util.h>
#include <r_list.h>
#include <r_skiplist.h>

#ifdef __cplusplus
extern "C" {
#endif

// TODO: rename to r_flag_XXX api
R_LIB_VERSION_HEADER(r_flag);

#define R_FLAG_NAME_SIZE 512
#define R_FLAG_SPACES_MAX 128

/* zones.c */

#define R_FLAG_ZONE_USE_SDB 0

typedef struct r_flag_zone_item_t {
	ut64 from;
	ut64 to;
#if R_FLAG_ZONE_USE_SDB
	const char *name;
#else
	char *name;
#endif
} RFlagZoneItem;

/* flag.c */

typedef struct r_flags_at_offset_t {
	ut64 off;
	RList *flags;   /* list of RFlagItem at offset */
} RFlagsAtOffset;

typedef struct r_flag_item_t {
	char *name;     /* unique name, escaped to avoid issues with r2 shell */
	char *realname; /* real name, without any escaping */
	ut64 offset;    /* offset flagged by this item */
	ut64 size;      /* size of the flag item */
	int space;      /* flag space this item belongs to */
	char *color;    /* item color */
	char *comment;  /* item comment */
	char *alias;    /* used to define a flag based on a math expression (e.g. foo + 3) */
} RFlagItem;

typedef struct r_flag_t {
	st64 base;         /* base address for all flag items */
	int space_idx;     /* index of the selected space in spaces array */
	bool space_strict; /* when true returned flag items must belong to the selected space */
	char *spaces[R_FLAG_SPACES_MAX]; /* array of flag spaces */
	RNum *num;
	RSkipList *by_off; /* flags sorted by offset, value=RFlagsAtOffset */
	SdbHash *ht_name; /* hashmap key=item name, value=RList of items */
	RList *flags;   /* list of RFlagItem contained in the flag */
	RList *spacestack;
	PrintfCallback cb_printf;
#if R_FLAG_ZONE_USE_SDB
	Sdb *zones;
#else
	RList *zones;
#endif
} RFlag;

/* compile time dependency */

typedef bool (*RFlagExistAt)(RFlag *f, const char *flag_prefix, ut16 fp_size, ut64 off);
typedef RFlagItem* (*RFlagGet)(RFlag *f, const char *name);
typedef RFlagItem* (*RFlagGetAt)(RFlag *f, ut64 addr, bool closest);
typedef RFlagItem* (*RFlagSet)(RFlag *f, const char *name, ut64 addr, ut32 size);
typedef int (*RFlagSetSpace)(RFlag *f, const char *name);

typedef struct r_flag_bind_t {
	int init;
	RFlag *f;
	RFlagExistAt exist_at;
	RFlagGet get;
	RFlagGetAt get_at;
	RFlagSet set;
	RFlagSetSpace set_fs;
} RFlagBind;

#define r_flag_bind_init(x) memset(&x,0,sizeof(x))
R_API int r_flag_bind(RFlag *io, RFlagBind *bnd);

#ifdef R_API
R_API RFlag * r_flag_new(void);
R_API RFlag * r_flag_free(RFlag *f);
R_API void r_flag_list(RFlag *f, int rad, const char *pfx);
R_API bool r_flag_exist_at(RFlag *f, const char *flag_prefix, ut16 fp_size, ut64 off);
R_API RFlagItem *r_flag_get(RFlag *f, const char *name);
R_API RFlagItem *r_flag_get_i(RFlag *f, ut64 off);
R_API RFlagItem *r_flag_get_i2(RFlag *f, ut64 off);
R_API RFlagItem *r_flag_get_at(RFlag *f, ut64 off, bool closest);
R_API const RList* /*<RFlagItem*>*/ r_flag_get_list(RFlag *f, ut64 off);
R_API char *r_flag_get_liststr(RFlag *f, ut64 off);
R_API int r_flag_unset(RFlag *f, RFlagItem *item);
R_API int r_flag_unset_name(RFlag *f, const char *name);
R_API int r_flag_unset_off(RFlag *f, ut64 addr);
R_API void r_flag_unset_all (RFlag *f);
R_API RFlagItem *r_flag_set(RFlag *fo, const char *name, ut64 addr, ut32 size);
R_API RFlagItem *r_flag_set_next(RFlag *fo, const char *name, ut64 addr, ut32 size);
R_API int r_flag_sort(RFlag *f, int namesort);
R_API void r_flag_item_set_alias(RFlagItem *item, const char *alias);
R_API void r_flag_item_free (RFlagItem *item);
R_API void r_flag_item_set_comment(RFlagItem *item, const char *comment);
R_API void r_flag_item_set_realname(RFlagItem *item, const char *realname);
R_API int r_flag_unset_glob(RFlag *f, const char *name);
R_API int r_flag_rename(RFlag *f, RFlagItem *item, const char *name);
R_API int r_flag_relocate (RFlag *f, ut64 off, ut64 off_mask, ut64 to);
R_API int r_flag_move (RFlag *f, ut64 at, ut64 to);
R_API const char *r_flag_color(RFlag *f, RFlagItem *it, const char *color);

/* spaces */
R_API int r_flag_space_get(RFlag *f, const char *name);
R_API const char *r_flag_space_get_i(RFlag *f, int idx);
R_API const char *r_flag_space_cur(RFlag *f);
R_API int r_flag_space_set(RFlag *f, const char *name);
R_API int r_flag_count (RFlag *f, const char *name);
R_API int r_flag_space_unset (RFlag *f, const char *fs);
R_API int r_flag_space_list(RFlag *f, int mode);
R_API int r_flag_space_rename (RFlag *f, const char *oname, const char *nname);
R_API int r_flag_space_pop(RFlag *f);
R_API int r_flag_space_push(RFlag *f, const char *name);
R_API int r_flag_space_stack_list(RFlag *f, int mode);

/* zones */

R_API void r_flag_zone_item_free(void *a);
R_API bool r_flag_zone_add(RFlag *fz, const char *name, ut64 addr);
R_API bool r_flag_zone_del(RFlag *fz, const char *name);
R_API bool r_flag_zone_around(RFlag *fz, ut64 addr, const char **prev, const char **next);
R_API bool r_flag_zone_list(RFlag *fz, int mode);
R_API bool r_flag_zone_reset(RFlag *f);

#endif

#ifdef __cplusplus
}
#endif

#endif
