#ifndef R2_FLAGS_H
#define R2_FLAGS_H

#include <r_types.h>
#include <r_util.h>
#include <r_list.h>
#include <r_skiplist.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_flag);

// XXX this is a soft limitation, there's no limits in the rflag api
#define R_FLAG_NAME_SIZE 512

/* zones.c */

typedef struct r_flag_zone_item_t {
	ut64 from;
	ut64 to;
	char *name;
} RFlagZoneItem;

/* flag.c */

typedef struct r_flags_at_addr_t {
	ut64 addr;
	RList *flags;   /* list of RFlagItem at addr */
} RFlagsAtOffset;

#define METAFLAG 1

#if METAFLAG
typedef struct r_flag_item_meta_t {
	char *type;
	char *color;    /* item color */
#if 0
	char *comment;  /* item comment */
	char *alias;    /* used to define a flag based on a math expression (e.g. foo + 3) */
	bool demangled; /* real name from demangling? */
#endif
} RFlagItemMeta;

typedef struct r_flag_item_t {
	ut32 id;
	char *name;     /* unique name, escaped to avoid issues with r2 shell */
	char *realname; /* real name, without any escaping */
	ut64 addr;      /* address of the flag */
	ut64 size;      /* size of the flag item */
	RSpace *space;  /* flag space this item belongs to */
	char *comment;  /* item comment */
	char *alias;    /* used to define a flag based on a math expression (e.g. foo + 3) */
	bool demangled; /* real name from demangling? */
#if 0
	char *color;    /* item color */
	char *type;
#endif
} RFlagItem;

#else

typedef struct r_flag_item_t {
	char *name;     /* unique name, escaped to avoid issues with r2 shell */
	char *realname; /* real name, without any escaping */
	bool demangled; /* real name from demangling? */
	ut64 addr;      /* address of the flag */
	ut64 size;      /* size of the flag item */
	RSpace *space;  /* flag space this item belongs to */
	char *color;    /* item color */
	char *comment;  /* item comment */
	char *alias;    /* used to define a flag based on a math expression (e.g. foo + 3) */
	char *type;
} RFlagItem;
#endif


typedef struct r_flag_t {
	RSpaces spaces;   /* handle flag spaces */
	st64 base;         /* base address for all flag items */
	bool realnames;
	Sdb *tags;
	RNum *num;
	RSkipList *by_addr; /* flags sorted by addr, value=RFlagsAtOffset */
	HtPP *ht_name; /* hashmap key=item name, value=RFlagItem */
	HtUP *ht_meta; // hashtable for the flags metadata
	PrintfCallback cb_printf;
	RList *zones;
	ut64 mask;
	RThreadLock *lock;
	ut32 lastid;
	R_DIRTY_VAR;
	// ??? RStrpool *pool; // stringpool can be tricky because removing flags wont free memory
} RFlag;

/* compile time dependency */

typedef bool (*RFlagExistAt)(RFlag *f, const char *flag_prefix, ut16 fp_size, ut64 addr);
typedef RFlagItem* (*RFlagGet)(RFlag *f, const char *name);
typedef RFlagItem* (*RFlagGetAtAddr) (RFlag *f, bool prionospace, ut64);
typedef RFlagItem* (*RFlagGetAt)(RFlag *f, ut64 addr, bool closest);
typedef const RList* (*RFlagGetList)(RFlag *f, ut64 addr);
typedef RFlagItem* (*RFlagSet)(RFlag *f, const char *name, ut64 addr, ut32 size);
typedef bool (*RFlagUnset)(RFlag *f, RFlagItem *item);
typedef bool (*RFlagUnsetName)(RFlag *f, const char *name);
typedef bool (*RFlagUnsetOff)(RFlag *f, ut64 addr);
typedef RSpace *(*RFlagSetSpace)(RFlag *f, const char *name);
typedef bool (*RFlagPopSpace)(RFlag *f);
typedef bool (*RFlagPushSpace)(RFlag *f, const char *name);

typedef bool (*RFlagItemCb)(RFlagItem *fi, void *user);

typedef struct r_flag_bind_t {
	int init;
	RFlag *f;
	RFlagExistAt exist_at;
	RFlagGet get;
	RFlagGetAt get_at;
	RFlagGetList get_list;
	RFlagSet set;
	RFlagUnset unset;
	RFlagUnsetName unset_name;
	RFlagUnsetOff unset_addr;
	RFlagSetSpace set_fs;
	RFlagPushSpace push_fs;
	RFlagPopSpace pop_fs;
} RFlagBind;

#ifdef R_API

/* flag */
R_API R_NULLABLE RFlagItemMeta *r_flag_get_meta(RFlag *f, ut32 id);
R_API RFlagItemMeta *r_flag_get_meta2(RFlag *f, ut32 id);
R_API void r_flag_del_meta(RFlag *f, ut32 id);

#define r_flag_bind_init(x) memset (&x, 0, sizeof (x))
R_API void r_flag_bind(RFlag *io, RFlagBind *bnd);
R_API RFlag *r_flag_new(void);
R_API void r_flag_free(RFlag *f);
R_API void r_flag_list(RFlag *f, int rad, const char *pfx);
R_API bool r_flag_exist_at(RFlag *f, const char *flag_prefix, ut16 fp_size, ut64 addr);
R_API RFlagItem *r_flag_get(RFlag *f, const char *name);
R_API RFlagItem *r_flag_get_in(RFlag *f, ut64 addr);
R_API RFlagItem *r_flag_get_by_spaces(RFlag *f, bool prionospace, ut64 addr, ...);
R_API RFlagItem *r_flag_get_at(RFlag *f, ut64 addr, bool closest);
R_API RList *r_flag_all_list(RFlag *f, bool by_space);
R_API const RList* /*<RFlagItem*>*/ r_flag_get_list(RFlag *f, ut64 addr);
R_API char *r_flag_get_liststr(RFlag *f, ut64 addr);
R_API bool r_flag_unset(RFlag *f, RFlagItem *item);
R_API bool r_flag_unset_name(RFlag *f, const char *name);
R_API void r_flag_item_set_type(RFlag *f, RFlagItem *fi, const char *type);
R_API bool r_flag_unset_addr(RFlag *f, ut64 addr);
R_API void r_flag_unset_all(RFlag *f);
R_API RFlagItem *r_flag_set(RFlag *fo, const char *name, ut64 addr, ut32 size);
R_API RFlagItem *r_flag_set_inspace(RFlag *f, const char *space, const char *name, ut64 addr, ut32 size);
R_API RFlagItem *r_flag_set_next(RFlag *fo, const char *name, ut64 addr, ut32 size);
R_API void r_flag_item_set_alias(RFlagItem *item, const char *alias);
R_API void r_flag_item_free(RFlagItem *item);
R_API void r_flag_item_set_comment(RFlagItem *item, const char *comment);
R_API void r_flag_item_set_realname(RFlagItem *item, const char *realname);
R_API const char *r_flag_item_set_color(RFlag *f, RFlagItem *item, R_NULLABLE const char *color);
R_API RFlagItem *r_flag_item_clone(RFlagItem *item);
R_API int r_flag_unset_glob(RFlag *f, const char *name);
R_API int r_flag_rename(RFlag *f, RFlagItem *item, const char *name);
R_API int r_flag_relocate(RFlag *f, ut64 addr, ut64 addr_mask, ut64 to);
R_API bool r_flag_move(RFlag *f, ut64 at, ut64 to);
R_API int r_flag_count(RFlag *f, const char *glob);
R_API void r_flag_foreach(RFlag *f, RFlagItemCb cb, void *user);
R_API void r_flag_foreach_prefix(RFlag *f, const char *pfx, int pfx_len, RFlagItemCb cb, void *user);
R_API void r_flag_foreach_range(RFlag *f, ut64 from, ut64 to, RFlagItemCb cb, void *user);
R_API void r_flag_foreach_glob(RFlag *f, const char *glob, RFlagItemCb cb, void *user);
R_API void r_flag_foreach_space(RFlag *f, const RSpace *space, RFlagItemCb cb, void *user);
R_API void r_flag_foreach_space_glob(RFlag *f, const char *glob, const RSpace *space, RFlagItemCb cb, void *user);

/* spaces */

static inline RSpace *r_flag_space_get(RFlag *f, const char *name) {
	return r_spaces_get (&f->spaces, name);
}

static inline RSpace *r_flag_space_cur(RFlag *f) {
	R_CRITICAL_ENTER (f);
	RSpace *sp = r_spaces_current (&f->spaces);
	R_CRITICAL_LEAVE (f);
	return sp;
}

static inline const char *r_flag_space_cur_name(RFlag *f) {
	R_CRITICAL_ENTER (f);
	const char *s = r_spaces_current_name (&f->spaces);
	R_CRITICAL_LEAVE (f);
	return s; // XXX should strdup
}

static inline RSpace *r_flag_space_set(RFlag *f, const char *name) {
	R_CRITICAL_ENTER (f);
	RSpace *s = r_spaces_set (&f->spaces, name);
	R_CRITICAL_LEAVE(f);
	return s;
}

static inline bool r_flag_space_unset(RFlag *f, const char *name) {
	R_CRITICAL_ENTER (f);
	bool res = r_spaces_unset (&f->spaces, name);
	R_CRITICAL_LEAVE(f);
	return res;
}

static inline bool r_flag_space_rename(RFlag *f, const char *oname, const char *nname) {
	R_CRITICAL_ENTER (f);
	const bool res = r_spaces_rename (&f->spaces, oname, nname);
	R_CRITICAL_LEAVE (f);
	return res;
}

static inline bool r_flag_space_push(RFlag *f, const char *name) {
	R_CRITICAL_ENTER (f);
	const bool res = r_spaces_push (&f->spaces, name);
	R_CRITICAL_LEAVE (f);
	return res;
}

static inline bool r_flag_space_pop(RFlag *f) {
	R_CRITICAL_ENTER (f);
	bool res = r_spaces_pop (&f->spaces);
	R_CRITICAL_LEAVE (f);
	return res;
}

static inline int r_flag_space_count(RFlag *f, const char *name) {
	return r_spaces_count (&f->spaces, name);
}

static inline bool r_flag_space_is_empty(RFlag *f) {
	return r_spaces_is_empty (&f->spaces);
}

#define r_flag_space_foreach(f, it, s) r_spaces_foreach (&(f)->spaces, (it), (s))

/* tags */
R_API RList *r_flag_tags_list(RFlag *f, const char *name);
R_API RList *r_flag_tags_set(RFlag *f, const char *name, const char *words);
R_API void r_flag_tags_reset(RFlag *f, const char *name);
R_API RList *r_flag_tags_get(RFlag *f, const char *name);

/* zones */

R_API void r_flag_zone_item_free(void *a);
R_API bool r_flag_zone_add(RFlag *fz, const char *name, ut64 addr);
R_API bool r_flag_zone_del(RFlag *fz, const char *name);
R_API bool r_flag_zone_around(RFlag *fz, ut64 addr, const char **prev, const char **next);
R_API bool r_flag_zone_list(RFlag *fz, int mode);
R_API bool r_flag_zone_reset(RFlag *f);
R_API RList *r_flag_zone_barlist(RFlag *f, ut64 from, ut64 bsize, int rows);

#endif

#ifdef __cplusplus
}
#endif

#endif
