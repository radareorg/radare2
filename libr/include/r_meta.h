#ifndef _INCLUDE_R_META_H_
#define _INCLUDE_R_META_H_

#include <r_types.h>
#include <r_util.h>
#include <list.h>

typedef struct r_meta_count_t {
	int functions;
	int xref_code;
	int xref_data;
	/* TODO: ... */
} RMetaCount;

#if 0
TODO:
We need a way to determine sections for other architectures, so we will
be able to read a mixed x86/ppc mach0 binary in a shot.
We also need a way to determine if the folder is opened or closed (bool)
We also need to specify which type of data is the contents of a data block
  (hexdump, structure, ...) select print format command
#endif

/* old data_t */
typedef struct r_meta_item_t {
	ut64 from;
	ut64 to;
	ut64 size;
	int type;
//	int times;
	char *str;
	struct list_head list;
} RMetaItem;

typedef struct r_meta_t {
	struct list_head data;
//	struct reflines_t *reflines = NULL;
//	struct list_head comments;
//	struct list_head xrefs;
} RMeta;

enum {
	R_META_WHERE_PREV = -1,
	R_META_WHERE_HERE = 0,
	R_META_WHERE_NEXT = 1,
};

enum {
	R_META_ANY = -1,
	/* content type */
	R_META_DATA = 'd',
	R_META_CODE = 'c',
	R_META_STRING = 's',
	R_META_STRUCT = 'm',
	/* line */
	R_META_FUNCTION = 'F',
	R_META_COMMENT = 'C',
	R_META_FOLDER = 'f', // XXX deprecate?
	R_META_XREF_CODE = 'x',
	R_META_XREF_DATA = 'X',
};

#ifdef R_API
R_API struct r_meta_t *r_meta_new();
R_API void r_meta_free(struct r_meta_t *m);
R_API int r_meta_count(struct r_meta_t *m, int type, ut64 from, ut64 to, struct r_meta_count_t *c);
R_API char *r_meta_get_string(struct r_meta_t *m, int type, ut64 addr);
R_API int r_meta_del(struct r_meta_t *m, int type, ut64 from, ut64 size, const char *str);
R_API int r_meta_add(struct r_meta_t *m, int type, ut64 from, ut64 size, const char *str);
R_API struct r_meta_item_t *r_meta_find(struct r_meta_t *m, ut64 off, int type, int where);
R_API const char *r_meta_type_to_string(int type);
R_API int r_meta_list(struct r_meta_t *m, int type);
#endif

#endif
