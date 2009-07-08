#ifndef _INCLUDE_R_META_H_
#define _INCLUDE_R_META_H_

#include <r_types.h>
#include <r_util.h>
#include <list.h>

struct r_meta_count_t {
	int functions;
	int xref_code;
	int xref_data;
	/* TODO: ... */
};

#if 0
TODO:
We need a way to determine sections for other architectures, so we will
be able to read a mixed x86/ppc mach0 binary in a shot.
We also need a way to determine if the folder is opened or closed (bool)
We also need to specify which type of data is the contents of a data block
  (hexdump, structure, ...) select print format command
#endif

/* old data_t */
struct r_meta_item_t {
	ut64 from;
	ut64 to;
	ut64 size;
	int type;
//	int times;
	char *str;
	struct list_head list;
};

struct r_meta_t {
	struct list_head data;
//	struct reflines_t *reflines = NULL;
//	struct list_head comments;
//	struct list_head xrefs;
};

enum {
	R_META_WHERE_PREV = -1,
	R_META_WHERE_HERE = 0,
	R_META_WHERE_NEXT = 1,
};

enum {
	R_META_ANY = -1,
	/* content type */
	R_META_DATA = 0,
	R_META_CODE,
	R_META_STRING,
	R_META_STRUCT,
	/* line */
	R_META_FUNCTION,
	R_META_COMMENT,
	R_META_FOLDER,
	R_META_XREF_CODE,
	R_META_XREF_DATA,
};

int r_meta_init(struct r_meta_t *m);
struct r_meta_t *r_meta_new();
void r_meta_free(struct r_meta_t *m);
int r_meta_count(struct r_meta_t *m, int type, ut64 from, ut64 to, struct r_meta_count_t *c);
char *r_meta_get_string(struct r_meta_t *m, int type, ut64 addr);
int r_meta_del(struct r_meta_t *m, int type, ut64 from, ut64 size, const char *str);
int r_meta_add(struct r_meta_t *m, int type, ut64 from, ut64 size, const char *str);
struct r_meta_item_t *r_meta_find(struct r_meta_t *m, ut64 off, int type, int where);
const char *r_meta_type_to_string(int type);
int r_meta_list(struct r_meta_t *m, int type);

#endif
