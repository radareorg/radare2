#ifndef _INCLUDE_R_META_H_
#define _INCLUDE_R_META_H_

/* old data_t */
struct r_meta_item_t {
	u64 from;
	u64 to;
	int type;
	int times;
	u64 size;
	char arg[128];
	struct list_head list;
};

struct r_meta_t {
//	struct reflines_t *reflines = NULL;
	struct list_head data;
	struct list_head comments;
	struct list_head xrefs;
};

#endif
