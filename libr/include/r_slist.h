/* radare - LGPL - Copyright 2013 - pancake */
/* sliced list */

#ifndef R2_SLIST_H
#define R2_SLIST_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_slist_item_t {
	ut64 from;
	ut64 to;
	void *data;
} RSListItem;

typedef struct r_slist_t {
	RList *list;
	ut64 min;
	ut64 max;
	int mod;
	int *last;
	int lastslot;
	int nitems;
	RSListItem ***items;
	void **alloc;
} RSList;

R_API RSList *r_slist_new ();
R_API void r_slist_free (RSList *s);
R_API int r_slist_get_slot(RSList *s, ut64 addr);
R_API RSList *r_slist_add (RSList *s, void *data, ut64 from, ut64 to);
R_API RSListItem **r_slist_get (RSList *s, ut64 addr);
R_API void r_slist_del (RSList *s, RSListItem *p);
R_API void *r_slist_get_at (RSList *list, ut64 addr);
R_API void r_slist_optimize (RSList *s);

#ifdef __cplusplus
}
#endif

#endif
