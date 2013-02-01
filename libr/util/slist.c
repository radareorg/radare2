/* radare - LGPL - Copyright 2013 - pancake */
// -- work in progress -- //

#include "r_util.h"
#include "r_slist.h"


R_API RSList *r_slist_new () {
	RSList *s = R_NEW0 (RSList);
	s->list = r_list_new ();
	return s;
}

R_API void r_slist_free (RSList *s) {
	free (s->items);
	free (s->alloc);
	r_list_free (s->list);
	free (s);
}

R_API int r_slist_get_slot(RSList *s, ut64 addr) {
	if (s->from == 0 && s->from == s->to)
		return -1;
	if (addr < s->from || addr > s->to)
		return -1;
	return (addr-s->from)/ s->mod;
}

R_API RSList *r_slist_add (RSList *s, void *data, ut64 from, ut64 to) {
	ut64 at = from;
	int slot, lastslot;
	RSListItem item = {0};
	RSListItem **items;
	// append to list
	item.from = from;
	item.to = to;
	item.data = data;
	r_list_append (s->list, &item); // item must be alloacted by slices
	// find slot
	slot = r_slist_get_slot(s, from);
	if (slot<0) {
		//r_slist_optimize ();
		return NULL;
	}
	while (at<to && slot < s->nitems) {
		lastslot = s->last[slot];
		if (lastslot == s->lastslot) {
			// must optimize and exit
			//r_slist_optimize();
			return NULL;
		}
		s->items[slot][lastslot] = item;
		s->last[slot]++;
		at += s->mod;
		slot++;
	}
	// append to slot
	//RSlistItem *item = additem (data, from, to);
	//r_list_append (item);
	s->items++;
	return NULL;
}

R_API RSListItem **r_slist_get (RSList *s, ut64 addr) {
	int idx;
	ut64 base;
	if (s->from == 0 && s->from == s->to)
		return NULL;
	if (addr < s->from || addr > s->to)
		return NULL;
	base = addr - s->from;
	idx = base / s->mod;
	return s->items[idx];
}

// r_slist_get_iter()
// r_slist_iter_has_next()

R_API void r_slist_del (RSList *s, RSListItem *p) {
	// delete from s->list
	// remove lists
}

R_API void *r_slist_get_at (RSList *list, ut64 addr) {
	return NULL;
}

// called on add and del
R_API void r_slist_optimize (RSList *s) {
	void *ptr;
	RListIter *iter;
	ut64 min, max, mid;
	int begin = 1;

#if 0
	r_list_foreach (s->list, iter, ptr) {
		if (begin) {
			min = ptr->from;
			max = ptr->to;
			begin = 0;
		} else {
			if (ptr->from < min)
				min = ptr->from;
			if (ptr->to > max)
				max = ptr->to;
		}
	}
#endif
	
	// find better distribution
	r_list_foreach (s->list, iter, ptr) {
		//...
	}
}
