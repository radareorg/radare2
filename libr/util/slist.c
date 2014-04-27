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
	if (s->min == 0 && s->min == s->max)
		return -1;
	if (addr < s->min || addr > s->max)
		return -1;
	return (addr-s->min) / s->mod;
}

static RSListItem *get_new_item () {
	// TODO: use slices here!
	return malloc (sizeof (RSListItem));
}

R_API RSList *r_slist_add (RSList *s, void *data, ut64 from, ut64 to) {
	ut64 at = from;
	int slot, lastslot;
	RSListItem *item = get_new_item ();
	//RSListItem **items;
	// append to list
	item->from = from;
	item->to = to;
	item->data = data;
	r_list_append (s->list, item); // item must be alloacted by slices
	// find slot
	slot = r_slist_get_slot (s, from);
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
	if (s->min == 0 && s->min == s->max)
		return NULL;
	if (addr < s->min || addr > s->max)
		return NULL;
	base = addr - s->min;
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
	RSListItem *ptr;
	RListIter *iter;
	ut64 min, max;
	int begin = 1;

	s->nitems = 0;
	min = max = 0;
	r_list_foreach (s->list, iter, ptr) {
		s->nitems++;
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

	eprintf ("MIN %d\nMAX %d\n", (int)min, (int)max);

	s->min = min;
	s->max = max;
	s->mod = ((max-min));
	s->items = malloc (1+ (sizeof (void*) * s->nitems));
	//eprintf ("MOD %d (block size)\n", s->mod);
// store integers as indexes inside the allocated heap

#if 0
	RArray *items = r_array_new (10, sizeof (RSListItem));
	RSListItem *idx = r_array_add (items);
		idx->from = from;
		idx->to = to;
		idx->data = data;
	items->length;
	items->capacity;
	int lidx = r_array_last_index (items);
	r_array_add (idx);

[  ptr ] [ -1 ] [  int ]
|   -1 |  '--'  |   -1 |

	items = malloc (sizeof (RSListItem), );
	items_capacity
	RSListItem *itm = getitem (s->items[0]);
	RSListItem item;
	item.data = ptr; // RAnalFunction;
	RSListItem *items;
INPUT
	number of items
	min offset
	max offset
OUTPUT
#endif
	// find better distribution
	r_list_foreach (s->list, iter, ptr) {
		//...
	}
}

#if 0
typedef struct {
	
} SListStore;
typedef struct {
	IntArray news;
	ItemArray heap;
	IntArray deleted;
} SList;
-+- Store     # We need N stores to avoid too sparsing
 |- min       |_
 |- max       |_
 `- data      |_
-+- QueueList # new additions are here
 `- idxlist   |_
--- RangeCmp  # user provided comparator function
--- IndexList # 
--- Storage   # Heap Array storing all elements
              | We always use 
--- StoreList # Heap Array of integers pointing to storage
              | we can probably just store a list of removed
              | items and the length
#endif
