
/* sliced list */

typedef struct r_slist_item_t {
	ut64 from;
	ut64 to;
	void *data;
} RSListItem;

typedef struct r_slist_t {
	RList *list;
	ut64 from;
	ut64 to;
	int mod;
	int nitems;
	int *last;
	int lastslot;
	RSListItem **items;
	void **alloc;
} RSList;
