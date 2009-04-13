/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_bp.h>
#include "../config.h"

static struct r_bp_handle_t *bp_static_plugins[] = 
	{ R_BP_STATIC_PLUGINS };

R_API int r_bp_init(struct r_bp_t *bp)
{
	int i;
	bp->nbps = 0;
fprintf(stderr, "bp.init()\n");
	bp->cur = NULL;
	INIT_LIST_HEAD(&bp->bps);
	for(i=0;bp_static_plugins[i];i++)
		r_bp_handle_add(bp, bp_static_plugins[i]);
	return R_TRUE;
}

R_API struct r_bp_t *r_bp_new()
{
	struct r_bp_t *bp = MALLOC_STRUCT(struct r_bp_t);
	r_bp_init(bp);
	return bp;
}

R_API int r_bp_handle_del(struct r_bp_t *bp, const char *name)
{
#warning TODO: r_bp_handle_del
	return R_FALSE;
}

R_API int r_bp_handle_add(struct r_bp_t *bp, struct r_bp_handle_t *foo)
{
	struct list_head *pos;
	if (bp == NULL) {
		eprintf("Cannot add plugin because dbg->bp is null and/or handle is null\n");
		return R_FALSE;
	}
	/* avoid dupped plugins */
	list_for_each_prev(pos, &bp->bps) {
		struct r_bp_handle_t *h = list_entry(pos, struct r_bp_handle_t, list);
		if (!strcmp(h->name, foo->name))
			return R_FALSE;
	}
	bp->nbps++;
	list_add_tail(&(foo->list), &(bp->bps));
	return R_TRUE;
}

R_API int r_bp_handle_set(struct r_bp_t *bp, const char *name)
{
	struct list_head *pos;
	list_for_each_prev(pos, &bp->bps) {
		struct r_bp_handle_t *h = list_entry(pos, struct r_bp_handle_t, list);
		if (!strcmp(h->name, name)) {
			bp->cur = h;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_bp_getbytes(struct r_bp_t *bp, u8 *buf, int len, int endian, int idx)
{
	int i;
	struct r_bp_arch_t *b;
	if (bp->cur) {
		/* XXX: can be buggy huh : infinite loop is possible */
		for(i=0;1;i++) {
			b = &bp->cur->bps[i%bp->cur->nbps];
			if (b->endian == endian && idx%(i+1)==0) {
				for(i=0;i<len;) {
					memcpy(buf+i, b->bytes, len);
					i += b->length;
				}
				return R_TRUE;
			}
		}
	}
	return R_FALSE;
}

R_API int r_bp_set_trace(struct r_bp_t *bp, u64 addr, int set)
{
	struct list_head *pos;
	struct r_bp_item_t *b;
	list_for_each(pos, &bp->bps) {
		b = list_entry(pos, struct r_bp_item_t, list);
		if (addr >= b->addr && addr <= b->addr+b->size) {
			b->trace = set;
			return R_TRUE;
		}
	}
	return R_TRUE;
}

R_API int r_bp_set_trace_bp(struct r_bp_t *bp, u64 addr, int set)
{
	bp->trace_all = set;
	bp->trace_bp = addr;
	return R_TRUE;
}

R_API struct r_bp_t *r_bp_free(struct r_bp_t *bp)
{
	/* XXX : properly destroy bp list */
	free(bp);
	return NULL;
}

// TODO: rename this method!
R_API int r_bp_in(struct r_bp_t *bp, u64 addr, int rwx)
{
	struct list_head *pos;
	struct r_bp_item_t *b;

	if (bp->trace_bp == addr)
		return R_TRUE;

	list_for_each(pos, &bp->bps) {
		b = list_entry(pos, struct r_bp_item_t, list);
		if (addr >= b->addr && addr <= b->addr+b->size && rwx&b->rwx)
			return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_bp_enable(struct r_bp_t *bp, u64 addr, int set)
{
	struct list_head *pos;
	struct r_bp_item_t *b;
	list_for_each(pos, &bp->bps) {
		b = list_entry(pos, struct r_bp_item_t, list);
		if (addr >= b->addr && addr <= b->addr+b->size) {
			b->enabled = set;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

/* TODO: detect overlapping of breakpoints */
R_API struct r_bp_item_t *r_bp_add(struct r_bp_t *bp, const u8 *obytes, u64 addr, int size, int hw, int rwx)
{
	int ret;
	struct r_bp_item_t *b;
	if (r_bp_in(bp, addr, rwx)) {
		eprintf("Breakpoint already set at this address.\n");
		return NULL;
	}
	b = MALLOC_STRUCT(struct r_bp_item_t);
	b->pids[0] = 0; /* for any pid */
	b->addr = addr;
	b->size = size;
	b->enabled = 1;
	b->obytes = malloc(size);
	b->bbytes = malloc(size+16);
	memcpy(b->obytes, obytes, size);
	/* XXX: endian always in little ?!?!? */
	ret = r_bp_getbytes(bp, b->bbytes, size, 0, 0);
	if (ret == R_FALSE) {
		fprintf(stderr, "Cannot get breakpoint bytes. No r_bp_set()?\n");
		free (b->bbytes);
		free (b);
		return NULL;
	}
	b->hw = hw;
	b->trace = 0;
	bp->nbps++;
	list_add_tail(&(b->list), &bp->bps);
	return b;
}

R_API int r_bp_del(struct r_bp_t *bp, u64 addr)
{
	struct list_head *pos;
	struct r_bp_item_t *b;
	list_for_each(pos, &bp->bps) {
		b = list_entry(pos, struct r_bp_item_t, list);
		if (b->addr == addr) {
			list_del(&b->list);
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_bp_list(struct r_bp_t *bp, int rad)
{
	struct r_bp_item_t *b;
	struct list_head *pos;
	eprintf("Breakpoint list:\n");
	list_for_each(pos, &bp->bps) {
		b = list_entry(pos, struct r_bp_item_t, list);
		printf("0x%08llx - 0x%08llx %d %c%c%c %s %s %s\n",
			b->addr, b->addr+b->size, b->size,
			(b->rwx & R_BP_READ)?'r':'-',
			(b->rwx & R_BP_WRITE)?'w':'-',
			(b->rwx & R_BP_EXEC)?'x':'-',
			b->hw?"hw":"sw",
			b->trace?"trace":"break",
			b->enabled?"enabled":"disabled");
		/* TODO: Show list of pids and trace points, conditionals */
	}
	return 0;
}
