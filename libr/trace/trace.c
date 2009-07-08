/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include "r_trace.h"
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int r_trace_init(struct r_trace_t *t)
{
	INIT_LIST_HEAD(&t->traces);
	t->dup = 0;
	t->tag = -1;
	t->changed = 0;
	t->num = 0;
	t->printf = printf;
	return R_TRUE;
}

struct r_trace_t *r_trace_new()
{
	struct r_trace_t *tr = MALLOC_STRUCT(struct r_trace_t);
	r_trace_init(tr);
	return tr;
}

struct r_trace_t *r_r_trace_free(struct r_trace_t *tr)
{
	r_trace_reset(tr);
	free(&tr->traces);
	free(tr);
	return NULL;
}

int r_trace_tag_get(struct r_trace_t *t)
{
	return t->tag;
}

int r_trace_tag_set(struct r_trace_t *t, int id)
{
	if (id>=-1&&id<64) {
		t->tag = id;
		return 1;
	}
	return 0;
}

int r_trace_sort(struct r_trace_t *t)
{
	struct list_head *pos, *pos2;
	struct list_head *n, *n2;
	int ch = R_FALSE;

	if (t->changed)
	list_for_each_safe(pos, n, &t->traces) {
		struct r_trace_item_t *r =
			list_entry(pos, struct r_trace_item_t, list);
		list_for_each_safe(pos2, n2, &t->traces) {
			struct r_trace_item_t *r2 =
				list_entry(pos2, struct r_trace_item_t, list);
			if ((r != r2) && (r->addr > r2->addr)) {
				list_move(pos, pos2);
				ch = R_TRUE;
			}
		}
	}
	return t->changed = ch;
}

struct r_trace_item_t *r_trace_get(struct r_trace_t *t, ut64 addr, int tag)
{
	struct list_head *pos;
	list_for_each(pos, &t->traces) {
		struct r_trace_item_t *h = list_entry(pos, struct r_trace_item_t, list);
		if (tag != -1 && !(h->tags & (1<<tag)))
			continue;
		if (h->addr == addr)
			return h;
	}
	return NULL;
}

// num of traces for an address
int r_trace_times(struct r_trace_t *tr, ut64 addr)
{
	struct r_trace_item_t *t = r_trace_get(tr, addr, tr->tag);
	return t?t->times:0;
}

int r_trace_count(struct r_trace_t *tr, ut64 addr)
{
	struct r_trace_item_t *t = r_trace_get(tr, addr, tr->tag);
	return t?t->count:0;
}

int r_trace_index(struct r_trace_t *tr, ut64 addr)
{
	int idx = -1;
	struct list_head *pos;
	list_for_each(pos, &tr->traces) {
		struct r_trace_item_t *h = list_entry
			(pos, struct r_trace_item_t, list);
		idx++;
		if (h->addr == addr)
			return idx;
	}
	return idx;
}

int r_trace_set_times(struct r_trace_t *tr, ut64 addr, int times)
{
	struct r_trace_item_t *t;
	struct list_head *pos;

	/* update times counter */
	list_for_each(pos, &tr->traces) {
		t = list_entry(pos, struct r_trace_item_t, list);
		if (t->addr == addr) {
			t->times = times;
			return 1;
		}
	}
	return 0;
}

int r_trace_add(struct r_trace_t *tr, ut64 addr, int opsize)
{
	struct r_trace_item_t *t;
	struct list_head *pos;

	/* update times counter */
	list_for_each(pos, &tr->traces) {
		t = list_entry(pos, struct r_trace_item_t, list);
		if (t->addr == addr) {
			if (tr->dup) {
				if (tr->tag != -1)
					t->tags |= tr->tag;
				++(t->times);
			} else {
				t->count = ++tr->num;
				gettimeofday(&(t->tm), NULL);
				if (tr->tag != -1)
					t->tags |= tr->tag;
				return ++(t->times);
			}
		}
	}

	t = MALLOC_STRUCT(struct r_trace_item_t);
	memset(t,'\0',sizeof(struct r_trace_item_t));
	t->addr = addr;
	t->times = 1;
	t->opsize = opsize;
	gettimeofday(&(t->tm), NULL);
	t->count = ++tr->num;
	if (tr->tag != -1)
		t->tags |= tr->tag;
	tr->changed = 1;
	list_add_tail(&(t->list), &tr->traces);

	//eprintf("new trace (0x%08x)\n", (unsigned long)addr);
	return t->times;
}

ut64 r_trace_range(struct r_trace_t *t, ut64 from, int tag)
{
	struct r_trace_item_t *h;
	ut64 last = from;
	ut64 last2 = 0LL;
	
	while(last != last2) {
		last2 = last;
		h = r_trace_get(t, last, tag);
		if (h) {
			if (tag != -1 && !(h->tags & (1<<tag)))
				continue;
			last = last + h->opsize;
		}
	}

	return last;
}

ut64 r_trace_next(struct r_trace_t *tr, ut64 from, int tag)
{
        ut64 next = U64_MAX;
        struct list_head *pos;
        struct r_trace_item_t *h;

        list_for_each(pos, &tr->traces) {
                h = list_entry(pos, struct r_trace_item_t, list);
		if (tag != -1 && !(h->tags & (1<<tag)))
			continue;
                if (h->addr > from && h->addr < next)
                        next = h->addr;
        }

        if (next == U64_MAX)
                return U64_MIN;
        return next;
}

#if 0
/* buggy version */
ut64 trace_next(ut64 from)
{
	ut64 next;
	int next_init = 0;
	struct list_head *pos;
	struct trace_t *h;

	list_for_each(pos, &traces) {
		h = list_entry(pos, struct trace_t, list);
		if (!next_init) {
			if (h->addr > from && h->addr < next) {
				next = h->addr;
				next_init = 1;
			}
			continue;
		}
		if (h->addr > from && h->addr < next)
			next = h->addr;
	}

	if (next_init == 0)
		return NULL;

	return next;
}
#endif

void r_trace_show(struct r_trace_t *tr, int plain, int tag)
{
	ut64 from = 0LL;
	ut64 last;
	char opcode[64];
	struct list_head *pos;
	struct r_trace_item_t *h;

	if (tag != -1)
		eprintf("Displaying tag: %d\n", tag+1);

	r_trace_sort(tr);
	opcode[0]='\0';
	/* get the lower address */
	list_for_each(pos, &tr->traces) {
		h = list_entry(pos, struct r_trace_item_t, list);
		if (from == 0LL)
			from = h->addr;
		if (h->addr < from)
			from = h->addr;
		if (tag != -1 && !(h->tags & (1<<tag)))
			continue;
		switch(plain) {
		case 1:
			tr->printf("0x%08llx %d %d tags=%08llx\n",
				h->addr, h->times, h->count, h->tags);
			break;
		case 2:
			//config.verbose=0;
			tr->printf("%03d %03d  ", h->times, h->count);
			sprintf(opcode, "pd 1 @ 0x%08llx", h->addr);
			tr->printf(opcode); // XXX
			// TODO: disassemble opcode here !!! WTF!
			//radare_cmd_raw(opcode, 0);
			//radare_read_at(h->addr, bytes, 32);
			//udis_arch_string(config.arch, opcode, bytes, config.endian, h->addr, 32, 0);
			break;
		}
	}
	if (plain>0)
		return;

	while(from) {
		last = r_trace_range(tr, from, tag);
		if (last == from)
			break;
		// TODO: show timestamps
		if (plain==0)
			tr->printf("0x%08llx - 0x%08llx\n", from, last);
		else tr->printf("ar+ 0x%08llx 0x%08llx\n", from, last);
		from = r_trace_next(tr, last, tag);
	}
}

void r_trace_reset(struct r_trace_t *tr)
{
	struct list_head *pos;
	struct r_trace_item_t *h;
	list_for_each(pos, &tr->traces) {
		h = list_entry(pos, struct r_trace_item_t, list);
		free(h);
	}
	INIT_LIST_HEAD(&tr->traces);
}

int r_trace_get_between(struct r_trace_t *tr, ut64 from, ut64 to)
{
	int ctr = 0;
	struct list_head *pos;
	struct r_trace_item_t *h;

	/* get the lower address */
	list_for_each(pos, &tr->traces) {
		h = list_entry(pos, struct r_trace_item_t, list);
		if (tr->tag != -1 && !(h->tags & (1<<tr->tag)))
			continue;
		if (h->addr >= from && h->addr <=to)
			ctr++;
	}

	return ctr;
}
