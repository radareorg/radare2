/*
 * Copyright (C) 2008
 *       pancake <youterm.com>
 *
 * radare is part of the radare project
 *
 * radare is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * radare is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with radare; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "main.h"
#include "code.h"
#include "utils.h"
#include "print.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct list_head traces;
static unsigned int n_traces = 0;
static int trace_changed = 0;
static int trace_tag = -1;

int trace_tag_get()
{
	return trace_tag;
}

int trace_tag_set(int id)
{
	if (id>=-1&&id<64) {
		trace_tag = id;
		return 1;
	}
	return 0;
}

int trace_sort()
{
	struct list_head *pos, *pos2;
	struct list_head *n, *n2;
	int ch=0;

	if (trace_changed==0)
		return 0;

	list_for_each_safe(pos, n, &traces) {
		struct trace_t *r = list_entry(pos, struct trace_t, list);
		list_for_each_safe(pos2, n2, &traces) {
			struct trace_t *r2 = list_entry(pos2, struct trace_t, list);
			if ((r != r2) && (r->addr > r2->addr)) {
				list_move(pos, pos2);
				ch=1;
			}
		}
	}
	return trace_changed = ch;
}

struct trace_t *trace_get(u64 addr, int tag)
{
	struct list_head *pos;
	list_for_each(pos, &traces) {
		struct trace_t *h= list_entry(pos, struct trace_t, list);
		if (tag != -1 && !(h->tags & (1<<tag)))
			continue;
		if (h->addr == addr)
			return h;
	}
	return NULL;
}

// num of traces for an address
int trace_times(u64 addr)
{
	struct trace_t *t = trace_get(addr, trace_tag);
	return t?t->times:0;
}

int trace_count(u64 addr)
{
	struct trace_t *t = trace_get(addr, trace_tag);
	return t?t->count:0;
}

int trace_index(u64 addr)
{
	int idx = -1;
	struct list_head *pos;
	list_for_each(pos, &traces) {
		struct trace_t *h = list_entry(pos, struct trace_t, list);
		idx++;
		if (h->addr == addr)
			return idx;
	}
	return idx;
}

int trace_set_times(u64 addr, int times)
{
	char bytes[16];
	struct trace_t *t;
	struct list_head *pos;

	if (arch_aop == NULL)
		return -1;
	/* update times counter */
	list_for_each(pos, &traces) {
		t = list_entry(pos, struct trace_t, list);
		if (t->addr == addr) {
			t->times = times;
			return 1;
		}
	}
	return 0;
}

int trace_add(u64 addr)
{
	char bytes[16];
	struct trace_t *t;
	struct list_head *pos;

	if (arch_aop == NULL)
		return -1;

	if (config_get("trace.dup")) {
		/* update times counter */
		list_for_each(pos, &traces) {
			t = list_entry(pos, struct trace_t, list);
			if (t->addr == addr) {
				if (trace_tag != -1)
					t->tags |= trace_tag;
				++(t->times);
			}
		}
	} else {
		list_for_each(pos, &traces) {
			t = list_entry(pos, struct trace_t, list);
			if (t->addr == addr) {
				t->count = ++n_traces;
				gettimeofday(&(t->tm), NULL);
				if (trace_tag != -1)
					t->tags |= trace_tag;
				return ++(t->times);
			}
		}
	}

	t = (struct trace_t *)malloc(sizeof(struct trace_t));
	memset(t,'\0',sizeof(struct trace_t));
	t->addr = addr;
	t->times = 1;
	radare_read_at(addr, bytes, 16);
	t->opsize = arch_aop(addr, bytes, NULL);
	gettimeofday(&(t->tm), NULL);
	t->count = ++n_traces;
	if (trace_tag != -1)
		t->tags |= trace_tag;
	trace_changed = 1;
	list_add_tail(&(t->list), &traces);

	//eprintf("new trace (0x%08x)\n", (unsigned long)addr);
	return t->times;
}

u64 trace_range(u64 from, int tag)
{
	struct trace_t *h;
	u64 last = from;
	u64 last2 = 0LL;
	
	while(last != last2) {
		last2 = last;
		h = trace_get(last, tag);
		if (h) {
			if (tag != -1 && !(h->tags & (1<<tag)))
				continue;
			last = last + h->opsize;
		}
	}

	return last;
}

#if 1
u64 trace_next(u64 from, int tag)
{
        u64 next = 0xFFFFFFFFFFFFFFFFLL;
        struct list_head *pos;
        struct trace_t *h;

        list_for_each(pos, &traces) {
                h = list_entry(pos, struct trace_t, list);
		if (tag != -1 && !(h->tags & (1<<tag)))
			continue;
                if (h->addr > from && h->addr < next)
                        next = h->addr;
        }

        if (next == 0xFFFFFFFFFFFFFFFFLL)
                return 0LL;
        return next;
}
#endif

#if 0
/* buggy version */
u64 trace_next(u64 from)
{
	u64 next;
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

void trace_show(int plain, int tag)
{
	u64 from = 0LL;
	u64 last;
	char bytes[32];
	char opcode[64];
	struct list_head *pos;
	struct trace_t *h;

	if (tag != -1)
		eprintf("Displaying tag: %d\n", tag+1);

	trace_sort();
	opcode[0]='\0';
	/* get the lower address */
	list_for_each(pos, &traces) {
		h = list_entry(pos, struct trace_t, list);
		if (from == 0LL)
			from = h->addr;
		if (h->addr < from)
			from = h->addr;
		if (tag != -1 && !(h->tags & (1<<tag)))
			continue;
		switch(plain) {
		case 1:
			cons_printf("0x%08llx %d %d tags=%08llx\n",
				h->addr, h->times, h->count, h->tags);
			break;
		case 2:
			config.verbose=0;
			cons_printf("%03d %03d  ", h->times, h->count);
			sprintf(opcode, "pd 1 @ 0x%08llx", h->addr);
			radare_cmd_raw(opcode, 0);
			//radare_read_at(h->addr, bytes, 32);
			//udis_arch_string(config.arch, opcode, bytes, config.endian, h->addr, 32, 0);
			break;
		}
	}
	if (plain>0)
		return;

	while(from) {
		last = trace_range(from, tag);
		if (last == from)
			break;
		// TODO: show timestamps
		if (plain==0)
			cons_printf("0x%08llx - 0x%08llx\n", from, last);
		else cons_printf("ar+ 0x%08llx 0x%08llx\n", from, last);
		from = trace_next(last, tag);
		cons_flush();
	}
}

void trace_init()
{
	INIT_LIST_HEAD(&traces);
}

void trace_reset()
{
	struct list_head *pos;
	struct trace_t *h;
	list_for_each(pos, &traces) {
		h = list_entry(pos, struct trace_t, list);
		free(h);
	}
	INIT_LIST_HEAD(&traces);
}

int trace_get_between(u64 from, u64 to)
{
	int ctr = 0;
	struct list_head *pos;
	struct trace_t *h;

	/* get the lower address */
	list_for_each(pos, &traces) {
		h = list_entry(pos, struct trace_t, list);
		if (trace_tag != -1 && !(h->tags & (1<<trace_tag)))
			continue;
		if (h->addr >= from && h->addr <=to)
			ctr++;
	}

	return ctr;
}
