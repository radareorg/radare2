/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include "r_io.h"

// TODO: io sections should not be global!! (per io sections)
// XXX use section->foo
#define cons_printf printf

//static struct list_head sections;

void r_io_section_set(struct r_io_t *io, ut64 from, ut64 to, ut64 vaddr, ut64 paddr, int rwx, const char *comment)
{
	struct list_head *pos;
	list_for_each(pos, &io->sections) {
		struct r_io_section_t *s = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
		if (s->from == from) {
			if (to != -1)
				s->to = to;
			if (vaddr != -1)
				s->vaddr = vaddr;
			if (paddr != -1)
				s->paddr = paddr;
			if (rwx != -1)
				s->rwx = rwx;
			if (comment)
				strncpy(s->comment, comment, 254);
		}
	}
}

void r_io_section_add(struct r_io_t *io, ut64 from, ut64 to, ut64 vaddr, ut64 paddr, int rwx, const char *comment)
{
	struct r_io_section_t *s = (struct r_io_section_t *)malloc(sizeof(struct r_io_section_t));
	s->from = from;
	s->to = to;
	s->vaddr = vaddr;
	s->paddr = paddr;
	s->rwx = rwx;
	if (comment)
		strncpy(s->comment, comment, 254);
	else s->comment[0]='\0';
	list_add(&(s->list), &io->sections);
}

struct r_io_section_t *r_io_section_get_i(struct r_io_t *io, int idx)
{
	int i = 0;
	struct list_head *pos;
	list_for_each_prev(pos, &io->sections) {
		struct r_io_section_t *s = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
		if (i == idx)
			return s;
		i++;
	}
	return NULL;
}

int r_io_section_rm(struct r_io_t *io, int idx)
{
	struct r_io_section_t *s = r_io_section_get_i(io, idx);
	if (s != NULL) {
		list_del((&s->list));
		free(s);
		return 1;
	}
	return 0;
}

// TODO: implement as callback
void r_io_section_list(struct r_io_t *io, ut64 addr, int rad)
{
	int i = 0;
	//char buf[128];
	struct list_head *pos;
	list_for_each_prev(pos, &io->sections) {
		struct r_io_section_t *s = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
		if (rad) {
			cons_printf("S 0x%08llx 0x%08llx %s @ 0x%08llx\n",
				s->to-s->from, s->vaddr, s->comment, s->from);
			cons_printf("Sd 0x%08llx @ 0x%08llx\n", s->paddr, s->from);
		} else {
			cons_printf("%02d %c 0x%08llx - 0x%08llx bs=0x%08llx sz=0x%08llx phy=0x%08llx %s",
				i, (addr>=s->from && addr <=s->to)?'*':'.',
				s->from, s->to, s->vaddr, (ut64)((s->to)-(s->from)), s->paddr, s->comment);
			

// TODO: IMPLEMENT AS CALLBACK
//			if (string_flag_offset(buf, s->from))
//				cons_printf(" ; %s", buf);
#if 0
			ol = r_io_section_overlaps(s);
			if (ol != -1)
				cons_printf(" ; Overlaps with %d", ol);
#endif
			cons_printf("\n");
		}
		i++;
	}
}

void r_io_section_list_visual(struct r_io_t *io, ut64 seek, ut64 len)
{
	ut64 min = -1;
	ut64 max = -1;
	ut64 mul;
	int j, i;
	struct list_head *pos;
	int width = 78; //config.width-30;

	list_for_each(pos, &io->sections) {
		struct r_io_section_t *s = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
		if (min == -1 || s->from < min)
			min = s->from;
		if (max == -1 || s->to > max)
			max = s->to;
	}

	mul = (max-min) / width;
	if (min != -1 && mul != 0) {
		i = 0;
		list_for_each_prev(pos, &io->sections) {
			struct r_io_section_t *s = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
			cons_printf("%02d  0x%08llx |", i, s->from);
			for(j=0;j<width;j++) {
				if ((j*mul)+min >= s->from && (j*mul)+min <=s->to)
					cons_printf("#");
				else
					cons_printf("-");
			}
			cons_printf("| 0x%08llx\n", s->to);
			i++;
		}
		/* current seek */
		if (i>0 && len != 0) {
			cons_printf("=>  0x%08llx |", seek);
			for(j=0;j<width;j++) {
				if ((j*mul)+min >= seek && (j*mul)+min <= seek+len)
					cons_printf("#");
				else
					cons_printf("-");
			}
			cons_printf("| 0x%08llx\n", seek+len);
		}
	}
}

struct r_io_section_t *r_io_section_get(struct r_io_t *io, ut64 addr)
{
	struct list_head *pos;
	list_for_each(pos, &io->sections) {
		struct r_io_section_t *s = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
		if (addr >= s->from && addr <= s->to)
			return s;
	}
	return NULL;
}

ut64 r_io_section_get_paddr(struct r_io_t *io, ut64 addr)
{
	struct r_io_section_t *s = r_io_section_get(io, addr);
	if (s != NULL)
		return s->paddr;
	return -1;
}

ut64 r_io_section_get_vaddr(struct r_io_t *io, ut64 addr)
{
	struct r_io_section_t *s = r_io_section_get(io, addr);
	if (s != NULL)
		return s->vaddr;
	return -1;
}

int r_io_section_overlaps(struct r_io_t *io, struct r_io_section_t *s)
{
	int i = 0;
	struct list_head *pos;
	list_for_each_prev(pos, &io->sections) {
		struct r_io_section_t *s2 = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
		if (s != s2) {
			if (s->from >= s2->from) {
				if (s2->to < s->from)
					return i;
			} else {
				if (s->to < s2->from)
					return i;
			}
		}
		i++;
	}
	return -1;
}

ut64 r_io_section_align(struct r_io_t *io, ut64 addr, ut64 vaddr, ut64 paddr)
{
	struct list_head *pos;
	if (addr == io->last_align)
		return io->last_align;

	list_for_each_prev(pos, &io->sections) {
		struct r_io_section_t *s = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
		if (addr >= s->from && addr <= s->to) {
#if 0
			saltem a 0x24324
			comença a 0x11000; (adreça vaddr)
			equival a la 0x400 (real de disc)
#endif
			return ( addr - s->vaddr + s->paddr ); 
		}
	}
	io->last_align = addr-vaddr+paddr;
	//printf("? 0x%llx-0x%llx+0x%llx\n", addr, vaddr, paddr);
	return io->last_align;
}

void r_io_section_init(struct r_io_t *io)
{
	INIT_LIST_HEAD(&(io->sections));
}
