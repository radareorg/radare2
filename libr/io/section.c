/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

#include "r_io.h"

// XXX use section->foo
#define r_cons_printf printf

R_API void r_io_section_init(struct r_io_t *io)
{
	io->enforce_rwx = 0; // do not enforce RWX section permissions by default
	io->enforce_seek = 0; // do not limit seeks out of the file by default
	INIT_LIST_HEAD(&(io->sections));
}

R_API void r_io_section_set(struct r_io_t *io, ut64 from, ut64 to, ut64 vaddr, ut64 paddr, int rwx, const char *name)
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
			if (name)
				strncpy(s->name, name, 254);
		}
	}
}

R_API void r_io_section_add(struct r_io_t *io, ut64 from, ut64 to, ut64 vaddr, ut64 paddr, int rwx, const char *name)
{
	struct r_io_section_t *s = (struct r_io_section_t *)malloc(sizeof(struct r_io_section_t));
	s->from = from;
	s->to = to;
	s->vaddr = vaddr;
	s->paddr = paddr;
	s->rwx = rwx;
	if (name)
		strncpy(s->name, name, 254);
	else s->name[0]='\0';
	list_add(&(s->list), &io->sections);
}

R_API struct r_io_section_t *r_io_section_get_i(struct r_io_t *io, int idx)
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

R_API int r_io_section_rm(struct r_io_t *io, int idx)
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
R_API void r_io_section_list(struct r_io_t *io, ut64 addr, int rad)
{
	int i = 0;
	//char buf[128];
	struct list_head *pos;
	list_for_each_prev(pos, &io->sections) {
		struct r_io_section_t *s = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
		if (rad) {
			r_cons_printf("S 0x%08llx 0x%08llx %s @ 0x%08llx\n",
				s->to-s->from, s->vaddr, s->name, s->from);
			r_cons_printf("Sd 0x%08llx @ 0x%08llx\n", s->paddr, s->from);
		} else {
			r_cons_printf("%02d %c 0x%08llx - 0x%08llx bs=0x%08llx sz=0x%08llx phy=0x%08llx %s",
				i, (addr>=s->from && addr <=s->to)?'*':'.',
				s->from, s->to, s->vaddr, (ut64)((s->to)-(s->from)), s->paddr, s->name);
			

// TODO: IMPLEMENT AS CALLBACK
//			if (string_flag_offset(buf, s->from))
//				r_cons_printf(" ; %s", buf);
#if 0
			ol = r_io_section_overlaps(s);
			if (ol != -1)
				r_cons_printf(" ; Overlaps with %d", ol);
#endif
			r_cons_printf("\n");
		}
		i++;
	}
}

/* TODO: move to print ??? support pretty print of ranges following an array of offsetof */
R_API void r_io_section_list_visual(struct r_io_t *io, ut64 seek, ut64 len)
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
			r_cons_printf("%02d  0x%08llx |", i, s->from);
			for(j=0;j<width;j++) {
				if ((j*mul)+min >= s->from && (j*mul)+min <=s->to)
					r_cons_printf("#");
				else
					r_cons_printf("-");
			}
			r_cons_printf("| 0x%08llx\n", s->to);
			i++;
		}
		/* current seek */
		if (i>0 && len != 0) {
			r_cons_printf("=>  0x%08llx |", seek);
			for(j=0;j<width;j++) {
				r_cons_printf (
					((j*mul)+min >= seek &&
					 (j*mul)+min <= seek+len)
					?"#":"-");
			}
			r_cons_printf("| 0x%08llx\n", seek+len);
		}
	}
}

R_API struct r_io_section_t *r_io_section_get(struct r_io_t *io, ut64 addr)
{
	struct list_head *pos;
	list_for_each (pos, &io->sections) {
		RIOSection *s = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
		if (addr >= s->from && addr <= s->to)
			return s;
	}
	return NULL;
}

R_API ut64 r_io_section_get_paddr(struct r_io_t *io, ut64 addr)
{
	RIOSection *s = r_io_section_get(io, addr);
	return s?s->paddr:-1;
}

R_API ut64 r_io_section_get_vaddr(struct r_io_t *io, ut64 addr)
{
	struct r_io_section_t *s = r_io_section_get(io, addr);
	return s?s->vaddr:-1;
}

R_API int r_io_section_get_rwx(struct r_io_t *io, ut64 addr)
{
	struct r_io_section_t *s = r_io_section_get(io, addr);
	return s?s->rwx:R_IO_READ|R_IO_WRITE|R_IO_EXEC;
}

R_API int r_io_section_overlaps(struct r_io_t *io, struct r_io_section_t *s)
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

R_API ut64 r_io_section_align(struct r_io_t *io, ut64 addr, ut64 vaddr, ut64 paddr)
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
