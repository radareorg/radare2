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

R_API void r_io_section_add(struct r_io_t *io, ut64 offset, ut64 vaddr, ut64 size, ut64 vsize, int rwx, const char *name)
{
	struct r_io_section_t *s = (struct r_io_section_t *)malloc(sizeof(struct r_io_section_t));
	s->offset = offset;
	s->vaddr = vaddr;
	s->size = size;
	s->vsize = vsize;
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
R_API void r_io_section_list(struct r_io_t *io, ut64 offset, int rad)
{
	int i = 0;
	struct list_head *pos;

	offset = io->va ? r_io_section_vaddr_to_offset (io, offset) : offset;
	list_for_each_prev(pos, &io->sections) {
		struct r_io_section_t *s = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
		if (rad) {
			r_cons_printf("S 0x%08llx 0x%08llx 0x%08llx 0x%08llx %s\n",
				s->offset, s->vaddr, s->size, s->vsize, s->name);
		} else {
			r_cons_printf("[%02d] %c offset=0x%08llx vaddr=0x%08llx size=0x%08llx vsize=%08llx %s",
				i, (offset>=s->offset && offset<s->offset+s->size)?'*':'.',
				s->offset, s->vaddr, s->size, s->vsize, s->name);
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

	seek = io->va ? r_io_section_vaddr_to_offset (io, seek) : seek;
	list_for_each(pos, &io->sections) {
		struct r_io_section_t *s = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
		if (min == -1 || s->offset < min)
			min = s->offset;
		if (max == -1 || s->offset+s->size > max)
			max = s->offset+s->size;
	}

	mul = (max-min) / width;
	if (min != -1 && mul != 0) {
		i = 0;
		list_for_each_prev(pos, &io->sections) {
			struct r_io_section_t *s = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
			r_cons_printf("%02d  0x%08llx |", i, s->offset);
			for(j=0;j<width;j++) {
				if ((j*mul)+min >= s->offset && (j*mul)+min <=s->offset+s->size)
					r_cons_printf("#");
				else
					r_cons_printf("-");
			}
			r_cons_printf("| 0x%08llx %s\n", s->offset+s->size, s->name);
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

R_API struct r_io_section_t *r_io_section_get(struct r_io_t *io, ut64 offset)
{
	struct list_head *pos;
	list_for_each (pos, &io->sections) {
		RIOSection *s = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
		if (offset >= s->offset && offset <= s->offset + s->size)
			return s;
	}
	return NULL;
}

R_API ut64 r_io_section_get_offset(struct r_io_t *io, ut64 offset)
{
	RIOSection *s = r_io_section_get(io, offset);
	return s?s->offset:-1;
}

R_API ut64 r_io_section_get_vaddr(struct r_io_t *io, ut64 offset)
{
	struct r_io_section_t *s = r_io_section_get(io, offset);
	return s?s->vaddr:-1;
}

R_API int r_io_section_get_rwx(struct r_io_t *io, ut64 offset)
{
	struct r_io_section_t *s = r_io_section_get(io, offset);
	return s?s->rwx:R_IO_READ|R_IO_WRITE|R_IO_EXEC;
}

R_API int r_io_section_overlaps(struct r_io_t *io, struct r_io_section_t *s)
{
	int i = 0;
	struct list_head *pos;
	list_for_each_prev(pos, &io->sections) {
		struct r_io_section_t *s2 = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
		if (s != s2) {
			if (s->offset >= s2->offset) {
				if (s2->offset+s2->size < s->offset)
					return i;
			} else {
				if (s->offset+s->size < s2->offset)
					return i;
			}
		}
		i++;
	}
	return -1;
}

R_API ut64 r_io_section_vaddr_to_offset(struct r_io_t *io, ut64 vaddr)
{
	struct list_head *pos;

	list_for_each_prev(pos, &io->sections) {
		struct r_io_section_t *s = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
		if (vaddr >= s->vaddr && vaddr < s->vaddr + s->vsize)
			return (vaddr - s->vaddr + s->offset); 
	}
	return vaddr;
}

R_API ut64 r_io_section_offset_to_vaddr(struct r_io_t *io, ut64 offset)
{
	struct list_head *pos;

	list_for_each_prev(pos, &io->sections) {
		struct r_io_section_t *s = (struct r_io_section_t *)list_entry(pos, struct r_io_section_t, list);
		if (offset >= s->offset && offset < s->offset + s->size)
			return (s->vaddr + offset - s->offset); 
	}
	return offset;
}
