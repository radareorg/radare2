/* mm.c - functions for memory manager */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2005,2007,2008,2009  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
  The design of this memory manager.

  This is a simple implementation of malloc with a few extensions. These are
  the extensions:

  - memalign is implemented efficiently.

  - multiple regions may be used as free space. They may not be
  contiguous.

  Regions are managed by a singly linked list, and the meta information is
  stored in the beginning of each region. Space after the meta information
  is used to allocate memory.

  The memory space is used as cells instead of bytes for simplicity. This
  is important for some CPUs which may not access multiple bytes at a time
  when the first byte is not aligned at a certain boundary (typically,
  4-byte or 8-byte). The size of each cell is equal to the size of struct
  grub_mm_header, so the header of each allocated/free block fits into one
  cell precisely. One cell is 16 bytes on 32-bit platforms and 32 bytes
  on 64-bit platforms.

  There are two types of blocks: allocated blocks and free blocks.

  In allocated blocks, the header of each block has only its size. Note that
  this size is based on cells but not on bytes. The header is located right
  before the returned pointer, that is, the header resides at the previous
  cell.

  Free blocks constitutes a ring, using a singly linked list. The first free
  block is pointed to by the meta information of a region. The allocator
  attempts to pick up the second block instead of the first one. This is
  a typical optimization against defragmentation, and makes the
  implementation a bit easier.

  For safety, both allocated blocks and free ones are marked by magic
  numbers. Whenever anything unexpected is detected, GRUB aborts the
  operation.
 */

#include <config.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/err.h>
#include <grub/types.h>
#include <grub/disk.h>
#include <grub/dl.h>

#include <string.h>
#include <stdlib.h>

#ifdef MM_DEBUG
# undef grub_malloc
# undef grub_zalloc
# undef grub_realloc
# undef grub_free
# undef grub_memalign

GRUB_EXPORT(grub_mm_debug);
GRUB_EXPORT(grub_debug_malloc);
GRUB_EXPORT(grub_debug_zalloc);
GRUB_EXPORT(grub_debug_free);
GRUB_EXPORT(grub_debug_realloc);
GRUB_EXPORT(grub_debug_memalign);
GRUB_EXPORT(grub_mm_get_free);

#endif

GRUB_EXPORT(grub_malloc);
GRUB_EXPORT(grub_zalloc);
GRUB_EXPORT(grub_free);
GRUB_EXPORT(grub_realloc);
GRUB_EXPORT(grub_memalign);

/* Magic words.  */
#define GRUB_MM_FREE_MAGIC	0x2d3c2808
#define GRUB_MM_ALLOC_MAGIC	0x6db08fa4

typedef struct grub_mm_header
{
  struct grub_mm_header *next;
  grub_size_t size;
  grub_size_t magic;
#if GRUB_CPU_SIZEOF_VOID_P == 4
  char padding[4];
#elif GRUB_CPU_SIZEOF_VOID_P == 8
  char padding[8];
#else
# error "unknown word size"
#endif
}
*grub_mm_header_t;

#if GRUB_CPU_SIZEOF_VOID_P == 4
# define GRUB_MM_ALIGN_LOG2	4
#elif GRUB_CPU_SIZEOF_VOID_P == 8
# define GRUB_MM_ALIGN_LOG2	5
#endif

#define GRUB_MM_ALIGN	(1 << GRUB_MM_ALIGN_LOG2)

typedef struct grub_mm_region
{
  struct grub_mm_header *first;
  struct grub_mm_region *next;
  grub_addr_t addr;
  grub_size_t size;
}
*grub_mm_region_t;



static grub_mm_region_t base;

/* Get a header from the pointer PTR, and set *P and *R to a pointer
   to the header and a pointer to its region, respectively. PTR must
   be allocated.  */
static void
get_header_from_pointer (void *ptr, grub_mm_header_t *p, grub_mm_region_t *r)
{
  if ((int)(size_t) ptr & (GRUB_MM_ALIGN - 1))
    grub_fatal ("unaligned pointer %p", ptr);

  for (*r = base; *r; *r = (*r)->next)
    if ((long) ptr > (*r)->addr
	&& (long)ptr <= (*r)->addr + (*r)->size)
      break;

  if (! *r)
    grub_fatal ("out of range pointer %p", ptr);

  *p = (grub_mm_header_t) ptr - 1;
  if ((*p)->magic != GRUB_MM_ALLOC_MAGIC)
    grub_fatal ("alloc magic is broken at %p", *p);
}

/* Initialize a region starting from ADDR and whose size is SIZE,
   to use it as free space.  */
void
grub_mm_init_region (void *addr, grub_size_t size)
{
  grub_mm_header_t h;
  grub_mm_region_t r, *p, q;

#if 0
  grub_printf ("Using memory for heap: start=%p, end=%p\n", addr, addr + (unsigned int) size);
#endif

  /* Allocate a region from the head.  */
  r = (grub_mm_region_t) ALIGN_UP ((long) addr, GRUB_MM_ALIGN);
  size -= (char *) r - (char *) addr + sizeof (*r);

  /* If this region is too small, ignore it.  */
  if (size < GRUB_MM_ALIGN)
    return;

  h = (grub_mm_header_t) ((char *) r + GRUB_MM_ALIGN);
  h->next = h;
  h->magic = GRUB_MM_FREE_MAGIC;
  h->size = (size >> GRUB_MM_ALIGN_LOG2);

  r->first = h;
  r->addr = (long) h;
  r->size = (h->size << GRUB_MM_ALIGN_LOG2);

  /* Find where to insert this region. Put a smaller one before bigger ones,
     to prevent fragmentation.  */
  for (p = &base, q = *p; q; p = &(q->next), q = *p)
    if (q->size > r->size)
      break;

  *p = r;
  r->next = q;
}

/* Allocate the number of units N with the alignment ALIGN from the ring
   buffer starting from *FIRST.  ALIGN must be a power of two. Both N and
   ALIGN are in units of GRUB_MM_ALIGN.  Return a non-NULL if successful,
   otherwise return NULL.  */
static void *
grub_real_malloc (grub_mm_header_t *first, grub_size_t n, grub_size_t align)
{
  grub_mm_header_t p, q;

  /* When everything is allocated side effect is that *first will have alloc
     magic marked, meaning that there is no room in this region.  */
  if ((*first)->magic == GRUB_MM_ALLOC_MAGIC)
    return 0;

  /* Try to search free slot for allocation in this memory region.  */
  for (q = *first, p = q->next; ; q = p, p = p->next)
    {
      grub_off_t extra;

      extra = ((long) (p + 1) >> GRUB_MM_ALIGN_LOG2) % align;
      if (extra)
	extra = align - extra;

      if (! p || !p->magic)
	grub_fatal ("null in the ring");

      if (p->magic != GRUB_MM_FREE_MAGIC)
	grub_fatal ("free magic is broken at %p: 0x%x", p, p->magic);

      if (p->size >= n + extra)
	{
	  if (extra == 0 && p->size == n)
	    {
	      /* There is no special alignment requirement and memory block
	         is complete match.

	         1. Just mark memory block as allocated and remove it from
	            free list.

	         Result:
	         +---------------+ previous block's next
	         | alloc, size=n |          |
	         +---------------+          v
	       */
	      q->next = p->next;
	    }
	  else if (align == 1 || p->size == n + extra)
	    {
	      /* There might be alignment requirement, when taking it into
	         account memory block fits in.

	         1. Allocate new area at end of memory block.
	         2. Reduce size of available blocks from original node.
	         3. Mark new area as allocated and "remove" it from free
	            list.

	         Result:
	         +---------------+
	         | free, size-=n | next --+
	         +---------------+        |
	         | alloc, size=n |        |
	         +---------------+        v
	       */

	      p->size -= n;
	      p += p->size;
	    }
	  else if (extra == 0)
	    {
	      grub_mm_header_t r;

	      r = p + extra + n;
	      r->magic = GRUB_MM_FREE_MAGIC;
	      r->size = p->size - extra - n;
	      r->next = p->next;
	      q->next = r;

	      if (q == p)
		{
		  q = r;
		  r->next = r;
		}
	    }
	  else
	    {
	      /* There is alignment requirement and there is room in memory
	         block.  Split memory block to three pieces.

	         1. Create new memory block right after section being
	            allocated.  Mark it as free.
	         2. Add new memory block to free chain.
	         3. Mark current memory block having only extra blocks.
	         4. Advance to aligned block and mark that as allocated and
	            "remove" it from free list.

	         Result:
	         +------------------------------+
	         | free, size=extra             | next --+
	         +------------------------------+        |
	         | alloc, size=n                |        |
	         +------------------------------+        |
	         | free, size=orig.size-extra-n | <------+, next --+
	         +------------------------------+                  v
	       */
	      grub_mm_header_t r;

	      r = p + extra + n;
	      r->magic = GRUB_MM_FREE_MAGIC;
	      r->size = p->size - extra - n;
	      r->next = p->next;

	      p->size = extra;
	      p->next = r;
	      p += extra;
	    }

	  p->magic = GRUB_MM_ALLOC_MAGIC;
	  p->size = n;

	  /* Mark find as a start marker for next allocation to fasten it.
	     This will have side effect of fragmenting memory as small
	     pieces before this will be un-used.  */
	  *first = q;

	  return p + 1;
	}

      /* Search was completed without result.  */
      if (p == *first)
	break;
    }

  return 0;
}

/* Allocate SIZE bytes with the alignment ALIGN and return the pointer.  */
void *
grub_memalign (grub_size_t align, grub_size_t size)
{
  grub_mm_region_t r;
  grub_size_t n = ((size + GRUB_MM_ALIGN - 1) >> GRUB_MM_ALIGN_LOG2) + 1;
  int count = 0;

  align = (align >> GRUB_MM_ALIGN_LOG2);
  if (align == 0)
    align = 1;

 again:

  for (r = base; r; r = r->next)
    {
      void *p;

      p = grub_real_malloc (&(r->first), n, align);
      if (p)
	return p;
    }

  /* If failed, increase free memory somehow.  */
  switch (count)
    {
    case 0:
      /* Invalidate disk caches.  */
      grub_disk_cache_invalidate_all ();
      count++;
      goto again;

    case 1:
      /* Unload unneeded modules.  */
      //grub_dl_unload_unneeded ();
      count++;
      goto again;

    default:
      break;
    }

  grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
  return 0;
}

/* Allocate SIZE bytes and return the pointer.  */
void *
grub_malloc (grub_size_t size)
{
//  return grub_memalign (0, size);
  return malloc(size);
}

void *grub_zalloc (grub_size_t size)
{
    void *ret;
    ret = malloc(size);
    memset (ret, 0, size);

    return ret;
}

/* Allocate SIZE bytes, clear them and return the pointer.  */
void *
grub_zalloc_orig (grub_size_t size)
{
  void *ret;

  ret = grub_memalign (0, size);
  if (ret)
    grub_memset (ret, 0, size);

  return ret;
}

void grub_free (void *ptr) {
    free(ptr);
}

/* Deallocate the pointer PTR.  */
void
grub_free_orig (void *ptr)
{
    
  grub_mm_header_t p;
  grub_mm_region_t r;

  if (! ptr)
    return;

  get_header_from_pointer (ptr, &p, &r);

  if (r->first->magic == GRUB_MM_ALLOC_MAGIC)
    {
      p->magic = GRUB_MM_FREE_MAGIC;
      r->first = p->next = p;
    }
  else
    {
      grub_mm_header_t q;

#if 0
      q = r->first;
      do
	{
	  grub_printf ("%s:%d: q=%p, q->size=0x%x, q->magic=0x%x\n",
		       GRUB_FILE, __LINE__, q, q->size, q->magic);
	  q = q->next;
	}
      while (q != r->first);
#endif

      for (q = r->first; q >= p || q->next <= p; q = q->next)
	{
	  if (q->magic != GRUB_MM_FREE_MAGIC)
	    grub_fatal ("free magic is broken at %p: 0x%x", q, q->magic);

	  if (q >= q->next && (q < p || q->next > p))
	    break;
	}

      p->magic = GRUB_MM_FREE_MAGIC;
      p->next = q->next;
      q->next = p;

      if (p + p->size == p->next)
	{
	  if (p->next == q)
	    q = p;

	  p->next->magic = 0;
	  p->size += p->next->size;
	  p->next = p->next->next;
	}

      if (q + q->size == p)
	{
	  p->magic = 0;
	  q->size += p->size;
	  q->next = p->next;
	}

      r->first = q;
    }
}

void * grub_realloc (void *ptr, grub_size_t size) {
    return realloc(ptr, size);
}

/* Reallocate SIZE bytes and return the pointer. The contents will be
   the same as that of PTR.  */
   
void *
grub_realloc_orig (void *ptr, grub_size_t size)
{
  grub_mm_header_t p;
  grub_mm_region_t r;
  void *q;
  grub_size_t n;

  if (! ptr)
    return grub_malloc (size);

  if (! size)
    {
      grub_free (ptr);
      return 0;
    }

  /* FIXME: Not optimal.  */
  n = ((size + GRUB_MM_ALIGN - 1) >> GRUB_MM_ALIGN_LOG2) + 1;
  get_header_from_pointer (ptr, &p, &r);

  if (p->size >= n)
    return ptr;

  q = grub_malloc (size);
  if (! q)
    return q;

  grub_memcpy (q, ptr, size);
  grub_free (ptr);
  return q;
}

#ifdef MM_DEBUG
int grub_mm_debug = 0;

void
grub_mm_dump_free (void)
{
  grub_mm_region_t r;

  for (r = base; r; r = r->next)
    {
      grub_mm_header_t p;

      /* Follow the free list.  */
      p = r->first;
      do
	{
	  if (p->magic != GRUB_MM_FREE_MAGIC)
	    grub_fatal ("free magic is broken at %p: 0x%x", p, p->magic);

	  grub_printf ("F:%p:%u:%p\n",
		       p, (unsigned int) p->size << GRUB_MM_ALIGN_LOG2, p->next);
	  p = p->next;
	}
      while (p != r->first);
    }

  grub_printf ("\n");
}

void
grub_mm_dump (unsigned lineno)
{
  grub_mm_region_t r;

  grub_printf ("called at line %u\n", lineno);
  for (r = base; r; r = r->next)
    {
      grub_mm_header_t p;

      for (p = (grub_mm_header_t) ((r->addr + GRUB_MM_ALIGN - 1)
				   & (~(GRUB_MM_ALIGN - 1)));
	   (grub_addr_t) p < r->addr + r->size;
	   p++)
	{
	  switch (p->magic)
	    {
	    case GRUB_MM_FREE_MAGIC:
	      grub_printf ("F:%p:%u:%p\n",
			   p, (unsigned int) p->size << GRUB_MM_ALIGN_LOG2, p->next);
	      break;
	    case GRUB_MM_ALLOC_MAGIC:
	      grub_printf ("A:%p:%u\n", p, (unsigned int) p->size << GRUB_MM_ALIGN_LOG2);
	      break;
	    }
	}
    }

  grub_printf ("\n");
}

void *
grub_debug_malloc (const char *file, int line, grub_size_t size)
{
  void *ptr;

  if (grub_mm_debug)
    grub_printf ("%s:%d: malloc (0x%zx) = ", file, line, size);
  ptr = grub_malloc (size);
  if (grub_mm_debug)
    grub_printf ("%p\n", ptr);
  return ptr;
}

void *
grub_debug_zalloc (const char *file, int line, grub_size_t size)
{
  void *ptr;

  if (grub_mm_debug)
    grub_printf ("%s:%d: zalloc (0x%zx) = ", file, line, size);
  ptr = grub_zalloc (size);
  if (grub_mm_debug)
    grub_printf ("%p\n", ptr);
  return ptr;
}

void
grub_debug_free (const char *file, int line, void *ptr)
{
  if (grub_mm_debug)
    grub_printf ("%s:%d: free (%p)\n", file, line, ptr);
  grub_free (ptr);
}

void *
grub_debug_realloc (const char *file, int line, void *ptr, grub_size_t size)
{
  if (grub_mm_debug)
    grub_printf ("%s:%d: realloc (%p, 0x%zx) = ", file, line, ptr, size);
  ptr = grub_realloc (ptr, size);
  if (grub_mm_debug)
    grub_printf ("%p\n", ptr);
  return ptr;
}

void *
grub_debug_memalign (const char *file, int line, grub_size_t align,
		    grub_size_t size)
{
  void *ptr;

  if (grub_mm_debug)
    grub_printf ("%s:%d: memalign (0x%zx, 0x%zx) = ",
		 file, line, align, size);
  ptr = grub_memalign (align, size);
  if (grub_mm_debug)
    grub_printf ("%p\n", ptr);
  return ptr;
}

#endif /* MM_DEBUG */
