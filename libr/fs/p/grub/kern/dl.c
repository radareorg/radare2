/* dl.c - loadable module support */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2003,2004,2005,2007,2008,2009  Free Software Foundation, Inc.
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

/* Force native word size */
#define GRUB_TARGET_WORDSIZE (8 * GRUB_CPU_SIZEOF_VOID_P)

#include <config.h>
#include <grub/dl.h>
//#include <grub/obj.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/types.h>
#include <grub/symbol.h>
#include <grub/file.h>
#include <grub/env.h>

GRUB_EXPORT(grub_dl_load_file);
GRUB_EXPORT(grub_dl_load);
GRUB_EXPORT(grub_dl_unload);
#ifndef GRUB_UTIL
GRUB_EXPORT(grub_dl_ref);
GRUB_EXPORT(grub_dl_unref);
#endif
GRUB_EXPORT(grub_dl_iterate);
GRUB_EXPORT(grub_dl_get);
GRUB_EXPORT(grub_dl_register_symbol);

/* Platforms where modules are in a readonly area of memory.  */
#if defined(GRUB_MACHINE_QEMU)
#define GRUB_MODULES_MACHINE_READONLY
#endif



struct grub_dl_list
{
  struct grub_dl_list *next;
  grub_dl_t mod;
};
typedef struct grub_dl_list *grub_dl_list_t;

static grub_dl_list_t grub_dl_head;

grub_err_t
grub_dl_add (grub_dl_t mod)
{
  grub_dl_list_t l;

  if (grub_dl_get (mod->name))
    return grub_error (GRUB_ERR_BAD_MODULE,
		       "`%s' is already loaded", mod->name);

  l = (grub_dl_list_t) grub_malloc (sizeof (*l));
  if (! l)
    return grub_errno;

  l->mod = mod;
  l->next = grub_dl_head;
  grub_dl_head = l;

  return GRUB_ERR_NONE;
}

static void
grub_dl_remove (grub_dl_t mod)
{
  grub_dl_list_t *p, q;

  for (p = &grub_dl_head, q = *p; q; p = &q->next, q = *p)
    if (q->mod == mod)
      {
	*p = q->next;
	grub_free (q);
	return;
      }
}

grub_dl_t
grub_dl_get (const char *name)
{
  grub_dl_list_t l;

  for (l = grub_dl_head; l; l = l->next)
    if (grub_strcmp (name, l->mod->name) == 0)
      return l->mod;

  return 0;
}

void
grub_dl_iterate (int (*hook) (grub_dl_t mod))
{
  grub_dl_list_t l;

  for (l = grub_dl_head; l; l = l->next)
    if (hook (l->mod))
      break;
}



struct grub_symbol
{
  struct grub_symbol *next;
  const char *name;
  void *addr;
  grub_dl_t mod;	/* The module to which this symbol belongs.  */
};
typedef struct grub_symbol *grub_symbol_t;

/* The size of the symbol table.  */
#define GRUB_SYMTAB_SIZE	509

/* The symbol table (using an open-hash).  */
static struct grub_symbol *grub_symtab[GRUB_SYMTAB_SIZE];

/* Simple hash function.  */
static unsigned
grub_symbol_hash (const char *s)
{
  unsigned key = 0;

  while (*s)
    key = key * 65599 + *s++;

  return (key + (key >> 5)) % GRUB_SYMTAB_SIZE;
}

/* Resolve the symbol name NAME and return the address.
   Return NULL, if not found.  */
static void *
grub_dl_resolve_symbol (const char *name)
{
  grub_symbol_t sym;

  for (sym = grub_symtab[grub_symbol_hash (name)]; sym; sym = sym->next)
    if (grub_strcmp (sym->name, name) == 0)
      return sym->addr;

  return 0;
}

/* Register a symbol with the name NAME and the address ADDR.  */
grub_err_t
grub_dl_register_symbol (const char *name, void *addr, grub_dl_t mod)
{
  grub_symbol_t sym;
  unsigned k;

  sym = (grub_symbol_t) grub_malloc (sizeof (*sym));
  if (! sym)
    return grub_errno;

  if (mod)
    {
      sym->name = grub_strdup (name);
      if (! sym->name)
	{
	  grub_free (sym);
	  return grub_errno;
	}
    }
  else
    sym->name = name;

  sym->addr = addr;
  sym->mod = mod;

  k = grub_symbol_hash (name);
  sym->next = grub_symtab[k];
  grub_symtab[k] = sym;

  return GRUB_ERR_NONE;
}

/* Unregister all the symbols defined in the module MOD.  */
static void
grub_dl_unregister_symbols (grub_dl_t mod)
{
  unsigned i;

  if (! mod)
    grub_fatal ("core symbols cannot be unregistered");

  for (i = 0; i < GRUB_SYMTAB_SIZE; i++)
    {
      grub_symbol_t sym, *p, q;

      for (p = &grub_symtab[i], sym = *p; sym; sym = q)
	{
	  q = sym->next;
	  if (sym->mod == mod)
	    {
	      *p = q;
	      grub_free ((void *) sym->name);
	      grub_free (sym);
	    }
	  else
	    p = &sym->next;
	}
    }
}

/* Return the address of a section whose index is N.  */
static void *
grub_dl_get_section_addr (grub_dl_t mod, unsigned n)
{
  grub_dl_segment_t seg;

  for (seg = mod->segment; seg; seg = seg->next)
    if (seg->section == n)
      return seg->addr;

  return 0;
}

/* Load all segments from memory specified by E.  */
static grub_err_t
grub_dl_load_segments (grub_dl_t mod, struct grub_obj_header *e)
{
  unsigned i;
  struct grub_obj_segment *s;

  for (i = 0, s = &e->segments[0]; s->type != GRUB_OBJ_SEGMENT_END; i++, s++)
    {
      grub_dl_segment_t seg;
      void *addr;

      seg = (grub_dl_segment_t) grub_malloc (sizeof (*seg));
      if (! seg)
	return grub_errno;

      addr = grub_memalign (s->align, s->size);
      if (! addr)
	{
	  grub_free (seg);
	  return grub_errno;
	}

      grub_memset (addr, 0, s->size);
      grub_memcpy (addr, (char *) e + s->offset,
		   (s + 1)->offset - s->offset);
      seg->addr = addr;

      seg->size = s->size;
      seg->section = i;
      seg->next = mod->segment;
      mod->segment = seg;

      if (! i)
	{
	  if (e->init_func != GRUB_OBJ_FUNC_NONE)
	    mod->init = (void (*) (grub_dl_t)) ((char *) addr + e->init_func);

	  if (e->fini_func != GRUB_OBJ_FUNC_NONE)
	    mod->fini = (void (*) (void)) ((char *) addr + e->fini_func);
	}
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_dl_resolve_symbols (grub_dl_t mod, struct grub_obj_header *e)
{
  char *strtab;
  struct grub_obj_symbol *sym;
  struct grub_obj_reloc_extern *rel;

  strtab = (char *) e + e->string_table;

  for (sym = (struct grub_obj_symbol *) ((char *) e + e->symbol_table);
       sym->segment != GRUB_OBJ_SEGMENT_END; sym++)
    {
      char *addr;

      addr = grub_dl_get_section_addr (mod, sym->segment);
      addr += sym->offset;

      if (grub_dl_register_symbol (strtab + sym->name, addr, mod))
	return grub_errno;
    }

  for (rel = (struct grub_obj_reloc_extern *) ((char *) e + e->reloc_table);
       rel->segment != GRUB_OBJ_SEGMENT_END;)
    {
      char *addr, *symbol_addr;
      grub_addr_t addend;
      int type;

      addr = grub_dl_get_section_addr (mod, rel->segment);
      addr += rel->offset;
      type = rel->type;

#if defined(GRUB_TARGET_USE_ADDEND)
      addend = rel->addend;
#else
      addend = *((grub_addr_t *) addr);
#endif

      if (rel->symbol_segment == GRUB_OBJ_SEGMENT_END)
	{
	  char *name;

	  name = strtab + rel->symbol_name;
	  symbol_addr = grub_dl_resolve_symbol (name);
	  if (! symbol_addr)
	    return grub_error (GRUB_ERR_BAD_MODULE,
			       "symbol not found: `%s'", name);
	  rel++;
	}
      else
	{
	  symbol_addr = grub_dl_get_section_addr (mod, rel->symbol_segment);
	  rel = (struct grub_obj_reloc_extern *)
	    ((char *) rel + sizeof (struct grub_obj_reloc));
	}

      addend += (grub_addr_t) symbol_addr;
      if (type & GRUB_OBJ_REL_FLAG_REL)
	addend -= (grub_addr_t) addr;

      type &= GRUB_OBJ_REL_TYPE_MASK;
      switch (type)
	{
	case GRUB_OBJ_REL_TYPE_32:
	  *((grub_uint32_t *) addr) = addend;
	  break;

#if GRUB_TARGET_SIZEOF_VOID_P == 8
	case GRUB_OBJ_REL_TYPE_64:
	  *((grub_uint64_t *) addr) = addend;
	  break;
#endif

#if defined(GRUB_TARGET_POWERPC)
	case GRUB_OBJ_REL_TYPE_16:
	  *((grub_uint16_t *) addr) = addend;
	  break;

	case GRUB_OBJ_REL_TYPE_16HI:
	  *((grub_uint16_t *) addr) = addend >> 16;
	  break;

	case GRUB_OBJ_REL_TYPE_16HA:
	  *((grub_uint16_t *) addr) = (addend + 0x8000) >> 16;
	  break;

	case GRUB_OBJ_REL_TYPE_24:
	  {
	    grub_uint32_t v;
	    grub_int32_t a;

	    v = *((grub_uint32_t *) addr);
	    a = addend;

	    if (a << 6 >> 6 != a)
	      return grub_error (GRUB_ERR_BAD_MODULE, "relocation overflow");

	    v = (v & 0xfc000003) | (addend & 0x3fffffc);
	    *((grub_uint32_t *) addr) = v;
	    break;
	  }
#endif

#if defined(GRUB_TARGET_SPARC64)
	case GRUB_OBJ_REL_TYPE_LO10:
	  {
	    grub_uint32_t v;

	    v = *((grub_uint32_t *) addr);
	    v = (v & ~0x3ff) | (addend & 0x3ff);
	    *((grub_uint32_t *) addr) = v;
	    break;
	  }

	case GRUB_OBJ_REL_TYPE_HI22:
	  {
	    grub_uint32_t v;

	    v = *((grub_uint32_t *) addr);
	    v = (v & ~0x3fffff) | ((addend >> 10) & 0x3fffff);
	    *((grub_uint32_t *) addr) = v;
	    break;
	  }

#if GRUB_TARGET_SIZEOF_VOID_P == 8
	case GRUB_OBJ_REL_TYPE_HM10:
	  {
	    grub_uint32_t v;

	    v = *((grub_uint32_t *) addr);
	    v = (v & ~0x3ff) | ((addend >> 32) & 0x3ff);
	    *((grub_uint32_t *) addr) = v;
	    break;
	  }

	case GRUB_OBJ_REL_TYPE_HH22:
	  {
	    grub_uint32_t v;

	    v = *((grub_uint32_t *) addr);
	    v = (v & ~0x3fffff) | ((addend >> 42) & 0x3fffff);
	    *((grub_uint32_t *) addr) = v;
	    break;
	  }
#endif

	case GRUB_OBJ_REL_TYPE_30:
	  {
	    grub_uint32_t v;
	    grub_int32_t a;

	    v = *((grub_uint32_t *) addr);
	    a = addend;

	    if (a << 2 >> 2 != a)
	      return grub_error (GRUB_ERR_BAD_MODULE, "relocation overflow");

	    v = (v & 0xc0000000) | ((addend >> 2) & 0x3fffffff);
	    *((grub_uint32_t *) addr) = v;
	    break;
	  }
#endif

	default:
	  return grub_error (GRUB_ERR_BAD_MODULE,
			     "unknown reloc type %d", type);
	}
    }

  return GRUB_ERR_NONE;
}

static void
grub_dl_call_init (grub_dl_t mod)
{
  if (mod->init)
    (mod->init) (mod);
}

grub_err_t
grub_dl_resolve_dependencies (grub_dl_t mod, char *name)
{
  while (1)
    {
      grub_dl_t m;
      grub_dl_dep_t dep;

      name += grub_strlen (name) + 1;
      if (! *name)
	return GRUB_ERR_NONE;

      m = grub_dl_load (name);
      if (! m)
	return grub_errno;

      grub_dl_ref (m);

      dep = (grub_dl_dep_t) grub_malloc (sizeof (*dep));
      if (! dep)
	return grub_errno;

      dep->mod = m;
      dep->next = mod->dep;
      mod->dep = dep;
    }
}

#if !GRUB_NO_MODULES
int
grub_dl_ref (grub_dl_t mod)
{
  grub_dl_dep_t dep;

  for (dep = mod->dep; dep; dep = dep->next)
    grub_dl_ref (dep->mod);

  return ++mod->ref_count;
}

int
grub_dl_unref (grub_dl_t mod)
{
  grub_dl_dep_t dep;

  for (dep = mod->dep; dep; dep = dep->next)
    grub_dl_unref (dep->mod);

  return --mod->ref_count;
}
#endif

static void
grub_dl_flush_cache (grub_dl_t mod)
{
  grub_dl_segment_t seg;

  for (seg = mod->segment; seg; seg = seg->next) {
    if (seg->size) {
      grub_dprintf ("modules", "flushing 0x%lx bytes at %p\n",
		    (unsigned long) seg->size, seg->addr);
      grub_arch_sync_caches (seg->addr, seg->size);
    }
  }
}

/* Load a module from core memory.  */
grub_dl_t
grub_dl_load_core (void *addr, grub_size_t size)
{
  struct grub_obj_header *e;
  grub_dl_t mod;
  char *name;

  grub_dprintf ("modules", "module at %p, size 0x%lx\n", addr,
		(unsigned long) size);

  e = addr;
  if ((e->magic != GRUB_OBJ_HEADER_MAGIC) ||
      (e->version != GRUB_OBJ_HEADER_VERSION))
    {
      grub_error (GRUB_ERR_BAD_OS, "invalid object file");
      return 0;
    }

  mod = (grub_dl_t) grub_malloc (sizeof (*mod));
  if (! mod)
    return 0;

  name = (char *) addr + e->mod_deps;

  mod->name = grub_strdup (name);
  mod->ref_count = 1;
  mod->dep = 0;
  mod->segment = 0;
  mod->init = 0;
  mod->fini = 0;

  grub_dprintf ("modules", "relocating to %p\n", mod);
  if (grub_dl_resolve_dependencies (mod, name)
      || grub_dl_load_segments (mod, e)
      || grub_dl_resolve_symbols (mod, e))
    {
      mod->fini = 0;
      grub_dl_unload (mod);
      return 0;
    }

  grub_dl_flush_cache (mod);

  grub_dprintf ("modules", "module name: %s\n", mod->name);
  grub_dprintf ("modules", "init function: %p\n", mod->init);
  grub_dl_call_init (mod);

  if (grub_dl_add (mod))
    {
      grub_dl_unload (mod);
      return 0;
    }

  return mod;
}

/* Load a module from the file FILENAME.  */
grub_dl_t
grub_dl_load_file (const char *filename)
{
  grub_file_t file = NULL;
  grub_ssize_t size;
  void *core = 0;
  grub_dl_t mod = 0;

  file = grub_file_open (filename);
  if (! file)
    return 0;

  size = grub_file_size (file);
  core = grub_malloc (size);
  if (! core)
    {
      grub_file_close (file);
      return 0;
    }

  if (grub_file_read (file, core, size) != (int) size)
    {
      grub_file_close (file);
      grub_free (core);
      return 0;
    }

  /* We must close this before we try to process dependencies.
     Some disk backends do not handle gracefully multiple concurrent
     opens of the same device.  */
  grub_file_close (file);

  mod = grub_dl_load_core (core, size);
  if (! mod)
    {
      grub_free (core);
      return 0;
    }

  mod->ref_count = 0;
  return mod;
}

/* Load a module using a symbolic name.  */
grub_dl_t
grub_dl_load (const char *name)
{
#if GRUB_NO_MODULES
  (void) name;
  return 0;
#else
  char *filename;
  grub_dl_t mod;
  char *grub_dl_dir = grub_env_get ("prefix");

  mod = grub_dl_get (name);
  if (mod)
    return mod;

  if (! grub_dl_dir) {
    grub_error (GRUB_ERR_FILE_NOT_FOUND, "\"prefix\" is not set");
    return 0;
  }

  filename = grub_xasprintf ("%s/%s.mod", grub_dl_dir, name);
  if (! filename)
    return 0;

  mod = grub_dl_load_file (filename);
  grub_free (filename);

  if (! mod)
    return 0;

  if (grub_strcmp (mod->name, name) != 0)
    grub_error (GRUB_ERR_BAD_MODULE, "mismatched names");

  return mod;
#endif
}

/* Unload the module MOD.  */
int
grub_dl_unload (grub_dl_t mod)
{
  grub_dl_dep_t dep, depn;
  grub_dl_segment_t seg, segn;

  if (mod->ref_count > 0)
    return 0;

  if (mod->fini)
    (mod->fini) ();

  grub_dl_remove (mod);
  grub_dl_unregister_symbols (mod);

  for (dep = mod->dep; dep; dep = depn)
    {
      depn = dep->next;

      if (! grub_dl_unref (dep->mod))
	grub_dl_unload (dep->mod);

      grub_free (dep);
    }

  for (seg = mod->segment; seg; seg = segn)
    {
      segn = seg->next;
      grub_free (seg->addr);
      grub_free (seg);
    }

  grub_free (mod->name);
#ifdef GRUB_MODULES_MACHINE_READONLY
  grub_free (mod->symtab);
#endif
  grub_free (mod);
  return 1;
}

/* Unload unneeded modules.  */
void
grub_dl_unload_unneeded (void)
{
  /* Because grub_dl_remove modifies the list of modules, this
     implementation is tricky.  */
  grub_dl_list_t p = grub_dl_head;

  while (p)
    {
      if (grub_dl_unload (p->mod))
	{
	  p = grub_dl_head;
	  continue;
	}

      p = p->next;
    }
}

/* Unload all modules.  */
void
grub_dl_unload_all (void)
{
  while (grub_dl_head)
    {
      grub_dl_list_t p;

      grub_dl_unload_unneeded ();

      /* Force to decrement the ref count. This will purge pre-loaded
	 modules and manually inserted modules.  */
      for (p = grub_dl_head; p; p = p->next)
	p->mod->ref_count--;
    }
}
