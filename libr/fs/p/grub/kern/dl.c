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
#include <grub/elf.h>
#include <grub/dl.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/types.h>
#include <grub/symbol.h>
#include <grub/file.h>
#include <grub/env.h>
#include <grub/cache.h>

/* Platforms where modules are in a readonly area of memory.  */
#if defined(GRUB_MACHINE_QEMU)
#define GRUB_MODULES_MACHINE_READONLY
#endif



grub_dl_t grub_dl_head = 0;

static grub_err_t
grub_dl_add (grub_dl_t mod)
{
  if (grub_dl_get (mod->name))
    return grub_error (GRUB_ERR_BAD_MODULE,
		       "`%s' is already loaded", mod->name);

  mod->next = grub_dl_head;
  grub_dl_head = mod;

  return GRUB_ERR_NONE;
}

static void
grub_dl_remove (grub_dl_t mod)
{
  grub_dl_t *p, q;

  for (p = &grub_dl_head, q = *p; q; p = &q->next, q = *p)
    if (q == mod)
      {
	*p = q->next;
	return;
      }
}

grub_dl_t
grub_dl_get (const char *name)
{
  grub_dl_t l;

  for (l = grub_dl_head; l; l = l->next)
    if (grub_strcmp (name, l->name) == 0)
      return l;

  return 0;
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

/* Check if EHDR is a valid ELF header.  */
static grub_err_t
grub_dl_check_header (void *ehdr, grub_size_t size)
{
  Elf_Ehdr *e = ehdr;

  /* Check the header size.  */
  if (size < sizeof (Elf_Ehdr))
    return grub_error (GRUB_ERR_BAD_OS, "ELF header smaller than expected");

  /* Check the magic numbers.  */
  if (grub_arch_dl_check_header (ehdr)
      || e->e_ident[EI_MAG0] != ELFMAG0
      || e->e_ident[EI_MAG1] != ELFMAG1
      || e->e_ident[EI_MAG2] != ELFMAG2
      || e->e_ident[EI_MAG3] != ELFMAG3
      || e->e_ident[EI_VERSION] != EV_CURRENT
      || e->e_version != EV_CURRENT)
    return grub_error (GRUB_ERR_BAD_OS, "invalid arch independent ELF magic");

  return GRUB_ERR_NONE;
}

/* Load all segments from memory specified by E.  */
static grub_err_t
grub_dl_load_segments (grub_dl_t mod, const Elf_Ehdr *e)
{
  unsigned i;
  Elf_Shdr *s;

  for (i = 0, s = (Elf_Shdr *)((char *) e + e->e_shoff);
       i < e->e_shnum;
       i++, s = (Elf_Shdr *)((char *) s + e->e_shentsize))
    {
      if (s->sh_flags & SHF_ALLOC)
	{
	  grub_dl_segment_t seg;

	  seg = (grub_dl_segment_t) grub_malloc (sizeof (*seg));
	  if (! seg)
	    return grub_errno;

	  if (s->sh_size)
	    {
	      void *addr;

	      addr = grub_memalign (s->sh_addralign, s->sh_size);
	      if (! addr)
		{
		  grub_free (seg);
		  return grub_errno;
		}

	      switch (s->sh_type)
		{
		case SHT_PROGBITS:
		  grub_memcpy (addr, (char *) e + s->sh_offset, s->sh_size);
		  break;
		case SHT_NOBITS:
		  grub_memset (addr, 0, s->sh_size);
		  break;
		}

	      seg->addr = addr;
	    }
	  else
	    seg->addr = 0;

	  seg->size = s->sh_size;
	  seg->section = i;
	  seg->next = mod->segment;
	  mod->segment = seg;
	}
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_dl_resolve_symbols (grub_dl_t mod, Elf_Ehdr *e)
{
  unsigned i;
  Elf_Shdr *s;
  Elf_Sym *sym;
  const char *str;
  Elf_Word size, entsize;

  for (i = 0, s = (Elf_Shdr *) ((char *) e + e->e_shoff);
       i < e->e_shnum;
       i++, s = (Elf_Shdr *) ((char *) s + e->e_shentsize))
    if (s->sh_type == SHT_SYMTAB)
      break;

  if (i == e->e_shnum)
    return grub_error (GRUB_ERR_BAD_MODULE, "no symbol table");

#ifdef GRUB_MODULES_MACHINE_READONLY
  mod->symtab = grub_malloc (s->sh_size);
  memcpy (mod->symtab, (char *) e + s->sh_offset, s->sh_size);
#else
  mod->symtab = (Elf_Sym *) ((char *) e + s->sh_offset);
#endif
  sym = mod->symtab;
  size = s->sh_size;
  entsize = s->sh_entsize;

  s = (Elf_Shdr *) ((char *) e + e->e_shoff + e->e_shentsize * s->sh_link);
  str = (char *) e + s->sh_offset;

  for (i = 0;
       i < size / entsize;
       i++, sym = (Elf_Sym *) ((char *) sym + entsize))
    {
      unsigned char type = ELF_ST_TYPE (sym->st_info);
      unsigned char bind = ELF_ST_BIND (sym->st_info);
      const char *name = str + sym->st_name;

      switch (type)
	{
	case STT_NOTYPE:
	case STT_OBJECT:
	  /* Resolve a global symbol.  */
	  if (sym->st_name != 0 && sym->st_shndx == 0)
	    {
	      sym->st_value = (Elf_Addr) grub_dl_resolve_symbol (name);
	      if (! sym->st_value)
		return grub_error (GRUB_ERR_BAD_MODULE,
				   "symbol not found: `%s'", name);
	    }
	  else
	    {
	      sym->st_value += (Elf_Addr) grub_dl_get_section_addr (mod,
								    sym->st_shndx);
	      if (bind != STB_LOCAL)
		if (grub_dl_register_symbol (name, (void *) sym->st_value, mod))
		  return grub_errno;
	    }
	  break;

	case STT_FUNC:
	  sym->st_value += (Elf_Addr) grub_dl_get_section_addr (mod,
								sym->st_shndx);
	  if (bind != STB_LOCAL)
	    if (grub_dl_register_symbol (name, (void *) sym->st_value, mod))
	      return grub_errno;

	  if (grub_strcmp (name, "grub_mod_init") == 0)
	    mod->init = (void (*) (grub_dl_t)) sym->st_value;
	  else if (grub_strcmp (name, "grub_mod_fini") == 0)
	    mod->fini = (void (*) (void)) sym->st_value;
	  break;

	case STT_SECTION:
	  sym->st_value = (Elf_Addr) grub_dl_get_section_addr (mod,
							       sym->st_shndx);
	  break;

	case STT_FILE:
	  sym->st_value = 0;
	  break;

	default:
	  return grub_error (GRUB_ERR_BAD_MODULE,
			     "unknown symbol type `%d'", (int) type);
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

static grub_err_t
grub_dl_resolve_name (grub_dl_t mod, Elf_Ehdr *e)
{
  Elf_Shdr *s;
  const char *str;
  unsigned i;

  s = (Elf_Shdr *) ((char *) e + e->e_shoff + e->e_shstrndx * e->e_shentsize);
  str = (char *) e + s->sh_offset;

  for (i = 0, s = (Elf_Shdr *) ((char *) e + e->e_shoff);
       i < e->e_shnum;
       i++, s = (Elf_Shdr *) ((char *) s + e->e_shentsize))
    if (grub_strcmp (str + s->sh_name, ".modname") == 0)
      {
	mod->name = grub_strdup ((char *) e + s->sh_offset);
	if (! mod->name)
	  return grub_errno;
	break;
      }

  if (i == e->e_shnum)
    return grub_error (GRUB_ERR_BAD_MODULE, "no module name found");

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_dl_resolve_dependencies (grub_dl_t mod, Elf_Ehdr *e)
{
  Elf_Shdr *s;
  const char *str;
  unsigned i;

  s = (Elf_Shdr *) ((char *) e + e->e_shoff + e->e_shstrndx * e->e_shentsize);
  str = (char *) e + s->sh_offset;

  for (i = 0, s = (Elf_Shdr *) ((char *) e + e->e_shoff);
       i < e->e_shnum;
       i++, s = (Elf_Shdr *) ((char *) s + e->e_shentsize))
    if (grub_strcmp (str + s->sh_name, ".moddeps") == 0)
      {
	const char *name = (char *) e + s->sh_offset;
	const char *max = name + s->sh_size;

	while ((name < max) && (*name))
	  {
	    grub_dl_t m;
	    grub_dl_dep_t dep;

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

	    name += grub_strlen (name) + 1;
	  }
      }

  return GRUB_ERR_NONE;
}

int
grub_dl_ref (grub_dl_t mod)
{
  grub_dl_dep_t dep;

  if (!mod)
    return 0;

  for (dep = mod->dep; dep; dep = dep->next)
    grub_dl_ref (dep->mod);

  return ++mod->ref_count;
}

int
grub_dl_unref (grub_dl_t mod)
{
  grub_dl_dep_t dep;

  if (!mod)
    return 0;

  for (dep = mod->dep; dep; dep = dep->next)
    grub_dl_unref (dep->mod);

  return --mod->ref_count;
}

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
  Elf_Ehdr *e;
  grub_dl_t mod;

  grub_dprintf ("modules", "module at %p, size 0x%lx\n", addr,
		(unsigned long) size);
  e = addr;
  if (grub_dl_check_header (e, size))
    return 0;

  if (e->e_type != ET_REL)
    {
      grub_error (GRUB_ERR_BAD_MODULE, "invalid ELF file type");
      return 0;
    }

  /* Make sure that every section is within the core.  */
  if (size < e->e_shoff + e->e_shentsize * e->e_shnum)
    {
      grub_error (GRUB_ERR_BAD_OS, "ELF sections outside core");
      return 0;
    }

  mod = (grub_dl_t) grub_zalloc (sizeof (*mod));
  if (! mod)
    return 0;

  mod->ref_count = 1;

  grub_dprintf ("modules", "relocating to %p\n", mod);
  if (grub_dl_resolve_name (mod, e)
      || grub_dl_resolve_dependencies (mod, e)
      || grub_dl_load_segments (mod, e)
      || grub_dl_resolve_symbols (mod, e)
      || grub_arch_dl_relocate_symbols (mod, e))
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
  grub_dl_t p = grub_dl_head;

  while (p)
    {
      if (grub_dl_unload (p))
	{
	  p = grub_dl_head;
	  continue;
	}

      p = p->next;
    }
}
