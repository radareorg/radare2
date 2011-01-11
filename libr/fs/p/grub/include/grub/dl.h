/* dl.h - types and prototypes for loadable module support */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2004,2005,2007,2008,2009  Free Software Foundation, Inc.
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

#ifndef GRUB_DL_H
#define GRUB_DL_H	1

#include <grub/symbol.h>
#include <grub/err.h>
#include <grub/types.h>
//#include <grub/elf.h>


/*
 * Macros GRUB_MOD_INIT and GRUB_MOD_FINI are also used by build rules
 * to collect module names, so we define them only when they are not
 * defined already.
 */

#ifndef GRUB_MOD_INIT
#define GRUB_MOD_INIT(name)	\
static void grub_mod_init (grub_dl_t mod __attribute__ ((unused))) __attribute__ ((used)); \
void grub_##name##_init (void); \
void \
grub_##name##_init (void) { grub_mod_init (0); } \
static void \
grub_mod_init (grub_dl_t mod __attribute__ ((unused)))
#endif

#ifndef GRUB_MOD_FINI
#define GRUB_MOD_FINI(name)	\
static void grub_mod_fini (void) __attribute__ ((used)); \
void grub_##name##_fini (void); \
void \
grub_##name##_fini (void) { grub_mod_fini (); } \
static void \
grub_mod_fini (void)
#endif

#ifdef APPLE_CC
#define GRUB_MOD_NAME(name)	\
static char grub_modname[] __attribute__ ((section ("_modname, _modname"), used)) = #name;

#define GRUB_MOD_DEP(name)	\
__asm__ (".section _moddeps, _moddeps\n.asciz \"" #name "\"\n")
#else
#define GRUB_MOD_NAME(name)	\
__asm__ (".section .modname\n.asciz \"" #name "\"\n")

#define GRUB_MOD_DEP(name)	\
__asm__ (".section .moddeps\n.asciz \"" #name "\"\n")
#endif

struct grub_dl_segment
{
  struct grub_dl_segment *next;
  void *addr;
  grub_size_t size;
  unsigned section;
};
typedef struct grub_dl_segment *grub_dl_segment_t;

struct grub_dl;

struct grub_dl_dep
{
  struct grub_dl_dep *next;
  struct grub_dl *mod;
};
typedef struct grub_dl_dep *grub_dl_dep_t;

struct grub_dl
{
  char *name;
  int ref_count;
  grub_dl_dep_t dep;
  grub_dl_segment_t segment;
  void *symtab;//Elf_Sym *symtab;
  void (*init) (struct grub_dl *mod);
  void (*fini) (void);
  struct grub_dl *next;
};
typedef struct grub_dl *grub_dl_t;

grub_dl_t EXPORT_FUNC(grub_dl_load_file) (const char *filename);
grub_dl_t EXPORT_FUNC(grub_dl_load) (const char *name);
grub_dl_t grub_dl_load_core (void *addr, grub_size_t size);
int EXPORT_FUNC(grub_dl_unload) (grub_dl_t mod);
//void grub_dl_unload_unneeded (void);
//int EXPORT_FUNC(grub_dl_ref) (grub_dl_t mod);
//int EXPORT_FUNC(grub_dl_unref) (grub_dl_t mod);
extern grub_dl_t EXPORT_VAR(grub_dl_head);

#define FOR_DL_MODULES(var) FOR_LIST_ELEMENTS ((var), (grub_dl_head))

grub_dl_t EXPORT_FUNC(grub_dl_get) (const char *name);
grub_err_t grub_dl_register_symbol (const char *name, void *addr,
				    grub_dl_t mod);

grub_err_t grub_arch_dl_check_header (void *ehdr);
grub_err_t grub_arch_dl_relocate_symbols (grub_dl_t mod, void *ehdr);

#if defined (_mips)
#define GRUB_LINKER_HAVE_INIT 1
void grub_arch_dl_init_linker (void);
#endif

#endif /* ! GRUB_DL_H */
