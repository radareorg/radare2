/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2005,2006,2007,2009  Free Software Foundation, Inc.
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

#ifndef GRUB_ENV_HEADER
#define GRUB_ENV_HEADER	1

#include <grub/symbol.h>
#include <grub/err.h>
#include <grub/types.h>
#include <grub/menu.h>

struct grub_env_var;

typedef char *(*grub_env_read_hook_t) (struct grub_env_var *var,
				       const char *val);
typedef char *(*grub_env_write_hook_t) (struct grub_env_var *var,
					const char *val);

struct grub_env_var
{
  char *name;
  char *value;
  grub_env_read_hook_t read_hook;
  grub_env_write_hook_t write_hook;
  struct grub_env_var *next;
  struct grub_env_var **prevp;
  int global;
};

grub_err_t grub_env_set (const char *name, const char *val);
char *grub_env_get (const char *name);
void grub_env_unset (const char *name);
void grub_env_iterate (int (*func) (struct grub_env_var *var, void *), void *);
struct grub_env_var *grub_env_find (const char *name);
grub_err_t grub_register_variable_hook (const char *name,
					grub_env_read_hook_t read_hook,
					grub_env_write_hook_t write_hook);

grub_err_t grub_env_context_open (int export);
grub_err_t grub_env_context_close (void);
grub_err_t grub_env_export (const char *name);

struct menu_pointer
{
  grub_menu_t menu;
  struct menu_pointer *prev;
};

extern struct menu_pointer *grub_current_menu;

static inline void
grub_env_unset_menu (void)
{
  grub_current_menu->menu = 0;
}

static inline grub_menu_t
grub_env_get_menu (void)
{
  return grub_current_menu->menu;
}

static inline void
grub_env_set_menu (grub_menu_t nmenu)
{
  grub_current_menu->menu = nmenu;
}

#endif /* ! GRUB_ENV_HEADER */
