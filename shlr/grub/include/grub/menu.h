/* menu.h - Menu model function prototypes and data structures. */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009  Free Software Foundation, Inc.
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

#ifndef GRUB_MENU_HEADER
#define GRUB_MENU_HEADER 1

struct grub_menu_entry_class
{
  char *name;
  struct grub_menu_entry_class *next;
};

/* The menu entry.  */
struct grub_menu_entry
{
  /* The title name.  */
  const char *title;

  /* If set means not everybody is allowed to boot this entry.  */
  int restricted;

  /* Allowed users.  */
  const char *users;

  /* The classes associated with the menu entry:
     used to choose an icon or other style attributes.
     This is a dummy head node for the linked list, so for an entry E,
     E.classes->next is the first class if it is not NULL.  */
  struct grub_menu_entry_class *classes;

  /* The sourcecode of the menu entry, used by the editor.  */
  const char *sourcecode;

  int hotkey;

  const char *group;

  /* The next element.  */
  struct grub_menu_entry *next;
};
typedef struct grub_menu_entry *grub_menu_entry_t;

/* The menu.  */
struct grub_menu
{
  /* The size of a menu.  */
  int size;

  /* The list of menu entries.  */
  grub_menu_entry_t entry_list;
};
typedef struct grub_menu *grub_menu_t;

grub_err_t grub_menu_entry_add (int argc, const char **args,
				const char *sourcecode);
void grub_menu_execute (const char *config, int nested, int batch);
const char *grub_menu_key2name (int key);
int grub_menu_name2key (const char *name);

#endif /* GRUB_MENU_HEADER */
