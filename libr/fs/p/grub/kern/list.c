/* list.c - grub list function */
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

#include <grub/list.h>
#include <grub/misc.h>
#include <grub/mm.h>

void
grub_list_push (grub_list_t *head, grub_list_t item)
{
  item->next = *head;
  *head = item;
}

void
grub_list_remove (grub_list_t *head, grub_list_t item)
{
  grub_list_t *p, q;

  for (p = head, q = *p; q; p = &(q->next), q = q->next)
    if (q == item)
      {
	*p = q->next;
	break;
      }
}

void *
grub_named_list_find (grub_named_list_t head, const char *name)
{
  grub_named_list_t item;

  FOR_LIST_ELEMENTS (item, head)
    if (grub_strcmp (item->name, name) == 0)
      return item;

  return NULL;
}

void
grub_prio_list_insert (grub_prio_list_t *head, grub_prio_list_t nitem)
{
  int inactive = 0;

  grub_prio_list_t *p, q;
    
  for (p = head, q = *p; q; p = &(q->next), q = q->next)
    {
      int r;

      r = grub_strcmp (nitem->name, q->name);
      if (r < 0)
	break;
      if (r > 0)
	continue;

      if (nitem->prio >= (q->prio & GRUB_PRIO_LIST_PRIO_MASK))
	{
	  q->prio &= ~GRUB_PRIO_LIST_FLAG_ACTIVE;
	  break;
	}

      inactive = 1;
    }

  *p = nitem;
  nitem->next = q;

  if (! inactive)
    nitem->prio |= GRUB_PRIO_LIST_FLAG_ACTIVE;
}
