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

GRUB_EXPORT(grub_list_push);
GRUB_EXPORT(grub_list_pop);
GRUB_EXPORT(grub_list_remove);
GRUB_EXPORT(grub_list_iterate);
GRUB_EXPORT(grub_list_insert);
GRUB_EXPORT(grub_prio_list_insert);
GRUB_EXPORT(grub_named_list_find);

void
grub_list_push (grub_list_t *head, grub_list_t item)
{
  item->next = *head;
  *head = item;
}

void *
grub_list_pop (grub_list_t *head)
{
  grub_list_t item;

  item = *head;
  if (item)
    *head = item->next;

  return item;
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

int
grub_list_iterate (grub_list_t head, grub_list_hook_t hook, void *closure)
{
  grub_list_t p;

  for (p = head; p; p = p->next)
    if (hook (p, closure))
      return 1;

  return 0;
}

void
grub_list_insert (grub_list_t *head, grub_list_t item,
		  grub_list_test_t test, void *closure)
{
  grub_list_t *p, q;

  for (p = head, q = *p; q; p = &(q->next), q = q->next)
    if (test (item, q, closure))
      break;

  *p = item;
  item->next = q;
}

void *
grub_named_list_find (grub_named_list_t head, const char *name)
{
  while (head)
    {
      if (! grub_strcmp (head->name, name))
	return head;

      head = head->next;
    }

  return 0;
}

struct grub_prio_list_insert_closure
{
  int inactive;
};

static int
grub_prio_list_insert_test (grub_prio_list_t new_item, grub_prio_list_t item,
			    void *closure)
{
  struct grub_prio_list_insert_closure *c = closure;
  int r;

  r = grub_strcmp (new_item->name, item->name);
  if (r)
    return (r < 0);

  if (new_item->prio >= (item->prio & GRUB_PRIO_LIST_PRIO_MASK))
    {
      item->prio &= ~GRUB_PRIO_LIST_FLAG_ACTIVE;
      return 1;
    }

  c->inactive = 1;
  return 0;
}

void
grub_prio_list_insert (grub_prio_list_t *head, grub_prio_list_t nitem)
{
  struct grub_prio_list_insert_closure c;

  c.inactive = 0;
  grub_list_insert (GRUB_AS_LIST_P (head), GRUB_AS_LIST (nitem),
		    (grub_list_test_t) grub_prio_list_insert_test, &c);
  if (! c.inactive)
    nitem->prio |= GRUB_PRIO_LIST_FLAG_ACTIVE;
}
