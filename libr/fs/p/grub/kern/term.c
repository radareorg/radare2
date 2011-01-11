/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2003,2005,2007,2008,2009  Free Software Foundation, Inc.
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

#include <grub/term.h>
#include <grub/err.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/env.h>
#include <grub/time.h>

struct grub_term_output *grub_term_outputs_disabled;
struct grub_term_input *grub_term_inputs_disabled;
struct grub_term_output *grub_term_outputs;
struct grub_term_input *grub_term_inputs;

void (*grub_term_poll_usb) (void) = NULL;

/* Put a Unicode character.  */
static void
grub_putcode_dumb (grub_uint32_t code,
		   struct grub_term_output *term)
{
  struct grub_unicode_glyph c =
    {
      .base = code,
      .variant = 0,
      .attributes = 0,
      .ncomb = 0,
      .combining = 0,
      .estimated_width = 1
    };

  if (code == '\t' && term->getxy)
    {
      int n;

      n = 8 - ((term->getxy (term) >> 8) & 7);
      while (n--)
	grub_putcode_dumb (' ', term);

      return;
    }

  (term->putchar) (term, &c);
  if (code == '\n')
    grub_putcode_dumb ('\r', term);
}

static void
grub_xputs_dumb (const char *str)
{
  for (; *str; str++)
    {
      grub_term_output_t term;
      grub_uint32_t code = *str;
      if (code > 0x7f)
	code = '?';

      FOR_ACTIVE_TERM_OUTPUTS(term)
	grub_putcode_dumb (code, term);
    }
}

void (*grub_xputs) (const char *str) = grub_xputs_dumb;

static int pending_key = GRUB_TERM_NO_KEY;

int
grub_checkkey (void)
{
  grub_term_input_t term;

  if (pending_key != GRUB_TERM_NO_KEY)
    return pending_key;

  if (grub_term_poll_usb)
    grub_term_poll_usb ();

  FOR_ACTIVE_TERM_INPUTS(term)
  {
    pending_key = term->getkey (term);
    if (pending_key != GRUB_TERM_NO_KEY)
      return pending_key;
  }

  return -1;
}

int
grub_getkey (void)
{
  int ret;

  grub_refresh ();

  grub_checkkey ();
  while (pending_key == GRUB_TERM_NO_KEY)
    {
      //grub_cpu_idle ();
      grub_checkkey ();
    }
  ret = pending_key;
  pending_key = GRUB_TERM_NO_KEY;
  return ret;
}


void
grub_refresh (void)
{
  struct grub_term_output *term;

  FOR_ACTIVE_TERM_OUTPUTS(term)
    grub_term_refresh (term);
}
