/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2003,2005,2007,2008,2009,2010  Free Software Foundation, Inc.
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

#ifndef GRUB_TERM_HEADER
#define GRUB_TERM_HEADER	1

#define GRUB_TERM_NO_KEY        0

/* Internal codes used by GRUB to represent terminal input.  */
/* Only for keys otherwise not having shifted modification.  */
#define GRUB_TERM_SHIFT         0x01000000
#define GRUB_TERM_CTRL          0x02000000
#define GRUB_TERM_ALT           0x04000000

/* Keys without associated character.  */
#define GRUB_TERM_EXTENDED      0x00800000
#define GRUB_TERM_KEY_MASK      0x00ffffff

#define GRUB_TERM_KEY_LEFT      (GRUB_TERM_EXTENDED | 0x4b)
#define GRUB_TERM_KEY_RIGHT     (GRUB_TERM_EXTENDED | 0x4d)
#define GRUB_TERM_KEY_UP        (GRUB_TERM_EXTENDED | 0x48)
#define GRUB_TERM_KEY_DOWN      (GRUB_TERM_EXTENDED | 0x50)
#define GRUB_TERM_KEY_HOME      (GRUB_TERM_EXTENDED | 0x47)
#define GRUB_TERM_KEY_END       (GRUB_TERM_EXTENDED | 0x4f)
#define GRUB_TERM_KEY_DC        (GRUB_TERM_EXTENDED | 0x53)
#define GRUB_TERM_KEY_PPAGE     (GRUB_TERM_EXTENDED | 0x49)
#define GRUB_TERM_KEY_NPAGE     (GRUB_TERM_EXTENDED | 0x51)
#define GRUB_TERM_KEY_F1        (GRUB_TERM_EXTENDED | 0x3b)
#define GRUB_TERM_KEY_F2        (GRUB_TERM_EXTENDED | 0x3c)
#define GRUB_TERM_KEY_F3        (GRUB_TERM_EXTENDED | 0x3d)
#define GRUB_TERM_KEY_F4        (GRUB_TERM_EXTENDED | 0x3e)
#define GRUB_TERM_KEY_F5        (GRUB_TERM_EXTENDED | 0x3f)
#define GRUB_TERM_KEY_F6        (GRUB_TERM_EXTENDED | 0x40)
#define GRUB_TERM_KEY_F7        (GRUB_TERM_EXTENDED | 0x41)
#define GRUB_TERM_KEY_F8        (GRUB_TERM_EXTENDED | 0x42)
#define GRUB_TERM_KEY_F9        (GRUB_TERM_EXTENDED | 0x43)
#define GRUB_TERM_KEY_F10       (GRUB_TERM_EXTENDED | 0x44)
#define GRUB_TERM_KEY_F11       (GRUB_TERM_EXTENDED | 0x57)
#define GRUB_TERM_KEY_F12       (GRUB_TERM_EXTENDED | 0x58)
#define GRUB_TERM_KEY_INSERT    (GRUB_TERM_EXTENDED | 0x52)
#define GRUB_TERM_KEY_CENTER    (GRUB_TERM_EXTENDED | 0x4c)

#define GRUB_TERM_ESC		'\e'
#define GRUB_TERM_TAB		'\t'
#define GRUB_TERM_BACKSPACE	'\b'

#ifndef ASM_FILE

#include <grub/err.h>
#include <grub/symbol.h>
#include <grub/types.h>
#include <grub/unicode.h>
#include <grub/list.h>

/* These are used to represent the various color states we use.  */
typedef enum
  {
    /* The color used to display all text that does not use the
       user defined colors below.  */
    GRUB_TERM_COLOR_STANDARD,
    /* The user defined colors for normal text.  */
    GRUB_TERM_COLOR_NORMAL,
    /* The user defined colors for highlighted text.  */
    GRUB_TERM_COLOR_HIGHLIGHT
  }
grub_term_color_state;

/* Flags for representing the capabilities of a terminal.  */
/* Some notes about the flags:
   - These flags are used by higher-level functions but not terminals
   themselves.
   - If a terminal is dumb, you may assume that only putchar, getkey and
   checkkey are called.
   - Some fancy features (setcolorstate, setcolor and setcursor) can be set
   to NULL.  */

/* Set when input characters shouldn't be echoed back.  */
#define GRUB_TERM_NO_ECHO	        (1 << 0)
/* Set when the editing feature should be disabled.  */
#define GRUB_TERM_NO_EDIT	        (1 << 1)
/* Set when the terminal cannot do fancy things.  */
#define GRUB_TERM_DUMB		        (1 << 2)
/* Which encoding does terminal expect stream to be.  */
#define GRUB_TERM_CODE_TYPE_SHIFT       3
#define GRUB_TERM_CODE_TYPE_MASK	        (7 << GRUB_TERM_CODE_TYPE_SHIFT)
/* Only ASCII characters accepted.  */
#define GRUB_TERM_CODE_TYPE_ASCII	        (0 << GRUB_TERM_CODE_TYPE_SHIFT)
/* Expects CP-437 characters (ASCII + pseudographics).  */
#define GRUB_TERM_CODE_TYPE_CP437	                (1 << GRUB_TERM_CODE_TYPE_SHIFT)
/* UTF-8 stream in logical order. Usually used for terminals
   which just forward the stream to another computer.  */
#define GRUB_TERM_CODE_TYPE_UTF8_LOGICAL	(2 << GRUB_TERM_CODE_TYPE_SHIFT)
/* UTF-8 in visual order. Like UTF-8 logical but for buggy endpoints.  */
#define GRUB_TERM_CODE_TYPE_UTF8_VISUAL	        (3 << GRUB_TERM_CODE_TYPE_SHIFT)
/* Glyph description in visual order.  */
#define GRUB_TERM_CODE_TYPE_VISUAL_GLYPHS       (4 << GRUB_TERM_CODE_TYPE_SHIFT)


/* Bitmasks for modifier keys returned by grub_getkeystatus.  */
#define GRUB_TERM_STATUS_RSHIFT	(1 << 0)
#define GRUB_TERM_STATUS_LSHIFT	(1 << 1)
#define GRUB_TERM_STATUS_RCTRL	(1 << 2)
#define GRUB_TERM_STATUS_RALT	(1 << 3)
#define GRUB_TERM_STATUS_SCROLL	(1 << 4)
#define GRUB_TERM_STATUS_NUM	(1 << 5)
#define GRUB_TERM_STATUS_CAPS	(1 << 6)
#define GRUB_TERM_STATUS_LCTRL	(1 << 8)
#define GRUB_TERM_STATUS_LALT	(1 << 9)

/* Menu-related geometrical constants.  */

/* The number of lines of "GRUB version..." at the top.  */
#define GRUB_TERM_INFO_HEIGHT	1

/* The number of columns/lines between messages/borders/etc.  */
#define GRUB_TERM_MARGIN	1

/* The number of columns of scroll information.  */
#define GRUB_TERM_SCROLL_WIDTH	1

/* The Y position of the top border.  */
#define GRUB_TERM_TOP_BORDER_Y	(GRUB_TERM_MARGIN + GRUB_TERM_INFO_HEIGHT \
                                 + GRUB_TERM_MARGIN)

/* The X position of the left border.  */
#define GRUB_TERM_LEFT_BORDER_X	GRUB_TERM_MARGIN

/* The number of lines of messages at the bottom.  */
#define GRUB_TERM_MESSAGE_HEIGHT	8

/* The Y position of the first entry.  */
#define GRUB_TERM_FIRST_ENTRY_Y	(GRUB_TERM_TOP_BORDER_Y + 1)

struct grub_term_input
{
  /* The next terminal.  */
  struct grub_term_input *next;

  /* The terminal name.  */
  const char *name;

  /* Initialize the terminal.  */
  grub_err_t (*init) (struct grub_term_input *term);

  /* Clean up the terminal.  */
  grub_err_t (*fini) (struct grub_term_input *term);

  /* Get a character if any input character is available. Otherwise return -1  */
  int (*getkey) (struct grub_term_input *term);

  /* Get keyboard modifier status.  */
  int (*getkeystatus) (struct grub_term_input *term);

  void *data;
};
typedef struct grub_term_input *grub_term_input_t;

struct grub_term_output
{
  /* The next terminal.  */
  struct grub_term_output *next;

  /* The terminal name.  */
  const char *name;

  /* Initialize the terminal.  */
  grub_err_t (*init) (struct grub_term_output *term);

  /* Clean up the terminal.  */
  grub_err_t (*fini) (struct grub_term_output *term);

  /* Put a character. C is encoded in Unicode.  */
  void (*putchar) (struct grub_term_output *term,
		   const struct grub_unicode_glyph *c);

  /* Get the number of columns occupied by a given character C. C is
     encoded in Unicode.  */
  grub_ssize_t (*getcharwidth) (struct grub_term_output *term,
				const struct grub_unicode_glyph *c);

  /* Get the screen size. The return value is ((Width << 8) | Height).  */
  grub_uint16_t (*getwh) (struct grub_term_output *term);

  /* Get the cursor position. The return value is ((X << 8) | Y).  */
  grub_uint16_t (*getxy) (struct grub_term_output *term);

  /* Go to the position (X, Y).  */
  void (*gotoxy) (struct grub_term_output *term,
		  grub_uint8_t x, grub_uint8_t y);

  /* Clear the screen.  */
  void (*cls) (struct grub_term_output *term);

  /* Set the current color to be used */
  void (*setcolorstate) (struct grub_term_output *term,
			 grub_term_color_state state);

  /* Turn on/off the cursor.  */
  void (*setcursor) (struct grub_term_output *term, int on);

  /* Update the screen.  */
  void (*refresh) (struct grub_term_output *term);

  /* The feature flags defined above.  */
  grub_uint32_t flags;

  /* Current color state.  */
  grub_uint8_t normal_color;
  grub_uint8_t highlight_color;

  void *data;
};
typedef struct grub_term_output *grub_term_output_t;

#define GRUB_TERM_DEFAULT_NORMAL_COLOR 0x07
#define GRUB_TERM_DEFAULT_HIGHLIGHT_COLOR 0x70
#define GRUB_TERM_DEFAULT_STANDARD_COLOR 0x07

extern struct grub_term_output *EXPORT_VAR(grub_term_outputs_disabled);
extern struct grub_term_input *EXPORT_VAR(grub_term_inputs_disabled);
extern struct grub_term_output *EXPORT_VAR(grub_term_outputs);
extern struct grub_term_input *EXPORT_VAR(grub_term_inputs);

static inline void
grub_term_register_input (const char *name __attribute__ ((unused)),
			  grub_term_input_t term)
{
  if (grub_term_inputs)
    grub_list_push (GRUB_AS_LIST_P (&grub_term_inputs_disabled),
		    GRUB_AS_LIST (term));
  else
    {
      /* If this is the first terminal, enable automatically.  */
      if (! term->init || term->init (term) == GRUB_ERR_NONE)
	grub_list_push (GRUB_AS_LIST_P (&grub_term_inputs), GRUB_AS_LIST (term));
    }
}

static inline void
grub_term_register_input_active (const char *name __attribute__ ((unused)),
				 grub_term_input_t term)
{
  if (! term->init || term->init (term) == GRUB_ERR_NONE)
    grub_list_push (GRUB_AS_LIST_P (&grub_term_inputs), GRUB_AS_LIST (term));
}

static inline void
grub_term_register_output (const char *name __attribute__ ((unused)),
			   grub_term_output_t term)
{
  if (grub_term_outputs)
    grub_list_push (GRUB_AS_LIST_P (&grub_term_outputs_disabled),
		    GRUB_AS_LIST (term));
  else
    {
      /* If this is the first terminal, enable automatically.  */
      if (! term->init || term->init (term) == GRUB_ERR_NONE)
	grub_list_push (GRUB_AS_LIST_P (&grub_term_outputs),
			GRUB_AS_LIST (term));
    }
}

static inline void
grub_term_register_output_active (const char *name __attribute__ ((unused)),
				  grub_term_output_t term)
{
  if (! term->init || term->init (term) == GRUB_ERR_NONE)
    grub_list_push (GRUB_AS_LIST_P (&grub_term_outputs),
		    GRUB_AS_LIST (term));
}

static inline void
grub_term_unregister_input (grub_term_input_t term)
{
  grub_list_remove (GRUB_AS_LIST_P (&grub_term_inputs), GRUB_AS_LIST (term));
  grub_list_remove (GRUB_AS_LIST_P (&grub_term_inputs_disabled),
		    GRUB_AS_LIST (term));
}

static inline void
grub_term_unregister_output (grub_term_output_t term)
{
  grub_list_remove (GRUB_AS_LIST_P (&grub_term_outputs), GRUB_AS_LIST (term));
  grub_list_remove (GRUB_AS_LIST_P (&(grub_term_outputs_disabled)),
		    GRUB_AS_LIST (term));
}

#define FOR_ACTIVE_TERM_INPUTS(var) FOR_LIST_ELEMENTS((var), (grub_term_inputs))
#define FOR_DISABLED_TERM_INPUTS(var) FOR_LIST_ELEMENTS((var), (grub_term_inputs_disabled))
#define FOR_ACTIVE_TERM_OUTPUTS(var) FOR_LIST_ELEMENTS((var), (grub_term_outputs))
#define FOR_DISABLED_TERM_OUTPUTS(var) FOR_LIST_ELEMENTS((var), (grub_term_outputs_disabled))

void grub_putcode (grub_uint32_t code, struct grub_term_output *term);
int EXPORT_FUNC(grub_getkey) (void);
int EXPORT_FUNC(grub_checkkey) (void);
void grub_cls (void);
void EXPORT_FUNC(grub_refresh) (void);
void grub_puts_terminal (const char *str, struct grub_term_output *term);
grub_uint16_t *grub_term_save_pos (void);
void grub_term_restore_pos (grub_uint16_t *pos);

static inline unsigned grub_term_width (struct grub_term_output *term)
{
  return ((term->getwh(term)&0xFF00)>>8);
}

static inline unsigned grub_term_height (struct grub_term_output *term)
{
  return (term->getwh(term)&0xFF);
}

/* The width of the border.  */
static inline unsigned
grub_term_border_width (struct grub_term_output *term)
{
  return grub_term_width (term) - GRUB_TERM_MARGIN * 3 - GRUB_TERM_SCROLL_WIDTH;
}

/* The max column number of an entry. The last "-1" is for a
   continuation marker.  */
static inline int
grub_term_entry_width (struct grub_term_output *term)
{
  return grub_term_border_width (term) - 2 - GRUB_TERM_MARGIN * 2 - 1;
}

/* The height of the border.  */

static inline unsigned
grub_term_border_height (struct grub_term_output *term)
{
  return grub_term_height (term) - GRUB_TERM_TOP_BORDER_Y
    - GRUB_TERM_MESSAGE_HEIGHT;
}

/* The number of entries shown at a time.  */
static inline int
grub_term_num_entries (struct grub_term_output *term)
{
  return grub_term_border_height (term) - 2;
}

static inline int
grub_term_cursor_x (struct grub_term_output *term)
{
  return (GRUB_TERM_LEFT_BORDER_X + grub_term_border_width (term) 
	  - GRUB_TERM_MARGIN - 1);
}

static inline grub_uint16_t
grub_term_getxy (struct grub_term_output *term)
{
  return term->getxy (term);
}

static inline void
grub_term_refresh (struct grub_term_output *term)
{
  if (term->refresh)
    term->refresh (term);
}

static inline void
grub_term_gotoxy (struct grub_term_output *term, grub_uint8_t x, grub_uint8_t y)
{
  term->gotoxy (term, x, y);
}

static inline void 
grub_term_setcolorstate (struct grub_term_output *term, 
			 grub_term_color_state state)
{
  if (term->setcolorstate)
    term->setcolorstate (term, state);
}

static inline void
grub_setcolorstate (grub_term_color_state state)
{
  struct grub_term_output *term;
  
  FOR_ACTIVE_TERM_OUTPUTS(term)
    grub_term_setcolorstate (term, state);
}

/* Set the normal color and the highlight color. The format of each
   color is VGA's.  */
static inline void 
grub_term_setcolor (struct grub_term_output *term,
		    grub_uint8_t normal_color, grub_uint8_t highlight_color)
{
  term->normal_color = normal_color;
  term->highlight_color = highlight_color;
}

/* Turn on/off the cursor.  */
static inline void 
grub_term_setcursor (struct grub_term_output *term, int on)
{
  if (term->setcursor)
    term->setcursor (term, on);
}

static inline void 
grub_term_cls (struct grub_term_output *term)
{
  if (term->cls)
    (term->cls) (term);
  else
    {
      grub_putcode ('\n', term);
      grub_term_refresh (term);
    }
}

#ifdef HAVE_UNIFONT_WIDTHSPEC

grub_ssize_t
grub_unicode_estimate_width (const struct grub_unicode_glyph *c);

#else

static inline grub_ssize_t
grub_unicode_estimate_width (const struct grub_unicode_glyph *c __attribute__ ((unused)))
{
  if (grub_unicode_get_comb_type (c->base))
    return 0;
  return 1;
}

#endif

static inline grub_ssize_t 
grub_term_getcharwidth (struct grub_term_output *term,
			const struct grub_unicode_glyph *c)
{
  if (term->getcharwidth)
    return term->getcharwidth (term, c);
  else if (((term->flags & GRUB_TERM_CODE_TYPE_MASK)
	    == GRUB_TERM_CODE_TYPE_UTF8_LOGICAL)
	   || ((term->flags & GRUB_TERM_CODE_TYPE_MASK)
	       == GRUB_TERM_CODE_TYPE_UTF8_VISUAL)
	   || ((term->flags & GRUB_TERM_CODE_TYPE_MASK)
	       == GRUB_TERM_CODE_TYPE_VISUAL_GLYPHS))
    return grub_unicode_estimate_width (c);
  else
    return 1;
}

static inline void 
grub_term_getcolor (struct grub_term_output *term, 
		    grub_uint8_t *normal_color, grub_uint8_t *highlight_color)
{
  *normal_color = term->normal_color;
  *highlight_color = term->highlight_color;
}

struct grub_term_autoload
{
  struct grub_term_autoload *next;
  char *name;
  char *modname;
};

extern struct grub_term_autoload *grub_term_input_autoload;
extern struct grub_term_autoload *grub_term_output_autoload;

static inline void
grub_print_spaces (struct grub_term_output *term, int number_spaces)
{
  while (--number_spaces >= 0)
    grub_putcode (' ', term);
}

extern void (*EXPORT_VAR (grub_term_poll_usb)) (void);

#define GRUB_TERM_REPEAT_PRE_INTERVAL 400
#define GRUB_TERM_REPEAT_INTERVAL 50

#endif /* ! ASM_FILE */

#endif /* ! GRUB_TERM_HEADER */
