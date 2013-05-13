/* misc.c - definitions of misc functions */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010  Free Software Foundation, Inc.
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

#include <grub/misc.h>
#include <grub/err.h>
#include <grub/mm.h>
#include <stdarg.h>
#include <grub/term.h>
#include <grub/env.h>
#include <grub/i18n.h>

GRUB_EXPORT(grub_memmove);
GRUB_EXPORT(grub_strcpy);
GRUB_EXPORT(grub_strncpy);
GRUB_EXPORT(grub_stpcpy);

GRUB_EXPORT(grub_memcmp);
GRUB_EXPORT(grub_strcmp);
GRUB_EXPORT(grub_strncmp);
GRUB_EXPORT(grub_strchr);
GRUB_EXPORT(grub_strrchr);
GRUB_EXPORT(grub_strword);
GRUB_EXPORT(grub_strstr);
GRUB_EXPORT(grub_isspace);
GRUB_EXPORT(grub_isprint);

GRUB_EXPORT(grub_strtoul);
GRUB_EXPORT(grub_strtoull);
GRUB_EXPORT(grub_strdup);
GRUB_EXPORT(grub_strndup);
GRUB_EXPORT(grub_memset);
GRUB_EXPORT(grub_strlen);
GRUB_EXPORT(grub_printf);
GRUB_EXPORT(grub_printf_);
GRUB_EXPORT(grub_puts);
GRUB_EXPORT(grub_puts_);
GRUB_EXPORT(grub_real_dprintf);
GRUB_EXPORT(grub_vprintf);
GRUB_EXPORT(grub_snprintf);
GRUB_EXPORT(grub_vsnprintf);
GRUB_EXPORT(grub_xasprintf);
GRUB_EXPORT(grub_xvasprintf);
GRUB_EXPORT(grub_exit);
GRUB_EXPORT(grub_abort);
GRUB_EXPORT(grub_utf8_to_ucs4);
GRUB_EXPORT(grub_divmod64);
GRUB_EXPORT(grub_gettext);

static int
grub_vsnprintf_real (char *str, grub_size_t n, const char *fmt, va_list args);

static int
grub_iswordseparator (int c)
{
  return (grub_isspace (c) || c == ',' || c == ';' || c == '|' || c == '&');
}

/* grub_gettext_dummy is not translating anything.  */
static const char *
grub_gettext_dummy (const char *s)
{
  return s;
}

const char* (*grub_gettext) (const char *s) = grub_gettext_dummy;

void *
grub_memmove (void *dest, const void *src, grub_size_t n)
{
  char *d = (char *) dest;
  const char *s = (const char *) src;

  if (d < s)
    while (n--)
      *d++ = *s++;
  else
    {
      d += n;
      s += n;

      while (n--)
	*--d = *--s;
    }

  return dest;
}

char *
grub_strcpy (char *dest, const char *src)
{
  char *p = dest;

  while ((*p++ = *src++) != '\0')
    ;

  return dest;
}

char *
grub_strncpy (char *dest, const char *src, int c)
{
  char *p = dest;

  while ((*p++ = *src++) != '\0' && --c)
    ;

  return dest;
}

char *
grub_stpcpy (char *dest, const char *src)
{
  char *d = dest;
  const char *s = src;

  do
    *d++ = *s;
  while (*s++ != '\0');

  return d - 1;
}

int
grub_printf (const char *fmt, ...)
{
  va_list ap;
  int ret;

  va_start (ap, fmt);
  ret = grub_vprintf (fmt, ap);
  va_end (ap);

  return ret;
}

int
grub_printf_ (const char *fmt, ...)
{
  va_list ap;
  int ret;

  va_start (ap, fmt);
  ret = grub_vprintf (_(fmt), ap);
  va_end (ap);

  return ret;
}

int
grub_puts (const char *s)
{
  while (*s)
    {
      grub_putchar (*s);
      s++;
    }
  grub_putchar ('\n');

  return 1;	/* Cannot fail.  */
}

int
grub_puts_ (const char *s)
{
  return grub_puts (_(s));
}

int
grub_err_printf (const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start (ap, fmt);
	ret = grub_vprintf (fmt, ap);
	va_end (ap);

	return ret;
}

void
grub_real_dprintf (const char *file, const int line, const char *condition,
		   const char *fmt, ...)
{
  va_list args;
  const char *debug = grub_env_get ("debug");

  if (! debug)
    return;

  if (grub_strword (debug, "all") || grub_strword (debug, condition))
    {
      grub_printf ("%s:%d: ", file, line);
      va_start (args, fmt);
      grub_vprintf (fmt, args);
      va_end (args);
    }
}

int
grub_vprintf (const char *fmt, va_list args)
{
  int ret;

  ret = grub_vsnprintf_real (0, 0, fmt, args);
  return ret;
}

int
grub_memcmp (const void *s1, const void *s2, grub_size_t n)
{
  const char *t1 = s1;
  const char *t2 = s2;

  while (n--)
    {
      if (*t1 != *t2)
	return (int) *t1 - (int) *t2;

      t1++;
      t2++;
    }

  return 0;
}

int
grub_strcmp (const char *s1, const char *s2)
{
  while (*s1 && *s2)
    {
      if (*s1 != *s2)
	break;

      s1++;
      s2++;
    }

  return (int) *s1 - (int) *s2;
}

int
grub_strncmp (const char *s1, const char *s2, grub_size_t n)
{
  if (n == 0)
    return 0;

  while (*s1 && *s2 && --n)
    {
      if (*s1 != *s2)
	break;

      s1++;
      s2++;
    }

  return (int) *s1 - (int) *s2;
}

char *
grub_strchr (const char *s, int c)
{
  do
    {
      if (*s == c)
	return (char *) s;
    }
  while (*s++);

  return 0;
}

char *
grub_strrchr (const char *s, int c)
{
  char *p = NULL;

  do
    {
      if (*s == c)
	p = (char *) s;
    }
  while (*s++);

  return p;
}

/* Copied from gnulib.
   Written by Bruno Haible <bruno@clisp.org>, 2005. */
char *
grub_strstr (const char *haystack, const char *needle)
{
  /* Be careful not to look at the entire extent of haystack or needle
     until needed.  This is useful because of these two cases:
       - haystack may be very long, and a match of needle found early,
       - needle may be very long, and not even a short initial segment of
       needle may be found in haystack.  */
  if (*needle != '\0')
    {
      /* Speed up the following searches of needle by caching its first
	 character.  */
      char b = *needle++;

      for (;; haystack++)
	{
	  if (*haystack == '\0')
	    /* No match.  */
	    return NULL;
	  if (*haystack == b)
	    /* The first character matches.  */
	    {
	      const char *rhaystack = haystack + 1;
	      const char *rneedle = needle;

	      for (;; rhaystack++, rneedle++)
		{
		  if (*rneedle == '\0')
		    /* Found a match.  */
		    return (char *) haystack;
		  if (*rhaystack == '\0')
		    /* No match.  */
		    return NULL;
		  if (*rhaystack != *rneedle)
		    /* Nothing in this round.  */
		    break;
		}
	    }
	}
    }
  else
    return (char *) haystack;
}

int
grub_strword (const char *haystack, const char *needle)
{
  const char *n_pos = needle;

  while (grub_iswordseparator (*haystack))
    haystack++;

  while (*haystack)
    {
      /* Crawl both the needle and the haystack word we're on.  */
      while(*haystack && !grub_iswordseparator (*haystack)
            && *haystack == *n_pos)
        {
          haystack++;
          n_pos++;
        }

      /* If we reached the end of both words at the same time, the word
      is found. If not, eat everything in the haystack that isn't the
      next word (or the end of string) and "reset" the needle.  */
      if ( (!*haystack || grub_iswordseparator (*haystack))
         && (!*n_pos || grub_iswordseparator (*n_pos)))
        return 1;
      else
        {
          n_pos = needle;
          while (*haystack && !grub_iswordseparator (*haystack))
            haystack++;
          while (grub_iswordseparator (*haystack))
            haystack++;
        }
    }

  return 0;
}

int
grub_isspace (int c)
{
  return (c == '\n' || c == '\r' || c == ' ' || c == '\t');
}

int
grub_isprint (int c)
{
  return (c >= ' ' && c <= '~');
}


unsigned long
grub_strtoul (const char *str, char **end, int base)
{
  unsigned long long num;

  num = grub_strtoull (str, end, base);
  if (num > ~0UL)
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, "overflow is detected");
      return ~0UL;
    }

  return (unsigned long) num;
}

unsigned long long
grub_strtoull (const char *str, char **end, int base)
{
  unsigned long long num = 0;
  int found = 0;

  /* Skip white spaces.  */
  while (*str && grub_isspace (*str))
    str++;

  /* Guess the base, if not specified. The prefix `0x' means 16, and
     the prefix `0' means 8.  */
  if (str[0] == '0')
    {
      if (str[1] == 'x')
	{
	  if (base == 0 || base == 16)
	    {
	      base = 16;
	      str += 2;
	    }
	}
      else if (base == 0 && str[1] >= '0' && str[1] <= '7')
	base = 8;
    }

  if (base == 0)
    base = 10;

  while (*str)
    {
      unsigned long digit;

      digit = grub_tolower (*str) - '0';
      if (digit > 9)
	{
	  digit += '0' - 'a' + 10;
	  if (digit >= (unsigned long) base)
	    break;
	}

      found = 1;

      /* NUM * BASE + DIGIT > ~0ULL */
      if (num > grub_divmod64 (~0ULL - digit, base, 0))
	{
	  grub_error (GRUB_ERR_OUT_OF_RANGE, "overflow is detected");
	  return ~0ULL;
	}

      num = num * base + digit;
      str++;
    }

  if (! found)
    {
      grub_error (GRUB_ERR_BAD_NUMBER, "unrecognized number");
      return 0;
    }

  if (end)
    *end = (char *) str;

  return num;
}

char *
grub_strdup (const char *s)
{
  grub_size_t len;
  char *p;

  len = grub_strlen (s) + 1;
  p = (char *) grub_malloc (len);
  if (! p)
    return 0;

  return grub_memcpy (p, s, len);
}

char *
grub_strndup (const char *s, grub_size_t n)
{
  grub_size_t len;
  char *p;

  len = grub_strlen (s);
  if (len > n)
    len = n;
  p = (char *) grub_malloc (len + 1);
  if (! p)
    return 0;

  grub_memcpy (p, s, len);
  p[len] = '\0';
  return p;
}

void *
grub_memset (void *s, int c, grub_size_t n)
{
  unsigned char *p = (unsigned char *) s;

  while (n--)
    *p++ = (unsigned char) c;

  return s;
}

grub_size_t
grub_strlen (const char *s)
{
  const char *p = s;

  while (*p)
    p++;

  return p - s;
}

static inline void
grub_reverse (char *str) {
	char tmp, *p = str + grub_strlen (str) - 1;
	while (str < p) {
		tmp = *str;
		*str = *p;
		*p = tmp;
		str++;
		p--;
	}
}

/* Divide N by D, return the quotient, and store the remainder in *R.  */
grub_uint64_t
grub_divmod64 (grub_uint64_t n, grub_uint32_t d, grub_uint32_t *r)
{
  /* This algorithm is typically implemented by hardware. The idea
     is to get the highest bit in N, 64 times, by keeping
     upper(N * 2^i) = upper((Q * 10 + M) * 2^i), where upper
     represents the high 64 bits in 128-bits space.  */
  unsigned bits = 64;
  unsigned long long q = 0;
  unsigned m = 0;

  /* Skip the slow computation if 32-bit arithmetic is possible.  */
  if (n < 0xffffffff)
    {
      if (r)
	*r = ((grub_uint32_t) n) % d;

      return ((grub_uint32_t) n) / d;
    }

  while (bits--)
    {
      m <<= 1;

      if (n & (1ULL << 63))
	m |= 1;

      q <<= 1;
      n <<= 1;

      if (m >= d)
	{
	  q |= 1;
	  m -= d;
	}
    }

  if (r)
    *r = m;

  return q;
}

/* Convert a long long value to a string. This function avoids 64-bit
   modular arithmetic or divisions.  */
static char *
grub_lltoa (char *str, int c, unsigned long long n)
{
  unsigned base = (c == 'x') ? 16 : 10;
  char *p;

  if ((long long) n < 0 && c == 'd')
    {
      n = (unsigned long long) (-((long long) n));
      *str++ = '-';
    }

  p = str;

  if (base == 16)
    do
      {
	unsigned d = (unsigned) (n & 0xf);
	*p++ = (d > 9) ? d + 'a' - 10 : d + '0';
      }
    while (n >>= 4);
  else
    /* BASE == 10 */
    do
      {
	unsigned m;

	n = grub_divmod64 (n, 10, &m);
	*p++ = m + '0';
      }
    while (n);

  *p = 0;

  grub_reverse (str);
  return p;
}

struct vsnprintf_closure
{
  char *str;
  grub_size_t count;
  grub_size_t max_len;
};

static void
write_char (unsigned char ch, struct vsnprintf_closure *cc)
{
  if (cc->str)
    {
      if (cc->count < cc->max_len)
	*(cc->str)++ = ch;
    }
  else
    grub_putchar (ch);

  (cc->count)++;
}

static void
write_str (const char *s, struct vsnprintf_closure *cc)
{
  while (*s)
    write_char (*s++, cc);
}

static void
write_fill (const char ch, int n, struct vsnprintf_closure *cc)
{
  int i;
  for (i = 0; i < n; i++)
    write_char (ch, cc);
}

static int
grub_vsnprintf_real (char *str, grub_size_t max_len, const char *fmt, va_list args)
{
  char c;
  struct vsnprintf_closure cc;

  cc.str = str;
  cc.max_len = max_len;
  cc.count = 0;

  while ((c = *fmt++) != 0)
    {
      if (c != '%')
	write_char (c, &cc);
      else
	{
	  char tmp[32];
	  char *p;
	  unsigned int format1 = 0;
	  unsigned int format2 = ~ 0U;
	  char zerofill = ' ';
	  int rightfill = 0;
	  int n;
	  int longfmt = 0;
	  int longlongfmt = 0;
	  int unsig = 0;

	  if (*fmt && *fmt =='-')
	    {
	      rightfill = 1;
	      fmt++;
	    }

	  p = (char *) fmt;
	  /* Read formatting parameters.  */
	  while (*p && grub_isdigit (*p))
	    p++;

	  if (p > fmt)
	    {
	      char s[p - fmt + 1];
	      grub_strncpy (s, fmt, p - fmt);
	      s[p - fmt] = 0;
	      if (s[0] == '0')
		zerofill = '0';
	      format1 = grub_strtoul (s, 0, 10);
	      fmt = p;
	    }

	  if (*p && *p == '.')
	    {
	      p++;
	      fmt++;
	      while (*p && grub_isdigit (*p))
		p++;

	      if (p > fmt)
		{
		  char fstr[p - fmt + 1];
		  grub_strncpy (fstr, fmt, p - fmt);
		  fstr[p - fmt] = 0;
		  format2 = grub_strtoul (fstr, 0, 10);
		  fmt = p;
		}
	    }

	  c = *fmt++;
	  if (c == 'l')
	    {
	      longfmt = 1;
	      c = *fmt++;
	      if (c == 'l')
		{
		  longlongfmt = 1;
		  c = *fmt++;
		}
	    }

	  switch (c)
	    {
	    case 'p':
	      write_str ("0x", &cc);
	      c = 'x';
	      longlongfmt |= (sizeof (void *) == sizeof (long long));
	      /* Fall through. */
	    case 'x':
	    case 'u':
	      unsig = 1;
	      /* Fall through. */
	    case 'd':
	      if (longlongfmt)
		{
		  long long ll;

		  ll = va_arg (args, long long);
		  grub_lltoa (tmp, c, ll);
		}
	      else if (longfmt && unsig)
		{
		  unsigned long l = va_arg (args, unsigned long);
		  grub_lltoa (tmp, c, l);
		}
	      else if (longfmt)
		{
		  long l = va_arg (args, long);
		  grub_lltoa (tmp, c, l);
		}
	      else if (unsig)
		{
		  unsigned u = va_arg (args, unsigned);
		  grub_lltoa (tmp, c, u);
		}
	      else
		{
		  n = va_arg (args, int);
		  grub_lltoa (tmp, c, n);
		}
	      if (! rightfill && grub_strlen (tmp) < format1)
		write_fill (zerofill, format1 - grub_strlen (tmp), &cc);
	      write_str (tmp, &cc);
	      if (rightfill && grub_strlen (tmp) < format1)
		write_fill (zerofill, format1 - grub_strlen (tmp), &cc);
	      break;

	    case 'c':
	      n = va_arg (args, int);
	      write_char (n & 0xff, &cc);
	      break;

	    case 'C':
	      {
		grub_uint32_t code = va_arg (args, grub_uint32_t);
		int shift;
		unsigned mask;

		if (code <= 0x7f)
		  {
		    shift = 0;
		    mask = 0;
		  }
		else if (code <= 0x7ff)
		  {
		    shift = 6;
		    mask = 0xc0;
		  }
		else if (code <= 0xffff)
		  {
		    shift = 12;
		    mask = 0xe0;
		  }
		else if (code <= 0x1fffff)
		  {
		    shift = 18;
		    mask = 0xf0;
		  }
		else if (code <= 0x3ffffff)
		  {
		    shift = 24;
		    mask = 0xf8;
		  }
		else if (code <= 0x7fffffff)
		  {
		    shift = 30;
		    mask = 0xfc;
		  }
		else
		  {
		    code = '?';
		    shift = 0;
		    mask = 0;
		  }

		write_char (mask | (code >> shift), &cc);

		for (shift -= 6; shift >= 0; shift -= 6)
		  write_char (0x80 | (0x3f & (code >> shift)), &cc);
	      }
	      break;

	    case 's':
	      p = va_arg (args, char *);
	      if (p)
		{
		  grub_size_t len = 0;
		  while (len < format2 && p[len])
		    len++;

		  if (!rightfill && len < format1)
		    write_fill (zerofill, format1 - len, &cc);

		  grub_size_t i;
		  for (i = 0; i < len; i++)
		    write_char (*p++, &cc);

		  if (rightfill && len < format1)
		    write_fill (zerofill, format1 - len, &cc);
		}
	      else
		write_str ("(null)", &cc);

	      break;

	    default:
	      write_char (c, &cc);
	      break;
	    }
	}
    }

  if (cc.str)
    *(cc.str) = '\0';

  return cc.count;
}

int
grub_vsnprintf (char *str, grub_size_t n, const char *fmt, va_list ap)
{
  grub_size_t ret;

  if (!n)
    return 0;

  n--;

  ret = grub_vsnprintf_real (str, n, fmt, ap);

  return ret < n ? ret : n;
}

int
grub_snprintf (char *str, grub_size_t n, const char *fmt, ...)
{
  va_list ap;
  int ret;

  va_start (ap, fmt);
  ret = grub_vsnprintf (str, n, fmt, ap);
  va_end (ap);

  return ret;
}

#define PREALLOC_SIZE 255

char *
grub_xvasprintf (const char *fmt, va_list ap)
{
  grub_size_t s, as = PREALLOC_SIZE;
  char *ret;

  while (1)
    {
      ret = grub_malloc (as + 1);
      if (!ret)
	return NULL;

      s = grub_vsnprintf_real (ret, as, fmt, ap);
      if (s <= as)
	return ret;

      grub_free (ret);
      as = s;
    }
}

char *
grub_xasprintf (const char *fmt, ...)
{
  va_list ap;
  char *ret;

  va_start (ap, fmt);
  ret = grub_xvasprintf (fmt, ap);
  va_end (ap);

  return ret;
}

/* Convert a (possibly null-terminated) UTF-8 string of at most SRCSIZE
   bytes (if SRCSIZE is -1, it is ignored) in length to a UCS-4 string.
   Return the number of characters converted. DEST must be able to hold
   at least DESTSIZE characters.
   If SRCEND is not NULL, then *SRCEND is set to the next byte after the
   last byte used in SRC.  */
grub_size_t
grub_utf8_to_ucs4 (grub_uint32_t *dest, grub_size_t destsize,
		   const grub_uint8_t *src, grub_size_t srcsize,
		   const grub_uint8_t **srcend)
{
  grub_uint32_t *p = dest;
  int count = 0;
  grub_uint32_t code = 0;

  if (srcend)
    *srcend = src;

  while (srcsize && destsize)
    {
      grub_uint32_t c = *src++;
      if (srcsize != (grub_size_t)-1)
	srcsize--;
      if (count)
	{
	  if ((c & 0xc0) != 0x80)
	    {
	      /* invalid */
	      code = '?';
	      /* Character c may be valid, don't eat it.  */
	      src--;
	      if (srcsize != (grub_size_t)-1)
		srcsize++;
	      count = 0;
	    }
	  else
	    {
	      code <<= 6;
	      code |= (c & 0x3f);
	      count--;
	    }
	}
      else
	{
	  if (c == 0)
	    break;

	  if ((c & 0x80) == 0x00)
	    code = c;
	  else if ((c & 0xe0) == 0xc0)
	    {
	      count = 1;
	      code = c & 0x1f;
	    }
	  else if ((c & 0xf0) == 0xe0)
	    {
	      count = 2;
	      code = c & 0x0f;
	    }
	  else if ((c & 0xf8) == 0xf0)
	    {
	      count = 3;
	      code = c & 0x07;
	    }
	  else if ((c & 0xfc) == 0xf8)
	    {
	      count = 4;
	      code = c & 0x03;
	    }
	  else if ((c & 0xfe) == 0xfc)
	    {
	      count = 5;
	      code = c & 0x01;
	    }
	  else
	    {
	      /* invalid */
	      code = '?';
	      count = 0;
	    }
	}

      if (count == 0)
	{
	  *p++ = code;
	  destsize--;
	}
    }

  if (srcend)
    *srcend = src;
  return p - dest;
}

/* Abort GRUB. This function does not return.  */
void
grub_abort (void)
{
  grub_printf ("\nAborted.");

#ifndef GRUB_UTIL
  if (grub_term_inputs)
#endif
    {
      grub_printf (" Press any key to exit.");
      grub_getkey ();
    }

  //grub_exit ();
}

#if defined(NEED_ENABLE_EXECUTE_STACK) && !defined(GRUB_UTIL)
/* Some gcc versions generate a call to this function
   in trampolines for nested functions.  */
void __enable_execute_stack (void *addr __attribute__ ((unused)))
{
}
#endif

#if defined (NEED_REGISTER_FRAME_INFO) && !defined(GRUB_UTIL)
void __register_frame_info (void)
{
}

void __deregister_frame_info (void)
{
}
#endif
