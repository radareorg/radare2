/* Demangler for the Rust programming language
   Copyright (C) 2016-2020 Free Software Foundation, Inc.
   Written by David Tolnay (dtolnay@gmail.com).

This file is part of the libiberty library.
Libiberty is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public
License as published by the Free Software Foundation; either
version 2 of the License, or (at your option) any later version.

In addition to the permissions in the GNU Library General Public
License, the Free Software Foundation gives you unlimited permission
to link the compiled version of this file into combinations with other
programs, and to distribute those combinations without any restriction
coming from the use of this file.  (The Library Public License
restrictions do apply in other respects; for example, they cover
modification of the file, and distribution when not linked into a
combined executable.)

Libiberty is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with libiberty; see the file COPYING.LIB.
If not, see <http://www.gnu.org/licenses/>.  */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// #include "safe-ctype.h"

#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "demangle.h"
#include "libiberty.h"

struct rust_demangler
{
  const char *sym;
  size_t sym_len;

  void *callback_opaque;
  demangle_callbackref callback;

  /* Position of the next character to read from the symbol. */
  size_t next;

  /* Non-zero if any error occurred. */
  int errored;

  /* Non-zero if printing should be verbose (e.g. include hashes). */
  int verbose;

  /* Rust mangling version, with legacy mangling being -1. */
  int version;
};

/* Parsing functions. */

static char
peek (const struct rust_demangler *rdm)
{
  if (rdm->next < rdm->sym_len)
    return rdm->sym[rdm->next];
  return 0;
}

static char
next (struct rust_demangler *rdm)
{
  char c = peek (rdm);
  if (!c)
    rdm->errored = 1;
  else
    rdm->next++;
  return c;
}

struct rust_mangled_ident
{
  /* ASCII part of the identifier. */
  const char *ascii;
  size_t ascii_len;
};

static struct rust_mangled_ident
parse_ident (struct rust_demangler *rdm)
{
  char c;
  size_t start, len;
  struct rust_mangled_ident ident;

  ident.ascii = NULL;
  ident.ascii_len = 0;

  c = next (rdm);
  if (!ISDIGIT (c))
    {
      rdm->errored = 1;
      return ident;
    }
  len = c - '0';

  if (c != '0')
    while (ISDIGIT (peek (rdm)))
      len = len * 10 + (next (rdm) - '0');

  start = rdm->next;
  rdm->next += len;
  /* Check for overflows. */
  if ((start > rdm->next) || (rdm->next > rdm->sym_len))
    {
      rdm->errored = 1;
      return ident;
    }

  ident.ascii = rdm->sym + start;
  ident.ascii_len = len;

  if (ident.ascii_len == 0)
    ident.ascii = NULL;

  return ident;
}

/* Printing functions. */

static void
print_str (struct rust_demangler *rdm, const char *data, size_t len)
{
  if (!rdm->errored)
    rdm->callback (data, len, rdm->callback_opaque);
}

#define PRINT(s) print_str (rdm, s, strlen (s))

/* Return a 0x0-0xf value if the char is 0-9a-f, and -1 otherwise. */
static int
decode_lower_hex_nibble (char nibble)
{
  if ('0' <= nibble && nibble <= '9')
    return nibble - '0';
  if ('a' <= nibble && nibble <= 'f')
    return 0xa + (nibble - 'a');
  return -1;
}

/* Return the unescaped character for a "$...$" escape, or 0 if invalid. */
static char
decode_legacy_escape (const char *e, size_t len, size_t *out_len)
{
  char c = 0;
  size_t escape_len = 0;
  int lo_nibble = -1, hi_nibble = -1;

  if (len < 3 || e[0] != '$')
    return 0;

  e++;
  len--;

  if (e[0] == 'C')
    {
      escape_len = 1;

      c = ',';
    }
  else if (len > 2)
    {
      escape_len = 2;

      if (e[0] == 'S' && e[1] == 'P')
        c = '@';
      else if (e[0] == 'B' && e[1] == 'P')
        c = '*';
      else if (e[0] == 'R' && e[1] == 'F')
        c = '&';
      else if (e[0] == 'L' && e[1] == 'T')
        c = '<';
      else if (e[0] == 'G' && e[1] == 'T')
        c = '>';
      else if (e[0] == 'L' && e[1] == 'P')
        c = '(';
      else if (e[0] == 'R' && e[1] == 'P')
        c = ')';
      else if (e[0] == 'u' && len > 3)
        {
          escape_len = 3;

          hi_nibble = decode_lower_hex_nibble (e[1]);
          if (hi_nibble < 0)
            return 0;
          lo_nibble = decode_lower_hex_nibble (e[2]);
          if (lo_nibble < 0)
            return 0;

          /* Only allow non-control ASCII characters. */
          if (hi_nibble > 7)
            return 0;
          c = (hi_nibble << 4) | lo_nibble;
          if (c < 0x20)
            return 0;
        }
    }

  if (!c || len <= escape_len || e[escape_len] != '$')
    return 0;

  *out_len = 2 + escape_len;
  return c;
}

static void
print_ident (struct rust_demangler *rdm, struct rust_mangled_ident ident)
{
  char unescaped;
  size_t len;

  if (rdm->errored)
    return;

  if (rdm->version == -1)
    {
      /* Ignore leading underscores preceding escape sequences.
         The mangler inserts an underscore to make sure the
         identifier begins with a XID_Start character. */
      if (ident.ascii_len >= 2 && ident.ascii[0] == '_'
          && ident.ascii[1] == '$')
        {
          ident.ascii++;
          ident.ascii_len--;
        }

      while (ident.ascii_len > 0)
        {
          /* Handle legacy escape sequences ("$...$", ".." or "."). */
          if (ident.ascii[0] == '$')
            {
              unescaped
                  = decode_legacy_escape (ident.ascii, ident.ascii_len, &len);
              if (unescaped)
                print_str (rdm, &unescaped, 1);
              else
                {
                  /* Unexpected escape sequence, print the rest verbatim. */
                  print_str (rdm, ident.ascii, ident.ascii_len);
                  return;
                }
            }
          else if (ident.ascii[0] == '.')
            {
              if (ident.ascii_len >= 2 && ident.ascii[1] == '.')
                {
                  /* ".." becomes "::" */
                  PRINT ("::");
                  len = 2;
                }
              else
                {
                  /* "." becomes "-" */
                  PRINT ("-");
                  len = 1;
                }
            }
          else
            {
              /* Print everything before the next escape sequence, at once. */
              for (len = 0; len < ident.ascii_len; len++)
                if (ident.ascii[len] == '$' || ident.ascii[len] == '.')
                  break;

              print_str (rdm, ident.ascii, len);
            }

          ident.ascii += len;
          ident.ascii_len -= len;
        }

      return;
    }
}

/* A legacy hash is the prefix "h" followed by 16 lowercase hex digits.
   The hex digits must contain at least 5 distinct digits. */
static int
is_legacy_prefixed_hash (struct rust_mangled_ident ident)
{
  uint16_t seen;
  int nibble;
  size_t i, count;

  if (ident.ascii_len != 17 || ident.ascii[0] != 'h')
    return 0;

  seen = 0;
  for (i = 0; i < 16; i++)
    {
      nibble = decode_lower_hex_nibble (ident.ascii[1 + i]);
      if (nibble < 0)
        return 0;
      seen |= (uint16_t)1 << nibble;
    }

  /* Count how many distinct digits were seen. */
  count = 0;
  while (seen)
    {
      if (seen & 1)
        count++;
      seen >>= 1;
    }

  return count >= 5;
}

int
rust_demangle_callback (const char *mangled, int options,
                        demangle_callbackref callback, void *opaque)
{
  const char *p;
  struct rust_demangler rdm;
  struct rust_mangled_ident ident;

  rdm.sym = mangled;
  rdm.sym_len = 0;

  rdm.callback_opaque = opaque;
  rdm.callback = callback;

  rdm.next = 0;
  rdm.errored = 0;
  rdm.verbose = (options & DMGL_VERBOSE) != 0;
  rdm.version = 0;

  /* Rust symbols always start with _ZN (legacy). */
  if (rdm.sym[0] == '_' && rdm.sym[1] == 'Z' && rdm.sym[2] == 'N')
    {
      rdm.sym += 3;
      rdm.version = -1;
    }
  else
    return 0;

  /* Legacy Rust symbols use only [_0-9a-zA-Z.:$] characters. */
  for (p = rdm.sym; *p; p++)
    {
      rdm.sym_len++;

      if (*p == '_' || isalnum (*p))
        continue;

      if (rdm.version == -1 && (*p == '$' || *p == '.' || *p == ':'))
        continue;

      return 0;
    }

  /* Legacy Rust symbols need to be handled separately. */
  if (rdm.version == -1)
    {
      /* Legacy Rust symbols always end with E. */
      if (!(rdm.sym_len > 0 && rdm.sym[rdm.sym_len - 1] == 'E'))
        return 0;
      rdm.sym_len--;

      /* Legacy Rust symbols also always end with a path segment
         that encodes a 16 hex digit hash, i.e. '17h[a-f0-9]{16}'.
         This early check, before any parse_ident calls, should
         quickly filter out most C++ symbols unrelated to Rust. */
      if (!(rdm.sym_len > 19
            && !memcmp (&rdm.sym[rdm.sym_len - 19], "17h", 3)))
        return 0;

      do
        {
          ident = parse_ident (&rdm);
          if (rdm.errored || !ident.ascii)
            return 0;
        }
      while (rdm.next < rdm.sym_len);

      /* The last path segment should be the hash. */
      if (!is_legacy_prefixed_hash (ident))
        return 0;

      /* Reset the state for a second pass, to print the symbol. */
      rdm.next = 0;
      if (!rdm.verbose && rdm.sym_len > 19)
        {
          /* Hide the last segment, containing the hash, if not verbose. */
          rdm.sym_len -= 19;
        }

      do
        {
          if (rdm.next > 0)
            print_str (&rdm, "::", 2);

          ident = parse_ident (&rdm);
          print_ident (&rdm, ident);
        }
      while (rdm.next < rdm.sym_len);
    }
  else
    return 0;

  return !rdm.errored;
}

/* Growable string buffers. */
struct str_buf
{
  char *ptr;
  size_t len;
  size_t cap;
  int errored;
};

static void
str_buf_reserve (struct str_buf *buf, size_t extra)
{
  size_t available, min_new_cap, new_cap;
  char *new_ptr;

  /* Allocation failed before. */
  if (buf->errored)
    return;

  available = buf->cap - buf->len;

  if (extra <= available)
    return;

  min_new_cap = buf->cap + (extra - available);

  /* Check for overflows. */
  if (min_new_cap < buf->cap)
    {
      buf->errored = 1;
      return;
    }

  new_cap = buf->cap;

  if (new_cap == 0)
    new_cap = 4;

  /* Double capacity until sufficiently large. */
  while (new_cap < min_new_cap)
    {
      new_cap *= 2;

      /* Check for overflows. */
      if (new_cap < buf->cap)
        {
          buf->errored = 1;
          return;
        }
    }

  new_ptr = (char *)realloc (buf->ptr, new_cap);
  if (new_ptr == NULL)
    {
      free (buf->ptr);
      buf->ptr = NULL;
      buf->len = 0;
      buf->cap = 0;
      buf->errored = 1;
    }
  else
    {
      buf->ptr = new_ptr;
      buf->cap = new_cap;
    }
}

static void
str_buf_append (struct str_buf *buf, const char *data, size_t len)
{
  str_buf_reserve (buf, len);
  if (buf->errored)
    return;

  memcpy (buf->ptr + buf->len, data, len);
  buf->len += len;
}

static void
str_buf_demangle_callback (const char *data, size_t len, void *opaque)
{
  str_buf_append ((struct str_buf *)opaque, data, len);
}

char *
rust_demangle (const char *mangled, int options)
{
  struct str_buf out;
  int success;

  out.ptr = NULL;
  out.len = 0;
  out.cap = 0;
  out.errored = 0;

  success = rust_demangle_callback (mangled, options,
                                    str_buf_demangle_callback, &out);

  if (!success)
    {
      free (out.ptr);
      return NULL;
    }

  str_buf_append (&out, "\0", 1);
  return out.ptr;
}
