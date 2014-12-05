/* Z80 assembler by shevek

   Copyright (C) 2002-2009 Bas Wijnen <wijnen@debian.org>
   Copyright (C) 2005 Jan Wilmans <jw@dds.nl>

   This file is part of z80asm.

   Z80asm is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   Z80asm is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

//#include "z80asm.h"

/* reading expressions. The following operators are supported
 * in order of precedence, with function name:
 * expr?expr:expr do_rd_expr
 * |              rd_expr_or
 * ^              rd_expr_xor
 * &              rd_expr_and
 * == !=          rd_expr_equal
 * >= <= > <      rd_expr_unequal
 * << >>          rd_expr_shift
 * + - (binary)   rd_term
 * * / %          rd_factor
 * ~ + - (unary)  rd_factor
 */

static int do_rd_expr (const char **p, char delimiter, int *valid, int level,
		       int *check, int print_errors);

static int
rd_number (const char **p, const char **endp, int base)
{
  int result = 0, i;
  char *c, num[] = "0123456789abcdefghijklmnopqrstuvwxyz";
  if (verbose >= 6)
    fprintf (stderr, "%5d (0x%04x): Starting to read number of base %d"
	     "(string=%s).\n", stack[sp].line, addr, base, *p);
  num[base] = '\0';
  *p = delspc (*p);
  while (**p && (c = strchr (num, tolower ((const unsigned char)**p))))
    {
      i = c - num;
      if (verbose >= 7)
	fprintf (stderr, "%5d (0x%04x): Digit found:%1x.\n", stack[sp].line,
		 addr, i);
      result = result * base + i;
      (*p)++;
    }
  if (endp)
    *endp = *p;
  *p = delspc (*p);
  if (verbose >= 7)
    fprintf (stderr, "%5d (0x%04x): rd_number returned %d (%04x).\n",
	     stack[sp].line, addr, result, result);
  return result;
}

static int
rd_otherbasenumber (const char **p, int *valid, int print_errors)
{
  char c;
  if (verbose >= 6)
    fprintf (stderr,
	     "%5d (0x%04x): Starting to read basenumber (string=%s).\n",
	     stack[sp].line, addr, *p);
  (*p)++;
  if (!**p)
    {
      if (valid)
	*valid = 0;
      else if (print_errors)
	printerr (1, "unexpected end of line after `@'\n");
      return 0;
    }
  if (**p == '0' || !isalnum ((const unsigned char)**p))
    {
      if (valid)
	*valid = 0;
      else if (print_errors)
	printerr (1, "base must be between 1 and z\n");
      return 0;
    }
  c = **p;
  (*p)++;
  if (isalpha ((const unsigned char)**p))
    return rd_number (p, NULL, tolower ((unsigned char)c) - 'a' + 1);
  return rd_number (p, NULL, c - '0' + 1);
}

static int
rd_character (const char **p, int *valid, int print_errors)
{
  int i;
  if (verbose >= 6)
    fprintf (stderr,
	     "%5d (0x%04x): Starting to read character (string=%s).\n",
	     stack[sp].line, addr, *p);
  i = **p;
  if (!i)
    {
      if (valid)
	*valid = 0;
      else if (print_errors)
	printerr (1, "unexpected end of line in string constant\n");
      return 0;
    }
  if (i == '\\')
    {
      (*p)++;
      if (**p >= '0' && **p <= '7')
	{
	  int b, num_digits;
	  i = 0;
	  if ((*p)[1] >= '0' && (*p)[1] <= '7')
	    {
	      if (**p <= '3' && (*p)[2] >= '0' && (*p)[2] <= '7')
		num_digits = 3;
	      else
		num_digits = 2;
	    }
	  else
	    num_digits = 1;
	  for (b = 0; b < num_digits; ++b)
	    {
	      int bit = (*p)[num_digits - 1 - b] - '0';
	      i += (1 << (b * 3)) * bit;
	    }
	  *p += num_digits;
	}
      else
	{
	  switch (**p)
	    {
	    case 'n':
	      i = 10;
	      break;
	    case 'r':
	      i = 13;
	      break;
	    case 't':
	      i = 9;
	      break;
	    case 'a':
	      i = 7;
	      break;
	    case '\'':
	      if (valid)
		*valid = 0;
	      else if (print_errors)
		printerr (1, "empty literal character\n");
	      return 0;
	    case 0:
	      if (valid)
		*valid = 0;
	      else if (print_errors)
		printerr (1, "unexpected end of line after "
			  "backslash in string constant\n");
	      return 0;
	    default:
	      i = **p;
	    }
	  (*p)++;
	}
    }
  else
    (*p)++;
  if (verbose >= 7)
    fprintf (stderr, "%5d (0x%04x): rd_character returned %d (%c).\n",
	     stack[sp].line, addr, i, i);
  return i;
}

static int
check_label (struct label *labels, const char **p, struct label **ret,
	     struct label **previous, int force_skip)
{
  struct label *l;
  const char *c;
  unsigned s2;
  *p = delspc (*p);
  for (c = *p; isalnum ((const unsigned char)*c) || *c == '_' || *c == '.'; ++c)
    {
    }
  s2 = c - *p;
  for (l = labels; l; l = l->next)
    {
      unsigned s1, s;
      int cmp;
      s1 = strlen (l->name);
      s = s1 < s2 ? s1 : s2;
      cmp = strncmp (l->name, *p, s);
      if (cmp > 0 || (cmp == 0 && s1 > s))
	{
	  if (force_skip)
	    *p = c;
	  return 0;
	}
      if (cmp < 0 || s2 > s)
	{
	  if (previous)
	    *previous = l;
	  continue;
	}
      *p = c;
      /* if label is not valid, compute it */
      if (l->ref)
	{
	  compute_ref (l->ref, 1);
	  if (!l->ref->done)
	    {
	      /* label was not valid, and isn't computable.  tell the
	       * caller that it doesn't exist, so it will try again later.
	       * Set ret to show actual existence.  */
	      if (verbose >= 6)
		fprintf (stderr,
			 "%5d (0x%04x): returning invalid label %s.\n",
			 stack[sp].line, addr, l->name);
	      *ret = l;
	      return 0;
	    }
	}
      *ret = l;
      return 1;
    }
  if (force_skip)
    *p = c;
  return 0;
}

static int
rd_label (const char **p, int *exists, struct label **previous, int level,
	  int print_errors)
{
  struct label *l = NULL;
  int s;
  if (exists)
    *exists = 0;
  if (previous)
    *previous = NULL;
  if (verbose >= 6)
    fprintf (stderr, "%5d (0x%04x): Starting to read label (string=%s).\n",
	     stack[sp].line, addr, *p);
  for (s = level; s >= 0; --s)
    {
      if (check_label (stack[s].labels, p, &l,
		       (**p == '.' && s == sp) ? previous : NULL, 0))
	break;
    }
  if (s < 0)
    {
      /* not yet found */
      const char *old_p = *p;
	  /* label does not exist, or is invalid.  This is an error if there
	   * is no existence check.  */
	  if (!exists && print_errors)
	    printerr (1, "using undefined label %.*s\n", *p - old_p, old_p);
	  /* Return a value to discriminate between non-existing and invalid */
	  if (verbose >= 7)
	    fprintf (stderr, "rd_label returns invalid value\n");
	  return l != NULL;
    }
  if (exists)
    *exists = 1;
  if (verbose >= 7)
    fprintf (stderr, "rd_label returns valid value 0x%x\n", l->value);
  return l->value;
}

static int
rd_value (const char **p, int *valid, int level, int *check, int print_errors)
{
  int sign = 1, not = 0, base, v;
  const char *p0, *p1, *p2;
  if (verbose >= 6)
    fprintf (stderr, "%5d (0x%04x): Starting to read value (string=%s).\n",
	     stack[sp].line, addr, *p);
  *p = delspc (*p);
  while (**p && strchr ("+-~", **p))
    {
      if (**p == '-')
	sign = -sign;
      else if (**p == '~')
	not = ~not;
      (*p)++;
      *p = delspc (*p);
    }
  base = 10;			/* Default base for suffixless numbers */

  /* Check for parenthesis around full expression: not if no parenthesis */
  if (**p != '(')
    *check = 0;

  switch (**p)
    {
      int exist, retval;
      char quote;
      int dummy_check;
    case '(':
      (*p)++;
      dummy_check = 0;
      retval = not ^ (sign * do_rd_expr (p, ')', valid, level, &dummy_check,
					 print_errors));
      ++*p;
      return retval;
    case '0':
      if ((*p)[1] == 'x')
	{
	  (*p) += 2;
	  return not ^ (sign * rd_number (p, NULL, 0x10));
	}
      base = 8;		/* If first digit it 0, assume octal unless suffix */
      /* fall through */
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      p0 = *p;
      rd_number (p, &p1, 36);	/* Advance to end of numeric string */
      p1--;			/* Last character in numeric string */
      switch (*p1)
	{
	case 'h':
	case 'H':
	  base = 16;
	  break;
	case 'b':
	case 'B':
	  base = 2;
	  break;
	case 'o':
	case 'O':
	case 'q':
	case 'Q':
	  base = 8;
	  break;
	case 'd':
	case 'D':
	  base = 10;
	  break;
	default:		/* No suffix */
	  p1++;
	  break;
	}
      v = rd_number (&p0, &p2, base);
      if (p1 != p2)
	{
	  if (valid)
	    *valid = 0;
	  else if (print_errors)
	    printerr (1, "invalid character in number: \'%c\'\n", *p2);
	}
      return not ^ (sign * v);
    case '$':
      ++*p;
      *p = delspc (*p);
      p0 = *p;
      v = rd_number (&p0, &p2, 0x10);
      if (p2 == *p)
	{
	  v = baseaddr;
	}
      else
	*p = p2;
      return not ^ (sign * v);
    case '%':
      (*p)++;
      return not ^ (sign * rd_number (p, NULL, 2));
    case '\'':
    case '"':
      quote = **p;
      ++*p;
      retval = not ^ (sign * rd_character (p, valid, print_errors));
      if (**p != quote)
	{
	  if (valid)
	    *valid = 0;
	  else if (print_errors)
	    printerr (1, "missing closing quote (%c)\n", quote);
	  return 0;
	}
      ++*p;
      return retval;
    case '@':
      return not ^ (sign * rd_otherbasenumber (p, valid, print_errors));
    case '?':
      rd_label (p, &exist, NULL, level, 0);
      return not ^ (sign * exist);
    case '&':
      {
	++*p;
	switch (**p)
	  {
	  case 'h':
	  case 'H':
	    base = 0x10;
	    break;
	  case 'o':
	  case 'O':
	    base = 010;
	    break;
	  case 'b':
	  case 'B':
	    base = 2;
	    break;
	  default:
	    if (valid)
	      *valid = 0;
	    else if (print_errors)
	      printerr (1, "invalid literal starting with &%c\n", **p);
	    return 0;
	  }
	++*p;
	return not ^ (sign * rd_number (p, NULL, base));
      }
    default:
      {
	int value;
	exist = 1;
	value = rd_label (p, valid ? &exist : NULL, NULL, level, print_errors);
	if (!exist)
	  *valid = 0;
	return not ^ (sign * value);
      }
    }
}

static int
rd_factor (const char **p, int *valid, int level, int *check, int print_errors)
{
  /* read a factor of an expression */
  int result;
  if (verbose >= 6)
    fprintf (stderr, "%5d (0x%04x): Starting to read factor (string=%s).\n",
	     stack[sp].line, addr, *p);
  result = rd_value (p, valid, level, check, print_errors);
  *p = delspc (*p);
  while (**p == '*' || **p == '/')
    {
      *check = 0;
      if (**p == '*')
	{
	  (*p)++;
	  result *= rd_value (p, valid, level, check, print_errors);
	}
      else if (**p == '/')
	{
	  (*p)++;
      int value = rd_value (p, valid, level, check, print_errors);
      if (value == 0){ 
        printerr (1, "division by zero\n");
        return -1;
      }
      result /= value;
	}
      *p = delspc (*p);
    }
  if (verbose >= 7)
    fprintf (stderr, "%5d (0x%04x): rd_factor returned %d (%04x).\n",
	     stack[sp].line, addr, result, result);
  return result;
}

static int
rd_term (const char **p, int *valid, int level, int *check, int print_errors)
{
  /* read a term of an expression */
  int result;
  if (verbose >= 6)
    fprintf (stderr, "%5d (0x%04x): Starting to read term (string=%s).\n",
	     stack[sp].line, addr, *p);
  result = rd_factor (p, valid, level, check, print_errors);
  *p = delspc (*p);
  while (**p == '+' || **p == '-')
    {
      *check = 0;
      if (**p == '+')
	{
	  (*p)++;
	  result += rd_factor (p, valid, level, check, print_errors);
	}
      else if (**p == '-')
	{
	  (*p)++;
	  result -= rd_factor (p, valid, level, check, print_errors);
	}
      *p = delspc (*p);
    }
  if (verbose >= 7)
    fprintf (stderr, "%5d (0x%04x): rd_term returned %d (%04x).\n",
	     stack[sp].line, addr, result, result);
  return result;
}

static int
rd_expr_shift (const char **p, int *valid, int level, int *check,
	       int print_errors)
{
  int result;
  if (verbose >= 6)
    fprintf (stderr, "%5d (0x%04x): Starting to read shift expression "
	     "(string=%s).\n", stack[sp].line, addr, *p);
  result = rd_term (p, valid, level, check, print_errors);
  *p = delspc (*p);
  while ((**p == '<' || **p == '>') && (*p)[1] == **p)
    {
      *check = 0;
      if (**p == '<')
	{
	  (*p) += 2;
	  result <<= rd_term (p, valid, level, check, print_errors);
	}
      else if (**p == '>')
	{
	  (*p) += 2;
	  result >>= rd_term (p, valid, level, check, print_errors);
	}
      *p = delspc (*p);
    }
  if (verbose >= 7)
    fprintf (stderr, "%5d (0x%04x): rd_shift returned %d (%04x).\n",
	     stack[sp].line, addr, result, result);
  return result;
}

static int
rd_expr_unequal (const char **p, int *valid, int level, int *check,
		 int print_errors)
{
  int result;
  if (verbose >= 6)
    fprintf (stderr, "%5d (0x%04x): Starting to read "
	     "unequality expression (string=%s).\n", stack[sp].line, addr,
	     *p);
  result = rd_expr_shift (p, valid, level, check, print_errors);
  *p = delspc (*p);
  if (**p == '<' && (*p)[1] == '=')
    {
      *check = 0;
      (*p) += 2;
      return result <= rd_expr_unequal (p, valid, level, check, print_errors);
    }
  else if (**p == '>' && (*p)[1] == '=')
    {
      *check = 0;
      (*p) += 2;
      return result >= rd_expr_unequal (p, valid, level, check, print_errors);
    }
  if (**p == '<' && (*p)[1] != '<')
    {
      *check = 0;
      (*p)++;
      return result < rd_expr_unequal (p, valid, level, check, print_errors);
    }
  else if (**p == '>' && (*p)[1] != '>')
    {
      *check = 0;
      (*p)++;
      return result > rd_expr_unequal (p, valid, level, check, print_errors);
    }
  if (verbose >= 7)
    fprintf (stderr, "%5d (0x%04x): rd_shift returned %d (%04x).\n",
	     stack[sp].line, addr, result, result);
  return result;
}

static int
rd_expr_equal (const char **p, int *valid, int level, int *check,
	       int print_errors)
{
  int result;
  if (verbose >= 6)
    fprintf (stderr, "%5d (0x%04x): Starting to read equality epression "
	     "(string=%s).\n", stack[sp].line, addr, *p);
  result = rd_expr_unequal (p, valid, level, check, print_errors);
  *p = delspc (*p);
  if (**p == '=')
    {
      *check = 0;
      ++*p;
      if (**p == '=')
	++ * p;
      return result == rd_expr_equal (p, valid, level, check, print_errors);
    }
  else if (**p == '!' && (*p)[1] == '=')
    {
      *check = 0;
      (*p) += 2;
      return result != rd_expr_equal (p, valid, level, check, print_errors);
    }
  if (verbose >= 7)
    fprintf (stderr, "%5d (0x%04x): rd_equal returned %d (%04x).\n",
	     stack[sp].line, addr, result, result);
  return result;
}

static int
rd_expr_and (const char **p, int *valid, int level, int *check,
	     int print_errors)
{
  int result;
  if (verbose >= 6)
    fprintf (stderr, "%5d (0x%04x): Starting to read and expression "
	     "(string=%s).\n", stack[sp].line, addr, *p);
  result = rd_expr_equal (p, valid, level, check, print_errors);
  *p = delspc (*p);
  if (**p == '&')
    {
      *check = 0;
      (*p)++;
      result &= rd_expr_and (p, valid, level, check, print_errors);
    }
  if (verbose >= 7)
    fprintf (stderr, "%5d (0x%04x): rd_expr_and returned %d (%04x).\n",
	     stack[sp].line, addr, result, result);
  return result;
}

static int
rd_expr_xor (const char **p, int *valid, int level, int *check,
	     int print_errors)
{
  int result;
  if (verbose >= 6)
    fprintf (stderr, "%5d (0x%04x): Starting to read xor expression "
	     "(string=%s).\n", stack[sp].line, addr, *p);
  result = rd_expr_and (p, valid, level, check, print_errors);
  if (verbose >= 7)
    fprintf (stderr, "%5d (0x%04x): rd_expr_xor: rd_expr_and returned %d "
	     "(%04x).\n", stack[sp].line, addr, result, result);
  *p = delspc (*p);
  if (**p == '^')
    {
      *check = 0;
      (*p)++;
      result ^= rd_expr_xor (p, valid, level, check, print_errors);
    }
  if (verbose >= 7)
    fprintf (stderr, "%5d (0x%04x): rd_expr_xor returned %d (%04x).\n",
	     stack[sp].line, addr, result, result);
  return result;
}

static int
rd_expr_or (const char **p, int *valid, int level, int *check,
	    int print_errors)
{
  int result;
  if (verbose >= 6)
    fprintf (stderr, "%5d (0x%04x): Starting to read or expression "
	     "(string=%s).\n", stack[sp].line, addr, *p);
  result = rd_expr_xor (p, valid, level, check, print_errors);
  if (verbose >= 7)
    fprintf (stderr, "%5d (0x%04x): rd_expr_or: rd_expr_xor returned %d "
	     "(%04x).\n", stack[sp].line, addr, result, result);
  *p = delspc (*p);
  if (**p == '|')
    {
      *check = 0;
      (*p)++;
      result |= rd_expr_or (p, valid, level, check, print_errors);
    }
  if (verbose >= 7)
    fprintf (stderr, "%5d (0x%04x): rd_expr_or returned %d (%04x).\n",
	     stack[sp].line, addr, result, result);
  return result;
}

static int
do_rd_expr (const char **p, char delimiter, int *valid, int level, int *check,
	    int print_errors)
{
  /* read an expression. delimiter can _not_ be '?' */
  int result = 0;
  if (verbose >= 6)
    fprintf (stderr,
	     "%5d (0x%04x): Starting to read expression "
	     "(string=%s, delimiter=%c).\n", stack[sp].line, addr, *p,
	     delimiter ? delimiter : ' ');
  *p = delspc (*p);
  if (!**p || **p == delimiter)
    {
      if (valid)
	*valid = 0;
      else if (print_errors)
	printerr (1, "expression expected (not %s)\n", *p);
      return 0;
    }
  result = rd_expr_or (p, valid, level, check, print_errors);
  *p = delspc (*p);
  if (**p == '?')
    {
      *check = 0;
      (*p)++;
      if (result)
	{
	  result = do_rd_expr (p, ':', valid, level, check, print_errors);
	  if (**p)
	    (*p)++;
	  do_rd_expr (p, delimiter, valid, level, check, print_errors);
	}
      else
	{
	  do_rd_expr (p, ':', valid, level, check, print_errors);
	  if (**p)
	    (*p)++;
	  result = do_rd_expr (p, delimiter, valid, level, check,
			       print_errors);
	}
    }
  *p = delspc (*p);
  if (**p && **p != delimiter)
    {
      if (valid)
	*valid = 0;
      else if (print_errors)
	printerr (1, "junk at end of expression: %s\n", *p);
    }
  if (verbose >= 7)
    {
      fprintf (stderr, "%5d (0x%04x): rd_expr returned %d (%04x).\n",
	       stack[sp].line, addr, result, result);
      if (valid && !*valid)
	fprintf (stderr, "%5d (0x%04x): Returning invalid result.\n",
		 stack[sp].line, addr);
    }
  return result;
}

static int
rd_expr (const char **p, char delimiter, int *valid, int level,
	 int print_errors)
{
  int check = 1;
  int result;
  if (valid)
    *valid = 1;
  result = do_rd_expr (p, delimiter, valid, level, &check, print_errors);
  if (print_errors && (!valid || *valid) && check)
    printerr (0, "expression fully enclosed in parenthesis\n");
  return result;
}
