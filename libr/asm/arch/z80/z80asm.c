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

#include "z80asm.h"

/* global variables */
/* mnemonics, used as argument to indx() in assemble */
const char *mnemonics[] = {
  "call", "cpdr", "cpir", "djnz", "halt", "indr", "inir", "lddr", "ldir",
  "otdr", "otir", "outd", "outi", "push", "reti", "retn", "rlca", "rrca",
  "defb", "defw", "defs", "defm",
  "adc", "add", "and", "bit", "ccf", "cpd", "cpi", "cpl", "daa", "dec", "equ",
  "exx", "inc", "ind", "ini", "ldd", "ldi", "neg", "nop", "out", "pop",
  "res", "ret", "rla", "rlc", "rld", "rra", "rrc", "rrd", "rst", "sbc",
  "scf", "set", "sla", "sll", "sli", "sra", "srl", "sub", "xor", "org",
  "cp", "di", "ei", "ex", "im", "in", "jp", "jr", "ld", "or", "rl", "rr",
  "db", "dw", "ds", "dm",
  "include", "incbin", "if", "else", "endif", "end", "macro", "endm",
  "seek", NULL
};

/* linked lists */
struct reference *firstreference = NULL;
struct label *firstlabel = NULL, *lastlabel = NULL;
struct name *firstname = NULL;
struct includedir *firstincludedir = NULL;
struct macro *firstmacro = NULL;

/* files */
FILE *realoutputfile, *outfile, *reallistfile, *listfile, *labelfile;
const char *realoutputfilename;
const char *labelfilename;
struct infile *infile;
/* prefix for labels in labelfile */
const char *labelprefix = "";
/* bools to see if files are opened */
int havelist = 0, label = 0;
/* number of infiles in array */
int infilecount;

/* number of errors seen so far */
int errors = 0;

/* current line, address and file */
int addr = 0, file;
/* current number of characters in list file, for indentation */
int listdepth;

/* use readbyte instead of (hl) if writebyte is true */
int writebyte;
const char *readbyte;
/* variables which are filled by rd_* functions and used later,
 * like readbyte */
const char *readword, *indexjmp, *bitsetres;

/* 0, 0xdd or 0xfd depening on which index prefix should be given */
int indexed;

/* increased for every -v option on the command line */
int verbose = 0;

/* read commas after indx() if comma > 1. increase for every call */
int comma;

/* address at start of line (for references) */
int baseaddr;

/* set by readword and readbyte, used for new_reference */
char mem_delimiter;

/* line currently being parsed */
char *buffer = NULL;

/* if a macro is currently being defined */
int define_macro = 0;

/* file (and macro) stack */
int sp;
struct stack stack[MAX_INCLUDE];	/* maximum level of includes */

/* Produce output even with errors.  */
int use_force = 0;

/* print an error message, including current line and file */
void
printerr (int error, const char *fmt, ...)
{
  va_list l;
  va_start (l, fmt);
  if ((sp < 0) || (stack[sp].name == 0))
    {
      fprintf (stderr, "internal assembler error, sp == %i\n", sp);
      vfprintf (stderr, fmt, l);
      exit (2);
    }
  fprintf (stderr, "%s%s:%d: %s: ", stack[sp].dir ? stack[sp].dir->name : "",
	   stack[sp].name, stack[sp].line, error ? "error" : "warning");
  vfprintf (stderr, fmt, l);
  va_end (l);
  if (error)
    errors++;
}

/* skip over spaces in string */
const char *
delspc (const char *ptr)
{
  while (*ptr && isspace (*ptr))
    ptr++;
  if (*ptr == ';')
    ptr = "";
  return ptr;
}

/* read away a comma, error if there is none */
static void
rd_comma (const char **p)
{
  *p = delspc (*p);
  if (**p != ',')
    {
      printerr (1, "`,' expected. Remainder of line: %s\n", *p);
      return;
    }
  *p = delspc ((*p) + 1);
}

/* look ahead for a comma, no error if not found */
static int
has_argument (const char **p)
{
  const char *q = delspc (*p);
  return (*q == ',');
}

/* During assembly, many literals are not parsed.  Instead, they are saved
 * until all labels are read.  After that, they are parsed.  This function
 * is used during assembly, to find the place where the command continues. */
static void
skipword (const char **pos, char delimiter)
{
  /* rd_expr will happily read the expression, and possibly return
   * an invalid result.  It will update pos, which is what we need.  */
  /* Pass valid to allow using undefined labels without errors.  */
  int valid;
  rd_expr (pos, delimiter, &valid, sp, 0);
}

/* callback function for argument parser, used to open output files. */
static FILE *
openfile (int *done,		/* flag to check that a file is opened only once. */
	  const char *type,	/* name of filetype for error message */
	  FILE * def,		/* default value, in case "-" is specified */
	  const char *name,	/* filename to open */
	  const char *flags)	/* open flags */
{
  FILE *retval;
  if (*done)
    {
      fprintf (stderr, "Error: more than one %s specified\n", type);
      exit (1);
    }
  *done = 1;
  if (def && (!name || (name[0] == '-' && name[1] == 0)))
    {
      return def;
    }
  if (!name || !name[0])
    {
      fprintf (stderr, "Error: no %s specified\n", type);
      exit (1);
    }
  if (!(retval = fopen (name, flags)))
    {
      fprintf (stderr, "Unable to open %s %s: %s\n",
	       type, name, strerror (errno));
      exit (1);
    }
  return retval;
}

/* open an included file, searching the path */
static FILE *
open_include_file (const char *name, struct includedir **dir,
		   const char *flags)
{
  FILE *result;
  struct includedir *i;
  /* always try the current directory first */
  result = fopen (name, flags);
  if (result)
    {
      if (dir)
	*dir = NULL;
      return result;
    }
  for (i = firstincludedir; i != NULL; i = i->next)
    {
      char *tmp = malloc (strlen (i->name) + strlen (name) + 1);
      if (!tmp)
	{
	  printerr (1, "not enough memory trying to open include file\n");
	  return NULL;
	}
      strcpy (tmp, i->name);
      strcat (tmp, name);
      result = fopen (tmp, flags);
      free (tmp);
      if (result)
	{
	  if (dir)
	    *dir = i;
	  return result;
	}
    }
  return NULL;
}

/* queue a file to be opened for reading */
static void
open_infile (const char *name)
{
  infile = realloc (infile, sizeof (struct infile) * (infilecount + 1));
  if (!infile)
    {
      fprintf (stderr, "Error: insufficient memory\n");
      exit (1);
    }
  /* only asm is currently supported */
  infile[infilecount].type = FILETYPE_ASM;
  infile[infilecount].name = name;
  if (verbose >= 5)
    fprintf (stderr, "queued inputfile %s\n", infile[infilecount].name);
  infilecount++;
}

/* add a directory to the include search path */
static void
add_include (const char *name)
{
  struct includedir *i;
  i = malloc (sizeof (struct includedir) + strlen (name) + 1);
  if (!i)
    {
      fprintf (stderr, "Error: insufficient memory\n");
      exit (1);
    }
  strcpy (i->name, name);
  if (name[strlen (name) - 1] != '/')
    strcat (i->name, "/");
  i->next = firstincludedir;
  firstincludedir = i;
}

static void
try_use_real_file (FILE * real, FILE ** backup)
{
  fpos_t pos;
  if (fgetpos (real, &pos) == 0)
    {
      *backup = real;
      return;
    }
  if (!(*backup = tmpfile ()))
    {
      fprintf (stderr, "Error: Unable to open temporary file: %s\n",
	       strerror (errno));
      exit (1);
    }
}

static void
flush_to_real_file (FILE * real, FILE * tmp)
{
  int l, size, len = 0;
  char buf[BUFLEN];
  if (tmp == real)
    {
      return;
    }
  rewind (tmp);
  while (1)
    {
      clearerr (tmp);
      errno = 0;
      len = fread (buf, 1, BUFLEN, tmp);
      if (len == 0 && feof (tmp))
	break;
      if (len <= 0)
	{
	  fprintf (stderr, "error reading temp file: %s\n", strerror (errno));
	  exit (1);
	}
      l = 0;
      while (l < len)
	{
	  clearerr (real);
	  size = fwrite (&buf[l], 1, len - l, real);
	  if (size <= 0)
	    {
	      fprintf (stderr, "error writing final file: %s\n",
		       strerror (errno));
	      exit (1);
	    }
	  l += size;
	}
    }
}

/* parse commandline arguments */
static void
parse_commandline (int argc, char **argv)
{
  const struct option opts[] = {
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'V'},
    {"verbose", no_argument, NULL, 'v'},
    {"list", optional_argument, NULL, 'l'},
    {"label", optional_argument, NULL, 'L'},
    {"input", required_argument, NULL, 'i'},
    {"output", required_argument, NULL, 'o'},
    {"label-prefix", required_argument, NULL, 'p'},
    {"includepath", required_argument, NULL, 'I'},
    {"force", no_argument, NULL, 'f'},
    {NULL, 0, NULL, 0}
  };
  const char *short_opts = "hVvl::L::i:o:p:I:f";
  int done = 0, i, out = 0;
  infile = NULL;
  while (!done)
    {
      switch (getopt_long (argc, argv, short_opts, opts, NULL))
	{
	case 'h':
	  /* split in two, to avoid too long string constant */
	  printf ("Usage: %s [options] [input files]\n"
		  "\n"
		  "Possible options are:\n"
		  "-h\t--help\t\tDisplay this help text and exit.\n"
		  "-V\t--version\tDisplay version information and exit.\n"
		  "-v\t--verbose\tBe verbose.  "
		  "Specify again to be more verbose.\n"
		  "-l\t--list\t\tWrite a list file.\n"
		  "-L\t--label\t\tWrite a label file.\n", argv[0]);
	  printf ("-p\t--label-prefix\tprefix all labels with this prefix.\n"
		  "-i\t--input\t\tSpecify an input file (-i may be omitted).\n"
		  "-o\t--output\tSpecify the output file.\n"
		  "-I\t--includepath\tAdd a directory to the include path.\n"
		  "Please send bug reports and feature requests to "
		  "<shevek@fmf.nl>\n");
	  exit (0);
	case 'V':
	  printf ("Z80 assembler version " VERSION "\n"
		  "Copyright (C) 2002-2007 Bas Wijnen "
		  "<shevek@fmf.nl>.\n"
		  "Copyright (C) 2005 Jan Wilmans "
		  "<jw@dds.nl>.\n"
		  "This program comes with ABSOLUTELY NO WARRANTY.\n"
		  "You may distribute copies of the program under the terms\n"
		  "of the GNU General Public License as published by\n"
		  "the Free Software Foundation; either version 2 of the\n"
		  "License, or (at your option) any later version.\n\n"
		  "The complete text of the GPL can be found in\n"
		  "/usr/share/common-licenses/GPL.\n");
	  exit (0);
	case 'v':
	  verbose++;
	  if (verbose >= 5)
	    fprintf (stderr, "Verbosity increased to level %d\n", verbose);
	  break;
	case 'o':
	  realoutputfile
	    = openfile (&out, "output file", stdout, optarg, "wb");
	  realoutputfilename = optarg;
	  if (verbose >= 5)
	    fprintf (stderr, "Opened outputfile\n");
	  break;
	case 'i':
	  open_infile (optarg);
	  break;
	case 'l':
	  reallistfile
	    = openfile (&havelist, "list file", stderr, optarg, "w");
	  if (verbose >= 5)
	    fprintf (stderr, "Opened list file\n");
	  break;
	case 'L':
	  labelfile = openfile (&label, "label file", stderr, optarg, "w");
	  labelfilename = optarg;
	  if (verbose >= 5)
	    fprintf (stderr, "Opened label file\n");
	  break;
	case 'p':
	  labelprefix = optarg;
	  break;
	case 'I':
	  add_include (optarg);
	  break;
	case 'f':
	  use_force = 1;
	  break;
	case -1:
	  done = 1;
	  break;
	default:
	  /* errors are handled by getopt_long */
	  break;
	}
    }
  for (i = optind; i < argc; ++i)
    open_infile (argv[i]);
  if (!infilecount)
    open_infile ("-");
  if (!out)
    realoutputfile = openfile (&out, "output file", stdout, "a.bin", "wb");
  try_use_real_file (realoutputfile, &outfile);
  if (havelist)
    try_use_real_file (reallistfile, &listfile);
}

/* find any of the list[] entries as the start of ptr and return index */
static int
indx (const char **ptr, const char **list, int error, const char **expr)
{
  int i, l;
  *ptr = delspc (*ptr);
  if (!**ptr)
    {
      if (error)
	{
	  printerr (1, "unexpected end of line\n");
	  return 0;
	}
      else
	return 0;
    }
  if (comma > 1)
    rd_comma (ptr);
  for (i = 0; list[i]; i++)
    {
      const char *input = *ptr;
      const char *check = list[i];
      int had_expr = 0;
      if (!list[i][0])
	continue;
      l = strlen (list[i]);
      while (*check)
	{
	  if (*check == ' ')
	    {
	      input = delspc (input);
	    }
	  else if (*check == '*')
	    {
	      *expr = input;
	      mem_delimiter = check[1];
	      rd_expr (&input, mem_delimiter, NULL, sp, 0);
	      had_expr = 1;
	    }
	  else if (*check == '+')
	    {
	      if (*input == '+' || *input == '-')
		{
		  *expr = input;
		  mem_delimiter = check[1];
		  rd_expr (&input, mem_delimiter, NULL, sp, 0);
		}
	    }
	  else if (*check == *input || (*check >= 'a' && *check <= 'z'
					&& *check - 'a' + 'A' == *input))
	    ++input;
	  else
	    break;

	  ++check;
	}
      if (*check || (isalnum (check[-1]) && isalnum (input[0])))
	continue;
      if (had_expr)
	{
	  input = delspc (input);
	  if (*input && *input != ',')
	    continue;
	}
      *ptr = input;
      if (verbose >= 4)
	fprintf (stderr, "%5d (0x%04x): Piece of code found:%s\n",
		 stack[sp].line, addr, list[i]);
      if (verbose >= 6)
	fprintf (stderr, "%5d (0x%04x): Remainder of line=%s.\n",
		 stack[sp].line, addr, *ptr);
      comma++;
      return i + 1;
    }
  if (error)
    {
      printerr (1, "parse error. Remainder of line=%s\n", *ptr);
      if (verbose >= 3)
	{
	  fprintf (stderr, "When looking for any of:\n");
	  for (i = 0; list[i]; i++)
	    fprintf (stderr, "%s\t", list[i]);
	  fprintf (stderr, "\n");
	}
    }
  return 0;
}

/* read a mnemonic */
static int
readcommand (const char **p)
{
  return indx (p, mnemonics, 0, NULL);
}

/* try to read a label and optionally store it in the list */
static void
readlabel (const char **p, int store)
{
  const char *c, *d, *pos, *dummy;
  int i, j;
  struct label *buf, *previous, **thefirstlabel;
  for (d = *p; *d && *d != ';'; ++d)
    {
    }
  for (c = *p; !strchr (" \r\n\t", *c) && c < d; ++c)
    {
    }
  pos = strchr (*p, ':');
  if (!pos || pos >= c)
    return;
  if (pos == *p)
    {
      printerr (1, "`:' found without a label");
      return;
    }
  if (!store)
    {
      *p = pos + 1;
      return;
    }
  c = pos + 1;
  dummy = *p;
  j = rd_label (&dummy, &i, &previous, sp, 0);
  if (i || j)
    {
      printerr (1, "duplicate definition of label %s\n", *p);
      *p = c;
      return;
    }
  if (NULL == (buf = malloc (sizeof (struct label) + c - *p)))
    {
      printerr (1, "not enough memory to store label %s\n", *p);
      *p = c;
      return;
    }
  strncpy (buf->name, *p, c - *p - 1);
  buf->name[c - *p - 1] = 0;
  if (verbose >= 3)
    fprintf (stderr, "%5d (0x%04x): Label found: %s\n", stack[sp].line,
	     addr, buf->name);
  *p = c;
  buf->value = addr;
  lastlabel = buf;
  if (buf->name[0] == '.')
    thefirstlabel = &stack[sp].labels;
  else
    thefirstlabel = &firstlabel;
  if (previous)
    buf->next = previous->next;
  else
    buf->next = *thefirstlabel;
  buf->prev = previous;
  buf->valid = 1;
  buf->busy = 0;
  buf->ref = NULL;
  if (buf->prev)
    buf->prev->next = buf;
  else
    *thefirstlabel = buf;
  if (buf->next)
    buf->next->prev = buf;
}

static void new_reference (const char *data, int type, char delimiter,
			   int ds_count);

/* write one byte to the outfile, and add it to the list file as well */
static void
write_one_byte (int b, int list)
{
  if (verbose >= 4)
    fprintf (stderr,
	     "%5d (0x%04x): write_one_byte called with argument 0x%02x\n",
	     stack[sp].line, addr, b);
  b &= 0xff;
  putc (b, outfile);
  if (list && havelist)
    {
      fprintf (listfile, " %02x", b);
      listdepth += 3;
    }
  addr++;
  addr &= 0xffff;
}

/* write byte to outfile and possibly some index things as well */
static void
wrtb (int b)
{
  if (verbose >= 4)
    fprintf (stderr, "%5d (0x%04x): wrtb called with argument 0x%02x\n",
	     stack[sp].line, addr, b);
  if (indexed)
    {
      if (verbose >= 5)
	fprintf (stderr, "%5d (0x%04x): writing indexed byte 0x%02x\n",
		 stack[sp].line, addr, indexed);
      write_one_byte (indexed, 1);
      indexed = 0;
    }
  if (writebyte)
    {
      if (verbose >= 5)
	fprintf (stderr, "%5d (0x%04x): using a xor on byte because there is "
		 "a writebyte.\n", stack[sp].line, addr);
      b ^= 0x40;
    }
  if (verbose >= 5)
    fprintf (stderr, "%5d (0x%04x): writing byte 0x%02x\n", stack[sp].line,
	     addr, b);
  if (bitsetres && b != 0xCB)
    {
      new_reference (bitsetres, TYPE_BSR, ',', b);
      bitsetres = NULL;
    }
  else
    {
      write_one_byte (b, 1);
    }
  if (indexjmp)
    {
      if (verbose >= 5)
	fprintf (stderr, "%5d (0x%04x): Making reference for index/jump %s\n",
		 stack[sp].line, addr, indexjmp);
      new_reference (indexjmp, TYPE_ABSB, ')', 1);
      indexjmp = NULL;
    }
  if (writebyte)
    {
      if (verbose >= 5)
	fprintf (stderr, "%5d (0x%04x): writing argument byte for padding\n",
		 stack[sp].line, addr);
      writebyte = 0;
      new_reference (readbyte, TYPE_ABSB, mem_delimiter, 1);
    }
}

int
compute_ref (struct reference *ref, int allow_invalid)
{
  const char *ptr;
  int valid = 0;
  int backup_addr = addr;
  int backup_baseaddr = baseaddr;
  int backup_comma = comma;
  int backup_file = file;
  int backup_sp = sp;
  sp = ref->level;
  addr = ref->addr;
  baseaddr = ref->baseaddr;
  comma = ref->comma;
  file = ref->infile;
  if (verbose >= 3)
    fprintf (stderr, "%5d (0x%04x): Making reference to %s (done=%d, "
	     "computed=%d)\n",
	     stack[sp].line, addr, ref->input, ref->done,
	     ref->computed_value);
  ptr = ref->input;
  if (!ref->done)
    {
      ref->computed_value = rd_expr (&ptr, ref->delimiter,
				     allow_invalid ? &valid : NULL,
				     ref->level, 1);
      if (valid)
	ref->done = 1;
    }
  if (verbose >= 4)
    fprintf (stderr, "%5d (0x%04x): Reference is %d (0x%04x).\n",
	     stack[sp].line, addr, ref->computed_value, ref->computed_value);
  sp = backup_sp;
  addr = backup_addr;
  baseaddr = backup_baseaddr;
  comma = backup_comma;
  file = backup_file;
  return ref->computed_value;
}

static void wrt_ref (int val, int type, int count);

/* Create a new reference, to be resolved after assembling (so all labels are
 * known.) */
static void
new_reference (const char *p, int type, char delimiter, int ds_count)
{
  struct reference *tmp = NULL;
  long opos, lpos;
  int valid, value;
  const char *c;
  c = p;
  value = rd_expr (&c, delimiter, &valid, sp, 1);
  if (valid)
    {
      if (verbose >= 5)
	{
	  fprintf (stderr, "%5d (0x%04x): Using calculated value %d (%x) "
		   "immediately.\n", stack[sp].line, addr, value, value);
	}
    }
  else
    {
      /* the expression is not valid (yet), we need to make a real reference.  */
      tmp = malloc (sizeof (struct reference) + strlen (p));
      if (!tmp)
	{
	  printerr (1, "unable to allocate memory for reference %s\n", p);
	  return;
	}
      tmp->file = malloc (strlen (stack[sp].name) + 1);
      if (!tmp->file)
	{
	  printerr (1, "unable to allocate memory for reference filename\n");
	  free (tmp);
	  return;
	}
      strcpy (tmp->file, stack[sp].name);
      if (stack[sp].dir)
	{
	  tmp->dir = malloc (strlen (stack[sp].dir->name)
			  + sizeof (struct includedir));
	  if (!tmp->dir)
	    {
	      printerr (1, "unable to allocate memory for reference dir\n");
	      free (tmp->file);
	      free (tmp);
	      return;
	    }
	  strcpy (tmp->dir->name, stack[sp].dir->name);
	}
      else
	tmp->dir = NULL;
      opos = ftell (outfile);
      lpos = havelist ? ftell (listfile) : 0;
      if (verbose >= 3)
	fprintf (stderr, "%5d (0x%04x): reference set to %s (delimiter=%c, "
		 "sp=%d)\n", stack[sp].line, addr, p, delimiter, sp);
      strcpy (tmp->input, p);
      tmp->line = stack[sp].line;
      tmp->addr = addr;
      tmp->baseaddr = baseaddr;
      tmp->count = ds_count;
      tmp->infile = file;
      tmp->comma = comma;
      tmp->oseekpos = opos;
      tmp->lseekpos = lpos;
      tmp->delimiter = delimiter;
      tmp->type = type;
      tmp->next = firstreference;
      tmp->done = 0;
      tmp->level = sp;
      if (type != TYPE_LABEL)
	{
	  if (firstreference)
	    firstreference->prev = tmp;
	  tmp->prev = NULL;
	  firstreference = tmp;
	}
      /* Dummy value which should not give warnings */
      value = (type == TYPE_RELB) ? ds_count : 0;
    }
  if (type != TYPE_LABEL)
    {
      wrt_ref (value, type, ds_count);
    }
  else
    {
      lastlabel->ref = tmp;
      lastlabel->valid = valid;
      lastlabel->value = value;
    }
}

/* write the last read word to file */
static void
write_word (void)
{
  new_reference (readword, TYPE_ABSW, mem_delimiter, 1);
}

/* write the last read byte to file (relative) */
static void
write_rel (void)
{
  new_reference (readbyte, TYPE_RELB, mem_delimiter, (addr + 1) & 0xffff);
  writebyte = 0;
}

/* read a word from input and store it in readword. return 1 on success */
static int
rd_word (const char **p, char delimiter)
{
  *p = delspc (*p);
  if (**p == 0)
    return 0;
  readword = *p;
  mem_delimiter = delimiter;
  skipword (p, delimiter);
  return 1;
}

/* read a byte from input and store it in readbyte. return 1 on success */
static int
rd_byte (const char **p, char delimiter)
{
  *p = delspc (*p);
  if (**p == 0)
    return 0;
  readbyte = *p;
  writebyte = 1;
  mem_delimiter = delimiter;
  skipword (p, delimiter);
  return 1;
}

/* read an address from infile and put it in reference table.
 * so that it will be written here afterwards */
static void
rd_wrt_addr (const char **p, char delimiter)
{
  if (!rd_word (p, delimiter))
    return;
  write_word ();
}

/* like rd_wrt_addr, but for a relative jump */
static void
rd_wrt_jr (const char **p, char delimiter)
{
  if (!rd_byte (p, delimiter))
    return;
  write_rel ();
}

/* read (SP), DE, or AF */
static int
rd_ex1 (const char **p)
{
#define DE 2
#define AF 3
  const char *list[] = { "( sp )", "de", "af", NULL };
  return indx (p, list, 1, NULL);
}

/* read first argument of IN */
static int
rd_in (const char **p)
{
#define A 8
  const char *list[] = { "b", "c", "d", "e", "h", "l", "f", "a", NULL };
  return indx (p, list, 1, NULL);
}

/* read second argument of out (c),x */
static int
rd_out (const char **p)
{
  const char *list[] = { "b", "c", "d", "e", "h", "l", "0", "a", NULL };
  return indx (p, list, 1, NULL);
}

/* read (c) or (nn) */
static int
rd_nnc (const char **p)
{
#define C 1
  int i;
  const char *list[] = { "( c )", "(*)", "a , (*)", NULL };
  i = indx (p, list, 1, &readbyte);
  if (i < 2)
    return i;
  return 2;
}

/* read (C) */
static int
rd_c (const char **p)
{
  const char *list[] = { "( c )", "( bc )", NULL };
  return indx (p, list, 1, NULL);
}

/* read a or hl */
static int
rd_a_hl (const char **p)
{
#define HL 2
  const char *list[] = { "a", "hl", NULL };
  return indx (p, list, 1, NULL);
}

/* read first argument of ld */
static int
rd_ld (const char **p)
{
#define ldBC	1
#define ldDE	2
#define ldHL	3
#define ldSP	4
#define ldIX	5
#define ldIY	6
#define ldB	7
#define ldC	8
#define ldD	9
#define ldE	10
#define ldH	11
#define ldL	12
#define ld_HL	13
#define ldA	14
#define ldI	15
#define ldR	16
#define ld_BC	17
#define ld_DE	18
#define ld_IX	19
#define ld_IY	20
#define ld_NN	21
  int i;
  const char *list[] = {
    "ixh", "ixl", "iyh", "iyl", "bc", "de", "hl", "sp", "ix",
    "iy", "b", "c", "d", "e", "h", "l", "( hl )", "a", "i",
    "r", "( bc )", "( de )", "( ix +)", "(iy +)", "(*)", NULL
  };
  const char *nn;
  i = indx (p, list, 1, &nn);
  if (!i)
    return 0;
  if (i <= 2)
    {
      indexed = 0xdd;
      return ldH + (i == 2);
    }
  if (i <= 4)
    {
      indexed = 0xfd;
      return ldH + (i == 4);
    }
  i -= 4;
  if (i == ldIX || i == ldIY)
    {
      indexed = i == ldIX ? 0xDD : 0xFD;
      return ldHL;
    }
  if (i == ld_IX || i == ld_IY)
    {
      indexjmp = nn;
      indexed = i == ld_IX ? 0xDD : 0xFD;
      return ld_HL;
    }
  if (i == ld_NN)
    readword = nn;
  return i;
}

/* read first argument of JP */
static int
rd_jp (const char **p)
{
  int i;
  const char *list[] = {
    "nz", "z", "nc", "c", "po", "pe", "p", "m", "( ix )", "( iy )",
    "(hl)", NULL
  };
  i = indx (p, list, 0, NULL);
  if (i < 9)
    return i;
  if (i == 11)
    return -1;
  indexed = 0xDD + 0x20 * (i - 9);
  return -1;
}

/* read first argument of JR */
static int
rd_jr (const char **p)
{
  const char *list[] = { "nz", "z", "nc", "c", NULL };
  return indx (p, list, 0, NULL);
}

/* read A */
static int
rd_a (const char **p)
{
  const char *list[] = { "a", NULL };
  return indx (p, list, 1, NULL);
}

/* read bc,de,hl,af */
static int
rd_stack (const char **p)
{
  int i;
  const char *list[] = { "bc", "de", "hl", "af", "ix", "iy", NULL };
  i = indx (p, list, 1, NULL);
  if (i < 5)
    return i;
  indexed = 0xDD + 0x20 * (i - 5);
  return 3;
}

#if 0
/* read a or hl(2) or i[xy](2) with variables set */
static int
rd_a_hlx (const char **p)
{
  int i;
  const char *list[] = { "a", "hl", "ix", "iy", NULL };
  i = indx (p, list, 1, NULL);
  if (i < 2)
    return i;
  if (i == 2)
    return 2;
  indexed = 0xDD + 0x20 * (i - 3);
  return 2;
}
#endif

/* read b,c,d,e,h,l,(hl),a,(ix+nn),(iy+nn),nn 
 * but now with extra hl or i[xy](15) for add-instruction
 * and set variables accordingly */
static int
rd_r_add (const char **p)
{
#define addHL 	15
  int i;
  const char *list[] = {
    "ixl", "ixh", "iyl", "iyh", "b", "c", "d", "e", "h", "l",
    "( hl )", "a", "( ix +)", "( iy +)", "hl", "ix", "iy", "*", NULL
  };
  const char *nn;
  i = indx (p, list, 0, &nn);
  if (i == 18)	/* expression */
    {
      readbyte = nn;
      writebyte = 1;
      return 7;
    }
  if (i > 14)	/* hl, ix, iy */
    {
      if (i > 15)
	indexed = 0xDD + 0x20 * (i - 16);
      return addHL;
    }
  if (i <= 4)	/* i[xy][hl]  */
    {
      indexed = 0xdd + 0x20 * (i > 2);
      return 6 - (i & 1);
    }
  i -= 4;
  if (i < 9)
    return i;
  indexed = 0xDD + 0x20 * (i - 9);	/* (i[xy] +) */
  indexjmp = nn;
  return 7;
}

/* read bc,de,hl, or sp */
static int
rd_rr_ (const char **p)
{
  const char *list[] = { "bc", "de", "hl", "sp", NULL };
  return indx (p, list, 1, NULL);
}

/* read bc,de,hl|ix|iy,sp. hl|ix|iy only if it is already indexed the same. */
static int
rd_rrxx (const char **p)
{
  const char *listx[] = { "bc", "de", "ix", "sp", NULL };
  const char *listy[] = { "bc", "de", "iy", "sp", NULL };
  const char *list[] = { "bc", "de", "hl", "sp", NULL };
  switch (indexed)
    {
    case 0xDD:
      return indx (p, listx, 1, NULL);
    case 0xFD:
      return indx (p, listy, 1, NULL);
    default:
      return indx (p, list, 1, NULL);
    }
}

/* read b,c,d,e,h,l,(hl),a,(ix+nn),(iy+nn),nn
 * and set variables accordingly */
static int
rd_r (const char **p)
{
  int i;
  const char *list[] = {
    "ixl", "ixh", "iyl", "iyh", "b", "c", "d", "e", "h", "l", "( hl )",
    "a", "( ix +)", "( iy +)", "*", NULL
  };
  const char *nn;
  i = indx (p, list, 0, &nn);
  if (i == 15)	/* expression */
    {
      readbyte = nn;
      writebyte = 1;
      return 7;
    }
  if (i <= 4)
    {
      indexed = 0xdd + 0x20 * (i > 2);
      return 6 - (i & 1);
    }
  i -= 4;
  if (i < 9)
    return i;
  indexed = 0xDD + 0x20 * (i - 9);
  indexjmp = nn;
  return 7;
}

/* like rd_r(), but without nn */
static int
rd_r_ (const char **p)
{
  int i;
  const char *list[] = {
    "b", "c", "d", "e", "h", "l", "( hl )", "a", "( ix +)", "( iy +)", NULL
  };
  i = indx (p, list, 1, &indexjmp);
  if (i < 9)
    return i;
  indexed = 0xDD + 0x20 * (i - 9);
  return 7;
}

/* read a number from 0 to 7, for bit, set or res */
static int
rd_0_7 (const char **p)
{
  *p = delspc (*p);
  if (**p == 0)
    return 0;
  bitsetres = *p;
  skipword (p, ',');
  return 1;
}

/* read long condition. do not error if not found. */
static int
rd_cc (const char **p)
{
  const char *list[] = { "nz", "z", "nc", "c", "po", "pe", "p", "m", NULL };
  return indx (p, list, 0, NULL);
}

/* read long or short register,  */
static int
rd_r_rr (const char **p)
{
  int i;
  const char *list[] = {
    "iy", "ix", "sp", "hl", "de", "bc", "", "b", "c", "d", "e", "h",
    "l", "( hl )", "a", "( ix +)", "( iy +)", NULL
  };
  i = indx (p, list, 1, &indexjmp);
  if (!i)
    return 0;
  if (i < 16 && i > 2)
    return 7 - i;
  if (i > 15)
    {
      indexed = 0xDD + (i - 16) * 0x20;
      return -7;
    }
  indexed = 0xDD + (2 - i) * 0x20;
  return 3;
}

/* read hl */
static int
rd_hl (const char **p)
{
  const char *list[] = { "hl", NULL };
  return indx (p, list, 1, NULL);
}

/* read hl, ix, or iy */
static int
rd_hlx (const char **p)
{
  int i;
  const char *list[] = { "hl", "ix", "iy", NULL };
  i = indx (p, list, 1, NULL);
  if (i < 2)
    return i;
  indexed = 0xDD + 0x20 * (i - 2);
  return 1;
}

/* read af' */
static int
rd_af_ (const char **p)
{
  const char *list[] = { "af'", NULL };
  return indx (p, list, 1, NULL);
}

/* read 0(1), 1(3), or 2(4) */
static int
rd_0_2 (const char **p)
{
  const char *list[] = { "0", "", "1", "2", NULL };
  return indx (p, list, 1, NULL);
}

/* read argument of ld (hl), */
static int
rd_ld_hl (const char **p)
{
  int i;
  const char *list[] = { "b", "c", "d", "e", "h", "l", "", "a", "*", NULL };
  i = indx (p, list, 0, &readbyte);
  if (i < 9)
    return i;
  writebyte = 1;
  return 7;
}

/* read argument of ld (nnnn), */
static int
rd_ld_nn (const char **p)
{
#define ld_nnHL 5
#define ld_nnA 6
  int i;
  const char *list[] = { "bc", "de", "", "sp", "hl", "a", "ix", "iy", NULL };
  i = indx (p, list, 1, NULL);
  if (i < 7)
    return i;
  indexed = 0xdd + 0x20 * (i == 8);
  return ld_nnHL;
}

/* read argument of ld a, */
static int
rd_lda (const char **p)
{
#define A_I 9
#define A_R 10
#define A_NN 11
  int i;
  const char *list[] = {
    "( sp )", "( iy +)", "( de )", "( bc )", "( ix +)", "b", "c", "d", "e", "h",
    "l", "( hl )", "a", "i", "r", "(*)", "*", NULL
  };
  const char *nn;
  i = indx (p, list, 0, &nn);
  if (i == 2 || i == 5)
    {
      indexed = (i == 2) ? 0xFD : 0xDD;
      indexjmp = nn;
      return 7;
    }
  if (i == 17)
    {
      readbyte = nn;
      writebyte = 1;
      return 7;
    }
  if (i == 16)
    {
      readword = nn;
    }
  return i - 5;
}

/* read argument of ld b|c|d|e|h|l */
static int
rd_ldbcdehla (const char **p)
{
  int i;
  const char *list[] = {
    "b", "c", "d", "e", "h", "l", "( hl )", "a", "( ix +)", "( iy +)", "ixh",
    "ixl", "iyh", "iyl", "*", NULL
  };
  const char *nn;
  i = indx (p, list, 0, &nn);
  if (i == 15)
    {
      readbyte = nn;
      writebyte = 1;
      return 7;
    }
  if (i > 10)
    {
      int x;
      x = 0xdd + 0x20 * (i > 12);
      if (indexed && indexed != x)
	{
	  printerr (1, "illegal use of index registers\n");
	  return 0;
	}
      indexed = x;
      return 6 - (i & 1);
    }
  if (i > 8)
    {
      if (indexed)
	{
	  printerr (1, "illegal use of index registers\n");
	  return 0;
	}
      indexed = 0xDD + 0x20 * (i == 10);
      indexjmp = nn;
      return 7;
    }
  return i;
}

/* read nnnn, or (nnnn) */
static int
rd_nn_nn (const char **p)
{
#define _NN 1
  const char *list[] = { "(*)", "*", NULL };
  return 2 - indx (p, list, 0, &readword);
}

/* read {HL|IX|IY},nnnn, or (nnnn) */
static int
rd_sp (const char **p)
{
#define SPNN 0
#define SPHL 1
  int i;
  const char *list[] = { "hl", "ix", "iy", "(*)", "*", NULL };
  const char *nn;
  i = indx (p, list, 0, &nn);
  if (i > 3)
    {
      readword = nn;
      return i == 4 ? 2 : 0;
    }
  if (i != 1)
    indexed = 0xDD + 0x20 * (i - 2);
  return 1;
}

/* write a reference after it has been computed */
static void
wrt_ref (int val, int type, int count)
{
  switch (type)
    {
    case TYPE_RST:
      if ((val & 0x38) != val)
	{
	  printerr (1, "incorrect RST value %d (0x%02x)\n", val, val);
	  return;
	}
      write_one_byte (val + 0xC7, 1);
      return;
    case TYPE_ABSW:
      if (val < -0x8000 || val >= 0x10000)
	printerr (0, "word value %d (0x%x) truncated\n", val, val);
      write_one_byte (val & 0xff, 1);
      write_one_byte ((val >> 8) & 0xff, 1);
      return;
    case TYPE_ABSB:
      if (val < -0x80 || val >= 0x100)
	printerr (0, "byte value %d (0x%x) truncated\n", val, val);
      write_one_byte (val & 0xff, 1);
      return;
    case TYPE_DS:
      if (val < -0x80 || val >= 0x100)
	printerr (0, "byte value %d (0x%x) truncated\n", val, val);
      if (havelist)
	{
	  fprintf (listfile, " 0x%02x...", val & 0xff);
	  listdepth += 6;
	}
      while (count--)
	{
	  write_one_byte (val & 0xff, 0);
	}
      return;
    case TYPE_BSR:
      if (val & ~7)
	{
	  printerr (1, "incorrect BIT/SET/RES value %d\n", val);
	  return;
	}
      write_one_byte (0x08 * val + count, 1);
      return;
    case TYPE_RELB:
      val -= count;
      if (val & 0xff80 && ~val & 0xff80) 
	{
	  printerr (1, "relative jump out of range (%d)\n", val);
	}
      write_one_byte (val & 0xff, 1);
      return;
    case TYPE_LABEL:
      printerr (1, "bug in the assembler: trying to write label reference.  "
		"Please report.\n");
      return;
    }
}

static char *
get_include_name (const char **ptr)
{
  int pos = 0;
  char quote;
  char *name;
  *ptr = delspc (*ptr);
  name = malloc (strlen (*ptr));
  if (!name)
    {
      printerr (1, "unable to allocate memory for filename %.*s\n",
		strlen (*ptr) - 1, *ptr);
      return NULL;
    }
  if (!**ptr)
    {
      printerr (1, "include without filename\n");
      free (name);
      return NULL;
    }
  quote = *(*ptr)++;
  while (**ptr != quote)
    {
      if (!**ptr)
	{
	  printerr (1, "filename without closing quote (%c)\n", quote);
	  free (name);
	  return NULL;
	}
      name[pos++] = *(*ptr)++;
    }
  name[pos] = 0;
  ++*ptr;
  return name;
}

static int
read_line (void)
{
  unsigned pos, newpos, size;
  struct macro_arg *arg;
  if (stack[sp].file)
    {
      FILE *f = stack[sp].file;
      static char short_buffer[BUFLEN + 1];
      if (buffer && buffer != short_buffer)
	free (buffer);
      buffer = NULL;
      if (!fgets (short_buffer, BUFLEN + 1, f))
	return 0;
      if (strlen (short_buffer) < BUFLEN)
	{
	  buffer = short_buffer;
	  return 1;
	}
      size = 2 * BUFLEN;
      buffer = malloc (size + 1);
      if (!buffer)
	{
	  printerr (1, "out of memory reading line\n");
	  return 0;
	}
      memcpy (buffer, short_buffer, BUFLEN + 1);
      while (1)
	{
	  char *b;
	  if (!fgets (&buffer[size - BUFLEN], BUFLEN + 1, f)
	      || (buffer[strlen (buffer) - 1] == '\n'))
	    {
	      return 1;
	    }
	  size += BUFLEN;
	  b = realloc (buffer, size + 1);
	  if (!b)
	    {
	      printerr (1, "out of memory reading line\n");
	      return 0;
	    }
	  buffer = b;
	}
    }
  /* macro line */
  if (!stack[sp].macro_line)
    {
      unsigned i;
      for (i = 0; i < stack[sp].macro->numargs; ++i)
	free (stack[sp].macro_args[i]);
      free (stack[sp].macro_args);
      return 0;
    }
  size = strlen (stack[sp].macro_line->line) + 1;
  for (arg = stack[sp].macro_line->args; arg; arg = arg->next)
    size += strlen (stack[sp].macro_args[arg->which]);
  buffer = malloc (size);
  if (!buffer)
    {
      printerr (1, "out of memory\n");
      return 0;
    }
  pos = 0;
  newpos = 0;
  for (arg = stack[sp].macro_line->args; arg; arg = arg->next)
    {
      memcpy (&buffer[newpos], &stack[sp].macro_line->line[pos],
	      arg->pos - pos);
      newpos += arg->pos - pos;
      strcpy (&buffer[newpos], stack[sp].macro_args[arg->which]);
      newpos += strlen (stack[sp].macro_args[arg->which]);
      pos = arg->pos + 1;
    }
  strcpy (&buffer[newpos], &stack[sp].macro_line->line[pos]);
  stack[sp].macro_line = stack[sp].macro_line->next;
  return 1;
}

static unsigned
get_macro_args (const char **ptr, char ***ret_args, int allow_empty)
{
  unsigned numargs = 0;
  *ret_args = NULL;
  while (1)
    {
      char **args;
      const char *c;
      *ptr = delspc (*ptr);
      if (!**ptr)
	break;
      c = *ptr;
      for (; **ptr && !strchr (" \r\n\t,;", **ptr); ++*ptr)
	{
	}
      if (*ptr == c && !allow_empty)
	{
	  printerr (1, "empty macro argument\n");
	  break;
	}
      ++numargs;
      args = realloc (*ret_args, sizeof (char *) * numargs);
      if (!args)
	{
	  printerr (1, "out of memory\n");
	  --numargs;
	  break;
	}
      *ret_args = args;
      args[numargs - 1] = malloc (*ptr - c + 1);
      if (!args[numargs - 1])
	{
	  printerr (1, "out of memory\n");
	  --numargs;
	  break;
	}
      memcpy (args[numargs - 1], c, *ptr - c);
      args[numargs - 1][*ptr - c] = 0;
    }
  return numargs;
}

/* do the actual work */
static void
assemble (void)
{
  int ifcount = 0, noifcount = 0;
  const char *ptr;
  struct label *l;
  char *bufptr;
  int r, s;			/* registers */
  /* continue assembling until the last input file is done */
  for (file = 0; file < infilecount; ++file)
    {
      int file_ended = 0;
      sp = 0;			/* clear stack */
      stack[sp].line = 0;
      stack[sp].shouldclose = 0;
      stack[sp].name = infile[file].name;
      stack[sp].dir = NULL;
      if (infile[file].name[0] == '-' && infile[file].name[1] == 0)
	{
	  stack[sp].file = stdin;
	}
      else
	{
	  stack[sp].file = fopen (infile[file].name, "r");
	  if (!stack[sp].file)
	    {
	      printerr (1, "unable to open %s. skipping\n", infile[file].name);
	      continue;
	    }
	  stack[sp].shouldclose = 1;
	}
      if (havelist)
	fprintf (listfile, "# File %s\n", stack[sp].name);
      if (buffer)
	buffer[0] = 0;
      /* loop until this source file is done */
      while (1)
	{
	  int cmd, cont = 1;
	  if (havelist)
	    {
	      if (buffer && buffer[0] != 0)
		{
		  int i, tabs;
		  ptr = delspc (ptr);
		  if (*ptr != 0)
		    {
		      printerr (1, "junk at end of line: %s\n", ptr);
		    }
		  if (listdepth < 8)
		    tabs = 3;
		  else if (listdepth < 16)
		    tabs = 2;
		  else
		    tabs = 1;
		  for (i = 0; i < tabs; ++i)
		    fputc ('\t', listfile);
		  fprintf (listfile, "%s\n", buffer);
		}
	      listdepth = 4;
	    }
	  /* throw away the rest of the file after end */
	  if (file_ended)
	    {
	      while (read_line ())
		{
		  if (havelist)
		    fprintf (listfile, "\t\t\t%s\n", buffer);
		}
	      file_ended = 0;
	    }
	  while (!read_line ())
	    {
	      struct reference *ref, *nextref;
	      struct label *next;
	      if (verbose >= 6)
		fprintf (stderr, "finished reading file %s\n",
			 stack[sp].name);
	      if (havelist)
		{
		  if (stack[sp].file)
		    fprintf (listfile, "# End of file %s\n", stack[sp].name);
		  else
		    fprintf (listfile, "# End of macro %s\n", stack[sp].name);
		}
	      if (stack[sp].shouldclose)
		fclose (stack[sp].file);
	      /* the top of stack is about to be popped off, throwing all
	       * local labels out of scope.  All references at this level
	       * which aren't computable are errors.  */
	      for (ref = firstreference; ref; ref = nextref)
		{
		  nextref = ref->next;
		  compute_ref (ref, 1);
		  if (ref->done)
		    continue;
		  if (ref->level == sp)
		    if (!ref->level--)
		      {
			printerr (1, "unable to resolve reference: %s\n",
				  ref->input);
			if (ref->prev)
			  ref->prev->next = ref->next;
			else
			  firstreference = ref->next;
			if (ref->next)
			  ref->next->prev = ref->prev;
			free (ref);
		      }
		}
	      /* Ok, now junk all local labels of the top stack level */
	      for (l = stack[sp].labels; l; l = next)
		{
		  next = l->next;
		  if (l->ref)
		    free (l->ref);
		  free (l);
		}
	      stack[sp].labels = NULL;
	      if (!sp--)
		{
		  cont = 0;
		  break;
		}
	    }
	  if (!cont)
	    break;		/* break to next source file */
	  if (havelist)
	    fprintf (listfile, "%04x", addr);
	  for (bufptr = buffer; (bufptr = strchr (bufptr, '\n'));)
	    *bufptr = ' ';
	  for (bufptr = buffer; (bufptr = strchr (bufptr, '\r'));)
	    *bufptr = ' ';
	  ptr = buffer;
	  lastlabel = NULL;
	  baseaddr = addr;
	  ++stack[sp].line;
	  ptr = delspc (ptr);
	  if (!*ptr)
	    continue;
	  if (!noifcount && !define_macro)
	    readlabel (&ptr, 1);
	  else
	    readlabel (&ptr, 0);
	  ptr = delspc (ptr);
	  if (!*ptr)
	    continue;
	  comma = 0;
	  indexed = 0;
	  indexjmp = 0;
	  writebyte = 0;
	  readbyte = 0;
	  readword = 0;
	  cmd = readcommand (&ptr) - 1;
	  if (noifcount)
	    {
	      switch (cmd)
		{
		case IF:
		  noifcount++;
		  break;
		case ELSE:
		  if (noifcount == 1)
		    {
		      noifcount = 0;
		      ifcount++;
		    }
		  break;
		case ENDIF:
		  noifcount--;
		}
	      ptr = "";
	      continue;
	    }
	  if (define_macro)
	    {
	      char *newptr;
	      struct macro_line **current_line;
	      for (current_line = &firstmacro->lines; *current_line;
		   current_line = &(*current_line)->next)
		{
		}
	      *current_line = malloc (sizeof (struct macro_line));
	      if (!*current_line)
		{
		  printerr (1, "out of memory\n");
		  continue;
		}
	      (*current_line)->next = NULL;
	      (*current_line)->args = NULL;
	      (*current_line)->line = malloc (strlen (buffer) + 1);
	      if (!(*current_line)->line)
		{
		  printerr (1, "out of memory\n");
		  free (*current_line);
		  *current_line = NULL;
		  continue;
		}
	      ptr = buffer;
	      newptr = (*current_line)->line;
	      while (*ptr)
		{
		  unsigned p;
		  struct macro_arg **last_arg = &(*current_line)->args;
		  for (p = 0; p < firstmacro->numargs; ++p)
		    {
		      if (strncmp (ptr, firstmacro->args[p],
				   strlen (firstmacro->args[p])) == 0)
			{
			  struct macro_arg *newarg;
			  newarg = malloc (sizeof (struct macro_arg));
			  if (!newarg)
			    {
			      printerr (1, "out of memory\n");
			      break;
			    }
			  newarg->next = NULL;
			  *last_arg = newarg;
			  last_arg = &newarg->next;
			  newarg->pos = newptr - (*current_line)->line;
			  newarg->which = p;
			  /* leave one character so two macros following each
			   * other keep their order. */
			  ptr += strlen (firstmacro->args[p]) - 1;
			  break;
			}
		    }
		  *newptr++ = *ptr++;
		}
	      *newptr = 0;
	      if (verbose >= 7)
		fprintf (stderr, "added line to macro (cmd = %d): %s\n", cmd,
			 (*current_line)->line);
	      if (cmd == ENDM)
		define_macro = 0;
	      continue;
	    }
	  switch (cmd)
	    {
	      int i, have_quote;
	    case ADC:
	      if (!(r = rd_a_hl (&ptr)))
		break;
	      if (r == HL)
		{
		  if (!(r = rd_rr_ (&ptr)))
		    break;
		  wrtb (0xED);
		  wrtb (0x4A + 0x10 * --r);
		  break;
		}
	      if (!(r = rd_r (&ptr)))
		break;
	      wrtb (0x88 + --r);
	      break;
	    case ADD:
	      if (!(r = rd_r_add (&ptr)))
		break;
	      if (r == addHL)
		{
		  if (!(r = rd_rrxx (&ptr)))
		    break;
		  wrtb (0x09 + 0x10 * --r);	/* ADD HL/IX/IY, qq  */
		  break;
		}
	      if (has_argument (&ptr))
		{
		  if (r != A)
		    {
		      printerr (1, "parse error before: %s\n", ptr);
		      break;
		    }
		  if (!(r = rd_r (&ptr)))
		    break;
		  wrtb (0x80 + --r);	/* ADD A,r  */
		  break;
		}
	      wrtb (0x80 + --r);	/* ADD r  */
	      break;
	    case AND:
	      if (!(r = rd_r (&ptr)))
		break;
	      wrtb (0xA0 + --r);
	      break;
	    case BIT:
	      if (!rd_0_7 (&ptr))
		break;
	      rd_comma (&ptr);
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x40 + (r - 1));
	      break;
	    case CALL:
	      if (!(r = rd_cc (&ptr)))
		{
		  wrtb (0xCD);
		}
	      else
		{
		  wrtb (0xC4 + 8 * --r);
		  rd_comma (&ptr);
		}
	      rd_wrt_addr (&ptr, '\0');
	      break;
	    case CCF:
	      wrtb (0x3F);
	      break;
	    case CP:
	      if (!(r = rd_r (&ptr)))
		break;
	      wrtb (0xB8 + --r);
	      break;
	    case CPD:
	      wrtb (0xED);
	      wrtb (0xA9);
	      break;
	    case CPDR:
	      wrtb (0xED);
	      wrtb (0xB9);
	      break;
	    case CPI:
	      wrtb (0xED);
	      wrtb (0xA1);
	      break;
	    case CPIR:
	      wrtb (0xED);
	      wrtb (0xB1);
	      break;
	    case CPL:
	      wrtb (0x2F);
	      break;
	    case DAA:
	      wrtb (0x27);
	      break;
	    case DEC:
	      if (!(r = rd_r_rr (&ptr)))
		break;
	      if (r < 0)
		{
		  wrtb (0x05 - 8 * ++r);
		  break;
		}
	      wrtb (0x0B + 0x10 * --r);
	      break;
	    case DI:
	      wrtb (0xF3);
	      break;
	    case DJNZ:
	      wrtb (0x10);
	      rd_wrt_jr (&ptr, '\0');
	      break;
	    case EI:
	      wrtb (0xFB);
	      break;
	    case EQU:
	      if (!lastlabel)
		{
		  printerr (1, "EQU without label\n");
		  break;
		}
	      new_reference (ptr, TYPE_LABEL, 0, 0);
	      if (verbose >= 4)
		{
		  if (lastlabel->valid)
		    fprintf (stderr, "Assigned value %d to label %s.\n",
			     lastlabel->value, lastlabel->name);
		  else
		    fprintf (stderr,
			     "Scheduled label %s for later computation.\n",
			     lastlabel->name);
		}
	      ptr = "";
	      break;
	    case EX:
	      if (!(r = rd_ex1 (&ptr)))
		break;
	      switch (r)
		{
		case DE:
		  if (!rd_hl (&ptr))
		    break;
		  wrtb (0xEB);
		  break;
		case AF:
		  if (!rd_af_ (&ptr))
		    break;
		  wrtb (0x08);
		  break;
		default:
		  if (!rd_hlx (&ptr))
		    break;
		  wrtb (0xE3);
		}
	      break;
	    case EXX:
	      wrtb (0xD9);
	      break;
	    case HALT:
	      wrtb (0x76);
	      break;
	    case IM:
	      if (!(r = rd_0_2 (&ptr)))
		break;
	      wrtb (0xED);
	      wrtb (0x46 + 8 * --r);
	      break;
	    case IN:
	      if (!(r = rd_in (&ptr)))
		break;
	      if (r == A)
		{
		  const char *tmp;
		  if (!(r = rd_nnc (&ptr)))
		    break;
		  if (r == C)
		    {
		      wrtb (0xED);
		      wrtb (0x40 + 8 * (A - 1));
		      break;
		    }
		  tmp = readbyte;
		  wrtb (0xDB);
		  new_reference (tmp, TYPE_ABSB, ')', 1);
		  break;
		}
	      if (!rd_c (&ptr))
		break;
	      wrtb (0xED);
	      wrtb (0x40 + 8 * --r);
	      break;
	    case INC:
	      if (!(r = rd_r_rr (&ptr)))
		break;
	      if (r < 0)
		{
		  wrtb (0x04 - 8 * ++r);
		  break;
		}
	      wrtb (0x03 + 0x10 * --r);
	      break;
	    case IND:
	      wrtb (0xED);
	      wrtb (0xAA);
	      break;
	    case INDR:
	      wrtb (0xED);
	      wrtb (0xBA);
	      break;
	    case INI:
	      wrtb (0xED);
	      wrtb (0xA2);
	      break;
	    case INIR:
	      wrtb (0xED);
	      wrtb (0xB2);
	      break;
	    case JP:
	      r = rd_jp (&ptr);
	      if (r < 0)
		{
		  wrtb (0xE9);
		  break;
		}
	      if (r == 0)
		{
		  wrtb (0xC3);
		}
	      else
		{
		  wrtb (0xC2 + 8 * --r);
		  rd_comma (&ptr);
		}
	      rd_wrt_addr (&ptr, '\0');
	      break;
	    case JR:
	      r = rd_jr (&ptr);
	      if (r)
		rd_comma (&ptr);
	      wrtb (0x18 + 8 * r);
	      rd_wrt_jr (&ptr, '\0');
	      break;
	    case LD:
	      if (!(r = rd_ld (&ptr)))
		break;
	      switch (r)
		{
		case ld_BC:
		case ld_DE:
		  if (!rd_a (&ptr))
		    break;
		  wrtb (0x02 + 0x10 * (r == ld_DE));
		  break;
		case ld_HL:
		  r = rd_ld_hl (&ptr);
		  wrtb (0x70 + --r);
		  break;
		case ld_NN:
		  if (!(r = rd_ld_nn (&ptr)))
		    break;
		  if (r == ld_nnA || r == ld_nnHL)
		    {
		      wrtb (0x22 + 0x10 * (r == ld_nnA));
		      write_word ();
		      break;
		    }
		  wrtb (0xED);
		  wrtb (0x43 + 0x10 * --r);
		  write_word ();
		  break;
		case ldA:
		  if (!(r = rd_lda (&ptr)))
		    break;
		  if (r == A_NN)
		    {
		      wrtb (0x3A);
		      write_word ();
		      break;
		    }
		  if (r == A_I || r == A_R)
		    {
		      wrtb (0xED);
		      wrtb (0x57 + 8 * (r == A_R));
		      break;
		    }
		  if (r < 0)
		    {
		      wrtb (0x0A - 0x10 * ++r);
		      break;
		    }
		  wrtb (0x78 + --r);
		  break;
		case ldB:
		case ldC:
		case ldD:
		case ldE:
		case ldH:
		case ldL:
		  if (!(s = rd_ldbcdehla (&ptr)))
		    break;
		  wrtb (0x40 + 0x08 * (r - 7) + (s - 1));
		  break;
		case ldBC:
		case ldDE:
		  s = rd_nn_nn (&ptr);
		  if (s == _NN)
		    {
		      wrtb (0xED);
		      wrtb (0x4B + 0x10 * (r == ldDE));
		      write_word ();
		      break;
		    }
		  wrtb (0x01 + (r == ldDE) * 0x10);
		  write_word ();
		  break;
		case ldHL:
		  r = rd_nn_nn (&ptr);
		  wrtb (0x21 + (r == _NN) * 9);
		  write_word ();
		  break;
		case ldI:
		case ldR:
		  if (!rd_a (&ptr))
		    break;
		  wrtb (0xED);
		  wrtb (0x47 + 0x08 * (r == ldR));
		  break;
		case ldSP:
		  r = rd_sp (&ptr);
		  if (r == SPHL)
		    {
		      wrtb (0xF9);
		      break;
		    }
		  if (r == SPNN)
		    {
		      wrtb (0x31);
		      write_word ();
		      break;
		    }
		  wrtb (0xED);
		  wrtb (0x7B);
		  write_word ();
		  break;
		}
	      break;
	    case LDD:
	      wrtb (0xED);
	      wrtb (0xA8);
	      break;
	    case LDDR:
	      wrtb (0xED);
	      wrtb (0xB8);
	      break;
	    case LDI:
	      wrtb (0xED);
	      wrtb (0xA0);
	      break;
	    case LDIR:
	      wrtb (0xED);
	      wrtb (0xB0);
	      break;
	    case NEG:
	      wrtb (0xED);
	      wrtb (0x44);
	      break;
	    case NOP:
	      wrtb (0x00);
	      break;
	    case OR:
	      if (!(r = rd_r (&ptr)))
		break;
	      wrtb (0xB0 + --r);
	      break;
	    case OTDR:
	      wrtb (0xED);
	      wrtb (0xBB);
	      break;
	    case OTIR:
	      wrtb (0xED);
	      wrtb (0xB3);
	      break;
	    case OUT:
	      if (!(r = rd_nnc (&ptr)))
		break;
	      if (r == C)
		{
		  if (!(r = rd_out (&ptr)))
		    break;
		  wrtb (0xED);
		  wrtb (0x41 + 8 * --r);
		  break;
		}
	      if (!rd_a (&ptr))
		break;
	      {
		const char *tmp = readbyte;
		wrtb (0xD3);
		new_reference (tmp, TYPE_ABSB, ')', 1);
	      }
	      break;
	    case OUTD:
	      wrtb (0xED);
	      wrtb (0xAB);
	      break;
	    case OUTI:
	      wrtb (0xED);
	      wrtb (0xA3);
	      break;
	    case POP:
	      if (!(r = rd_stack (&ptr)))
		break;
	      wrtb (0xC1 + 0x10 * --r);
	      break;
	    case PUSH:
	      if (!(r = rd_stack (&ptr)))
		break;
	      wrtb (0xC5 + 0x10 * --r);
	      break;
	    case RES:
	      if (!rd_0_7 (&ptr))
		break;
	      rd_comma (&ptr);
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x80 + --r);
	      break;
	    case RET:
	      if (!(r = rd_cc (&ptr)))
		{
		  wrtb (0xC9);
		  break;
		}
	      wrtb (0xC0 + 8 * --r);
	      break;
	    case RETI:
	      wrtb (0xED);
	      wrtb (0x4D);
	      break;
	    case RETN:
	      wrtb (0xED);
	      wrtb (0x45);
	      break;
	    case RL:
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x10 + --r);
	      break;
	    case RLA:
	      wrtb (0x17);
	      break;
	    case RLC:
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x00 + --r);
	      break;
	    case RLCA:
	      wrtb (0x07);
	      break;
	    case RLD:
	      wrtb (0xED);
	      wrtb (0x6F);
	      break;
	    case RR:
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x18 + --r);
	      break;
	    case RRA:
	      wrtb (0x1F);
	      break;
	    case RRC:
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x08 + --r);
	      break;
	    case RRCA:
	      wrtb (0x0F);
	      break;
	    case RRD:
	      wrtb (0xED);
	      wrtb (0x67);
	      break;
	    case RST:
	      new_reference (ptr, TYPE_RST, '\0', 1);
	      ptr = "";
	      break;
	    case SBC:
	      if (!(r = rd_a_hl (&ptr)))
		break;
	      if (r == HL)
		{
		  if (!(r = rd_rr_ (&ptr)))
		    break;
		  wrtb (0xED);
		  wrtb (0x42 + 0x10 * --r);
		  break;
		}
	      if (!(r = rd_r (&ptr)))
		break;
	      wrtb (0x98 + --r);
	      break;
	    case SCF:
	      wrtb (0x37);
	      break;
	    case SET:
	      if (!rd_0_7 (&ptr))
		break;
	      rd_comma (&ptr);
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0xC0 + --r);
	      break;
	    case SLA:
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x20 + --r);
	      break;
	    case SLI:
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x30 + --r);
	      break;
	    case SRA:
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x28 + --r);
	      break;
	    case SRL:
	      if (!(r = rd_r_ (&ptr)))
		break;
	      wrtb (0xCB);
	      wrtb (0x38 + --r);
	      break;
	    case SUB:
	      if (!(r = rd_r (&ptr)))
		break;
	      if (has_argument (&ptr))	/* SUB A,r ?  */
		{
		  if (r != A)
		    {
		      printerr (1, "parse error before: %s\n", ptr);
		      break;
		    }
		  if (!(r = rd_r (&ptr)))
		    break;
		}
	      wrtb (0x90 + --r);
	      break;
	    case XOR:
	      if (!(r = rd_r (&ptr)))
		break;
	      wrtb (0xA8 + --r);
	      break;
	    case DEFB:
	    case DB:
	    case DEFM:
	    case DM:
	      ptr = delspc (ptr);
	      while (1)
		{
		  have_quote = (*ptr == '"' || *ptr == '\'');
		  if (have_quote)
		    {
		      /* Read string.  */
		      int quote = *ptr;
		      if (listfile)
			{
			  fprintf (listfile, " ..");
			  listdepth += 3;
			}
		      ++ptr;
		      while (*ptr != quote)
			{
			  write_one_byte (rd_character (&ptr, NULL, 1), 0);
			  if (*ptr == 0)
			    {
			      printerr (1, "end of line in quoted string\n");
			      break;
			    }
			}
		      ++ptr;
		    }
		  else
		    {
		      /* Read expression.  */
		      new_reference (ptr, TYPE_ABSB, ',', 1);
		      skipword (&ptr, ',');
		    }
		  ptr = delspc (ptr);
		  if (*ptr == ',')
		    {
		      ++ptr;
		      continue;
		    }
		  if (*ptr != 0)
		    printerr (1, "junk in byte definition: %s\n", ptr);
		  break;
		}
	      break;
	    case DEFW:
	    case DW:
	      if (!(r = rd_word (&ptr, ',')))
		{
		  printerr (1, "No data for word definition\n");
		  break;
		}
	      while (1)
		{
		  new_reference (readword, TYPE_ABSW, ',', 1);
		  ptr = delspc (ptr);
		  if (*ptr != ',')
		    break;
		  ++ptr;
		  if (!(r = rd_word (&ptr, ',')))
		    printerr (1, "Missing expression in defw\n");
		}
	      break;
	    case DEFS:
	    case DS:
	      r = rd_expr (&ptr, ',', NULL, sp, 1);
	      if (r < 0)
		{
		  printerr (1, "ds should have its first argument >=0"
			    " (not -0x%x)\n", -r);
		  break;
		}
	      ptr = delspc (ptr);
	      if (*ptr)
		{
		  rd_comma (&ptr);
		  readbyte = 0;
		  rd_byte (&ptr, '\0');
		  writebyte = 0;
		  new_reference (readbyte, TYPE_DS, '\0', r);
		  break;
		}
	      if (havelist)
		{
		  fprintf (listfile, " 00...");
		  listdepth += 6;
		}
	      for (i = 0; i < r; i++)
		{
		  write_one_byte (0, 0);
		}
	      break;
	    case END:
	      file_ended = 1;
	      break;
	    case ORG:
	      addr = rd_expr (&ptr, '\0', NULL, sp, 1) & 0xffff;
	      break;
	    case INCLUDE:
	      if (sp + 1 >= MAX_INCLUDE)
		{
		  printerr (1, "stack overflow (circular include?)");
		  if (verbose >= 5)
		    {
		      int x;
		      fprintf (stderr, "Stack dump:\nframe  line file\n");
		      for (x = 0; x < MAX_INCLUDE; ++x)
			fprintf (stderr, "%5d %5d %s\n", x, stack[x].line,
				 stack[x].name);
		    }
		  break;
		}
	      {
		struct name *name;
		char *nm = get_include_name (&ptr);
		if (!nm)
		  break;
		name = malloc (sizeof (struct name) + strlen (nm));
		if (!name)
		  {
		    printerr (1, "out of memory while allocating name\n");
		    free (nm);
		    break;
		  }
		strcpy (name->name, nm);
		free (nm);
		++sp;
		stack[sp].name = name->name;
		stack[sp].shouldclose = 1;
		stack[sp].line = 0;
		stack[sp].file = open_include_file (name->name,
						    &stack[sp].dir, "r");
		if (!stack[sp].file)
		  {
		    printerr (1, "unable to open file %s\n", name->name);
		    free (name);
		    --sp;
		    break;
		  }
		name->next = firstname;
		name->prev = NULL;
		if (name->next)
		  name->next->prev = name;
		firstname = name;
		if (verbose >= 4)
		  fprintf (stderr, "Reading file %s\n", name->name);
	      }
	      break;
	    case INCBIN:
	      {
		FILE *incfile;
		char *name = get_include_name (&ptr);
		if (!name)
		  break;
		incfile = open_include_file (name, NULL, "rb");
		if (!incfile)
		  {
		    printerr (1, "unable to open binary file %s\n", name);
		    free (name);
		    break;
		  }
		while (1)
		  {
		    char filebuffer[4096];
		    size_t num = fread (filebuffer, 1, 4096, incfile);
		    if (num == 0)
		      break;
		    if (num != fwrite (filebuffer, 1, num, outfile))
		      {
			printerr (1, "error including binary file %s: %s\n",
				  name, strerror (errno));
			break;
		      }
		    addr += num;
		    addr &= 0xffff;
		  }
		fclose (incfile);
		free (name);
		break;
	      }
	    case IF:
	      if (rd_expr (&ptr, '\0', NULL, sp, 1))
		ifcount++;
	      else
		noifcount++;
	      break;
	    case ELSE:
	      if (ifcount == 0)
		{
		  printerr (1, "else without if\n");
		  break;
		}
	      noifcount = 1;
	      ifcount--;
	      break;
	    case ENDIF:
	      if (noifcount == 0 && ifcount == 0)
		{
		  printerr (1, "endif without if\n");
		  break;
		}
	      if (noifcount)
		noifcount--;
	      else
		ifcount--;
	      break;
	    case MACRO:
	      if (!lastlabel)
		{
		  printerr (1, "macro without label\n");
		  break;
		}
	      if (define_macro)
		{
		  printerr (1, "nested macro definition\n");
		  break;
		}
	      {
		struct macro *m;
		for (m = firstmacro; m; m = m->next)
		  {
		    if (strcmp (m->name, lastlabel->name) == 0)
		      {
			printerr (1, "duplicate macro definition\n");
			break;
		      }
		  }
		m = malloc (sizeof (struct macro));
		if (!m)
		  {
		    printerr (1, "out of memory\n");
		    break;
		  }
		m->name = malloc (strlen (lastlabel->name) + 1);
		if (!m->name)
		  {
		    printerr (1, "out of memory\n");
		    free (m);
		    break;
		  }
		strcpy (m->name, lastlabel->name);
		if (lastlabel->prev)
		  lastlabel->prev->next = lastlabel->next;
		else
		  firstlabel = lastlabel->next;
		if (lastlabel->next)
		  lastlabel->next->prev = lastlabel->prev;
		free (lastlabel);
		m->next = firstmacro;
		firstmacro = m;
		m->lines = NULL;
		m->numargs = get_macro_args (&ptr, &m->args, 0);
		define_macro = 1;
	      }
	      break;
	    case ENDM:
	      if (stack[sp].file)
		printerr (1, "endm outside macro definition\n");
	      break;
	    case SEEK:
	      {
		unsigned int seekaddr = rd_expr (&ptr, '\0', NULL, sp, 1);
		if (verbose >= 2)
		  {
		    fprintf (stderr, "%s%s:%d: ",
			     stack[sp].dir ? stack[sp].dir->name : "",
			     stack[sp].name, stack[sp].line);
		    fprintf (stderr, "[Message] seeking to 0x%0X \n",
			     seekaddr);
		  }
		fseek (outfile, seekaddr, SEEK_SET);
		break;
	      }
	    default:
	      {
		struct macro *m;
		for (m = firstmacro; m; m = m->next)
		  {
		    if (strncmp (m->name, ptr, strlen (m->name)) == 0)
		      {
			unsigned numargs;
			if (sp + 1 >= MAX_INCLUDE)
			  {
			    printerr (1, "stack overflow (circular include?)\n");
			    if (verbose >= 5)
			      {
				int x;
				fprintf (stderr,
					 "Stack dump:\nframe  line file\n");
				for (x = 0; x < MAX_INCLUDE; ++x)
				  fprintf (stderr, "%5d %5d %s\n", x,
					   stack[x].line, stack[x].name);
			      }
			    break;
			  }
			++sp;
			ptr += strlen (m->name);
			numargs = get_macro_args (&ptr, &stack[sp].macro_args,
						  1);
			if (numargs != m->numargs)
			  {
			    unsigned a;
			    printerr (1, "invalid number of arguments for macro "
				      "(is %d, must be %d)\n", numargs,
				      m->numargs);
			    for (a = 0; a < numargs; ++a)
			      free (stack[sp].macro_args[a]);
			    free (stack[sp].macro_args);
			    break;
			  }
			stack[sp].name = m->name;
			stack[sp].file = NULL;
			stack[sp].line = 0;
			stack[sp].macro = m;
			stack[sp].macro_line = m->lines;
			stack[sp].shouldclose = 0;
			stack[sp].dir = NULL;
			break;
		      }
		  }
		if (m)
		  break;
	      }
	      printerr (1, "command or comment expected (was %s)\n", ptr);
	    }
	}
    }
  if (ifcount || noifcount)
    {
      printerr (1, "reached EOF at IF level %d\n", ifcount + noifcount);
    }
  if (havelist)
    {
      fprintf (listfile, "%04x\n", addr);
    }
  {
    struct reference *next;
    struct reference *tmp;
    /* Add a stack frame for error reporting.  */
    ++sp;
    for (tmp = firstreference; tmp; tmp = next)
      {
	int ref;
	next = tmp->next;
	fseek (outfile, tmp->oseekpos, SEEK_SET);
	if (havelist)
	  fseek (listfile, tmp->lseekpos, SEEK_SET);
	stack[sp].name = tmp->file;
	stack[sp].dir = tmp->dir;
	stack[sp].line = tmp->line;
	ref = compute_ref (tmp, 0);
	wrt_ref (ref, tmp->type, tmp->count);
	if (tmp->dir)
	  free (tmp->dir);
	free (tmp->file);
	free (tmp);
      }
  }
  if (!errors || use_force)
    {
      flush_to_real_file (realoutputfile, outfile);
      if (havelist)
	flush_to_real_file (reallistfile, listfile);
    }
  /* write all labels */
  if (label)
    fseek (labelfile, 0, SEEK_END);
  for (l = firstlabel; l; l = l->next)
    {
      if (l->ref)
	{
	  compute_ref (l->ref, 0);
	}
      if (label)
	{
	  fprintf (labelfile, "%s%s:\tequ $%04x\n", labelprefix, l->name,
		   l->value);
	}
    }
  if (label)
    fclose (labelfile);
  while (firstlabel)
    {
      l = firstlabel->next;
      free (firstlabel);
      firstlabel = l;
    }
  fclose (outfile);
  if (outfile != realoutputfile)
    fclose (realoutputfile);
  if (havelist)
    {
      fclose (listfile);
      if (listfile != reallistfile && reallistfile != stderr)
	fclose (reallistfile);
    }
  free (infile);
}

#if 0
int
main (int argc, char **argv)
{
  /* default include file location */
  add_include ("/usr/share/z80asm/headers/");
  parse_commandline (argc, argv);
  if (verbose >= 1)
    fprintf (stderr, "Assembling....\n");
  assemble ();
  if (errors)
    {
      if (errors == 1)
	fprintf (stderr, "*** 1 error found ***\n");
      else
	fprintf (stderr, "*** %d errors found ***\n", errors);
      if (realoutputfile == outfile && !use_force)
	{
	  unlink (realoutputfilename);
	  unlink (labelfilename);
	}
      return 1;
    }
  else
    {
      if (verbose >= 1)
	fprintf (stderr, "Assembly succesful.\n");
      return 0;
    }
}
#endif
