/* parser.h - prototypes for the command line parser.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2005,2007,2009  Free Software Foundation, Inc.
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

#ifndef GRUB_PARSER_HEADER
#define GRUB_PARSER_HEADER	1

#include <grub/types.h>
#include <grub/err.h>
#include <grub/reader.h>

/* All the states for the command line.  */
typedef enum
  {
    GRUB_PARSER_STATE_TEXT = 1,
    GRUB_PARSER_STATE_ESC,
    GRUB_PARSER_STATE_QUOTE,
    GRUB_PARSER_STATE_DQUOTE,
    GRUB_PARSER_STATE_VAR,
    GRUB_PARSER_STATE_VARNAME,
    GRUB_PARSER_STATE_VARNAME2,
    GRUB_PARSER_STATE_QVAR,
    GRUB_PARSER_STATE_QVARNAME,
    GRUB_PARSER_STATE_QVARNAME2
  } grub_parser_state_t;

/* A single state transition.  */
struct grub_parser_state_transition
{
  /* The state that is looked up.  */
  grub_parser_state_t from_state;

  /* The next state, determined by FROM_STATE and INPUT.  */
  grub_parser_state_t to_state;

  /* The input that will determine the next state from FROM_STATE.  */
  char input;

  /* If set to 1, the input is valid and should be used.  */
  int keep_value;
};

/* Determines the state following STATE, determined by C.  */
grub_parser_state_t
EXPORT_FUNC (grub_parser_cmdline_state) (grub_parser_state_t state,
					 char c, char *result);

grub_err_t
EXPORT_FUNC (grub_parser_split_cmdline) (const char *cmdline,
					 grub_reader_getline_t getline,
					 int *argc, char ***argv);

struct grub_parser
{
  /* The next parser.  */
  struct grub_parser *next;

  /* The parser name.  */
  const char *name;

  /* Initialize the parser.  */
  grub_err_t (*init) (void);

  /* Clean up the parser.  */
  grub_err_t (*fini) (void);

  grub_err_t (*parse_line) (char *line, grub_reader_getline_t getline);
};
typedef struct grub_parser *grub_parser_t;

grub_err_t grub_parser_execute (char *source);

grub_err_t
grub_rescue_parse_line (char *line, grub_reader_getline_t getline);

#endif /* ! GRUB_PARSER_HEADER */
