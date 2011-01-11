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

#ifndef GRUB_COMMAND_HEADER
#define GRUB_COMMAND_HEADER	1

#include <grub/symbol.h>
#include <grub/err.h>
#include <grub/list.h>

typedef enum grub_command_flags
  {
    /* This is an extended command.  */
    GRUB_COMMAND_FLAG_EXTCMD = 0x10,
    /* This is an dynamic command.  */
    GRUB_COMMAND_FLAG_DYNCMD = 0x20,
    /* This command accepts block arguments.  */
    GRUB_COMMAND_FLAG_BLOCKS = 0x40,
    /* This command accepts unknown arguments as direct parameters.  */
    GRUB_COMMAND_ACCEPT_DASH = 0x80,
    /* This command accepts only options preceding direct arguments.  */
    GRUB_COMMAND_OPTIONS_AT_START = 0x100,
    /* Can be executed in an entries extractor.  */
    GRUB_COMMAND_FLAG_EXTRACTOR = 0x200
  } grub_command_flags_t;

struct grub_command;

typedef grub_err_t (*grub_command_func_t) (struct grub_command *cmd,
					   int argc, char **argv);

/* The command description.  */
struct grub_command
{
  /* The next element.  */
  struct grub_command *next;

  /* The name.  */
  const char *name;

    /* The priority.  */
  int prio;

  /* The callback function.  */
  grub_command_func_t func;

  /* The flags.  */
  grub_command_flags_t flags;

  /* The summary of the command usage.  */
  const char *summary;

  /* The description of the command.  */
  const char *description;

  /* Arbitrary data.  */
  void *data;
};
typedef struct grub_command *grub_command_t;

extern grub_command_t EXPORT_VAR(grub_command_list);

grub_command_t
EXPORT_FUNC(grub_register_command_prio) (const char *name,
					 grub_command_func_t func,
					 const char *summary,
					 const char *description,
					 int prio);
void EXPORT_FUNC(grub_unregister_command) (grub_command_t cmd);

static inline grub_command_t
grub_register_command (const char *name,
		       grub_command_func_t func,
		       const char *summary,
		       const char *description)
{
  return grub_register_command_prio (name, func, summary, description, 0);
}

static inline grub_command_t
grub_register_command_p1 (const char *name,
			  grub_command_func_t func,
			  const char *summary,
			  const char *description)
{
  return grub_register_command_prio (name, func, summary, description, 1);
}

static inline grub_command_t
grub_command_find (const char *name)
{
  return grub_named_list_find (GRUB_AS_NAMED_LIST (grub_command_list), name);
}

static inline grub_err_t
grub_command_execute (const char *name, int argc, char **argv)
{
  grub_command_t cmd;

  cmd = grub_command_find (name);
  return (cmd) ? cmd->func (cmd, argc, argv) : GRUB_ERR_FILE_NOT_FOUND;
}

#define FOR_COMMANDS(var) FOR_LIST_ELEMENTS((var), grub_command_list)

void grub_register_core_commands (void);

#endif /* ! GRUB_COMMAND_HEADER */
