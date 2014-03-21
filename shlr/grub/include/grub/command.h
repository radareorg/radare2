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

/* Can be run in the command-line.  */
#define GRUB_COMMAND_FLAG_CMDLINE	0x1
/* Can be run in the menu.  */
#define GRUB_COMMAND_FLAG_MENU		0x2
/* Can be run in both interfaces.  */
#define GRUB_COMMAND_FLAG_BOTH		0x3
/* Only for the command title.  */
#define GRUB_COMMAND_FLAG_TITLE		0x4
/* Don't print the command on booting.  */
#define GRUB_COMMAND_FLAG_NO_ECHO	0x8
/* This is an extended command.  */
#define GRUB_COMMAND_FLAG_EXTCMD	0x10
/* This is an dynamic command.  */
#define GRUB_COMMAND_FLAG_DYNCMD	0x20

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
  unsigned flags;

  /* The summary of the command usage.  */
  const char *summary;

  /* The description of the command.  */
  const char *description;

  /* Arbitrary data.  */
  void *data;
};
typedef struct grub_command *grub_command_t;

extern grub_command_t grub_command_list;

grub_command_t grub_reg_cmd (const char *name,
			     grub_command_func_t func,
			     const char *summary,
			     const char *description,
			     int prio);
void grub_unregister_command (grub_command_t cmd);

#define grub_register_command(name, func, summary, description) \
  grub_reg_cmd (name, func, summary, description, 0); \
  GRUB_MODATTR ("command", name);

#define grub_register_command_p1(name, func, summary, description) \
  grub_reg_cmd (name, func, summary, description, 1); \
  GRUB_MODATTR ("command", "*" name);

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

static inline int
grub_command_iterate (int (*func) (grub_command_t, void *closure),
		      void *closure)
{
  return grub_list_iterate (GRUB_AS_LIST (grub_command_list),
			    (grub_list_hook_t) func, closure);
}

void grub_register_core_commands (void);

#endif /* ! GRUB_COMMAND_HEADER */
