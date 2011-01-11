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

#ifndef GRUB_EXTCMD_HEADER
#define GRUB_EXTCMD_HEADER	1

#include <grub/lib/arg.h>
#include <grub/command.h>
#include <grub/script_sh.h>

struct grub_extcmd;
struct grub_extcmd_context;

typedef grub_err_t (*grub_extcmd_func_t) (struct grub_extcmd_context *ctxt,
					  int argc, char **args);

/* The argcmd description.  */
struct grub_extcmd
{
  grub_command_t cmd;

  grub_extcmd_func_t func;

  /* The argument parser optionlist.  */
  const struct grub_arg_option *options;

  void *data;
};
typedef struct grub_extcmd *grub_extcmd_t;

/* Command context for each instance of execution.  */
struct grub_extcmd_context
{
  struct grub_extcmd *extcmd;

  struct grub_arg_list *state;

  /* Script parameter, if any.  */
  struct grub_script *script;
};
typedef struct grub_extcmd_context *grub_extcmd_context_t;

grub_extcmd_t EXPORT_FUNC(grub_register_extcmd) (const char *name,
						 grub_extcmd_func_t func,
						 grub_command_flags_t flags,
						 const char *summary,
						 const char *description,
						 const struct grub_arg_option *parser);

grub_extcmd_t EXPORT_FUNC(grub_register_extcmd_prio) (const char *name,
						      grub_extcmd_func_t func,
						      grub_command_flags_t flags,
						      const char *summary,
						      const char *description,
						      const struct grub_arg_option *parser,
						      int prio);

void EXPORT_FUNC(grub_unregister_extcmd) (grub_extcmd_t cmd);

grub_err_t EXPORT_FUNC(grub_extcmd_dispatcher) (struct grub_command *cmd,
						int argc, char **args,
						struct grub_script *script);

#endif /* ! GRUB_EXTCMD_HEADER */
