/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2005,2006,2007,2009  Free Software Foundation, Inc.
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

#ifndef GRUB_ENV_PRIVATE_HEADER
#define GRUB_ENV_PRIVATE_HEADER	1

#include <grub/env.h>

/* The size of the hash table.  */
#define	HASHSZ	13

/* A hashtable for quick lookup of variables.  */
struct grub_env_context
{
  /* A hash table for variables.  */
  struct grub_env_var *vars[HASHSZ];

  /* One level deeper on the stack.  */
  struct grub_env_context *prev;
};

/* This is used for sorting only.  */
struct grub_env_sorted_var
{
  struct grub_env_var *var;
  struct grub_env_sorted_var *next;
};

extern struct grub_env_context *EXPORT_VAR(grub_current_context);

#endif /* ! GRUB_ENV_PRIVATE_HEADER */
