/* fs.h - filesystem manager */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2003,2004,2007,2008,2009  Free Software Foundation, Inc.
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

#ifndef GRUB_FS_HEADER
#define GRUB_FS_HEADER	1

#include <grub/device.h>
#include <grub/symbol.h>
#include <grub/types.h>

#include <grub/list.h>

/* Forward declaration is required, because of mutual reference.  */
struct grub_file;

struct grub_dirhook_info
{
  int dir:1;
  int mtimeset:1;
  int case_insensitive:1;
  grub_int32_t mtime;
};

/* Filesystem descriptor.  */
struct grub_fs
{
  /* The next filesystem.  */
  struct grub_fs *next;

  /* My name.  */
  const char *name;

  /* Call HOOK with each file under DIR.  */
  grub_err_t (*dir) (grub_device_t device, const char *path,
		     int (*hook) (const char *filename,
				  const struct grub_dirhook_info *info));

  /* Open a file named NAME and initialize FILE.  */
  grub_err_t (*open) (struct grub_file *file, const char *name);

  /* Read LEN bytes data from FILE into BUF.  */
  grub_ssize_t (*read) (struct grub_file *file, char *buf, grub_size_t len);

  /* Close the file FILE.  */
  grub_err_t (*close) (struct grub_file *file);

  /* Return the label of the device DEVICE in LABEL.  The label is
     returned in a grub_malloc'ed buffer and should be freed by the
     caller.  */
  grub_err_t (*label) (grub_device_t device, char **label);

  /* Return the uuid of the device DEVICE in UUID.  The uuid is
     returned in a grub_malloc'ed buffer and should be freed by the
     caller.  */
  grub_err_t (*uuid) (grub_device_t device, char **uuid);

  /* Get writing time of filesystem. */
  grub_err_t (*mtime) (grub_device_t device, grub_int32_t *timebuf);

#ifdef GRUB_UTIL
  /* Whether this filesystem reserves first sector for DOS-style boot.  */
  int reserved_first_sector;
#endif
};
typedef struct grub_fs *grub_fs_t;

/* This is special, because block lists are not files in usual sense.  */
extern struct grub_fs grub_fs_blocklist;

/* This hook is used to automatically load filesystem modules.
   If this hook loads a module, return non-zero. Otherwise return zero.
   The newly loaded filesystem is assumed to be inserted into the head of
   the linked list GRUB_FS_LIST through the function grub_fs_register.  */
typedef int (*grub_fs_autoload_hook_t) (void);
extern grub_fs_autoload_hook_t EXPORT_VAR(grub_fs_autoload_hook);
extern grub_fs_t EXPORT_VAR (grub_fs_list);

#ifndef GRUB_LST_GENERATOR
static inline void
grub_fs_register (grub_fs_t fs)
{
  grub_list_push (GRUB_AS_LIST_P (&grub_fs_list), GRUB_AS_LIST (fs));
}
#endif

static inline void
grub_fs_unregister (grub_fs_t fs)
{
  grub_list_remove (GRUB_AS_LIST_P (&grub_fs_list), GRUB_AS_LIST (fs));
}

#define FOR_FILESYSTEMS(var) FOR_LIST_ELEMENTS((var), (grub_fs_list))

grub_fs_t EXPORT_FUNC(grub_fs_probe) (grub_device_t device);

#endif /* ! GRUB_FS_HEADER */
