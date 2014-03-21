/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010  Free Software Foundation, Inc.
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

#ifndef GRUB_EMU_MISC_H
#define GRUB_EMU_MISC_H 1

#include <config.h>
#include <stdarg.h>

#include <grub/symbol.h>
#include <grub/types.h>

#ifdef __CYGWIN__
# include <sys/fcntl.h>
# include <sys/cygwin.h>
# include <limits.h>
# define DEV_CYGDRIVE_MAJOR 98
#endif

#ifdef __NetBSD__
/* NetBSD uses /boot for its boot block.  */
# define DEFAULT_DIRECTORY	"/"GRUB_DIR_NAME
#else
# define DEFAULT_DIRECTORY	"/"GRUB_BOOT_DIR_NAME"/"GRUB_DIR_NAME
#endif

#define DEFAULT_DEVICE_MAP	DEFAULT_DIRECTORY "/device.map"

extern int verbosity;
extern const char *program_name;

void grub_emu_init (void);
void grub_init_all (void);
void grub_fini_all (void);
void grub_emu_post_init (void);

void grub_find_zpool_from_dir (const char *dir,
			       char **poolname, char **poolfs);

char *grub_make_system_path_relative_to_its_root (const char *path)
  __attribute__ ((warn_unused_result));

void * EXPORT_FUNC(xmalloc) (grub_size_t size) __attribute__ ((warn_unused_result));
void * EXPORT_FUNC(xrealloc) (void *ptr, grub_size_t size) __attribute__ ((warn_unused_result));
char * EXPORT_FUNC(xstrdup) (const char *str) __attribute__ ((warn_unused_result));
char * EXPORT_FUNC(xasprintf) (const char *fmt, ...) __attribute__ ((warn_unused_result));

void EXPORT_FUNC(grub_util_warn) (const char *fmt, ...);
void EXPORT_FUNC(grub_util_info) (const char *fmt, ...);
void EXPORT_FUNC(grub_util_error) (const char *fmt, ...) __attribute__ ((noreturn));

#ifndef HAVE_VASPRINTF
int EXPORT_FUNC(vasprintf) (char **buf, const char *fmt, va_list ap);
#endif

#ifndef  HAVE_ASPRINTF
int EXPORT_FUNC(asprintf) (char **buf, const char *fmt, ...);
#endif

extern char * canonicalize_file_name (const char *path);

#ifdef HAVE_DEVICE_MAPPER
int grub_device_mapper_supported (void);
#endif

#endif /* GRUB_EMU_MISC_H */
