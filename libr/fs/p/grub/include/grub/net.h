/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2007  Free Software Foundation, Inc.
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

#ifndef GRUB_NET_HEADER
#define GRUB_NET_HEADER	1

#include <grub/symbol.h>
#include <grub/err.h>
#include <grub/types.h>

struct grub_net;

struct grub_net_dev
{
  /* The device name.  */
  const char *name;

  /* FIXME: Just a template.  */
  int (*probe) (struct grub_net *net, const void *addr);
  void (*reset) (struct grub_net *net);
  int (*poll) (struct grub_net *net);
  void (*transmit) (struct grub_net *net, const void *destip,
		    unsigned srcsock, unsigned destsock, const void *packet);
  void (*disable) (struct grub_net *net);

  /* The next net device.  */
  struct grub_net_dev *next;
};
typedef struct grub_net_dev *grub_net_dev_t;

struct grub_fs;

struct grub_net
{
  /* The net name.  */
  const char *name;

  /* The underlying disk device.  */
  grub_net_dev_t dev;

  /* The binding filesystem.  */
  struct grub_fs *fs;

  /* FIXME: More data would be required, such as an IP address, a mask,
     a gateway, etc.  */

  /* Device-specific data.  */
  void *data;
};
typedef struct grub_net *grub_net_t;

/* FIXME: How to abstract networks? More consideration is necessary.  */

/* Note: Networks are very different from disks, because networks must
   be initialized before used, and the status is persistent.  */

#endif /* ! GRUB_NET_HEADER */
