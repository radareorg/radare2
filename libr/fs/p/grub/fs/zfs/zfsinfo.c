/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004,2009  Free Software Foundation, Inc.
 *  Copyright 2008  Sun Microsystems, Inc.
 *
 *  GRUB is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
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

#include <grub/zfs/zfs.h>
#include <grub/device.h>
#include <grub/file.h>
#include <grub/command.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/env.h>

static inline void
print_tabs (int n)
{
  int i;

  for (i = 0; i < n; i++)
    grub_printf (" ");
}

static grub_err_t
print_state (char *nvlist, int tab)
{
  grub_uint64_t ival;
  int isok = 1;

  print_tabs (tab);
  grub_printf ("State: ");

  if (grub_zfs_nvlist_lookup_uint64 (nvlist, ZPOOL_CONFIG_REMOVED, &ival))
    {
      grub_printf ("removed ");
      isok = 0;
    }

  if (grub_zfs_nvlist_lookup_uint64 (nvlist, ZPOOL_CONFIG_FAULTED, &ival))
    {
      grub_printf ("faulted ");
      isok = 0;
    }

  if (grub_zfs_nvlist_lookup_uint64 (nvlist, ZPOOL_CONFIG_OFFLINE, &ival))
    {
      grub_printf ("offline ");
      isok = 0;
    }

  if (grub_zfs_nvlist_lookup_uint64 (nvlist, ZPOOL_CONFIG_FAULTED, &ival))
    grub_printf ("degraded ");

  if (isok)
    grub_printf ("online");
  grub_printf ("\n");

  return GRUB_ERR_NONE;
}

static grub_err_t
print_vdev_info (char *nvlist, int tab)
{
  char *type = 0;

  type = grub_zfs_nvlist_lookup_string (nvlist, ZPOOL_CONFIG_TYPE);

  if (!type)
    {
      print_tabs (tab);
      grub_printf ("Incorrect VDEV: no type available\n");
      return grub_errno;
    }

  if (grub_strcmp (type, VDEV_TYPE_DISK) == 0)
    {
      char *bootpath = 0;
      char *path = 0;
      char *devid = 0;

      print_tabs (tab);
      grub_printf ("Leaf VDEV\n");

      print_state (nvlist, tab);

      bootpath =
	grub_zfs_nvlist_lookup_string (nvlist, ZPOOL_CONFIG_PHYS_PATH);
      print_tabs (tab);
      if (!bootpath)
	grub_printf ("Bootpath: unavailable\n");
      else
	grub_printf ("Bootpath: %s\n", bootpath);

      path = grub_zfs_nvlist_lookup_string (nvlist, "path");
      print_tabs (tab);
      if (!path)
	grub_printf ("Path: unavailable\n");
      else
	grub_printf ("Path: %s\n", path);

      devid = grub_zfs_nvlist_lookup_string (nvlist, ZPOOL_CONFIG_DEVID);
      print_tabs (tab);
      if (!devid)
	grub_printf ("Devid: unavailable\n");
      else
	grub_printf ("Devid: %s\n", devid);
      grub_free (bootpath);
      grub_free (devid);
      grub_free (path);
      return GRUB_ERR_NONE;
    }

  if (grub_strcmp (type, VDEV_TYPE_MIRROR) == 0)
    {
      int nelm, i;

      nelm = grub_zfs_nvlist_lookup_nvlist_array_get_nelm
	(nvlist, ZPOOL_CONFIG_CHILDREN);

      print_tabs (tab);
      if (nelm <= 0)
	{
	  grub_printf ("Incorrect mirror VDEV\n");
	  return GRUB_ERR_NONE;
	}
      grub_printf ("Mirror VDEV with %d children\n", nelm);
      print_state (nvlist, tab);

      for (i = 0; i < nelm; i++)
	{
	  char *child;

	  child = grub_zfs_nvlist_lookup_nvlist_array
	    (nvlist, ZPOOL_CONFIG_CHILDREN, i);

	  print_tabs (tab);
	  if (!child)
	    {
	      grub_printf ("Mirror VDEV element %d isn't correct\n", i);
	      continue;
	    }

	  grub_printf ("Mirror VDEV element %d:\n", i);
	  print_vdev_info (child, tab + 1);

	  grub_free (child);
	}
    }

  print_tabs (tab);
  grub_printf ("Unknown VDEV type: %s\n", type);

  return GRUB_ERR_NONE;
}

static grub_err_t
get_bootpath (char *nvlist, char **bootpath, char **devid)
{
  char *type = 0;

  type = grub_zfs_nvlist_lookup_string (nvlist, ZPOOL_CONFIG_TYPE);

  if (!type)
    return grub_errno;

  if (grub_strcmp (type, VDEV_TYPE_DISK) == 0)
    {
      *bootpath = grub_zfs_nvlist_lookup_string (nvlist,
						 ZPOOL_CONFIG_PHYS_PATH);
      *devid = grub_zfs_nvlist_lookup_string (nvlist, ZPOOL_CONFIG_DEVID);
      if (!*bootpath || !*devid)
	{
	  grub_free (*bootpath);
	  grub_free (*devid);
	  *bootpath = 0;
	  *devid = 0;
	}
      return GRUB_ERR_NONE;
    }

  if (grub_strcmp (type, VDEV_TYPE_MIRROR) == 0)
    {
      int nelm, i;

      nelm = grub_zfs_nvlist_lookup_nvlist_array_get_nelm
	(nvlist, ZPOOL_CONFIG_CHILDREN);

      for (i = 0; i < nelm; i++)
	{
	  char *child;

	  child = grub_zfs_nvlist_lookup_nvlist_array (nvlist,
						       ZPOOL_CONFIG_CHILDREN,
						       i);

	  get_bootpath (child, bootpath, devid);

	  grub_free (child);

	  if (*bootpath && *devid)
	    return GRUB_ERR_NONE;
	}
    }

  return GRUB_ERR_NONE;
}

static char *poolstates[] = {
  [POOL_STATE_ACTIVE] = "active",
  [POOL_STATE_EXPORTED] = "exported",
  [POOL_STATE_DESTROYED] = "destroyed",
  [POOL_STATE_SPARE] = "reserved for hot spare",
  [POOL_STATE_L2CACHE] = "level 2 ARC device",
  [POOL_STATE_UNINITIALIZED] = "uninitialized",
  [POOL_STATE_UNAVAIL] = "unavailable",
  [POOL_STATE_POTENTIALLY_ACTIVE] = "potentially active"
};

static grub_err_t
grub_cmd_zfsinfo (grub_command_t cmd __attribute__ ((unused)), int argc,
		  char **args)
{
  grub_device_t dev;
  char *devname;
  grub_err_t err;
  char *nvlist = 0;
  char *nv = 0;
  char *poolname;
  grub_uint64_t guid;
  grub_uint64_t pool_state;
  int found;

  if (argc < 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "device name required");

  if (args[0][0] == '(' && args[0][grub_strlen (args[0]) - 1] == ')')
    {
      devname = grub_strdup (args[0] + 1);
      if (devname)
	devname[grub_strlen (devname) - 1] = 0;
    }
  else
    devname = grub_strdup (args[0]);
  if (!devname)
    return grub_errno;

  dev = grub_device_open (devname);
  grub_free (devname);
  if (!dev)
    return grub_errno;

  err = grub_zfs_fetch_nvlist (dev, &nvlist);

  grub_device_close (dev);

  if (err)
    return err;

  poolname = grub_zfs_nvlist_lookup_string (nvlist, ZPOOL_CONFIG_POOL_NAME);
  if (!poolname)
    grub_printf ("Pool name: unavailable\n");
  else
    grub_printf ("Pool name: %s\n", poolname);

  found =
    grub_zfs_nvlist_lookup_uint64 (nvlist, ZPOOL_CONFIG_POOL_GUID, &guid);
  if (!found)
    grub_printf ("Pool GUID: unavailable\n");
  else
    grub_printf ("Pool GUID: %016llx\n", (long long unsigned) guid);

  found = grub_zfs_nvlist_lookup_uint64 (nvlist, ZPOOL_CONFIG_POOL_STATE,
					 &pool_state);
  if (!found)
    grub_printf ("Unable to retrieve pool state\n");
  else if (pool_state >= ARRAY_SIZE (poolstates))
    grub_printf ("Unrecognized pool state\n");
  else
    grub_printf ("Pool state: %s\n", poolstates[pool_state]);

  nv = grub_zfs_nvlist_lookup_nvlist (nvlist, ZPOOL_CONFIG_VDEV_TREE);

  if (!nv)
    grub_printf ("No vdev tree available\n");
  else
    print_vdev_info (nv, 1);

  grub_free (nv);
  grub_free (nvlist);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_zfs_bootfs (grub_command_t cmd __attribute__ ((unused)), int argc,
		     char **args)
{
  grub_device_t dev;
  char *devname;
  grub_err_t err;
  char *nvlist = 0;
  char *nv = 0;
  char *bootpath = 0, *devid = 0;
  char *fsname;
  char *bootfs;
  char *poolname;
  grub_uint64_t mdnobj;

  if (argc < 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "filesystem name required");

  devname = grub_file_get_device_name (args[0]);
  if (grub_errno)
    return grub_errno;

  dev = grub_device_open (devname);
  grub_free (devname);
  if (!dev)
    return grub_errno;

  err = grub_zfs_fetch_nvlist (dev, &nvlist);

  fsname = grub_strchr (args[0], ')');
  if (fsname)
    fsname++;
  else
    fsname = args[0];

  if (!err)
    err = grub_zfs_getmdnobj (dev, fsname, &mdnobj);

  grub_device_close (dev);

  if (err)
    return err;

  poolname = grub_zfs_nvlist_lookup_string (nvlist, ZPOOL_CONFIG_POOL_NAME);
  if (!poolname)
    {
      if (!grub_errno)
	grub_error (GRUB_ERR_BAD_FS, "No poolname found");
      return grub_errno;
    }

  nv = grub_zfs_nvlist_lookup_nvlist (nvlist, ZPOOL_CONFIG_VDEV_TREE);

  if (nv)
    get_bootpath (nv, &bootpath, &devid);

  grub_free (nv);
  grub_free (nvlist);

  if (bootpath && devid)
    {
      bootfs = grub_xasprintf ("zfs-bootfs=%s/%llu bootpath=%s diskdevid=%s",
			       poolname, (unsigned long long) mdnobj,
			       bootpath, devid);
      if (!bootfs)
	return grub_errno;
    }
  else
    {
      bootfs = grub_xasprintf ("zfs-bootfs=%s/%llu",
			       poolname, (unsigned long long) mdnobj);
      if (!bootfs)
	return grub_errno;
    }
  if (argc >= 2)
    grub_env_set (args[1], bootfs);
  else
    grub_printf ("%s\n", bootfs);

  grub_free (bootfs);
  grub_free (poolname);
  grub_free (bootpath);
  grub_free (devid);

  return GRUB_ERR_NONE;
}


static grub_command_t cmd_info, cmd_bootfs;

GRUB_MOD_INIT (zfsinfo)
{
  cmd_info = grub_register_command ("zfsinfo", grub_cmd_zfsinfo,
				    "zfsinfo DEVICE",
				    "Print ZFS info about DEVICE.");
  cmd_bootfs = grub_register_command ("zfs-bootfs", grub_cmd_zfs_bootfs,
				      "zfs-bootfs FILESYSTEM [VARIABLE]",
				      "Print ZFS-BOOTFSOBJ or set it to VARIABLE");
}

GRUB_MOD_FINI (zfsinfo)
{
  grub_unregister_command (cmd_info);
  grub_unregister_command (cmd_bootfs);
}
