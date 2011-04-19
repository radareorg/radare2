/* iso9660.c - iso9660 implementation with extensions:
   SUSP, Rock Ridge.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2004,2005,2006,2007,2008,2009,2010  Free Software Foundation, Inc.
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

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/fshelp.h>
#include <grub/charset.h>

#define GRUB_ISO9660_FSTYPE_DIR		0040000
#define GRUB_ISO9660_FSTYPE_REG		0100000
#define GRUB_ISO9660_FSTYPE_SYMLINK	0120000
#define GRUB_ISO9660_FSTYPE_MASK	0170000

#define GRUB_ISO9660_LOG2_BLKSZ		2
#define GRUB_ISO9660_BLKSZ		2048

#define GRUB_ISO9660_RR_DOT		2
#define GRUB_ISO9660_RR_DOTDOT		4

#define GRUB_ISO9660_VOLDESC_BOOT	0
#define GRUB_ISO9660_VOLDESC_PRIMARY	1
#define GRUB_ISO9660_VOLDESC_SUPP	2
#define GRUB_ISO9660_VOLDESC_PART	3
#define GRUB_ISO9660_VOLDESC_END	255

/* The head of a volume descriptor.  */
struct grub_iso9660_voldesc
{
  grub_uint8_t type;
  grub_uint8_t magic[5];
  grub_uint8_t version;
} __attribute__ ((packed));

/* A directory entry.  */
struct grub_iso9660_dir
{
  grub_uint8_t len;
  grub_uint8_t ext_sectors;
  grub_uint32_t first_sector;
  grub_uint32_t first_sector_be;
  grub_uint32_t size;
  grub_uint32_t size_be;
  grub_uint8_t unused1[7];
  grub_uint8_t flags;
  grub_uint8_t unused2[6];
  grub_uint8_t namelen;
} __attribute__ ((packed));

struct grub_iso9660_date
{
  grub_uint8_t year[4];
  grub_uint8_t month[2];
  grub_uint8_t day[2];
  grub_uint8_t hour[2];
  grub_uint8_t minute[2];
  grub_uint8_t second[2];
  grub_uint8_t hundredth[2];
  grub_uint8_t offset;
} __attribute__ ((packed));

/* The primary volume descriptor.  Only little endian is used.  */
struct grub_iso9660_primary_voldesc
{
  struct grub_iso9660_voldesc voldesc;
  grub_uint8_t unused1[33];
  grub_uint8_t volname[32];
  grub_uint8_t unused2[16];
  grub_uint8_t escape[32];
  grub_uint8_t unused3[12];
  grub_uint32_t path_table_size;
  grub_uint8_t unused4[4];
  grub_uint32_t path_table;
  grub_uint8_t unused5[12];
  struct grub_iso9660_dir rootdir;
  grub_uint8_t unused6[624];
  struct grub_iso9660_date created;
  struct grub_iso9660_date modified;
} __attribute__ ((packed));

/* A single entry in the path table.  */
struct grub_iso9660_path
{
  grub_uint8_t len;
  grub_uint8_t sectors;
  grub_uint32_t first_sector;
  grub_uint16_t parentdir;
  grub_uint8_t name[0];
} __attribute__ ((packed));

/* An entry in the System Usage area of the directory entry.  */
struct grub_iso9660_susp_entry
{
  grub_uint8_t sig[2];
  grub_uint8_t len;
  grub_uint8_t version;
  grub_uint8_t data[0];
} __attribute__ ((packed));

/* The CE entry.  This is used to describe the next block where data
   can be found.  */
struct grub_iso9660_susp_ce
{
  struct grub_iso9660_susp_entry entry;
  grub_uint32_t blk;
  grub_uint32_t blk_be;
  grub_uint32_t off;
  grub_uint32_t off_be;
  grub_uint32_t len;
  grub_uint32_t len_be;
} __attribute__ ((packed));

struct grub_iso9660_data
{
  struct grub_iso9660_primary_voldesc voldesc;
  grub_disk_t disk;
  unsigned int first_sector;
  int rockridge;
  int susp_skip;
  int joliet;
};

struct grub_fshelp_node
{
  struct grub_iso9660_data *data;
  unsigned int size;
  unsigned int blk;
  unsigned int dir_blk;
  unsigned int dir_off;
};

static grub_dl_t my_mod;


static char *
load_sua (struct grub_iso9660_data *data, int sua_block, int sua_pos,
	  int sua_size)
{
  char *sua;

  sua = grub_malloc (sua_size);
  if (!sua)
    return 0;

  if (grub_disk_read (data->disk, sua_block, sua_pos, sua_size, sua))
    {
      grub_free (sua);
      return 0;
    }

  return sua;
}

/* Iterate over the susp entries, starting with block SUA_BLOCK on the
   offset SUA_POS with a size of SUA_SIZE bytes.  Hook is called for
   every entry.  */
static grub_err_t
grub_iso9660_susp_iterate (struct grub_iso9660_data *data,
			   int sua_block, int sua_pos, int sua_size,
			   grub_err_t (*hook)
			   (struct grub_iso9660_susp_entry *entry,
			    void *closure),
			   void *closure)
{
  char *sua;
  struct grub_iso9660_susp_entry *entry;

  /* Load a part of the System Usage Area.  */
  sua = load_sua (data, sua_block, sua_pos, sua_size);
  if (!sua)
    return grub_errno;
  entry = (struct grub_iso9660_susp_entry *) sua;

  if (hook)
  for (; (char *) entry < (char *) sua + sua_size - 1;
       entry = (struct grub_iso9660_susp_entry *)
	 ((char *) entry + entry->len))
    {
      /* The last entry.  */
      if (grub_strncmp ((char *) entry->sig, "ST", 2) == 0)
	break;

      /* Additional entries are stored elsewhere.  */
      if (grub_strncmp ((char *) entry->sig, "CE", 2) == 0)
	{
	  struct grub_iso9660_susp_ce *ce;

	  ce = (struct grub_iso9660_susp_ce *) entry;
	  sua_size = grub_le_to_cpu32 (ce->len);
	  sua_pos = grub_le_to_cpu32 (ce->off);
	  sua_block = grub_le_to_cpu32 (ce->blk) << GRUB_ISO9660_LOG2_BLKSZ;

	  grub_free (sua);
	  sua = load_sua (data, sua_block, sua_pos, sua_size);
	  if (!sua)
	    return grub_errno;
	  entry = (struct grub_iso9660_susp_entry *) sua;
	}

      if (hook (entry, closure))
	{
	  grub_free (sua);
	  return 0;
	}
    }

  grub_free (sua);
  return 0;
}

static char *
grub_iso9660_convert_string (grub_uint16_t *us, int len)
{
  char *p;
  int i;

  p = grub_malloc (len * 4 + 1);
  if (! p)
    return p;

  for (i=0; i<len; i++)
    us[i] = grub_be_to_cpu16 (us[i]);

  *grub_utf16_to_utf8 ((grub_uint8_t *) p, us, len) = '\0';

  return p;
}

static grub_err_t
susp_iterate (struct grub_iso9660_susp_entry *susp_entry,
	      void *closure)
{
  struct grub_iso9660_data *data = closure;
  /* The "ER" entry is used to detect extensions.  The
     `IEEE_P1285' extension means Rock ridge.  */
  if (grub_strncmp ((char *) susp_entry->sig, "ER", 2) == 0)
    {
      data->rockridge = 1;
      return 1;
    }
  return 0;
}

static struct grub_iso9660_data *
grub_iso9660_mount (grub_disk_t disk)
{
  struct grub_iso9660_data *data = 0;
  struct grub_iso9660_dir rootdir;
  int sua_pos;
  int sua_size;
  char *sua;
  struct grub_iso9660_susp_entry *entry;
  struct grub_iso9660_primary_voldesc voldesc;
  int block;

  data = grub_zalloc (sizeof (struct grub_iso9660_data));
  if (! data)
    return 0;

  data->disk = disk;

  block = 16;
  do
    {
      int copy_voldesc = 0;

      /* Read the superblock.  */
      if (grub_disk_read (disk, block << GRUB_ISO9660_LOG2_BLKSZ, 0,
			  sizeof (struct grub_iso9660_primary_voldesc),
			  (char *) &voldesc))
        {
          grub_error (GRUB_ERR_BAD_FS, "not a ISO9660 filesystem");
          goto fail;
        }

      if (grub_strncmp ((char *) voldesc.voldesc.magic, "CD001", 5) != 0)
        {
          grub_error (GRUB_ERR_BAD_FS, "not a ISO9660 filesystem");
          goto fail;
        }

      if (voldesc.voldesc.type == GRUB_ISO9660_VOLDESC_PRIMARY)
        copy_voldesc = 1;
      else if ((voldesc.voldesc.type == GRUB_ISO9660_VOLDESC_SUPP) &&
               (voldesc.escape[0] == 0x25) && (voldesc.escape[1] == 0x2f) &&
               ((voldesc.escape[2] == 0x40) ||	/* UCS-2 Level 1.  */
                (voldesc.escape[2] == 0x43) ||  /* UCS-2 Level 2.  */
                (voldesc.escape[2] == 0x45)))	/* UCS-2 Level 3.  */
        {
          copy_voldesc = 1;
          data->joliet = 1;
        }

      if (copy_voldesc)
        grub_memcpy((char *) &data->voldesc, (char *) &voldesc,
                    sizeof (struct grub_iso9660_primary_voldesc));

      block++;
    } while (voldesc.voldesc.type != GRUB_ISO9660_VOLDESC_END);

  /* Read the system use area and test it to see if SUSP is
     supported.  */
  if (grub_disk_read (disk,
		      (grub_le_to_cpu32 (data->voldesc.rootdir.first_sector)
		       << GRUB_ISO9660_LOG2_BLKSZ), 0,
		      sizeof (rootdir), (char *) &rootdir))
    {
      grub_error (GRUB_ERR_BAD_FS, "not a ISO9660 filesystem");
      goto fail;
    }

  sua_pos = (sizeof (rootdir) + rootdir.namelen
	     + (rootdir.namelen % 2) - 1);
  sua_size = rootdir.len - sua_pos;

  sua = grub_malloc (sua_size);
  if (! sua)
    goto fail;

  if (grub_disk_read (disk,
		      (grub_le_to_cpu32 (data->voldesc.rootdir.first_sector)
		       << GRUB_ISO9660_LOG2_BLKSZ), sua_pos,
		      sua_size, sua))
    {
      grub_error (GRUB_ERR_BAD_FS, "not a ISO9660 filesystem");
      goto fail;
    }

  entry = (struct grub_iso9660_susp_entry *) sua;

  /* Test if the SUSP protocol is used on this filesystem.  */
  if (grub_strncmp ((char *) entry->sig, "SP", 2) == 0)
    {
      /* The 2nd data byte stored how many bytes are skipped every time
	 to get to the SUA (System Usage Area).  */
      data->susp_skip = entry->data[2];
      entry = (struct grub_iso9660_susp_entry *) ((char *) entry + entry->len);

      /* Iterate over the entries in the SUA area to detect
	 extensions.  */
      if (grub_iso9660_susp_iterate (data,
				     (grub_le_to_cpu32 (data->voldesc.rootdir.first_sector)
				      << GRUB_ISO9660_LOG2_BLKSZ),
				     sua_pos, sua_size, susp_iterate, data))
	goto fail;
    }

  return data;

 fail:
  grub_free (data);
  return 0;
}

struct grub_iso9660_read_symlink_closure
{
  char *symlink;
  int addslash;
};

/* Extend the symlink.  */
static void
add_part (const char *part, int len,
	  struct grub_iso9660_read_symlink_closure *c)
{
  int size = grub_strlen (c->symlink);

  c->symlink = grub_realloc (c->symlink, size + len + 1);
  if (! c->symlink)
    return;

  grub_strncat (c->symlink, part, len);
}

/* Read in a symlink.  */
static grub_err_t
susp_iterate_sl (struct grub_iso9660_susp_entry *entry, void *closure)
{
  struct grub_iso9660_read_symlink_closure *c = closure;

  if (grub_strncmp ("SL", (char *) entry->sig, 2) == 0)
    {
      unsigned int pos = 1;

      /* The symlink is not stored as a POSIX symlink, translate it.  */
      while (pos < grub_le_to_cpu32 (entry->len))
	{
	  if (c->addslash)
	    {
	      add_part ("/", 1, c);
	      c->addslash = 0;
	    }

	  /* The current position is the `Component Flag'.  */
	  switch (entry->data[pos] & 30)
	    {
	    case 0:
	      {
		/* The data on pos + 2 is the actual data, pos + 1
		   is the length.  Both are part of the `Component
		   Record'.  */
		add_part ((char *) &entry->data[pos + 2],
			  entry->data[pos + 1], c);
		if ((entry->data[pos] & 1))
		  c->addslash = 1;

		break;
	      }

	    case 2:
	      add_part ("./", 2, c);
	      break;

	    case 4:
	      add_part ("../", 3, c);
	      break;

	    case 8:
	      add_part ("/", 1, c);
	      break;
	    }
	  /* In pos + 1 the length of the `Component Record' is
	     stored.  */
	  pos += entry->data[pos + 1] + 2;
	}

      /* Check if `grub_realloc' failed.  */
      if (grub_errno)
	return grub_errno;
    }

  return 0;
}

static char *
grub_iso9660_read_symlink (grub_fshelp_node_t node)
{
  struct grub_iso9660_dir dirent;
  int sua_off;
  int sua_size;
  struct grub_iso9660_read_symlink_closure c;

  if (grub_disk_read (node->data->disk, node->dir_blk, node->dir_off,
		      sizeof (dirent), (char *) &dirent))
    return 0;

  sua_off = (sizeof (dirent) + dirent.namelen + 1 - (dirent.namelen % 2)
	     + node->data->susp_skip);
  sua_size = dirent.len - sua_off;

  c.symlink = grub_malloc (1);
  if (!c.symlink)
    return 0;

  *c.symlink = '\0';

  c.addslash = 0;
  if (grub_iso9660_susp_iterate (node->data, node->dir_blk,
				 node->dir_off + sua_off,
				 sua_size, susp_iterate_sl, &c))
    {
      grub_free (c.symlink);
      return 0;
    }

  return c.symlink;
}

struct grub_iso9660_iterate_dir_closure
{
  char **filename;
  int filename_alloc;
  enum grub_fshelp_filetype type;
};

static grub_err_t
susp_iterate_dir (struct grub_iso9660_susp_entry *entry, void *closure)
{
  struct grub_iso9660_iterate_dir_closure *c = closure;
  char *filename = *(c->filename);

  /* The filename in the rock ridge entry.  */
  if (grub_strncmp ("NM", (char *) entry->sig, 2) == 0)
    {
      /* The flags are stored at the data position 0, here the
	 filename type is stored.  */
      if (entry->data[0] & GRUB_ISO9660_RR_DOT)
	filename = ".";
      else if (entry->data[0] & GRUB_ISO9660_RR_DOTDOT)
	filename = "..";
      else
	{
	  int size = 1;
	  if (filename)
	    {
	      size += grub_strlen (filename);
	      grub_realloc (filename,
			    grub_strlen (filename)
			    + entry->len);
	    }
	  else
	    {
	      size = entry->len - 5;
	      filename = grub_zalloc (size + 1);
	    }
	  c->filename_alloc = 1;
	  grub_strncpy (filename, (char *) &entry->data[1], size);
	  filename[size] = '\0';
	}
    }
  /* The mode information (st_mode).  */
  else if (grub_strncmp ((char *) entry->sig, "PX", 2) == 0)
    {
      /* At position 0 of the PX record the st_mode information is
	 stored (little-endian).  */
      grub_uint32_t mode = ((entry->data[0] + (entry->data[1] << 8))
			    & GRUB_ISO9660_FSTYPE_MASK);

      switch (mode)
	{
	case GRUB_ISO9660_FSTYPE_DIR:
	  c->type = GRUB_FSHELP_DIR;
	  break;
	case GRUB_ISO9660_FSTYPE_REG:
	  c->type = GRUB_FSHELP_REG;
	  break;
	case GRUB_ISO9660_FSTYPE_SYMLINK:
	  c->type = GRUB_FSHELP_SYMLINK;
	  break;
	default:
	  c->type = GRUB_FSHELP_UNKNOWN;
	}
    }

  *(c->filename) = filename;
  return 0;
}

static int
grub_iso9660_iterate_dir (grub_fshelp_node_t dir,
			  int (*hook) (const char *filename,
				       enum grub_fshelp_filetype filetype,
				       grub_fshelp_node_t node,
				       void *closure),
			  void *closure)
{
  struct grub_iso9660_dir dirent;
  unsigned int offset = 0;
  char *filename;

  while (offset < dir->size)
    {
      if (grub_disk_read (dir->data->disk,
			  (dir->blk << GRUB_ISO9660_LOG2_BLKSZ)
			  + offset / GRUB_DISK_SECTOR_SIZE,
			  offset % GRUB_DISK_SECTOR_SIZE,
			  sizeof (dirent), (char *) &dirent))
	return 0;

      /* The end of the block, skip to the next one.  */
      if (!dirent.len)
	{
	  offset = (offset / GRUB_ISO9660_BLKSZ + 1) * GRUB_ISO9660_BLKSZ;
	  continue;
	}

      {
	char name[dirent.namelen + 1];
	int nameoffset = offset + sizeof (dirent);
	struct grub_fshelp_node *node;
	int sua_off = (sizeof (dirent) + dirent.namelen + 1
		       - (dirent.namelen % 2));
	int sua_size = dirent.len - sua_off;
	struct grub_iso9660_iterate_dir_closure c;

	sua_off += offset + dir->data->susp_skip;

	filename = 0;
	c.filename = &filename;
	c.filename_alloc = 0;
	c.type = GRUB_FSHELP_UNKNOWN;
	if (dir->data->rockridge
	    && grub_iso9660_susp_iterate (dir->data,
					  (dir->blk << GRUB_ISO9660_LOG2_BLKSZ)
					  + (sua_off
					     / GRUB_DISK_SECTOR_SIZE),
					  sua_off % GRUB_DISK_SECTOR_SIZE,
					  sua_size, susp_iterate_dir, &c))
	  return 0;

	/* Read the name.  */
	if (grub_disk_read (dir->data->disk,
			    (dir->blk << GRUB_ISO9660_LOG2_BLKSZ)
			    + nameoffset / GRUB_DISK_SECTOR_SIZE,
			    nameoffset % GRUB_DISK_SECTOR_SIZE,
			    dirent.namelen, (char *) name))
	  return 0;

	node = grub_malloc (sizeof (struct grub_fshelp_node));
	if (!node)
	  return 0;

	/* Setup a new node.  */
	node->data = dir->data;
	node->size = grub_le_to_cpu32 (dirent.size);
	node->blk = grub_le_to_cpu32 (dirent.first_sector);
	node->dir_blk = ((dir->blk << GRUB_ISO9660_LOG2_BLKSZ)
			 + offset / GRUB_DISK_SECTOR_SIZE);
	node->dir_off = offset % GRUB_DISK_SECTOR_SIZE;

	/* If the filetype was not stored using rockridge, use
	   whatever is stored in the iso9660 filesystem.  */
	if (c.type == GRUB_FSHELP_UNKNOWN)
	  {
	    if ((dirent.flags & 3) == 2)
	      c.type = GRUB_FSHELP_DIR;
	    else
	      c.type = GRUB_FSHELP_REG;
	  }

	/* The filename was not stored in a rock ridge entry.  Read it
	   from the iso9660 filesystem.  */
	if (!filename)
	  {
	    name[dirent.namelen] = '\0';
	    filename = grub_strrchr (name, ';');
	    if (filename)
	      *filename = '\0';

	    if (dirent.namelen == 1 && name[0] == 0)
	      filename = ".";
	    else if (dirent.namelen == 1 && name[0] == 1)
	      filename = "..";
	    else
	      filename = name;
	  }

        if (dir->data->joliet)
          {
            char *oldname, *semicolon;

            oldname = filename;
            filename = grub_iso9660_convert_string
                  ((grub_uint16_t *) oldname, dirent.namelen >> 1);

	    semicolon = grub_strrchr (filename, ';');
	    if (semicolon)
	      *semicolon = '\0';

            if (c.filename_alloc)
              grub_free (oldname);

            c.filename_alloc = 1;
          }

	if (hook (filename, c.type, node, closure))
	  {
	    if (c.filename_alloc)
	      grub_free (filename);
	    return 1;
	  }
	if (c.filename_alloc)
	  grub_free (filename);
      }

      offset += dirent.len;
    }

  return 0;
}

struct grub_iso9660_dir_closure
{
  int (*hook) (const char *filename,
	       const struct grub_dirhook_info *info,
	       void *closure);
  void *closure;
};

static int
iterate (const char *filename,
	 enum grub_fshelp_filetype filetype,
	 grub_fshelp_node_t node, void *closure)
{
  struct grub_iso9660_dir_closure *c = closure;
  struct grub_dirhook_info info;
  grub_memset (&info, 0, sizeof (info));
  info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
  grub_free (node);
  return c->hook (filename, &info, c->closure);
}


static grub_err_t
grub_iso9660_dir (grub_device_t device, const char *path,
		  int (*hook) (const char *filename,
			       const struct grub_dirhook_info *info,
			       void *closure),
		  void *closure)
{
  struct grub_iso9660_data *data = 0;
  struct grub_fshelp_node rootnode;
  struct grub_fshelp_node *foundnode;
  struct grub_iso9660_dir_closure c;

  grub_dl_ref (my_mod);

  data = grub_iso9660_mount (device->disk);
  if (! data)
    goto fail;

  rootnode.data = data;
  rootnode.blk = grub_le_to_cpu32 (data->voldesc.rootdir.first_sector);
  rootnode.size = grub_le_to_cpu32 (data->voldesc.rootdir.size);

  /* Use the fshelp function to traverse the path.  */
  if (grub_fshelp_find_file (path, &rootnode,
			     &foundnode,
			     grub_iso9660_iterate_dir, 0,
			     grub_iso9660_read_symlink,
			     GRUB_FSHELP_DIR))
    goto fail;

  c.hook = hook;
  c.closure = closure;
  /* List the files in the directory.  */
  grub_iso9660_iterate_dir (foundnode, iterate, &c);

  if (foundnode != &rootnode)
    grub_free (foundnode);

 fail:
  grub_free (data);

  grub_dl_unref (my_mod);

  return grub_errno;
}


/* Open a file named NAME and initialize FILE.  */
static grub_err_t
grub_iso9660_open (struct grub_file *file, const char *name)
{
  struct grub_iso9660_data *data;
  struct grub_fshelp_node rootnode;
  struct grub_fshelp_node *foundnode;

  grub_dl_ref (my_mod);

  data = grub_iso9660_mount (file->device->disk);
  if (!data)
    goto fail;

  rootnode.data = data;
  rootnode.blk = grub_le_to_cpu32 (data->voldesc.rootdir.first_sector);
  rootnode.size = grub_le_to_cpu32 (data->voldesc.rootdir.size);

  /* Use the fshelp function to traverse the path.  */
  if (grub_fshelp_find_file (name, &rootnode,
			     &foundnode,
			     grub_iso9660_iterate_dir, 0,
			     grub_iso9660_read_symlink,
			     GRUB_FSHELP_REG))
    goto fail;

  data->first_sector = foundnode->blk;

  file->data = data;
  file->size = foundnode->size;
  file->offset = 0;

  return 0;

 fail:
  grub_dl_unref (my_mod);

  grub_free (data);

  return grub_errno;
}


static grub_ssize_t
grub_iso9660_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_iso9660_data *data =
    (struct grub_iso9660_data *) file->data;

  /* XXX: The file is stored in as a single extent.  */
  data->disk->read_hook = file->read_hook;
  data->disk->closure = file->closure;
  grub_disk_read_ex (data->disk,
		     data->first_sector << GRUB_ISO9660_LOG2_BLKSZ,
		     file->offset,
		     len, buf, file->flags);
  data->disk->read_hook = NULL;

  if (grub_errno)
    return -1;

  return len;
}


static grub_err_t
grub_iso9660_close (grub_file_t file)
{
  grub_free (file->data);

  grub_dl_unref (my_mod);

  return GRUB_ERR_NONE;
}


static grub_err_t
grub_iso9660_label (grub_device_t device, char **label)
{
  struct grub_iso9660_data *data;
  data = grub_iso9660_mount (device->disk);

  if (data)
    {
      if (data->joliet)
        *label = grub_iso9660_convert_string
                 ((grub_uint16_t *) &data->voldesc.volname, 16);
      else
        *label = grub_strndup ((char *) data->voldesc.volname, 32);
      grub_free (data);
    }
  else
    *label = 0;

  return grub_errno;
}


static grub_err_t
grub_iso9660_uuid (grub_device_t device, char **uuid)
{
  struct grub_iso9660_data *data;
  grub_disk_t disk = device->disk;

  grub_dl_ref (my_mod);

  data = grub_iso9660_mount (disk);
  if (data)
    {
      if (! data->voldesc.modified.year[0] && ! data->voldesc.modified.year[1]
	  && ! data->voldesc.modified.year[2] && ! data->voldesc.modified.year[3]
	  && ! data->voldesc.modified.month[0] && ! data->voldesc.modified.month[1]
	  && ! data->voldesc.modified.day[0] && ! data->voldesc.modified.day[1]
	  && ! data->voldesc.modified.hour[0] && ! data->voldesc.modified.hour[1]
	  && ! data->voldesc.modified.minute[0] && ! data->voldesc.modified.minute[1]
	  && ! data->voldesc.modified.second[0] && ! data->voldesc.modified.second[1]
	  && ! data->voldesc.modified.hundredth[0] && ! data->voldesc.modified.hundredth[1])
	{
	  grub_error (GRUB_ERR_BAD_NUMBER, "no creation date in filesystem to generate UUID");
	  *uuid = NULL;
	}
      else
	{
	  *uuid = grub_xasprintf ("%c%c%c%c-%c%c-%c%c-%c%c-%c%c-%c%c-%c%c",
				 data->voldesc.modified.year[0],
				 data->voldesc.modified.year[1],
				 data->voldesc.modified.year[2],
				 data->voldesc.modified.year[3],
				 data->voldesc.modified.month[0],
				 data->voldesc.modified.month[1],
				 data->voldesc.modified.day[0],
				 data->voldesc.modified.day[1],
				 data->voldesc.modified.hour[0],
				 data->voldesc.modified.hour[1],
				 data->voldesc.modified.minute[0],
				 data->voldesc.modified.minute[1],
				 data->voldesc.modified.second[0],
				 data->voldesc.modified.second[1],
				 data->voldesc.modified.hundredth[0],
				 data->voldesc.modified.hundredth[1]);
	}
    }
  else
    *uuid = NULL;

	grub_dl_unref (my_mod);

  grub_free (data);

  return grub_errno;
}



struct grub_fs grub_iso9660_fs =
  {
    .name = "iso9660",
    .dir = grub_iso9660_dir,
    .open = grub_iso9660_open,
    .read = grub_iso9660_read,
    .close = grub_iso9660_close,
    .label = grub_iso9660_label,
    .uuid = grub_iso9660_uuid,
    .next = 0
  };
