/* fshelp.c -- Filesystem helper functions */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2004,2005,2006,2007,2008  Free Software Foundation, Inc.
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
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/fshelp.h>


/* Lookup the node PATH.  The node ROOTNODE describes the root of the
   directory tree.  The node found is returned in FOUNDNODE, which is
   either a ROOTNODE or a new malloc'ed node.  ITERATE_DIR is used to
   iterate over all directory entries in the current node.
   READ_SYMLINK is used to read the symlink if a node is a symlink.
   EXPECTTYPE is the type node that is expected by the called, an
   error is generated if the node is not of the expected type.  Make
   sure you use the NESTED_FUNC_ATTR macro for HOOK, this is required
   because GCC has a nasty bug when using regparm=3.  */
grub_err_t
grub_fshelp_find_file (const char *path, grub_fshelp_node_t rootnode,
		       grub_fshelp_node_t *foundnode,
		       int (*iterate_dir) (grub_fshelp_node_t dir,
					   int NESTED_FUNC_ATTR (*hook)
					   (const char *filename,
					    enum grub_fshelp_filetype filetype,
					    grub_fshelp_node_t node)),
		       char *(*read_symlink) (grub_fshelp_node_t node),
		       enum grub_fshelp_filetype expecttype)
{
  grub_err_t err;
  enum grub_fshelp_filetype foundtype = GRUB_FSHELP_DIR;
  int symlinknest = 0;

  auto grub_err_t NESTED_FUNC_ATTR find_file (const char *currpath,
					      grub_fshelp_node_t currroot,
					      grub_fshelp_node_t *currfound);

  grub_err_t NESTED_FUNC_ATTR find_file (const char *currpath,
					 grub_fshelp_node_t currroot,
					 grub_fshelp_node_t *currfound)
    {
      char fpath[grub_strlen (currpath) + 1];
      char *name = fpath;
      char *next;
      //  unsigned int pos = 0;
      enum grub_fshelp_filetype type = GRUB_FSHELP_DIR;
      grub_fshelp_node_t currnode = currroot;
      grub_fshelp_node_t oldnode = currroot;

      auto int NESTED_FUNC_ATTR iterate (const char *filename,
					 enum grub_fshelp_filetype filetype,
					 grub_fshelp_node_t node);

      auto void free_node (grub_fshelp_node_t node);

      void free_node (grub_fshelp_node_t node)
	{
          if (node != rootnode && node != currroot)
	    grub_free (node);
	}

      int NESTED_FUNC_ATTR iterate (const char *filename,
				    enum grub_fshelp_filetype filetype,
				    grub_fshelp_node_t node)
	{
	  if (filetype == GRUB_FSHELP_UNKNOWN ||
              (grub_strcmp (name, filename) &&
               (! (filetype & GRUB_FSHELP_CASE_INSENSITIVE) ||
                grub_strncasecmp (name, filename, GRUB_LONG_MAX))))
	    {
	      grub_free (node);
	      return 0;
	    }

	  /* The node is found, stop iterating over the nodes.  */
	  type = filetype & ~GRUB_FSHELP_CASE_INSENSITIVE;
	  oldnode = currnode;
	  currnode = node;

	  return 1;
	}

      grub_strncpy (fpath, currpath, grub_strlen (currpath) + 1);

      /* Remove all leading slashes.  */
      while (*name == '/')
	name++;

      if (! *name)
	{
	  *currfound = currnode;
	  return 0;
	}

      for (;;)
	{
	  int found;

	  /* Extract the actual part from the pathname.  */
	  next = grub_strchr (name, '/');
	  if (next)
	    {
	      /* Remove all leading slashes.  */
	      while (*next == '/')
		*(next++) = '\0';
	    }

	  /* At this point it is expected that the current node is a
	     directory, check if this is true.  */
	  if (type != GRUB_FSHELP_DIR)
	    {
	      free_node (currnode);
	      return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a directory");
	    }

	  /* Iterate over the directory.  */
	  found = iterate_dir (currnode, iterate);
	  if (! found)
	    {
	      if (grub_errno)
		return grub_errno;

	      break;
	    }

	  /* Read in the symlink and follow it.  */
	  if (type == GRUB_FSHELP_SYMLINK)
	    {
	      char *symlink;

	      /* Test if the symlink does not loop.  */
	      if (++symlinknest == 8)
		{
		  free_node (currnode);
		  free_node (oldnode);
		  return grub_error (GRUB_ERR_SYMLINK_LOOP,
                                     "too deep nesting of symlinks");
		}

	      symlink = read_symlink (currnode);
	      free_node (currnode);

	      if (!symlink)
		{
		  free_node (oldnode);
		  return grub_errno;
		}

	      /* The symlink is an absolute path, go back to the root inode.  */
	      if (symlink[0] == '/')
		{
		  free_node (oldnode);
		  oldnode = rootnode;
		}

	      /* Lookup the node the symlink points to.  */
	      find_file (symlink, oldnode, &currnode);
	      type = foundtype;
	      grub_free (symlink);

	      if (grub_errno)
		{
		  free_node (oldnode);
		  return grub_errno;
		}
	    }

	  free_node (oldnode);

	  /* Found the node!  */
	  if (! next || *next == '\0')
	    {
	      *currfound = currnode;
	      foundtype = type;
	      return 0;
	    }

	  name = next;
	}

      return grub_error (GRUB_ERR_FILE_NOT_FOUND, "file not found");
    }

  if (!path || path[0] != '/')
    {
      grub_error (GRUB_ERR_BAD_FILENAME, "bad filename");
      return grub_errno;
    }

  err = find_file (path, rootnode, foundnode);
  if (err)
    return err;

  /* Check if the node that was found was of the expected type.  */
  if (expecttype == GRUB_FSHELP_REG && foundtype != expecttype)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a regular file");
  else if (expecttype == GRUB_FSHELP_DIR && foundtype != expecttype)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a directory");

  return 0;
}

/* Read LEN bytes from the file NODE on disk DISK into the buffer BUF,
   beginning with the block POS.  READ_HOOK should be set before
   reading a block from the file.  GET_BLOCK is used to translate file
   blocks to disk blocks.  The file is FILESIZE bytes big and the
   blocks have a size of LOG2BLOCKSIZE (in log2).  */
grub_ssize_t
grub_fshelp_read_file (grub_disk_t disk, grub_fshelp_node_t node,
		       void NESTED_FUNC_ATTR (*read_hook) (grub_disk_addr_t sector,
                                                           unsigned offset,
                                                           unsigned length),
		       grub_off_t pos, grub_size_t len, char *buf,
		       grub_disk_addr_t (*get_block) (grub_fshelp_node_t node,
                                                      grub_disk_addr_t block),
		       grub_off_t filesize, int log2blocksize)
{
  grub_disk_addr_t i, blockcnt;
  int blocksize = 1 << (log2blocksize + GRUB_DISK_SECTOR_BITS);

  /* Adjust LEN so it we can't read past the end of the file.  */
  if (pos + len > filesize)
    len = filesize - pos;

  blockcnt = ((len + pos) + blocksize - 1) >> (log2blocksize + GRUB_DISK_SECTOR_BITS);

  for (i = pos >> (log2blocksize + GRUB_DISK_SECTOR_BITS); i < blockcnt; i++)
    {
      grub_disk_addr_t blknr;
      int blockoff = pos & (blocksize - 1);
      int blockend = blocksize;

      int skipfirst = 0;

      blknr = get_block (node, i);
      if (grub_errno)
	return -1;

      blknr = blknr << log2blocksize;

      /* Last block.  */
      if (i == blockcnt - 1)
	{
	  blockend = (len + pos) & (blocksize - 1);

	  /* The last portion is exactly blocksize.  */
	  if (! blockend)
	    blockend = blocksize;
	}

      /* First block.  */
      if (i == (pos >> (log2blocksize + GRUB_DISK_SECTOR_BITS)))
	{
	  skipfirst = blockoff;
	  blockend -= skipfirst;
	}

      /* If the block number is 0 this block is not stored on disk but
	 is zero filled instead.  */
      if (blknr)
	{
	  disk->read_hook = read_hook;

	  grub_disk_read (disk, blknr, skipfirst,
			  blockend, buf);
	  disk->read_hook = 0;
	  if (grub_errno)
	    return -1;
	}
      else
	grub_memset (buf, 0, blockend);

      buf += blocksize - skipfirst;
    }

  return len;
}

unsigned int
grub_fshelp_log2blksize (unsigned int blksize, unsigned int *pow)
{
  int mod;

  *pow = 0;
  while (blksize > 1)
    {
      mod = blksize - ((blksize >> 1) << 1);
      blksize >>= 1;

      /* Check if it really is a power of two.  */
      if (mod)
	return grub_error (GRUB_ERR_BAD_NUMBER,
			   "the blocksize is not a power of two");
      (*pow)++;
    }

  return GRUB_ERR_NONE;
}
