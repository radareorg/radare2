/* fshelp.h -- Filesystem helper functions */
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

#ifndef GRUB_FSHELP_HEADER
#define GRUB_FSHELP_HEADER	1

#include <grub/types.h>
#include <grub/symbol.h>
#include <grub/err.h>
#include <grub/disk.h>

typedef struct grub_fshelp_node *grub_fshelp_node_t;

extern int grub_fshelp_view;
#define GRUB_FSHELP_CASE_INSENSITIVE	0x100
#define GRUB_FSHELP_TYPE_MASK	0xff
#define GRUB_FSHELP_FLAGS_MASK	0x100

enum grub_fshelp_filetype
  {
    GRUB_FSHELP_UNKNOWN,
    GRUB_FSHELP_REG,
    GRUB_FSHELP_DIR,
    GRUB_FSHELP_SYMLINK
  };

/* Lookup the node PATH.  The node ROOTNODE describes the root of the
   directory tree.  The node found is returned in FOUNDNODE, which is
   either a ROOTNODE or a new malloc'ed node.  ITERATE_DIR is used to
   iterate over all directory entries in the current node.
   READ_SYMLINK is used to read the symlink if a node is a symlink.
   EXPECTTYPE is the type node that is expected by the called, an
   error is generated if the node is not of the expected type.  Make
   sure you use the NESTED_FUNC_ATTR macro for HOOK, this is required
   because GCC has a nasty bug when using regparm=3.  */
grub_err_t grub_fshelp_find_file (const char *path,
				  grub_fshelp_node_t rootnode,
				  grub_fshelp_node_t *foundnode,
				  int (*iterate_dir)
				  (grub_fshelp_node_t dir,
				   int (*hook)
				   (const char *filename,
				    enum grub_fshelp_filetype filetype,
				    grub_fshelp_node_t node,
				    void *closure),
				   void *closure),
				  void *closure,
				  char *(*read_symlink) (grub_fshelp_node_t node),
				  enum grub_fshelp_filetype expect);


/* Read LEN bytes from the file NODE on disk DISK into the buffer BUF,
   beginning with the block POS.  READ_HOOK should be set before
   reading a block from the file.  GET_BLOCK is used to translate file
   blocks to disk blocks.  The file is FILESIZE bytes big and the
   blocks have a size of LOG2BLOCKSIZE (in log2).  
*/
grub_ssize_t grub_fshelp_read_file (grub_disk_t disk, grub_fshelp_node_t node,
				    void (*read_hook)
				    (grub_disk_addr_t sector,
				     unsigned offset,
				     unsigned length,
				     void *closure),
				    void *closure, int flags,
				    grub_off_t pos, grub_size_t len, char *buf,
				    grub_disk_addr_t (*get_block)
				    (grub_fshelp_node_t node,
				     grub_disk_addr_t block),
				    grub_off_t filesize, int log2blocksize);

unsigned int grub_fshelp_log2blksize (unsigned int blksize,
				      unsigned int *pow);

#endif /* ! GRUB_FSHELP_HEADER */
