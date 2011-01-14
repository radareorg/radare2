#ifndef _INCLUDE_GRUBFS_H_
#define _INCLUDE_GRUBFS_H_

#include <r_io.h>
#include <grub/file.h>
#include <grub/disk.h>

typedef struct grubfs {
	struct grub_file *file;
} GrubFS;

GrubFS *grubfs_new (struct grub_fs *myfs, void *data);
void grubfs_free (GrubFS *gf);
void grubfs_bind_io (RIOBind *iob, ut64 _delta);

extern struct grub_fs grub_ext2_fs;

#endif
