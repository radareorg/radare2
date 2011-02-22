#ifndef _INCLUDE_GRUBFS_H_
#define _INCLUDE_GRUBFS_H_
extern unsigned long long grub_hack_lastoff;

#include <r_io.h>
#include <grub/file.h>
#include <grub/disk.h>
#include <grub/partition.h>

typedef struct grubfs {
	struct grub_file *file;
} GrubFS;

GrubFS *grubfs_new (struct grub_fs *myfs, void *data);
void grubfs_free (GrubFS *gf);
void grubfs_bind_io (RIOBind *iob, ut64 _delta);
grub_disk_t grubfs_disk (void *data);
void grubfs_disk_free (struct grub_disk *gd);

extern struct grub_fs grub_ext2_fs;
extern struct grub_fs grub_fat_fs;
extern struct grub_fs grub_ntfs_fs;
extern struct grub_fs grub_ntfscomp_fs;
extern struct grub_fs grub_reiserfs_fs;
extern struct grub_fs grub_hfs_fs;
extern struct grub_fs grub_hfsplus_fs;
extern struct grub_fs grub_ufs_fs;
extern struct grub_fs grub_ufs2_fs;
extern struct grub_fs grub_udf_fs;
extern struct grub_fs grub_iso9660_fs;
extern struct grub_fs grub_jfs_fs;
extern struct grub_fs grub_sfs_fs;
extern struct grub_fs grub_btrfs_fs;
extern struct grub_fs grub_xfs_fs;
extern struct grub_fs grub_tar_fs;
extern struct grub_fs grub_cpio_fs;
extern struct grub_fs grub_udf_fs;
extern struct grub_fs grub_minix_fs;
extern struct grub_fs grub_fb_fs;

extern struct grub_partition_map grub_msdos_partition_map;
extern struct grub_partition_map grub_apple_partition_map;
extern struct grub_partition_map grub_sun_partition_map;
extern struct grub_partition_map grub_sun_pc_partition_map;
extern struct grub_partition_map grub_bsdlabel_partition_map;
extern struct grub_partition_map grub_netbsdlabel_partition_map;
extern struct grub_partition_map grub_openbsdlabel_partition_map;
extern struct grub_partition_map grub_amiga_partition_map;
extern struct grub_partition_map grub_acorn_partition_map;
extern struct grub_partition_map grub_gpt_partition_map;

#endif
