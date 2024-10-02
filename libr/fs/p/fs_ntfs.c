/* radare - LGPL - Copyright 2011-2023 pancake */

#define FSP(x) ntfs_##x
#define FSS(x) x##_ntfs
#define FSNAME "ntfs"
#define FSDESC "NTFS filesystem"
#define FSPRFX ntfs
#define FSIPTR grub_ntfs_fs

#include "fs_grub_base.inc.c"
