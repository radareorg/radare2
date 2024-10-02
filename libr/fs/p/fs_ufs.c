/* radare - LGPL - Copyright 2011-2023 pancake */

#define FSP(x) ufs_##x
#define FSS(x) x##_ufs
#define FSNAME "ufs"
#define FSDESC "UFS filesystem"
#define FSPRFX ufs
#define FSIPTR grub_ufs_fs

#include "fs_grub_base.inc.c"
