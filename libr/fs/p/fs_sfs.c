/* radare - LGPL - Copyright 2011-2023 pancake */

#define FSP(x) sfs_##x
#define FSS(x) x##_sfs
#define FSNAME "sfs"
#define FSDESC "Amiga Smart FileSystem"
#define FSPRFX sfs
#define FSIPTR grub_sfs_fs

#include "fs_grub_base.inc.c"
