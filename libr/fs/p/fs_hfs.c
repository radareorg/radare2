/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#define FSP(x) grub_hfs##x
#define FSS(x) x##_hfs
#define FSNAME "hfs"
#define FSDESC "HFS filesystem"
#define FSPRFX hfs
#define FSIPTR grub_hfs_fs

#include "fs_grub_base.c"
