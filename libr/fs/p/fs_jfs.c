/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#define FSP(x) jfs_##x
#define FSS(x) x##_jfs
#define FSNAME "jfs"
#define FSDESC "JFS filesystem"
#define FSPRFX jfs
#define FSIPTR grub_jfs_fs

#include "fs_grub_base.c"
