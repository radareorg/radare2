/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#define FSP(x) sfs_##x
#define FSS(x) x##_sfs
#define FSNAME "sfs"
#define FSDESC "SFS filesystem"
#define FSPRFX sfs
#define FSIPTR grub_sfs_fs

#include "fs_grub_base.c"
