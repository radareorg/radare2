/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#define FSP(x) reiserfs_##x
#define FSS(x) x##_reiserfs
#define FSNAME "reiserfs"
#define FSDESC "REISERFS filesystem"
#define FSPRFX reiserfs
#define FSIPTR grub_reiserfs_fs

#include "fs_grub_base.c"
