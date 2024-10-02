/* radare - LGPL - Copyright 2011-2023 pancake */

#define FSP(x) reiserfs_##x
#define FSS(x) x##_reiserfs
#define FSNAME "reiserfs"
#define FSDESC "REISERFS filesystem"
#define FSPRFX reiserfs
#define FSIPTR grub_reiserfs_fs

#include "fs_grub_base.inc.c"
