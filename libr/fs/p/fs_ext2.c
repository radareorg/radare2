/* radare - LGPL - Copyright 2011-2023 pancake */

#define FSP(x) ext2_##x
#define FSS(x) x##_ext2
#define FSNAME "ext2"
#define FSDESC "ext2 filesystem"
#define FSPRFX ext2
#define FSIPTR grub_ext2_fs

#include "fs_grub_base.inc.c"
