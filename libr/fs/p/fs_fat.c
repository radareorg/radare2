/* radare - LGPL - Copyright 2011-2023 pancake */

#define FSP(x) fat_##x
#define FSS(x) x##_fat
#define FSNAME "fat"
#define FSDESC "FAT filesystem"
#define FSPRFX fat
#define FSIPTR grub_fat_fs

#include "fs_grub_base.inc.c"
