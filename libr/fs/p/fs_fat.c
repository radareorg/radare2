/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#define FSP(x) fat_##x
#define FSS(x) x##_fat
#define FSNAME "fat"
#define FSDESC "FAT filesystem"
#define FSPRFX fat
#define FSIPTR grub_fat_fs

#include "fs_grub_base.c"
