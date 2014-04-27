/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#define FSP(x) hfsplus_##x
#define FSS(x) x##_hfsplus
#define FSNAME "hfsplus"
#define FSDESC "HFSPLUS filesystem"
#define FSPRFX hfsplus
#define FSIPTR grub_hfsplus_fs

#include "fs_grub_base.c"
