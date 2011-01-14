/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#define FSP(x) ufs2_##x
#define FSS(x) x##_ufs2
#define FSNAME "ufs2"
#define FSDESC "UFS2 filesystem"
#define FSPRFX ufs2
#define FSIPTR grub_ufs2_fs

#include "fs_grub_base.c"
