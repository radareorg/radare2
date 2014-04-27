/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#define FSP(x) minix_##x
#define FSS(x) x##_minix
#define FSNAME "minix"
#define FSDESC "MINIX filesystem"
#define FSPRFX minix
#define FSIPTR grub_minix_fs

#include "fs_grub_base.c"
