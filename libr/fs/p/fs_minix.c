/* radare - LGPL - Copyright 2011-2023 pancake */

#define FSP(x) minix_##x
#define FSS(x) x##_minix
#define FSNAME "minix"
#define FSDESC "MINIX filesystem"
#define FSPRFX minix
#define FSIPTR grub_minix_fs

#include "fs_grub_base.inc.c"
