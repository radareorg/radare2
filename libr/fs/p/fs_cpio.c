/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#define FSP(x) cpio_##x
#define FSS(x) x##_cpio
#define FSNAME "cpio"
#define FSDESC "CPIO filesystem"
#define FSPRFX cpio
#define FSIPTR grub_cpio_fs

#include "fs_grub_base.c"
