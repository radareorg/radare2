/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#define FSP(x) tar_##x
#define FSS(x) x##_tar
#define FSNAME "tar"
#define FSDESC "TAR filesystem"
#define FSPRFX tar
#define FSIPTR grub_tar_fs

#include "fs_grub_base.c"
