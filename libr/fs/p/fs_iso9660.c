/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#define FSP(x) iso9660_##x
#define FSS(x) x##_iso9660
#define FSNAME "iso9660"
#define FSDESC "ISO9660 filesystem"
#define FSPRFX iso9660
#define FSIPTR grub_iso9660_fs

#include "fs_grub_base.c"
