/* radare - LGPL - Copyright 2011-2023 pancake */

#define FSP(x) fb_##x
#define FSS(x) x##_fb
#define FSNAME "fb"
#define FSDESC "FB filesystem"
#define FSPRFX fb
#define FSIPTR grub_fb_fs

#include "fs_grub_base.inc.c"
