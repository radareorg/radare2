/* radare - LGPL - Copyright 2011-2023 pancake */

#define FSP(x) hfsplus_##x
#define FSS(x) x##_hfsplus
#define FSNAME "hfsplus"
#define FSDESC "HFSPLUS filesystem"
#define FSPRFX hfsplus
#define FSIPTR grub_hfsplus_fs

#include "fs_grub_reader.inc.c"

#if WITH_GPL
#include "fs_hfsplus_forensic.inc.c"
#endif

RFSPlugin r_fs_plugin_hfsplus = {
	.meta = {
		.name = FSNAME,
		.author = "pancake",
		.desc = FSDESC,
		.license = "GPL-3.0-only",
	},
#if WITH_GPL
	.open = FSP(_forensic_open),
	.read = FSP(_forensic_read),
	.close = FSP(_forensic_close),
	.dir = FSP(_forensic_dir),
	.open_id = FSP(_forensic_open_id),
	.extents = FSP(_forensic_extents),
	.ranges = FSP(_forensic_ranges),
	.mount = FSP(_forensic_mount),
	.umount = FSP(_forensic_umount),
#endif
};
