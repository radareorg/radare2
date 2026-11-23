#include "fs_grub_reader.inc.c"

#if WITH_GPL
RFSPlugin FSS(r_fs_plugin) = {
	.meta = {
		.name = FSNAME,
		.author = "pancake",
		.desc = FSDESC,
		.license = "GPL-3.0-only",
	},
	.open = FSP(_open),
	.read = FSP(_read),
	.close = FSP(_close),
	.dir = FSP(_dir),
	.mount = FSP(_mount),
	.umount = FSP(_umount),
#ifdef FSDETAILS
	.details = FSP(details),
#endif
};
#else
RFSPlugin FSS(r_fs_plugin) = {
	.meta = {
		.name = FSNAME,
		.desc = FSDESC,
	}
};
#endif
