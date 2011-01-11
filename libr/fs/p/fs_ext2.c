/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

#include <r_fs.h>

static RFSFile* ext2_open(const char *path) {
	return NULL;
}

static boolt ext2_read(RFSFile *fs, ut64 addr, int len) {
	return R_FALSE;
}

static void ext2_close(RFSFile *fs) {
}

static RList *ext2_dir(RFSRoot *root, const char *path) {
	return NULL;
}

struct r_fs_plugin_t r_fs_plugin_ext2 = {
	.name = "ext2",
	.desc = "ext2 filesystem",
	.open = ext2_open,
	.read = ext2_read,
	.close = ext2_close,
	.dir = ext2_dir
};
