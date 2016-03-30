/* radare - LGPL - Copyright 2016 - pancake */

#include <r_fs.h>
#include <dirent.h>
#include <sys/stat.h>

static RFSFile* fs_squash_open(RFSRoot *root, const char *path) {
	return NULL;
}

static bool fs_squash_read(RFSFile *file, ut64 addr, int len) {
	return false;
}

static void fs_squash_close(RFSFile *file) {
	//fclose (file->ptr);
}

static RList *fs_squash_dir(RFSRoot *root, const char *path, int view /*ignored*/) {
	/* not implemented yet */
	return NULL;
}

static int fs_squash_mount(RFSRoot *root) {
	root->ptr = NULL; // XXX: TODO
	return true;
}

static void fs_squash_umount(RFSRoot *root) {
	root->ptr = NULL;
}

struct r_fs_plugin_t r_fs_plugin_squash = {
	.name = "squash",
	.desc = "SQUASH filesystem (gz, xz)",
	.open = fs_squash_open,
	.read = fs_squash_read,
	.close = fs_squash_close,
	.dir = &fs_squash_dir,
	.mount = fs_squash_mount,
	.umount = fs_squash_umount,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
        .type = R_LIB_TYPE_FS,
        .data = &r_asm_plugin_squash,
        .version = R2_VERSION
};
#endif
