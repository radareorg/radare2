/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

#include <r_fs.h>

// TODO: needs much more love
R_API RFS *r_fs_new () {
	RFS *fs = R_NEW (RFS);
	if (fs) {
		fs->plugins = r_list_new ();
	}
	return fs;
}

R_API void r_fs_free (RFS* fs) {
	free (fs);
}

R_API RFSRoot *r_fs_mount (RFS* fs) {
	return NULL;
}

R_API int r_fs_umount (RFS* fs, 
