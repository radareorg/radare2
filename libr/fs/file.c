/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <r_fs.h>

R_API RFSFile *r_fs_file_new (const char *path) {
	RFSFile *file = R_NEW (RFSFile);
	memset (file, 0, sizeof (RFSFile));
	file->name = strdup (path);
	return file;
}

R_API void r_fs_file_free (RFSFile *file) {
	free (file->name);
	free (file->data);
	free (file);
}

// TODO: Use RFSRoot and pass it in the stack instead of heap? problematic with bindings
R_API RFSRoot *r_fs_root_new (const char *path, ut64 delta) {
	RFSRoot *root = R_NEW (RFSRoot);
	root->path = strdup (path);
	root->delta = delta;
	return root;
}

R_API void r_fs_root_free (RFSRoot *root) {
	free (root->path);
	free (root);
}
