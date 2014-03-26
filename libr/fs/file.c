/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <r_fs.h>

R_API RFSFile *r_fs_file_new (RFSRoot *root, const char *path) {
	RFSFile *file = R_NEW0 (RFSFile);
	file->root = root;
	file->name = strdup (path);
	// TODO: concat path?
	return file;
}

R_API void r_fs_file_free (RFSFile *file) {
	free (file->name);
	free (file->data);
	free (file);
}

// TODO: Use RFSRoot and pass it in the stack instead of heap? problematic with bindings
R_API RFSRoot *r_fs_root_new (const char *path, ut64 delta) {
	char *p;
	RFSRoot *root = R_NEW (RFSRoot);
	root->path = strdup (path);
	p = root->path + strlen (path);
	if (*p == '/') *p = 0; // chop tailing slash
	root->delta = delta;
	return root;
}

R_API void r_fs_root_free (RFSRoot *root) {
	if (root) {
		if (root->p && root->p->umount)
			root->p->umount (root);
		free (root->path);
		free (root);
	}
}

R_API RFSPartition *r_fs_partition_new(int num, ut64 start, ut64 length) {
	RFSPartition *p = R_NEW0 (RFSPartition);
	p->number = num;
	p->start = start;
	p->length = length;
	return p;
}

R_API void r_fs_partition_free (RFSPartition *p) {
	free (p);
}
