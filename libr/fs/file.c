/* radare - LGPL - Copyright 2011-2019 - pancake */

#include <r_fs.h>

R_API RFSFile* r_fs_file_new(RFSRoot* root, const char* path) {
	RFSFile* file = R_NEW0 (RFSFile);
	if (!file) {
		return NULL;
	}
	file->root = root;
	if (root) {
		file->p = file->root->p; // XXX dupe
	}
	file->path = strdup (path);
	char *last = (char *)r_str_rchr (file->path, NULL, '/');
	if (last) {
		*last++ = 0;
		file->name = strdup (last);
	} else {
		file->name = strdup (path);
	}
	return file;
}

R_API void r_fs_file_free(RFSFile* file) {
	if (file) {
		free (file->path);
		free (file->name);
		free (file->data);
		free (file);
	}
}

R_API char* r_fs_file_copy_abs_path(RFSFile* file) {
	if (!file) {
		return NULL;
	}
	if (!strcmp (file->path, file->name)) {
		return strdup (file->path);
	}
	return r_str_newf ("%s/%s", file->path, file->name);
}

// TODO: Use RFSRoot and pass it in the stack instead of heap? problematic with bindings
R_API RFSRoot* r_fs_root_new(const char* path, ut64 delta) {
	char* p;
	RFSRoot* root = R_NEW0 (RFSRoot);
	if (!root) {
		return NULL;
	}
	root->path = strdup (path);
	if (!root->path) {
		R_FREE (root);
		return NULL;
	}
	p = root->path + strlen (path);
	if (*p == '/') {
		*p = 0;        // chop tailing slash
	}
	root->delta = delta;
	return root;
}

R_API void r_fs_root_free(RFSRoot* root) {
	if (root) {
		if (root->p && root->p->umount) {
			root->p->umount (root);
		}
		free (root->path);
		free (root);
	}
}

R_API RFSPartition* r_fs_partition_new(int num, ut64 start, ut64 length) {
	RFSPartition* p = R_NEW0 (RFSPartition);
	if (!p) {
		return NULL;
	}
	p->number = num;
	p->type = 0; // TODO we need an enum with all the partition types
	p->start = start;
	p->length = length;
	return p;
}

R_API void r_fs_partition_free(RFSPartition* p) {
	free (p);
}
