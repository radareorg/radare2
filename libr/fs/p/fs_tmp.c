/* radare - LGPL - Copyright 2025 - pancake */

#include <r_fs.h>

typedef struct r_fs_tmp_node_t {
	char *name;
	bool is_dir;
	RList *children;
	ut8 *data;
	ut32 size;
	ut64 time;
} RFSTmpNode;

static void tmp_node_free(void *ptr);

static RFSTmpNode *tmp_node_new(const char *name, bool is_dir) {
	R_RETURN_VAL_IF_FAIL (name, NULL);
	RFSTmpNode *node = R_NEW0 (RFSTmpNode);
	node->name = strdup (name);
	if (!node->name) {
		tmp_node_free (node);
		return NULL;
	}
	node->is_dir = is_dir;
	node->time = r_time_now ();
	if (is_dir) {
		node->children = r_list_newf (tmp_node_free);
		if (!node->children) {
			tmp_node_free (node);
			return NULL;
		}
	}
	return node;
}

static void tmp_node_free(void *ptr) {
	if (ptr) {
		RFSTmpNode *node = (RFSTmpNode *)ptr;
		if (node->children) {
			r_list_free (node->children);
		}
		free (node->data);
		free (node->name);
		free (node);
	}
}

static RFSTmpNode *tmp_node_child(RFSTmpNode *dir, const char *name) {
	R_RETURN_VAL_IF_FAIL (dir && dir->children && name, NULL);
	RListIter *iter;
	RFSTmpNode *child;
	r_list_foreach (dir->children, iter, child) {
		if (!strcmp (child->name, name)) {
			return child;
		}
	}
	return NULL;
}

static RFSTmpNode *tmp_walk(RFSTmpNode *root, const char *path, bool create_dirs, bool create_leaf, bool leaf_is_dir) {
	R_RETURN_VAL_IF_FAIL (root && path, NULL);
	char *norm = r_str_trim_dup (path);
	if (!norm) {
		return NULL;
	}
	r_str_trim_path (norm);
	if (!*norm) {
		free (norm);
		norm = strdup ("/");
		if (!norm) {
			return NULL;
		}
	}
	if (*norm != '/') {
		char *tmp = r_str_newf ("/%s", norm);
		free (norm);
		norm = tmp;
		if (!norm) {
			return NULL;
		}
	}
	if (!strcmp (norm, "/")) {
		free (norm);
		return root;
	}
	RFSTmpNode *cur = root;
	char *seg = norm + 1;
	while (seg && *seg) {
		char *slash = strchr (seg, '/');
		bool last = !slash;
		if (slash) {
			*slash = 0;
			if (!*(slash + 1)) {
				last = true;
			}
		}
		if (!*seg) {
			if (slash) {
				seg = slash + 1;
				continue;
			}
			break;
		}
		bool need_dir = last ? leaf_is_dir: true;
		RFSTmpNode *child = tmp_node_child (cur, seg);
		if (!child) {
			if (!(create_dirs || (last && create_leaf))) {
				cur = NULL;
				break;
			}
			child = tmp_node_new (seg, need_dir);
			if (!child) {
				cur = NULL;
				break;
			}
			if (!cur->children) {
				cur->children = r_list_newf (tmp_node_free);
				if (!cur->children) {
					tmp_node_free (child);
					cur = NULL;
					break;
				}
			}
			r_list_append (cur->children, child);
		} else if (child->is_dir != need_dir) {
			cur = NULL;
			break;
		}
		cur = child;
		if (!slash) {
			break;
		}
		seg = slash + 1;
	}
	free (norm);
	return cur;
}

static RFSTmpNode *tmp_root(RFSRoot *root) {
	return root? (RFSTmpNode *)root->ptr: NULL;
}

static char *tmp_file_fullpath(RFSFile *file) {
	R_RETURN_VAL_IF_FAIL (file, NULL);
	char *rel = r_fs_file_copy_abs_path (file);
	if (!rel) {
		return NULL;
	}
	r_str_trim_path (rel);
	char *path = NULL;
	if (!*rel) {
		path = strdup ("/");
	} else if (*rel == '/') {
		path = strdup (rel);
	} else {
		path = r_str_newf ("/%s", rel);
	}
	free (rel);
	return path;
}

static RFSFile *fs_tmp_open(RFSRoot *root, const char *path, bool create) {
	if (create) {
		return NULL;
	}
	RFSTmpNode *tnode = tmp_root (root);
	if (!tnode) {
		return NULL;
	}
	RFSTmpNode *node = tmp_walk (tnode, path, false, false, false);
	if (!node || node->is_dir) {
		return NULL;
	}
	RFSFile *file = r_fs_file_new (root, path);
	if (!file) {
		return NULL;
	}
	file->ptr = node;
	file->size = node->size;
	file->type = R_FS_FILE_TYPE_REGULAR;
	file->time = node->time;
	return file;
}

static int fs_tmp_read(RFSFile *file, ut64 addr, int len) {
	R_RETURN_VAL_IF_FAIL (file && file->ptr && len >= 0, -1);
	RFSTmpNode *node = (RFSTmpNode *)file->ptr;
	if (!node || node->is_dir) {
		return -1;
	}
	if ((ut64)node->size <= addr) {
		R_FREE (file->data);
		file->size = 0;
		return 0;
	}
	ut64 remaining = node->size - addr;
	ut64 tocopy = R_MIN ((ut64)len, remaining);
	R_FREE (file->data);
	if (tocopy > 0) {
		file->data = malloc ((size_t)tocopy);
		if (!file->data) {
			return -1;
		}
		memcpy (file->data, node->data + (size_t)addr, (size_t)tocopy);
	}
	file->size = (ut32)tocopy;
	return (int)tocopy;
}

static int fs_tmp_write(RFSFile *file, ut64 addr, const ut8 *data, int len) {
	R_RETURN_VAL_IF_FAIL (file && file->root && data && len >= 0, -1);
	RFSTmpNode *tnode = tmp_root (file->root);
	if (!tnode) {
		return -1;
	}
	char *full = tmp_file_fullpath (file);
	if (!full) {
		return -1;
	}
	RFSTmpNode *node = tmp_walk (tnode, full, true, true, false);
	free (full);
	if (!node || node->is_dir) {
		return -1;
	}
	ut64 needed = addr + len;
	if (needed > UT32_MAX) {
		return -1;
	}
	if (needed > node->size) {
		ut8 *newdata = realloc (node->data, (size_t)needed);
		if (!newdata && needed) {
			return -1;
		}
		if (needed > node->size) {
			memset (newdata + node->size, 0, (size_t)(needed - node->size));
		}
		node->data = newdata;
		node->size = (ut32)needed;
	}
	if (len > 0) {
		memcpy (node->data + (size_t)addr, data, (size_t)len);
	}
	node->time = r_time_now ();
	file->ptr = node;
	file->size = node->size;
	file->type = R_FS_FILE_TYPE_REGULAR;
	return len;
}

static RList *fs_tmp_dir(RFSRoot *root, const char *path, R_UNUSED int view) {
	RFSTmpNode *tnode = tmp_root (root);
	if (!tnode) {
		return NULL;
	}
	RFSTmpNode *dir = tmp_walk (tnode, path, false, false, true);
	if (!dir || !dir->is_dir) {
		return NULL;
	}
	RList *list = r_list_newf ((RListFree)r_fs_file_free);
	if (!list) {
		return NULL;
	}
	RListIter *iter;
	RFSTmpNode *child;
	r_list_foreach (dir->children, iter, child) {
		RFSFile *f = r_fs_file_new (NULL, child->name);
		if (!f) {
			break;
		}
		f->type = child->is_dir? R_FS_FILE_TYPE_DIRECTORY: R_FS_FILE_TYPE_REGULAR;
		f->size = child->size;
		f->time = child->time;
		f->perm = child->is_dir? 0755: 0644;
		r_list_append (list, f);
	}
	return list;
}

static bool fs_tmp_mkdir(RFSRoot *root, const char *path) {
	RFSTmpNode *tnode = tmp_root (root);
	if (!tnode) {
		return false;
	}
	RFSTmpNode *dir = tmp_walk (tnode, path, true, true, true);
	return dir != NULL;
}

static bool fs_tmp_mount(RFSRoot *root) {
	RFSTmpNode *node = tmp_node_new ("", true);
	if (!node) {
		return false;
	}
	free (node->name);
	node->name = strdup ("/");
	if (!node->name) {
		tmp_node_free (node);
		return false;
	}
	root->ptr = node;
	return true;
}

static void fs_tmp_umount(RFSRoot *root) {
	R_RETURN_IF_FAIL (root);
	if (root->ptr) {
		tmp_node_free (root->ptr);
		root->ptr = NULL;
	}
}

RFSPlugin r_fs_plugin_tmp = {
	.meta = {
		.name = "tmp",
		.desc = "Temporary in-memory filesystem",
		.author = "pancake",
		.license = "MIT",
	},
	.open = fs_tmp_open,
	.write = fs_tmp_write,
	.read = fs_tmp_read,
	.dir = fs_tmp_dir,
	.mkdir = fs_tmp_mkdir,
	.mount = fs_tmp_mount,
	.umount = fs_tmp_umount,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_tmp,
	.versr2n = R2_VERSION
};
#endif
