/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <r_fs.h>
#include "../config.h"

static RFSPlugin *fs_static_plugins[] = 
	{ R_FS_STATIC_PLUGINS };

/* lifecycle */
// TODO: needs much more love
R_API RFS *r_fs_new () {
	int i;
	RFSPlugin *static_plugin;
	RFS *fs = R_NEW (RFS);
	if (fs) {
		fs->roots = r_list_new ();
		fs->roots->free = (RListFree)r_fs_root_free;
		fs->plugins = r_list_new ();
		// XXX fs->roots->free = r_fs_plugin_free;
		for (i=0; fs_static_plugins[i]; i++) {
			static_plugin = R_NEW (RFSPlugin);
			memcpy (static_plugin, fs_static_plugins[i], sizeof (RFSPlugin));
			r_fs_add (fs, static_plugin);
		}
	}
	return fs;
}

R_API RFSPlugin *r_fs_plugin_get (RFS *fs, const char *name) {
	RListIter *iter;
	RFSPlugin *p;
	r_list_foreach (fs->plugins, iter, p) {
		if (!strcmp (p->name, name))
			return p;
	}
	return NULL;
}

R_API void r_fs_free (RFS* fs) {
	r_list_free (fs->plugins);
	r_list_free (fs->roots);
	free (fs);
}

/* plugins */

R_API void r_fs_add (RFS *fs, RFSPlugin *p) {
	// find coliding plugin name
	if (p) {
		if (p->init)
			p->init ();
	}
	r_list_append (fs->plugins, p);
}

R_API void r_fs_del (RFS *fs, RFSPlugin *p) {
	// TODO: implement
}

/* mountpoint */

R_API RFSRoot *r_fs_mount (RFS* fs, const char *fstype, const char *path) {
	RFSPlugin *p;
	RFSRoot * root;
	if (path[0] != '/') {
		eprintf ("r_fs_mount: invalid mountpoint\n");
		return NULL;
	}
	//r_fs
	p = r_fs_plugin_get (fs, fstype);
	if (p != NULL) {
		root = r_fs_root_new (path, 0); // XXX hardcoded offset
		root->fs = p;
		r_list_append (fs->roots, root);
		eprintf ("Mounted %s on %s at 0x%llx\n", fstype, path, 0LL);
	} else eprintf ("r_fs_mount: Invalid filesystem type\n");
	return root;
}

static inline int r_fs_match (const char *root, const char *path) {
	return (!strncmp (path, root, strlen (path)));
}

R_API int r_fs_umount (RFS* fs, const char *path) {
        RFSRoot *root;
	RListIter *iter;
        r_list_foreach (fs->roots, iter, root) {
		if (r_fs_match (path, root->path)) {
			r_list_delete (fs->roots, iter);
			return R_TRUE;
		}
        }
        return R_FALSE;
}

R_API RFSRoot *r_fs_root (RFS *fs, const char *path) {
        RFSRoot *root;
	RListIter *iter;
        r_list_foreach (fs->roots, iter, root) {
		if (r_fs_match (path, root->path))
			return root;
        }
	return NULL;
}

/* filez */

R_API RFSFile *r_fs_open (RFS* fs, const char *path) {
	RFSRoot *root = r_fs_root (fs, path);
	if (root)
		return root->fs->open (path);
        return NULL;
}

R_API void r_fs_close (RFS* fs, RFSFile *file) {
	if (fs && file)
		file->fs->close (file);
}

R_API int r_fs_read (RFS* fs, RFSFile *file, ut64 addr, int len) {
	if (fs && file) {
		free (file->data);
		file->data = malloc (file->size);
		file->fs->read (file, addr, len);
	}
	return R_FALSE;
}

R_API RList *r_fs_dir(RFS* fs, const char *path) {
	if (fs) {
		RFSRoot *root = r_fs_root (fs, path);
		if (root)
			return root->fs->dir (root, path);
		eprintf ("r_fs_dir: error, path %s is not mounted\n", path);
	}
	return NULL;
}
