/* radare2 - LGPL - Copyright 2011-2024 - pancake */

#define R_LOG_ORIGIN "fs"

#include <r_fs.h>
#include <config.h>

#if WITH_GPL
#ifndef USE_GRUB
#define USE_GRUB 1
#endif
#endif

#if WITH_GPL && USE_GRUB
#include "../../shlr/grub/include/grubfs.h"
#include "../../shlr/grub/include/grub/msdos_partition.h"
#endif

R_LIB_VERSION(r_fs);

static const RFSPlugin *fs_static_plugins[] = {
	R_FS_STATIC_PLUGINS
};

static const RFSType fstypes[] = {
	{ "hfs", 0x400, "BD", 2, 0, 0, 0x400 },
	{ "hfsplus", 0x400, "H+", 2, 0, 0, 0x400 },
	{ "ubifs", 0x0, "\x31\x18", 2, 0, 0, 0 },
	{ "fat", 0x36, "FAT12", 5, 0, 0, 0 },
	{ "fat", 0x52, "FAT32", 5, 0, 0, 0 },
	{ "ext2", 0x438, "\x53\xef", 2, 0, 0, 0 },
	{ "btrfs", 0x10040, "_BHRfS_M", 8, 0, 0, 0x0 },
	{ "iso9660", 0x8000, "\x01"
			"CD0",
		4, 0, 0, 0x8000 },
	{ "ntfs", 0x3, "NTFS    ", 8, 0, 0, 0 },
	{ "minix", 0x410, "\x7f\x13", 2, 0, 0, 0 },
	{ "jfs", 0x8000, "JFS1", 4, 0, 0, 0 },
	{ "reiserfs", 0x10034, "ReIsEr", 6, 0, 0, 0 },
	{ "squashfs", 0, "hsqs", 4, 0, 0, 0 },
	{ "xfs", 0, "XFSB", 4, 0, 0, 0 },
	{ "udf", 0x8000, "BEA01", 5, 0, 0, 0 },
	{ "affs", 0, "DOS", 3, 0, 0, 0 },
	{ "bfs", 544, "\x31\x53\x46\x42", 4, 0, 0, 0 },
	{ "bfs", 544, "\x31\x53\x42\x4f", 4, 0, 0, 0 }, // openbfs, handled by the same plugin
#if AUTOZIP
	{ "tar", 0x101, "ustar", 5, 0, 0, 0 },
	{ "cpio", 0, "070701", 6, 0, 0, 0 },
	{ "zip", 0, "PK", 2, 0, 0, 0 },
#endif
	{ NULL }
};

R_API R_MUSTUSE const RFSType *r_fs_type_index(int i) {
	if (i < 0 || i >= R_ARRAY_SIZE (fstypes)) {
		return NULL;
	}
	return &fstypes[i];
}

R_API R_MUSTUSE RFS *r_fs_new(void) {
	RFSPlugin *static_plugin;
	RFS *fs = R_NEW0 (RFS);
	fs->view = R_FS_VIEW_NORMAL;
	fs->roots = r_list_new ();
	if (!fs->roots) {
		r_fs_free (fs);
		return NULL;
	}
	fs->roots->free = (RListFree)r_fs_root_free;
	fs->plugins = r_list_new ();
	if (!fs->plugins) {
		r_fs_free (fs);
		return NULL;
	}
	fs->plugins->free = free;
	// XXX fs->roots->free = r_fs_plugin_free;
	size_t i;
	for (i = 0; fs_static_plugins[i]; i++) {
		if (!fs_static_plugins[i]->meta.name) {
			continue;
		}
		static_plugin = R_NEW (RFSPlugin);
		if (!static_plugin) {
			continue;
		}
		memcpy (static_plugin, fs_static_plugins[i], sizeof (RFSPlugin));
		r_fs_plugin_add (fs, static_plugin);
		free (static_plugin);
	}
	return fs;
}

R_API RFSPlugin *r_fs_plugin_get(RFS *fs, const char *name) {
	R_RETURN_VAL_IF_FAIL (fs && name, NULL);
	RListIter *iter;
	RFSPlugin *p;
	r_list_foreach (fs->plugins, iter, p) {
		if (!strcmp (p->meta.name, name)) {
			return p;
		}
	}
	return NULL;
}

R_API bool r_fs_cmd(RFS *fs, const char *cmd) {
	R_RETURN_VAL_IF_FAIL (fs && cmd, false);
	RFSRoot *root = NULL;
	RFSPlugin *p;
	/* Prefer plugin associated to last mounted root */
	if (fs->roots) {
		root = r_list_last (fs->roots);
	}
	if (root && root->p && root->p->cmd) {
		if (root->p->cmd (fs, cmd)) {
			return true;
		}
	}
	RListIter *iter;
	r_list_foreach (fs->plugins, iter, p) {
		if (p->cmd && p->cmd (fs, cmd)) {
			return true;
		}
	}
	return false;
}

R_API void r_fs_free(RFS *fs) {
	if (fs) {
		// r_io_free (fs->iob.io);
		// root makes use of plugin so revert to avoid UaF
		r_list_free (fs->roots);
		r_list_free (fs->plugins);
		free (fs);
	}
}

/* plugins */
R_API bool r_fs_plugin_add(RFS *fs, RFSPlugin *p) {
	R_RETURN_VAL_IF_FAIL (fs && p, false);
	if (p->init) {
		// TODO. return false if init fails?
		if (!p->init ()) {
			return false;
		}
	}
	RFSPlugin *sp = R_NEW0 (RFSPlugin);
	memcpy (sp, p, sizeof (RFSPlugin));
	r_list_append (fs->plugins, sp);
	return true;
}

R_API bool r_fs_plugin_remove(RFS *fs, RFSPlugin *p) {
	// XXX TODO
	return true;
}

R_API void r_fs_del(RFS *fs, RFSPlugin *p) {
	// TODO: implement r_fs_del
}

/* mountpoint */
R_API RFSRoot *r_fs_mount(RFS *fs, const char *R_NULLABLE fstype, const char *path, ut64 delta) {
	R_RETURN_VAL_IF_FAIL (fs && path, NULL);
	RFSRoot *root;
	RListIter *iter;
	char *str;
	int len, lenstr;
	char *heapFsType = NULL;

	if (path[0] != '/') {
		R_LOG_ERROR ("Invalid mountpoint %s", path);
		return NULL;
	}
	if (R_STR_ISEMPTY (fstype)) {
		heapFsType = r_fs_name (fs, delta);
		fstype = (const char *)heapFsType;
	}
	if (fstype == NULL) {
		return NULL;
	}
	RFSPlugin *p = r_fs_plugin_get (fs, fstype);
	if (!p) {
		R_LOG_ERROR ("Invalid filesystem type '%s'", fstype);
		free (heapFsType);
		return NULL;
	}
	str = strdup (path);
	if (!str) {
		free (heapFsType);
		return NULL;
	}
	r_str_trim_path (str);
	if (*str && strchr (str + 1, '/')) {
		R_LOG_ERROR ("mountpoint must have no subdirectories");
		free (heapFsType);
		return NULL;
	}
	/* Check if path exists */
	r_list_foreach (fs->roots, iter, root) {
		len = strlen (root->path);
		lenstr = strlen (str);
		if (!strncmp (str, root->path, len)) {
			if (len < lenstr && str[len] != '/') {
				continue;
			}
			if (len > lenstr && root->path[lenstr] == '/') {
				continue;
			}
			R_LOG_ERROR ("Invalid mount point");
			free (str);
			free (heapFsType);
			return NULL;
		}
	}
	RFSFile *file = r_fs_open (fs, str, false);
	if (file) {
		r_fs_close (fs, file);
		R_LOG_ERROR ("Invalid mount point");
		free (heapFsType);
		free (str);
		return NULL;
	}
	RList *list = r_fs_dir (fs, str);
	if (!r_list_empty (list)) {
		// XXX: list need free??
		R_LOG_ERROR ("r_fs_mount: Invalid mount point");
		free (str);
		free (heapFsType);
		return NULL;
	}
	// TODO: we should just construct the root with the rfs instance
	root = r_fs_root_new (str, delta);
	root->p = p;
	root->iob = fs->iob;
	root->cob = fs->cob;
	if (p->mount && !p->mount (root)) {
		free (str);
		free (heapFsType);
		r_fs_root_free (root);
		return NULL;
	}
	r_list_append (fs->roots, root);
	R_LOG_INFO ("Mounted %s on %s at 0x%" PFMT64x, fstype, str, delta);
	free (str);
	free (heapFsType);
	return root;
}

static inline bool r_fs_match(const char *root, const char *path, int len) {
	return (!strncmp (path, root, len));
}

R_API bool r_fs_umount(RFS *fs, const char *path) {
	R_RETURN_VAL_IF_FAIL (fs && path, false);
	RFSRoot *root;
	RListIter *iter, *riter = NULL;

	r_list_foreach (fs->roots, iter, root) {
		int len = strlen (root->path);
		if (r_fs_match (path, root->path, len)) {
			riter = iter;
		}
	}
	if (riter) {
		r_list_delete (fs->roots, riter);
		return true;
	}
	return false;
}

R_API RList *r_fs_root(RFS *fs, const char *p) {
	R_RETURN_VAL_IF_FAIL (fs && p, NULL);
	RFSRoot *root;
	RListIter *iter;
	int len, olen;
	char *path = strdup (p);
	if (!path) {
		return NULL;
	}
	RList *roots = r_list_new ();
	r_str_trim_path (path);
	r_list_foreach (fs->roots, iter, root) {
		len = strlen (root->path);
		if (r_fs_match (path, root->path, len)) {
			olen = strlen (path);
			if (len == 1 || olen == len) {
				r_list_append (roots, root);
			} else if (olen > len && path[len] == '/') {
				r_list_append (roots, root);
			}
		}
	}
	free (path);
	return roots;
}

/* filez */
R_API RFSFile *r_fs_open(RFS *fs, const char *p, bool create) {
	R_RETURN_VAL_IF_FAIL (fs && p, NULL);
	RFSRoot *root;
	RListIter *iter;
	RFSFile *f = NULL;
	const char *dir;
	char *path = r_str_trim_dup (p);
	r_str_trim_path (path);
	RList *roots = r_fs_root (fs, path);
	if (!r_list_empty (roots)) {
		r_list_foreach (roots, iter, root) {
			if (create) {
				if (root && root->p && root->p->write) {
					f = r_fs_file_new (root, path + strlen (root->path));
					break;
				}
				continue;
			}
			if (root && root->p && root->p->open) {
				if (strlen (root->path) == 1) {
					dir = path;
				} else {
					dir = path + strlen (root->path);
				}
				f = root->p->open (root, dir, false);
				if (f) {
					break;
				}
			}
		}
	}
	free (roots);
	free (path);
	return f;
}

// NOTE: close doesnt free
R_API void r_fs_close(RFS *fs, RFSFile *file) {
	R_RETURN_IF_FAIL (fs && file);
	R_FREE (file->data);
	if (file->p && file->p->close) {
		file->p->close (file);
	}
}

R_API int r_fs_write(RFS *fs, RFSFile *file, ut64 addr, const ut8 *data, int len) {
	R_RETURN_VAL_IF_FAIL (fs && file && data && len >= 0, -1);
	if (fs && file) {
		// TODO: fill file->data? looks like dupe of rbuffer
		if (file->p && file->p->write) {
			return file->p->write (file, addr, data, len);
		}
		R_LOG_ERROR ("null file->p->write");
	}
	return -1;
}

R_API int r_fs_read(RFS *fs, RFSFile *file, ut64 addr, int len) {
	R_RETURN_VAL_IF_FAIL (fs && file && len > 0, -1);
	if (file->p && file->p->read) {
		if (!file->data) {
			free (file->data);
			file->data = calloc (1, len + 1);
		}
		return file->p->read (file, addr, len);
	}
	R_LOG_ERROR ("null file->p->read");
	return -1;
}

R_API RList *r_fs_dir(RFS *fs, const char *p) {
	R_RETURN_VAL_IF_FAIL (fs && p, NULL);
	RList *ret = NULL;
	RFSRoot *root;
	RListIter *iter;
	char *path = strdup (p);
	r_str_trim_path (path);
	RList *roots = r_fs_root (fs, path);
	r_list_foreach (roots, iter, root) {
		if (root && root->p && root->p->dir) {
			const char *dir = r_str_nlen (root->path, 2) == 1
				? path
				: path + strlen (root->path);
			if (!*dir) {
				dir = "/";
			}
			ret = root->p->dir (root, dir, fs->view);
			if (ret) {
				break;
			}
		}
	}
	r_list_free (roots);
	free (path);
	return ret;
}

R_API bool r_fs_mkdir(RFS *fs, const char *path) {
	R_RETURN_VAL_IF_FAIL (fs && path, false);
	char *npath = r_str_trim_dup (path);
	if (!npath) {
		return false;
	}
	r_str_trim_path (npath);
	if (!*npath) {
		free (npath);
		return false;
	}
	if (*npath != '/') {
		free (npath);
		return false;
	}
	bool res = false;
	RList *roots = r_fs_root (fs, npath);
	RListIter *iter;
	RFSRoot *root;
	r_list_foreach (roots, iter, root) {
		if (!root || !root->p || !root->p->mkdir) {
			continue;
		}
		const char *dir = npath;
		size_t plen = strlen (root->path);
		if (plen > 1) {
			if (strncmp (npath, root->path, plen)) {
				continue;
			}
			dir = npath + plen;
			if (!*dir) {
				dir = "/";
			}
		}
		res = root->p->mkdir (root, dir);
		if (res) {
			break;
		}
	}
	r_list_free (roots);
	free (npath);
	return res;
}

R_API bool r_fs_dir_dump(RFS *fs, const char *path, const char *name) {
	R_RETURN_VAL_IF_FAIL (fs && path && name, false);
	RListIter *iter;
	RFSFile *file, *item;

	RList *list = r_fs_dir (fs, path);
	if (!list) {
		return false;
	}
	if (!r_sys_mkdir (name)) {
		if (r_sys_mkdir_failed ()) {
			R_LOG_ERROR ("Cannot create \"%s\"", name);
			return false;
		}
	}
	r_list_foreach (list, iter, file) {
		if (!strcmp (file->name, ".") || !strcmp (file->name, "..")) {
			continue;
		}
		char *str = r_str_newf ("%s/%s", name, file->name);
		char *npath = r_str_newf ("%s/%s", path, file->name);

		switch (file->type) {
		// DON'T FOLLOW MOUNTPOINTS
		case R_FS_FILE_TYPE_DIRECTORY:
			if (!r_fs_dir_dump (fs, npath, str)) {
				free (npath);
				free (str);
				return false;
			}
			break;
		case R_FS_FILE_TYPE_REGULAR:
			item = r_fs_open (fs, npath, false);
			if (item) {
				r_fs_read (fs, item, 0, item->size);
				if (!r_file_dump (str, item->data, item->size, 0)) {
					free (npath);
					free (str);
					return false;
				}
				r_fs_close (fs, item);
			}
			break;
		}
		free (npath);
		free (str);
	}
	return true;
}

static void r_fs_find_off_aux(RFS *fs, const char *name, ut64 offset, RList *list) {
	RListIter *iter;
	RFSFile *item, *file;
	RList *dirs = r_fs_dir (fs, name);
	r_list_foreach (dirs, iter, item) {
		if (!strcmp (item->name, ".") || !strcmp (item->name, "..")) {
			continue;
		}

		char *found = (char *)malloc (strlen (name) + strlen (item->name) + 2);
		if (!found) {
			break;
		}
		strcpy (found, name);
		strcat (found, "/");
		strcat (found, item->name);

		if (item->type == R_FS_FILE_TYPE_DIRECTORY) {
			r_fs_find_off_aux (fs, found, offset, list);
		} else {
			file = r_fs_open (fs, found, false);
			if (file) {
				r_fs_read (fs, file, 0, file->size);
				if (file->off == offset) {
					r_list_append (list, found);
				}
				r_fs_close (fs, file);
			}
		}
		free (found);
	}
}

R_API RList *r_fs_find_off(RFS *fs, const char *name, ut64 off) {
	RList *list = r_list_new ();
	if (!list) {
		return NULL;
	}
	list->free = free;
	r_fs_find_off_aux (fs, name, off, list);
	return list;
}

static void r_fs_find_name_aux(RFS *fs, const char *name, const char *glob, RList *list) {
	RListIter *iter;
	RFSFile *item;
	char *found;

	RList *dirs = r_fs_dir (fs, name);
	r_list_foreach (dirs, iter, item) {
		if (r_str_glob (item->name, glob)) {
			found = (char *)malloc (strlen (name) + strlen (item->name) + 2);
			if (!found) {
				break;
			}
			strcpy (found, name);
			strcat (found, "/");
			strcat (found, item->name);
			r_list_append (list, found);
		}
		if (!strcmp (item->name, ".") || !strcmp (item->name, "..")) {
			continue;
		}
		if (item->type == R_FS_FILE_TYPE_DIRECTORY) {
			found = (char *)malloc (strlen (name) + strlen (item->name) + 2);
			if (!found) {
				break;
			}
			strcpy (found, name);
			strcat (found, "/");
			strcat (found, item->name);
			r_fs_find_name_aux (fs, found, glob, list);
			free (found);
		}
	}
}

R_API RList *r_fs_find_name(RFS *fs, const char *name, const char *glob) {
	R_RETURN_VAL_IF_FAIL (fs && name && glob, NULL);
	RList *list = r_list_newf (free);
	if (list) {
		r_fs_find_name_aux (fs, name, glob, list);
	}
	return list;
}

R_API RFSFile *r_fs_slurp(RFS *fs, const char *path) {
	R_RETURN_VAL_IF_FAIL (fs && path, NULL);
	RFSFile *file = NULL;
	RFSRoot *root;
	RList *roots = r_fs_root (fs, path);
	RListIter *iter;
	r_list_foreach (roots, iter, root) {
		if (!root || !root->p) {
			continue;
		}
		if (root->p->open && root->p->read && root->p->close) {
			file = root->p->open (root, path, false);
			if (file) {
				root->p->read (file, 0, file->size); // file->data
			} else {
				R_LOG_ERROR ("cannot open file");
			}
		} else {
			if (root->p->slurp) {
				free (roots);
				return root->p->slurp (root, path);
			}
			R_LOG_ERROR ("null root->p->slurp");
		}
	}
	free (roots);
	return file;
}

#if USE_GRUB && WITH_GPL
static int grub_parhook(void *disk, void *ptr, void *closure) {
	struct grub_partition *par = ptr;
	RList *list = (RList *)closure;
	RFSPartition *p = r_fs_partition_new (
		r_list_length (list),
		par->start * 512, 512 * par->len);
	p->type = par->msdostype;
	r_list_append (list, p);
	return 0;
}
#endif

static int fs_parhook(void *disk, void *ptr, void *closure) {
	RFSPartition *par = ptr;
	RList *list = (RList *)closure;
	r_list_append (list, par);
	return 0;
}

#include "p/part_dos.c"

static RFSPartitionType partitions[] = {
	/* LGPL code */
	{ "dos", &fs_part_dos, fs_parhook },
#if USE_GRUB
/* WARNING GPL code */
#if !__EMSCRIPTEN__
	// wtf for some reason is not available on emscripten
	{ "msdos", &grub_msdos_partition_map, grub_parhook },
#endif
	{ "apple", &grub_apple_partition_map, grub_parhook },
	{ "sun", &grub_sun_partition_map, grub_parhook },
	{ "sunpc", &grub_sun_pc_partition_map, grub_parhook },
	{ "amiga", &grub_amiga_partition_map, grub_parhook },
	{ "bsdlabel", &grub_bsdlabel_partition_map, grub_parhook },
	{ "gpt", &grub_gpt_partition_map, grub_parhook },
#endif
	// XXX: In BURG all bsd partition map are in bsdlabel
	//{ "openbsdlabel", &grub_openbsd_partition_map },
	//{ "netbsdlabel", &grub_netbsd_partition_map },
	//{ "acorn", &grub_acorn_partition_map },
	{ NULL }
};

R_API const char *r_fs_partition_type_get(int n) {
	if (n < 0 || n >= R_FS_PARTITIONS_LENGTH) {
		return NULL;
	}
	return partitions[n].name;
}

R_API RList *r_fs_partitions(RFS *fs, const char *ptype, ut64 delta) {
	R_RETURN_VAL_IF_FAIL (fs && ptype, NULL);
	int i, cur = -1;
	for (i = 0; partitions[i].name; i++) {
		if (!strcmp (ptype, partitions[i].name)) {
			cur = i;
			break;
		}
	}
	if (cur != -1) {
		RList *list = r_list_newf ((RListFree)r_fs_partition_free);
#if USE_GRUB
		void *disk = NULL;
		if (partitions[i].iterate == grub_parhook) {
			struct grub_partition_map *gpt = partitions[i].ptr;
			grubfs_bind_io (NULL, 0);
			disk = (void *)grubfs_disk (&fs->iob);
			if (gpt) {
				gpt->iterate (disk,
					(void *)partitions[i].iterate, list);
			}
			grubfs_free (disk);
		} else {
#else
		{
#endif
			RFSPartitionIterator iterate = partitions[i].ptr;
			iterate (fs, partitions[i].iterate, list);
		}
		return list;
	}
	if (R_STR_ISNOTEMPTY (ptype)) {
		R_LOG_ERROR ("Unknown partition type '%s'. Use 'mL' command to list them all", ptype);
	}
	return NULL;
}

R_API int r_fs_partition_type_str(const char *type) {
#if USE_GRUB && WITH_GPL
	// TODO: properly implement our types to not depend on grub
	if (!strcmp (type, "fat")) {
		return GRUB_PC_PARTITION_TYPE_FAT32;
	}
	if (!strcmp (type, "ext2")) {
		return GRUB_PC_PARTITION_TYPE_EXT2FS;
	}
	if (!strcmp (type, "hfs")) {
		return GRUB_PC_PARTITION_TYPE_HFS;
	}
#endif
	return 0;
}

R_API const char *r_fs_partition_type(const char *part, int type) {
#if USE_GRUB && WITH_GPL
	// XXX: part is ignored O_o
	switch (type) {
	case GRUB_PC_PARTITION_TYPE_FAT12:
	case GRUB_PC_PARTITION_TYPE_FAT16_GT32M:
	case GRUB_PC_PARTITION_TYPE_FAT16_LT32M:
	case GRUB_PC_PARTITION_TYPE_FAT32:
	case GRUB_PC_PARTITION_TYPE_FAT32_LBA:
	case GRUB_PC_PARTITION_TYPE_FAT16_LBA:
		return strdup ("fat");
	case GRUB_PC_PARTITION_TYPE_EXT2FS:
		return strdup ("ext2");
	case GRUB_PC_PARTITION_TYPE_MINIX:
	case GRUB_PC_PARTITION_TYPE_LINUX_MINIX:
		return strdup ("minix");
	case GRUB_PC_PARTITION_TYPE_NTFS:
		return strdup ("ntfs");
	case GRUB_PC_PARTITION_TYPE_EXTENDED:
	case GRUB_PC_PARTITION_TYPE_LINUX_EXTENDED:
		return strdup ("ext3"); // XXX
	case GRUB_PC_PARTITION_TYPE_HFS:
		return strdup ("hfs");
	case GRUB_PC_PARTITION_TYPE_WIN95_EXTENDED: // fat?
	case GRUB_PC_PARTITION_TYPE_EZD:
	case GRUB_PC_PARTITION_TYPE_VSTAFS:
	case GRUB_PC_PARTITION_TYPE_FREEBSD: // ufs
	case GRUB_PC_PARTITION_TYPE_OPENBSD: // ufs
	case GRUB_PC_PARTITION_TYPE_NETBSD: // ufs
	case GRUB_PC_PARTITION_TYPE_GPT_DISK:
	case GRUB_PC_PARTITION_TYPE_LINUX_RAID:
	case GRUB_PC_PARTITION_TYPE_NONE:
	default:
		return NULL;
	}
#endif
	return NULL;
}

R_API char *r_fs_name(RFS *fs, ut64 offset) {
	R_RETURN_VAL_IF_FAIL (fs, NULL);
	ut8 buf[1024];
	int i, j, len, ret = false;

	for (i = 0; fstypes[i].name; i++) {
		const RFSType *f = &fstypes[i];
		len = R_MIN (f->buflen, sizeof (buf) - 1);
		fs->iob.read_at (fs->iob.io, offset + f->bufoff, buf, len);
		if (f->buflen > 0 && !memcmp (buf, f->buf, f->buflen)) {
			ret = true;
			len = R_MIN (f->bytelen, sizeof (buf));
			fs->iob.read_at (fs->iob.io, offset + f->byteoff, buf, len);
			// for (j = 0; j < f->bytelen; j++) {
			for (j = 0; j < len; j++) {
				if (buf[j] != f->byte) {
					ret = false;
					break;
				}
			}
			if (ret) {
				return strdup (f->name);
			}
		}
	}
	return NULL;
}

R_API void r_fs_view(RFS *fs, int view) {
	R_RETURN_IF_FAIL (fs);
	fs->view = view;
}

R_API bool r_fs_check(RFS *fs, const char *p) {
	R_RETURN_VAL_IF_FAIL (fs && p, false);
	RFSRoot *root;
	RListIter *iter;
	char *path = strdup (p);
	if (path) {
		r_str_trim_path (path);
		r_list_foreach (fs->roots, iter, root) {
			if (r_fs_match (path, root->path, strlen (root->path))) {
				free (path);
				return true;
			}
		}
		free (path);
	}
	return false;
}
