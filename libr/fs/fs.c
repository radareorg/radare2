/* radare2 - LGPL - Copyright 2011-2018 - pancake */

#include <r_fs.h>
#include "config.h"
#include "types.h"
#include <errno.h>
#include "../../shlr/grub/include/grub/msdos_partition.h"

#if WITH_GPL
# ifndef USE_GRUB
#  define USE_GRUB 1
# endif
#endif

R_LIB_VERSION (r_fs);

static RFSPlugin* fs_static_plugins[] = {
	R_FS_STATIC_PLUGINS
};

R_API RFS* r_fs_new() {
	int i;
	RFSPlugin* static_plugin;
	RFS* fs = R_NEW0 (RFS);
	if (fs) {
		fs->view = R_FS_VIEW_NORMAL;
		fs->roots = r_list_new ();
		if (!fs->roots) {
			r_fs_free (fs);
			return NULL;
		}
		fs->roots->free = (RListFree) r_fs_root_free;
		fs->plugins = r_list_new ();
		if (!fs->plugins) {
			r_fs_free (fs);
			return NULL;
		}
		fs->plugins->free = free;
		// XXX fs->roots->free = r_fs_plugin_free;
		for (i = 0; fs_static_plugins[i]; i++) {
			static_plugin = R_NEW (RFSPlugin);
			if (!static_plugin) {
				continue;
			}
			memcpy (static_plugin, fs_static_plugins[i], sizeof (RFSPlugin));
			r_fs_add (fs, static_plugin);
			free (static_plugin);
		}
	}
	return fs;
}

R_API RFSPlugin* r_fs_plugin_get(RFS* fs, const char* name) {
	RListIter* iter;
	RFSPlugin* p;
	if (!fs || !name) {
		return NULL;
	}
	r_list_foreach (fs->plugins, iter, p) {
		if (!strcmp (p->name, name)) {
			return p;
		}
	}
	return NULL;
}

R_API void r_fs_free(RFS* fs) {
	if (!fs) {
		return;
	}
	//r_io_free (fs->iob.io);
	//root makes use of plugin so revert to avoid UaF
	r_list_free (fs->roots);
	r_list_free (fs->plugins);
	free (fs);
}

/* plugins */
R_API void r_fs_add(RFS* fs, RFSPlugin* p) {
	// TODO: find coliding plugin name
	if (p && p->init) {
		p->init ();
	}
	RFSPlugin* sp = R_NEW0 (RFSPlugin);
	if (!sp) {
		return;
	}
	if (p) {
		memcpy (sp, p, sizeof (RFSPlugin));
	}
	r_list_append (fs->plugins, sp);
}

R_API void r_fs_del(RFS* fs, RFSPlugin* p) {
	// TODO: implement r_fs_del
}

/* mountpoint */
R_API RFSRoot* r_fs_mount(RFS* fs, const char* fstype, const char* path, ut64 delta) {
	RFSPlugin* p;
	RFSRoot* root;
	RFSFile* file;
	RList* list;
	RListIter* iter;
	char* str;
	int len, lenstr;
	char *heapFsType = NULL;

	if (path[0] != '/') {
		eprintf ("r_fs_mount: invalid mountpoint %s\n", path);
		return NULL;
	}
	if (!fstype || !*fstype) {
		heapFsType = r_fs_name (fs, delta);
		fstype = (const char *)heapFsType;
	}
	if (!(p = r_fs_plugin_get (fs, fstype))) {
		// eprintf ("r_fs_mount: Invalid filesystem type\n");
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
		eprintf ("r_fs_mount: mountpoint must have no subdirectories\n");
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
			eprintf ("r_fs_mount: Invalid mount point\n");
			free (str);
			free (heapFsType);
			return NULL;
		}
	}
	file = r_fs_open (fs, str);
	if (file) {
		r_fs_close (fs, file);
		eprintf ("r_fs_mount: Invalid mount point\n");
		free (heapFsType);
		free (str);
		return NULL;
	}
	list = r_fs_dir (fs, str);
	if (!r_list_empty (list)) {
		//XXX: list need free ??
		eprintf ("r_fs_mount: Invalid mount point\n");
		free (str);
		free (heapFsType);
		return NULL;
	}
	root = r_fs_root_new (str, delta);
	root->p = p;
	//memcpy (&root->iob, &fs->iob, sizeof (root->iob));
	root->iob = fs->iob;
	root->cob = fs->cob;
	if (!p->mount (root)) {
		free (str);
		free (heapFsType);
		r_fs_root_free (root);
		return NULL;
	}
	r_list_append (fs->roots, root);
	eprintf ("Mounted %s on %s at 0x%" PFMT64x "\n", fstype, str, delta);
	free (str);
	free (heapFsType);
	return root;
}

static inline bool r_fs_match(const char* root, const char* path, int len) {
	return (!strncmp (path, root, len));
}

R_API bool r_fs_umount(RFS* fs, const char* path) {
	int len;
	RFSRoot* root;
	RListIter* iter, * riter = NULL;

	if (!path) {
		return false;
	}

	r_list_foreach (fs->roots, iter, root) {
		len = strlen (root->path);
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

R_API RList* r_fs_root(RFS* fs, const char* p) {
	RList* roots;
	RFSRoot* root;
	RListIter* iter;
	int len, olen;
	char* path = strdup (p);
	if (!path) {
		return NULL;
	}
	roots = r_list_new ();
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
R_API RFSFile* r_fs_open(RFS* fs, const char* p) {
	RFSRoot* root;
	RList* roots;
	RListIter* iter;
	RFSFile* f = NULL;
	const char* dir;
	char* path = strdup (p);
	//r_str_trim_path (path);
	roots = r_fs_root (fs, path);
	if (!r_list_empty (roots)) {
		r_list_foreach (roots, iter, root) {
			if (root && root->p && root->p->open) {
				if (strlen (root->path) == 1) {
					dir = path;
				} else {
					dir = path + strlen (root->path);
				}
				f = root->p->open (root, dir);
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

// TODO: close or free?
R_API void r_fs_close(RFS* fs, RFSFile* file) {
	if (fs && file) {
		R_FREE (file->data);
		if (file->p && file->p->close) {
			file->p->close (file);
		}
	}
}

R_API int r_fs_read(RFS* fs, RFSFile* file, ut64 addr, int len) {
	if (len < 1) {
		eprintf ("r_fs_read: too short read\n");
		return false;
	}
	if (fs && file) {
		free (file->data);
		file->data = calloc (1, len + 1);
		// file->data_len = len;
		if (file->p && file->data && file->p->read) {
			file->p->read (file, addr, len);
			return true;
		} else {
			eprintf ("r_fs_read: file->p->read is null\n");
		}
	}
	return false;
}

R_API RList* r_fs_dir(RFS* fs, const char* p) {
	RList* roots, * ret = NULL;
	RFSRoot* root;
	RListIter* iter;
	const char* dir;
	char* path = strdup (p);
	r_str_trim_path (path);
	roots = r_fs_root (fs, path);
	r_list_foreach (roots, iter, root) {
		if (root) {
			if (strlen (root->path) == 1) {
				dir = path;
			} else {
				dir = path + strlen (root->path);
			}
			if (!*dir) {
				dir = "/";
			}
			ret = root->p->dir (root, dir, fs->view);
			if (ret) {
				break;
			}
		}
	}
	free (roots);
	free (path);
	return ret;
}

R_API int r_fs_dir_dump(RFS* fs, const char* path, const char* name) {
	RList* list;
	RListIter* iter;
	RFSFile* file, * item;
	char* str, * npath;

	list = r_fs_dir (fs, path);
	if (!list) {
		return false;
	}
	if (!r_sys_mkdir (name)) {
		if (r_sys_mkdir_failed ()) {
			eprintf ("Cannot create \"%s\"\n", name);
			return false;
		}
	}
	r_list_foreach (list, iter, file) {
		if (!strcmp (file->name, ".") || !strcmp (file->name, "..")) {
			continue;
		}
		str = (char*) malloc (strlen (name) + strlen (file->name) + 2);
		if (!str) {
			return false;
		}
		strcpy (str, name);
		strcat (str, "/");
		strcat (str, file->name);
		npath = malloc (strlen (path) + strlen (file->name) + 2);
		if (!npath) {
			free (str);
			return false;
		}
		strcpy (npath, path);
		strcat (npath, "/");
		strcat (npath, file->name);
		switch (file->type) {
		// DONT FOLLOW MOUNTPOINTS
		case R_FS_FILE_TYPE_DIRECTORY:
			if (!r_fs_dir_dump (fs, npath, str)) {
				free (npath);
				free (str);
				return false;
			}
			break;
		case R_FS_FILE_TYPE_REGULAR:
			item = r_fs_open (fs, npath);
			if (item) {
				r_fs_read (fs, item, 0, item->size);
				if (!r_file_dump (str, item->data, item->size, 0)) {
					free (npath);
					free (str);
					return false;
				}
				free (item->data);
				r_fs_close (fs, item);
			}
			break;
		}
		free (npath);
		free (str);
	}
	return true;
}

static void r_fs_find_off_aux(RFS* fs, const char* name, ut64 offset, RList* list) {
	RList* dirs;
	RListIter* iter;
	RFSFile* item, * file;
	char* found = NULL;

	dirs = r_fs_dir (fs, name);
	r_list_foreach (dirs, iter, item) {
		if (!strcmp (item->name, ".") || !strcmp (item->name, "..")) {
			continue;
		}

		found = (char*) malloc (strlen (name) + strlen (item->name) + 2);
		if (!found) {
			break;
		}
		strcpy (found, name);
		strcat (found, "/");
		strcat (found, item->name);

		if (item->type == R_FS_FILE_TYPE_DIRECTORY) {
			r_fs_find_off_aux (fs, found, offset, list);
		} else {
			file = r_fs_open (fs, found);
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

R_API RList* r_fs_find_off(RFS* fs, const char* name, ut64 off) {
	RList* list = r_list_new ();
	if (!list) {
		return NULL;
	}
	list->free = free;
	r_fs_find_off_aux (fs, name, off, list);
	return list;
}

static void r_fs_find_name_aux(RFS* fs, const char* name, const char* glob, RList* list) {
	RList* dirs;
	RListIter* iter;
	RFSFile* item;
	char* found;

	dirs = r_fs_dir (fs, name);
	r_list_foreach (dirs, iter, item) {
		if (r_str_glob (item->name, glob)) {
			found = (char*) malloc (strlen (name) + strlen (item->name) + 2);
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
			found = (char*) malloc (strlen (name) + strlen (item->name) + 2);
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

R_API RList* r_fs_find_name(RFS* fs, const char* name, const char* glob) {
	RList* list = r_list_newf (free);
	if (!list) {
		return NULL;
	}
	r_fs_find_name_aux (fs, name, glob, list);
	return list;
}

R_API RFSFile* r_fs_slurp(RFS* fs, const char* path) {
	RFSFile* file = NULL;
	RFSRoot* root;
	RList* roots = r_fs_root (fs, path);
	RListIter* iter;
	r_list_foreach (roots, iter, root) {
		if (!root || !root->p) {
			continue;
		}
		if (root->p->open && root->p->read && root->p->close) {
			file = root->p->open (root, path);
			if (file) {
				root->p->read (file, 0, file->size); //file->data
			}else {
				eprintf ("r_fs_slurp: cannot open file\n");
			}
		} else {
			if (root->p->slurp) {
				free (roots);
				return root->p->slurp (root, path);
			}
			eprintf ("r_fs_slurp: null root->p->slurp\n");
		}
	}
	free (roots);
	return file;
}

// TODO: move into grubfs
#include "../../shlr/grub/include/grubfs.h"

#if USE_GRUB
static int grub_parhook(void* disk, void* ptr, void* closure) {
	struct grub_partition* par = ptr;
	RList* list = (RList*) closure;
	RFSPartition* p = r_fs_partition_new (
		r_list_length (list),
		par->start * 512, 512 * par->len);
	p->type = par->msdostype;
	r_list_append (list, p);
	return 0;
}
#endif

static int fs_parhook(void* disk, void* ptr, void* closure) {
	RFSPartition* par = ptr;
	RList* list = (RList*) closure;
	r_list_append (list, par);
	return 0;
}

#include "p/part_dos.c"

static RFSPartitionType partitions[] = {
	/* LGPL code */
	{"dos", &fs_part_dos, fs_parhook},
#if USE_GRUB
	/* WARNING GPL code */
	{"msdos", &grub_msdos_partition_map, grub_parhook},
	{"apple", &grub_apple_partition_map, grub_parhook},
	{"sun", &grub_sun_partition_map, grub_parhook},
	{"sunpc", &grub_sun_pc_partition_map, grub_parhook},
	{"amiga", &grub_amiga_partition_map, grub_parhook},
	{"bsdlabel", &grub_bsdlabel_partition_map, grub_parhook},
	{"gpt", &grub_gpt_partition_map, grub_parhook},
#endif
	// XXX: In BURG all bsd partition map are in bsdlabel
	//{ "openbsdlabel", &grub_openbsd_partition_map },
	//{ "netbsdlabel", &grub_netbsd_partition_map },
	//{ "acorn", &grub_acorn_partition_map },
	{ NULL }
};

R_API const char* r_fs_partition_type_get(int n) {
	if (n < 0 || n >= R_FS_PARTITIONS_LENGTH) {
		return NULL;
	}
	return partitions[n].name;
}

R_API int r_fs_partition_get_size() {
	return R_FS_PARTITIONS_LENGTH;
}

R_API RList* r_fs_partitions(RFS* fs, const char* ptype, ut64 delta) {
	int i, cur = -1;
	for (i = 0; partitions[i].name; i++) {
		if (!strcmp (ptype, partitions[i].name)) {
			cur = i;
			break;
		}
	}
	if (cur != -1) {
		RList* list = r_list_newf ((RListFree) r_fs_partition_free);
#if USE_GRUB
		void* disk = NULL;
		if (partitions[i].iterate == grub_parhook) {
			struct grub_partition_map* gpt = partitions[i].ptr;
			grubfs_bind_io (NULL, 0);
			disk = (void*) grubfs_disk (&fs->iob);
			if (gpt) {
				gpt->iterate (disk,
					(void*) partitions[i].iterate, list);
			}
			grubfs_free (disk);
		} else {
#else
		{
#endif
			RFSPartitionIterator iterate = partitions[i].ptr;
			iterate (fs, partitions[i].iterate, list); //grub_parhook, list);
		}
		return list;
	}
	if (ptype && *ptype) {
		eprintf ("Unknown partition type '%s'.\n", ptype);
	}
	eprintf ("Supported types:\n");
	for (i = 0; partitions[i].name; i++) {
		eprintf (" %s", partitions[i].name);
	}
	eprintf ("\n");
	return NULL;
}

R_API int r_fs_partition_type_str(const char* type) {
	// TODO: implement
	return 0;
}

R_API const char* r_fs_partition_type(const char* part, int type) {
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
		return strdup ("ext3");

	case GRUB_PC_PARTITION_TYPE_HFS:
		return strdup ("hfs");

	case GRUB_PC_PARTITION_TYPE_WIN95_EXTENDED: // fat?
	case GRUB_PC_PARTITION_TYPE_EZD:
	case GRUB_PC_PARTITION_TYPE_VSTAFS:
	case GRUB_PC_PARTITION_TYPE_FREEBSD: // ufs
	case GRUB_PC_PARTITION_TYPE_OPENBSD: // ufs
	case GRUB_PC_PARTITION_TYPE_NETBSD:  // ufs
	case GRUB_PC_PARTITION_TYPE_GPT_DISK:
	case GRUB_PC_PARTITION_TYPE_LINUX_RAID:
	case GRUB_PC_PARTITION_TYPE_NONE:
	default:
		return NULL;
	}
}

R_API char* r_fs_name(RFS* fs, ut64 offset) {
	ut8 buf[1024];
	int i, j, len, ret = false;

	for (i = 0; fstypes[i].name; i++) {
		RFSType* f = &fstypes[i];
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

R_API void r_fs_view(RFS* fs, int view) {
	fs->view = view;
}

R_API bool r_fs_check(RFS *fs, const char *p) {
	RFSRoot *root;
	RListIter *iter;
	char* path = strdup (p);
	if (!path) {
		return false;
	}
	r_str_trim_path (path);
	r_list_foreach (fs->roots, iter, root) {
		if (r_fs_match (path, root->path, strlen (root->path))) {
			free (path);
			return true;
		}
	}
	free (path);
	return false;
}
