/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <r_fs.h>
#include "../config.h"

static RFSPlugin *fs_static_plugins[] = { R_FS_STATIC_PLUGINS };

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
	// TODO: find coliding plugin name
	if (p && p->init)
		p->init ();
	r_list_append (fs->plugins, p);
}

R_API void r_fs_del (RFS *fs, RFSPlugin *p) {
	// TODO: implement
}

/* mountpoint */

R_API RFSRoot *r_fs_mount (RFS* fs, const char *fstype, const char *path, ut64 delta) {
	RFSPlugin *p;
	RFSRoot *root;

	if (path[0] != '/') {
		eprintf ("r_fs_mount: invalid mountpoint\n");
		return NULL;
	}
	p = r_fs_plugin_get (fs, fstype);
	if (p != NULL) {
		root = r_fs_root_new (path, delta);
		root->p = p;
		//memcpy (&root->iob, &fs->iob, sizeof (root->iob));
		root->iob = fs->iob;
		p->mount (root);
		r_list_append (fs->roots, root);
		eprintf ("Mounted %s on %s at 0x%llx\n", fstype, path, 0LL);
	} else eprintf ("r_fs_mount: Invalid filesystem type\n");
	return root;
}

static inline int r_fs_match (const char *root, const char *path, int len, int olen) {
	return ((len>olen) && (!strncmp (path, root, len)));
}

R_API int r_fs_umount (RFS* fs, const char *path) {
	int olen = 0;
        RFSRoot *root;
	RListIter *iter, *riter = NULL;
        r_list_foreach (fs->roots, iter, root) {
		int len = strlen (root->path);
		if (r_fs_match (path, root->path, len, olen)) {
			olen = len;
			riter = iter;
		}
        }
	if (riter) {
		r_list_delete (fs->roots, riter);
		return R_TRUE;
	}
        return R_FALSE;
}

R_API RFSRoot *r_fs_root (RFS *fs, const char *path) {
	int olen = 0;
	RListIter *iter;
        RFSRoot *root, *oroot = NULL;
        r_list_foreach (fs->roots, iter, root) {
		int len = strlen (root->path);
		if (r_fs_match (path, root->path, len, olen)) {
			olen = len;
			oroot = root;
		}
        }
	return oroot;
}

/* filez */
R_API RFSFile *r_fs_open (RFS* fs, const char *p) {
	RFSRoot *root;
	char *path = strdup (p);
	//r_str_chop_path (path);
	root = r_fs_root (fs, path);
	if (root && root->p && root->p->open) {
		RFSFile *f = root->p->open (root, path+strlen (root->path));
		free (path);
		return f;
	} else eprintf ("r_fs_open: null root->p->open\n");
	free (path);
        return NULL;
}

// TODO: close or free?
R_API void r_fs_close (RFS* fs, RFSFile *file) {
	if (fs && file && file->p && file->p->close)
		file->p->close (file);
}

R_API int r_fs_read (RFS* fs, RFSFile *file, ut64 addr, int len) {
	if (len<1) {
		eprintf ("r_fs_read: too short read\n");
		return R_FALSE;
	}
	if (fs && file) {
		free (file->data);
		file->data = malloc (len+1);
		if (file->p && file->p->read) {
			file->p->read (file, addr, len);
			return R_TRUE;
		} else eprintf ("r_fs_read: file->p->read is null\n");
	}
	return R_FALSE;
}

R_API RList *r_fs_dir(RFS* fs, const char *p) {
	if (fs) {
		char *path = strdup (p);
		r_str_chop (path);
		RFSRoot *root = r_fs_root (fs, path);
		if (root) {
			const char *dir = path + strlen (root->path)-1;
			if (!*dir) dir = "/";
			if (root) {
				RList *ret = root->p->dir (root, dir);
				free (path);
				return ret;
			}
		}
		eprintf ("r_fs_dir: not mounted '%s'\n", path);
		free (path);
	}
	return NULL;
}

R_API RFSFile *r_fs_slurp(RFS* fs, const char *path) {
	RFSFile *file = NULL;
	RFSRoot *root = r_fs_root (fs, path);
	if (root && root->p) {
		if (root->p->open && root->p->read && root->p->close) {
			file = root->p->open (root, path);
			if (file) root->p->read (file, 0, file->size); //file->data
			else eprintf ("r_fs_slurp: cannot open file\n");
		} else {
			if (root->p->slurp) return root->p->slurp (root, path);
			else eprintf ("r_fs_slurp: null root->p->slurp\n");
		}
	}
	return file;
}

// TODO: move into grubfs
#include "p/grub/include/grubfs.h"
RList *list = NULL;
static int parhook (struct grub_disk *disk, struct grub_partition *par, void *closure) {
	RFSPartition *p = r_fs_partition_new (r_list_length (list), par->start*512, 512*par->len);
	p->type = par->msdostype;
	r_list_append (list, p);
	return 0;
}

R_API RList *r_fs_partitions (RFS *fs, const char *ptype, ut64 delta) {
	struct grub_partition_map *gpm = NULL;
	if (!strcmp (ptype, "msdos"))
		gpm = &grub_msdos_partition_map;
	else if (!strcmp (ptype, "apple"))
		gpm = &grub_apple_partition_map;
	else if (!strcmp (ptype, "sun"))
		gpm = &grub_sun_partition_map;
	else if (!strcmp (ptype, "sunpc"))
		gpm = &grub_sun_pc_partition_map;
	else if (!strcmp (ptype, "amiga"))
		gpm = &grub_amiga_partition_map;
	else if (!strcmp (ptype, "bsdlabel"))
		gpm = &grub_bsdlabel_partition_map;
// XXX: In BURG all bsd partition map are in bsdlabel
//	else if (!strcmp (ptype, "openbsdlabel"))
//		gpm = &grub_openbsdlabel_partition_map;
//	else if (!strcmp (ptype, "netbsdlabel"))
//		gpm = &grub_netbsdlabel_partition_map;
//	else if (!strcmp (ptype, "acorn"))
//		gpm = &grub_acorn_partition_map;
	else if (!strcmp (ptype, "gpt"))
		gpm = &grub_gpt_partition_map;

	if (gpm) {
		list = r_list_new ();
		list->free = (RListFree)r_fs_partition_free;
		struct grub_disk *disk = grubfs_disk (&fs->iob);
		gpm->iterate (disk, parhook, 0);
		return list;
	}
	if (ptype&&*ptype)
		eprintf ("Unknown partition type '%s'.\n", ptype);
	eprintf ("Supported types:\n"
		"  msdos, apple, sun, sunpc, amiga, bsdlabel, acorn, gpt\n");
	return NULL;
}

R_API int r_fs_prompt (RFS *fs, char *root) {
	char buf[1024];
	char path[1024];
	char str[2048];
	char *input;
	RList *list;
	RListIter *iter;
	RFSFile *file;

	if (root && *root) {
		r_str_chop_path (root);
		if (!r_fs_root (fs, root)) {
			printf ("Unknown root\n");
			return R_FALSE;
		}
		strncpy (path, root, sizeof (path)-1);
	} else strcpy (path, "/");

	for (;;) {
		printf (Color_MAGENTA"[%s]> "Color_RESET, path);
		fflush (stdout);
		fgets (buf, sizeof (buf)-1, stdin);
		if (feof (stdin)) break;
		buf[strlen (buf)-1] = '\0';
		if (!strcmp (buf, "q") || !strcmp (buf, "exit"))
			return R_TRUE;
		if (buf[0]=='!') {
			system (buf+1);
		} else
		if (!memcmp (buf, "ls", 2)) {
			if (buf[2]==' ') {
				list = r_fs_dir (fs, buf+3);
			} else list = r_fs_dir (fs, path);
			if (list) {
				r_list_foreach (list, iter, file)
					printf ("%c %s\n", file->type, file->name);
				r_list_free (list);
			} else eprintf ("Unknown path: %s\n", path);
		} else if (!strncmp (buf, "pwd", 3)) {
			eprintf ("%s\n", path);
		} else if (!memcmp (buf, "cd ", 3)) {
			char opath[4096];
			strcpy (opath, path);
			input = buf+3;
			while (*input == ' ')
				input++;
			if (!strcmp (input, "..")) {
				char *p = r_str_lchr (path, '/');
				if (p) p[(p==path)?1:0]=0;
			} else {
				if (*input=='/')
					strcpy (path, input);
				else strcat (path, input);
			}
			list = r_fs_dir (fs, path);
			if (r_list_empty (list)) {
				strcpy (path, opath);
				eprintf ("cd: unknown path: %s\n", path);
			} else r_list_free (list);
		} else if (!memcmp (buf, "cat ", 4)) {
			input = buf+3;
			while (input[0] == ' ')
				input++;
			if (input[0] == '/')
				strncpy (str, root, sizeof (str)-1);
			else strncpy (str, path, sizeof (str)-1);
			strcat (str, "/");
			strcat (str, input);
			file = r_fs_open (fs, str);
			if (file) {
				r_fs_read (fs, file, 0, file->size);
				write (1, file->data, file->size);
				r_fs_close (fs, file);
			} else eprintf ("Cannot open file\n");
		} else if (!memcmp (buf, "mount", 5)) {
			RFSRoot *root;
			r_list_foreach (fs->roots, iter, root) {
				eprintf ("%s %s\n", root->path, root->p->name);
			}
		} else if (!memcmp (buf, "get ",4)) {
			input = buf+3;
			while (input[0] == ' ')
				input++;
			if (input[0] == '/')
				strncpy (str, root, sizeof (str)-1);
			else strncpy (str, path, sizeof (str)-1);
			strcat (str, "/");
			strcat (str, input);
			file = r_fs_open (fs, str);
			if (file) {
				r_fs_read (fs, file, 0, file->size);
				r_file_dump (input, file->data, file->size);
				r_fs_close (fs, file);
			} else printf ("Cannot open file\n");
		} else if (!memcmp (buf, "help", 4) || !strcmp (buf, "?")) {
			printf (
			"Commands:\n"
			" !cmd        ; escape to system\n"
			" ls          ; list current directory\n"
			" cd path     ; change current directory\n"
			" cat file    ; print contents of file\n"
			" get file    ; dump file to disk\n"
			" mount       ; list mount points\n"
			" q/exit      ; leave prompt mode\n"
			" ?/help      ; show this help\n"
			);
		} else {
			printf ("Unknown command %s\n", buf);
		}
	}
	clearerr (stdin);
	printf ("\n");
	return R_TRUE;
}
