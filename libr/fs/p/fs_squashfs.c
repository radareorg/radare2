/* radare - BSD2 - Copyright 2024 - Enno Boland */

#include <r_fs.h>
#include <r_userconf.h>

#if R2_USE_SQSH
#include <sqsh.h>

static char sqsh_to_r_type(enum SqshFileType type) {
	switch (type) {
	case SQSH_FILE_TYPE_DIRECTORY:
		return R_FS_FILE_TYPE_DIRECTORY;
	case SQSH_FILE_TYPE_FILE:
		return R_FS_FILE_TYPE_REGULAR;
	case SQSH_FILE_TYPE_BLOCK:
		return R_FS_FILE_TYPE_BLOCK;
	case SQSH_FILE_TYPE_CHAR:
		return R_FS_FILE_TYPE_CHAR;
	case SQSH_FILE_TYPE_FIFO:
	case SQSH_FILE_TYPE_SOCKET:
		return R_FS_FILE_TYPE_SPECIAL;
	default:
		return 0;
	}
}

static void prepare_file(RFSFile *fsf, struct SqshFile *file, bool is_symlink) {
	fsf->ptr = file;
	fsf->size = sqsh_file_size (file);
	fsf->time = sqsh_file_modified_time (file);
	fsf->type = sqsh_to_r_type (sqsh_file_type (file));
	if (is_symlink) {
		fsf->type = toupper (fsf->type);
	}
}

static int fs_sqsh_mapper_init(
	struct SqshMapper *mapper, const void *input, size_t *size) {
	(void)size;
	// takes the input pointer, which is a RFSRoot object here and sets it as user data.
	sqsh_mapper_set_user_data (mapper, (void *)input);
	return 0;
}

static int fs_sqsh_mapper_map(
	const struct SqshMapper *mapper, sqsh_index_t offset, size_t size,
	uint8_t **data) {
	RFSRoot *root = sqsh_mapper_user_data (mapper);

	ut8 *buf = calloc (size, 1);
	if (!buf) {
		R_LOG_ERROR ("cannot allocate %d bytes", size);
		return -1;
	}
	int res = root->iob.read_at (root->iob.io, offset, buf, size);
	if (res < 1) {
		R_LOG_ERROR ("cannot allocate %d bytes", size);
		free (buf);
		return -1;
	}
	*data = buf;
	return 0;
}

static int fs_sqsh_mapper_cleanup(struct SqshMapper *mapper) {
	// Do nothing, cleanup happens in _umount.
	return 0;
}

static int fs_sqsh_mapping_unmap(
	const struct SqshMapper *mapper, uint8_t *data, size_t size) {
	(void)size;
	free (data);
	return 0;
}

const static struct SqshMemoryMapperImpl r_sqsh_mapper = {
	// 16 KB block size
	.block_size_hint = 16 * 1024,
	.init = fs_sqsh_mapper_init,
	.map = fs_sqsh_mapper_map,
	.unmap = fs_sqsh_mapping_unmap,
	.cleanup = fs_sqsh_mapper_cleanup,
};

static RFSFile *fs_squashfs_open(RFSRoot *root, const char *path, bool create) {
	int err = 0;
	struct SqshArchive *archive = root->ptr;

	RFSFile *fsf = r_fs_file_new (root, path);
	if (!fsf) {
		return NULL;
	}
	struct SqshFile *file = sqsh_open (archive, path, &err);
	if (err < 0) {
		R_LOG_ERROR ("squashfs: %s", sqsh_error_str (err));
		r_fs_file_free (fsf);
		return NULL;
	}
	prepare_file (fsf, file, false);
	return fsf;
}

static int fs_squashfs_read(RFSFile *file, ut64 addr, int len) {
	int err = 0;
	struct SqshFile *sqsh_file = file->ptr;
	struct SqshFileReader *reader = sqsh_file_reader_new (sqsh_file, &err);
	if (err < 0) {
		R_LOG_ERROR ("squashfs: %s", sqsh_error_str (err));
		return -1;
	}
	err = sqsh_file_reader_advance (reader, addr, len);
	if (err < 0) {
		R_LOG_ERROR ("squashfs: %s", sqsh_error_str (err));
		sqsh_file_reader_free (reader);
		return -1;
	}
	memcpy (file->data, sqsh_file_reader_data (reader), len);
	sqsh_file_reader_free (reader);
	return 0;
}

static void fs_squashfs_close(RFSFile *file) {
	sqsh_close (file->ptr);
}

static int append_file(RList *list, struct SqshDirectoryIterator *entry) {
	int err = 0;
	enum SqshFileType sqsh_type;
	struct SqshFile *file = sqsh_directory_iterator_open_file (entry, &err);
	if (err < 0) {
		R_LOG_ERROR ("squashfs: %s", sqsh_error_str (err));
		return -1;
	}
	char *name = sqsh_directory_iterator_name_dup (entry);
	RFSFile *fsf = r_fs_file_new (NULL, name);
	if (!fsf) {
		free (name);
		sqsh_close (file);
		return -1;
	}

	sqsh_type = sqsh_file_type (file);
	if (sqsh_type == SQSH_FILE_TYPE_SYMLINK) {
		err = sqsh_file_symlink_resolve_all (file);
		if (err < 0) {
			R_LOG_ERROR ("squashfs: %s", sqsh_error_str (err));
			sqsh_close (file);
			return -1;
		}
		prepare_file (fsf, file, true);
	} else {
		prepare_file (fsf, file, false);
	}
	if (fsf->type == 0) {
		R_LOG_ERROR ("squashfs: Unknown file type. This is a bug");
		sqsh_close (file);
		r_fs_file_free (fsf);
		return -1;
	}
	r_list_append (list, fsf);

	free (name);
	sqsh_close (file);
	return 0;
}

static RList *fs_squashfs_dir(RFSRoot *root, const char *path, int view /*ignored*/) {
	int err = 0;
	struct SqshArchive *archive = root->ptr;
	struct SqshFile *file = sqsh_open (archive, path, &err);
	if (!file) {
		R_LOG_ERROR ("squashfs: %s", sqsh_error_str (err));
		return NULL;
	}
	struct SqshDirectoryIterator *it = sqsh_directory_iterator_new (file, &err);
	if (err < 0) {
		sqsh_close (file);
		R_LOG_ERROR ("squashfs: %s", sqsh_error_str (err));
		return NULL;
	}
	RList *list = r_list_new ();
	if (!list) {
		sqsh_close (file);
		return NULL;
	}

	while (sqsh_directory_iterator_next (it, &err)) {
		int err2 = append_file (list, it);
		if (err2 != 0) {
			break;
		}
	}
	if (err != 0) {
		R_LOG_ERROR ("squashfs: %s", sqsh_error_str (err));
		r_list_free (list);
		sqsh_directory_iterator_free (it);
		sqsh_close (file);
		return NULL;
	}

	sqsh_directory_iterator_free (it);
	sqsh_close (file);
	return list;
}

static bool fs_squashfs_mount(RFSRoot *root) {
	int err = 0;
	RIOMap *map = root->iob.map_get_at (root->iob.io, 0);
	if (!map) {
		R_LOG_ERROR ("no map");
		return NULL;
	}
	int size = r_itv_size (map->itv);

	const struct SqshConfig cfg = {
		.source_mapper = &r_sqsh_mapper,
		.archive_offset = root->delta,
		.source_size = size,
	};

	struct SqshArchive *archive = sqsh_archive_open (root, &cfg, &err);
	if (err < 0) {
		R_LOG_ERROR ("squashfs: %s", sqsh_error_str (err));
		return false;
	}
	root->ptr = archive;
	return true;
}

static void fs_squashfs_umount(RFSRoot *root) {
	struct SqshArchive *archive = root->ptr;
	sqsh_archive_close (archive);
	root->ptr = NULL;
}

RFSPlugin r_fs_plugin_squashfs = {
	.meta = {
		.name = "squashfs",
		.desc = "squashfs filesystem (libsqsh)",
		.license = "MIT",
		.author = "Enno Boland",
	},
	.open = fs_squashfs_open,
	.read = fs_squashfs_read,
	.close = fs_squashfs_close,
	.dir = fs_squashfs_dir,
	.mount = fs_squashfs_mount,
	.umount = fs_squashfs_umount,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_squashfs,
	.version = R2_VERSION
};
#endif

#else
RFSPlugin r_fs_plugin_squashfs = {
	.meta = {0}, 0
};
#endif
