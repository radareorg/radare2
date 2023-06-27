#ifndef R2_FS_H
#define R2_FS_H

#include <r_types.h>
#include <r_list.h>
#include <r_bind.h> // RCoreBind
#include <r_io.h> // RIOBind
#include <r_util.h>
#include <r_cons.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER (r_fs);

struct r_fs_plugin_t;
struct r_fs_root_t;
struct r_fs_t;

typedef struct r_fs_t {
	RIOBind iob;
	RCoreBind cob;
	RConsBind csb;
	RList /*<RFSPlugin>*/ *plugins;
	RList /*<RFSRoot>*/ *roots;
	int view;
	void *ptr;
} RFS;

typedef struct r_fs_partition_plugin_t {
	const char *name;
} RFSPartitionPlugin;

typedef struct r_fs_file_t {
	char *name;
	char *path;
	ut64 off;
	ut32 size;
	ut8 *data;
	void *ctx;
	char type;
	ut64 time;
	struct r_fs_plugin_t *p;
	struct r_fs_root_t *root;
	void *ptr; // internal pointer
} RFSFile;

typedef struct r_fs_root_t {
	char *path;
	ut64 delta;
	struct r_fs_plugin_t *p;
	void *ptr;
	// TODO: deprecate
	RIOBind iob;
	RCoreBind cob;
} RFSRoot;

typedef struct r_fs_plugin_t {
	const char *name;
	const char *desc;
	const char *author;
	const char *license;
	RFSFile* (*slurp)(RFSRoot *root, const char *path);
	RFSFile* (*open)(RFSRoot *root, const char *path, bool create);
	bool (*unlink)(RFSRoot *root, const char *path);
	int (*write)(RFSFile *fs, ut64 addr, const ut8 *data, int len);
	int (*read)(RFSFile *fs, ut64 addr, int len);
	void (*close)(RFSFile *fs);
	RList *(*dir)(RFSRoot *root, const char *path, int view);
	void (*init)(void);
	void (*fini)(void);
	bool (*mount)(RFSRoot *root);
	void (*umount)(RFSRoot *root);
} RFSPlugin;

typedef struct r_fs_partition_t {
	int number;
	ut64 start;
	ut64 length;
	int index;
	int type;
} RFSPartition;

typedef struct r_fs_shell_t {
	char *cwd;
	void (*set_prompt)(const char *prompt);
	const char* (*readline)(void);
	int (*hist_add)(const char *line);
} RFSShell;

typedef struct r_fs_type_t {
	const char * const name;
	int bufoff;
	const char * const buf;
	int buflen;
	int byteoff;
	ut8 byte;
	int bytelen;
} RFSType;

static inline RFSShell *r_fs_shell_new(void) {
	return R_NEW0 (RFSShell);
}

static inline void r_fs_shell_free(RFSShell *s) {
	free (s->cwd);
	free (s);
}

#define R_FS_FILE_TYPE_MOUNTPOINT 'm'
#define R_FS_FILE_TYPE_DIRECTORY 'd'
#define R_FS_FILE_TYPE_REGULAR 'r'
#define R_FS_FILE_TYPE_DELETED 'x'
#define R_FS_FILE_TYPE_SPECIAL 's'
#define R_FS_FILE_TYPE_MOUNT 'm'

typedef int (*RFSPartitionIterator)(void *disk, void *ptr, void *user);
typedef struct r_fs_partition_type_t {
	const char *name;
	void *ptr; // grub_msdos_partition_map
	RFSPartitionIterator iterate;
	//RFSPartitionIterator parhook;
} RFSPartitionType;
#define R_FS_PARTITIONS_LENGTH (int)(sizeof (partitions)/sizeof (RFSPartitionType)-1)

enum {
	R_FS_VIEW_NORMAL = 0,
	R_FS_VIEW_DELETED = 1,
	R_FS_VIEW_SPECIAL = 2,
	R_FS_VIEW_ALL = 0xff,
};

#ifdef R_API
R_API RFS *r_fs_new(void);
R_API void r_fs_free(RFS* fs);

R_API void r_fs_view(RFS* fs, int view);
R_API bool r_fs_plugin_add(RFS *fs, RFSPlugin *p);
R_API bool r_fs_plugin_remove(RFS *fs, RFSPlugin *p);
R_API void r_fs_del(RFS *fs, RFSPlugin *p);

R_API RFSRoot *r_fs_mount(RFS* fs, const char *fstype, const char *path, ut64 delta);
R_API bool r_fs_umount(RFS* fs, const char *path);

R_API RFSFile *r_fs_open(RFS* fs, const char *path, bool create);
R_API void r_fs_close(RFS* fs, RFSFile *file);
R_API int r_fs_read(RFS* fs, RFSFile *file, ut64 addr, int len);
R_API int r_fs_write(RFS* fs, RFSFile* file, ut64 addr, const ut8 *data, int len);
R_API RFSFile *r_fs_slurp(RFS* fs, const char *path);
R_API RList *r_fs_dir(RFS* fs, const char *path);
R_API bool r_fs_dir_dump(RFS* fs, const char *path, const char *name);

R_API RList *r_fs_find_name(RFS* fs, const char *name, const char *glob);
R_API RList *r_fs_find_off(RFS* fs, const char *name, ut64 off);
R_API RList *r_fs_partitions(RFS* fs, const char *ptype, ut64 delta);

R_API R_MUSTUSE const RFSType *r_fs_type_index(int i);

R_API char *r_fs_name(RFS *fs, ut64 offset);
R_API bool r_fs_check(RFS *fs, const char *p);
R_API bool r_fs_shell(RFSShell *shell, RFS *fs, const char *root);

/* file.c */
R_API RFSFile *r_fs_file_new(RFSRoot *root, const char *path);
R_API void r_fs_file_free(RFSFile *file);
R_API char* r_fs_file_copy_abs_path(RFSFile* file);

// root
R_API RList *r_fs_root(RFS *fs, const char *path);
R_API RFSRoot *r_fs_root_new(const char *path, ut64 delta);
R_API void r_fs_root_free(RFSRoot *root);
R_API RFSPartition *r_fs_partition_new(int num, ut64 start, ut64 length);
R_API void r_fs_partition_free(RFSPartition *p);
R_API const char *r_fs_partition_type(const char *part, int type);
R_API const char *r_fs_partition_type_get(int n);

/* plugins */
extern RFSPlugin r_fs_plugin_affs;
extern RFSPlugin r_fs_plugin_afs;
extern RFSPlugin r_fs_plugin_btrfs;
extern RFSPlugin r_fs_plugin_cpio;
extern RFSPlugin r_fs_plugin_ext2;
extern RFSPlugin r_fs_plugin_fat;
extern RFSPlugin r_fs_plugin_fb;
extern RFSPlugin r_fs_plugin_hfs;
extern RFSPlugin r_fs_plugin_hfsplus;
extern RFSPlugin r_fs_plugin_io;
extern RFSPlugin r_fs_plugin_iso9660;
extern RFSPlugin r_fs_plugin_jfs;
extern RFSPlugin r_fs_plugin_minix;
extern RFSPlugin r_fs_plugin_ntfs;
extern RFSPlugin r_fs_plugin_posix;
extern RFSPlugin r_fs_plugin_r2;
extern RFSPlugin r_fs_plugin_reiserfs;
extern RFSPlugin r_fs_plugin_sfs;
extern RFSPlugin r_fs_plugin_tar;
extern RFSPlugin r_fs_plugin_tar;
extern RFSPlugin r_fs_plugin_udf;
extern RFSPlugin r_fs_plugin_ufs2;
extern RFSPlugin r_fs_plugin_ufs;
extern RFSPlugin r_fs_plugin_xfs;
extern RFSPlugin r_fs_plugin_zip;
#endif

#ifdef __cplusplus
}
#endif

#endif
