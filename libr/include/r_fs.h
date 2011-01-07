#ifndef _LIB_R_FS_H_
#define _LIB_R_FS_H_

#include <r_types.h>
#include <r_io.h>

typedef struct r_fs_t {
	RIOBind iob;
	RList *plugins;
	RList *mounts;
} RFS;

typedef struct r_fs_plugin_t {
	const char *name;
} RFSPlugin;

typedef struct r_fs_mount_t {
	const char *path;
	RFSPlugin *plugin;
} RFSRoot;

#endif
