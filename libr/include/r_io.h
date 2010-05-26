#ifndef _LIB_R_IO_H_
#define _LIB_R_IO_H_

#include <r_types.h>
#include <r_util.h>
#include <list.h>

#define R_IO_READ  4
#define R_IO_WRITE 2
#define R_IO_EXEC  1

#define R_IO_SEEK_SET 0
#define R_IO_SEEK_CUR 1
#define R_IO_SEEK_END 2

#define R_IO_NFDS 32

#define IO_MAP_N 128
typedef struct r_io_map_t {
        int fd;
	int flags;
        ut64 delta;
        ut64 from;
        ut64 to;
        struct list_head list;
} RIOMap;

/* stores write and seek changes */
#define R_IO_UNDOS 64
typedef struct r_io_undo_t {
	int s_enable;
	int w_enable;
	/* write stuff */
	struct list_head w_list;
	int w_init;
	/* seek stuff */
	ut64 seek[R_IO_UNDOS];
	int fd[R_IO_UNDOS];
	int idx;
	int limit;
} RIOUndo;

typedef struct r_io_undo_w_t {
	int set;
	ut64 off;
	ut8 *o;   /* old data */
	ut8 *n;   /* new data */
	int len;  /* length */
	struct list_head list;
} RIOUndoWrite;

typedef struct r_io_t {
	int fd;
	int enforce_rwx;
	int enforce_seek;
	int cached;
	int cached_read;
	ut64 off;
	int va;
	char *redirect;
	/* write mask */
	void (*printf)(const char *str, ...);
	int write_mask_fd;
	ut8 *write_mask_buf;
	int write_mask_len;
	struct r_io_plugin_t *plugin;
	struct r_io_undo_t undo;
	struct list_head io_list;
	struct list_head sections;
	/* maps */
	struct list_head maps;
	struct list_head desc;
	struct list_head cache;
} RIO;

//struct r_io_plugin_fd_t {
// ... store io changes here
//};

typedef struct r_io_plugin_t {
        void *plugin;
        char *name;
        char *desc;
        void *widget;
        int (*init)();
	struct r_io_undo_t undo;
        struct debug_t *debug; // ???
        int (*system)(RIO *io, int fd, const char *);
        int (*open)(RIO *io, const char *, int rw, int mode);
        int (*read)(RIO *io, int fd, ut8 *buf, int count);
        ut64 (*lseek)(RIO *io, int fildes, ut64 offset, int whence);
        int (*write)(RIO *io, int fd, const ut8 *buf, int count);
        int (*close)(RIO *io, int fd);
        int (*resize)(RIO *io, int fd, ut64 size);
        int (*plugin_open)(RIO *io, const char *);
        //int (*plugin_fd)(RIO *, int);
	int fds[R_IO_NFDS];
} RIOPlugin;

typedef struct r_io_list_t {
	struct r_io_plugin_t *plugin;
	struct list_head list;
} RIOList;

/* TODO: find better name... RIOSetFd_Callback? ..Func? .. too camels here */
typedef int (*RIOSetFd)(RIO *io, int fd);
typedef int (*RIOReadAt)(RIO *io, ut64 addr, ut8 *buf, int size);
typedef int (*RIOWriteAt)(RIO *io, ut64 addr, const ut8 *buf, int size);

/* compile time dependency */
typedef struct r_io_bind_t {
	int init;
	RIO *io;
	RIOSetFd set_fd;
	RIOReadAt read_at;
	RIOWriteAt write_at;
} RIOBind;

/* sections */
typedef struct r_io_section_t {
	char name[256];
	ut64 offset;
	ut64 vaddr;
	ut64 size;
	ut64 vsize;
	int rwx;
	struct list_head list;
} RIOSection;

typedef struct r_io_cache_t {
	ut64 from;
	ut64 to;
	int size;
	ut8 *data;
	struct list_head list;
} RIOCache;

typedef struct r_io_desc_t {
	int fd;
	int flags;
	char name[4096];
	struct r_io_plugin_t *plugin;
	struct list_head list;
} RIODesc;

#ifdef R_API
#define r_io_bind_init(x) memset(&x,0,sizeof(x))

/* io/plugin.c */
R_API RIO *r_io_new();
R_API RIO *r_io_free(RIO *io);
R_API int r_io_plugin_init(RIO *io);
R_API int r_io_plugin_open(RIO *io, int fd, struct r_io_plugin_t *plugin);
R_API int r_io_plugin_close(RIO *io, int fd, struct r_io_plugin_t *plugin);
R_API int r_io_plugin_generate(RIO *io);
R_API int r_io_plugin_add(RIO *io, struct r_io_plugin_t *plugin);
R_API int r_io_plugin_list(RIO *io);
// TODO: _del ??
R_API struct r_io_plugin_t *r_io_plugin_resolve(RIO *io, const char *filename);
R_API struct r_io_plugin_t *r_io_plugin_resolve_fd(RIO *io, int fd);

/* io/io.c */
R_API int r_io_set_write_mask(RIO *io, const ut8 *buf, int len);
R_API int r_io_open(RIO *io, const char *file, int flags, int mode);
R_API int r_io_open_as(RIO *io, const char *urihandler, const char *file, int flags, int mode);
R_API int r_io_redirect(RIO *io, const char *file);
R_API int r_io_set_fd(RIO *io, int fd);
R_API RBuffer *r_io_read_buf(RIO *io, ut64 addr, int len);
R_API int r_io_read(RIO *io, ut8 *buf, int len);
R_API int r_io_read_at(RIO *io, ut64 addr, ut8 *buf, int len);
R_API ut64 r_io_read_i(RIO *io, ut64 addr, int sz, int endian);
R_API int r_io_write(RIO *io, const ut8 *buf, int len);
R_API int r_io_write_at(RIO *io, ut64 addr, const ut8 *buf, int len);
R_API ut64 r_io_seek(RIO *io, ut64 offset, int whence);
R_API int r_io_system(RIO *io,  const char *cmd);
R_API int r_io_close(RIO *io, int fd);
R_API ut64 r_io_size(RIO *io, int fd);

/* io/cache.c */
R_API void r_io_cache_commit(RIO *io);
R_API void r_io_cache_enable(RIO *io, int read, int write);
R_API void r_io_cache_init(RIO *io);
R_API int r_io_cache_list(struct r_io_t *io, int rad);
R_API void r_io_cache_reset(struct r_io_t *io, int set);
R_API int r_io_cache_write(RIO *io, ut64 addr, const ut8 *buf, int len);
R_API int r_io_cache_read(RIO *io, ut64 addr, ut8 *buf, int len);

/* io/bind.c */
R_API int r_io_bind(RIO *io, struct r_io_bind_t *bnd);

/* io/map.c */
R_API void r_io_map_init(RIO *io);
R_API int r_io_map_add(RIO *io, int fd, int flags, ut64 delta, ut64 offset, ut64 size);
R_API int r_io_map_del(RIO *io, int fd);
R_API int r_io_map_list(RIO *io);
R_API int r_io_map(RIO *io, const char *file, ut64 offset);
R_API int r_io_map_read_at(RIO *io, ut64 off, ut8 *buf, int len);
//R_API int r_io_map_read_rest(RIO *io, ut64 off, ut8 *buf, ut64 len);
R_API int r_io_map_write_at(RIO *io, ut64 off, const ut8 *buf, int len);
R_API RIOMap *r_io_map_resolve(RIO *io, int fd);

/* io/section.c */
R_API void r_io_section_init(RIO *io);
R_API void r_io_section_add(RIO *io, ut64 offset, ut64 vaddr, ut64 size, ut64 vsize, int rwx, const char *name);
R_API struct r_io_section_t *r_io_section_get_i(RIO *io, int idx);
R_API int r_io_section_rm(RIO *io, int idx);
R_API void r_io_section_list(RIO *io, ut64 offset, int rad);
R_API void r_io_section_list_visual(RIO *io, ut64 seek, ut64 len);
R_API struct r_io_section_t *r_io_section_get(RIO *io, ut64 offset);
R_API ut64 r_io_section_get_offset(RIO *io, ut64 offset);
R_API ut64 r_io_section_get_vaddr(RIO *io, ut64 offset);
R_API int r_io_section_get_rwx(RIO *io, ut64 offset);
R_API int r_io_section_overlaps(RIO *io, struct r_io_section_t *s);
R_API ut64 r_io_section_vaddr_to_offset(RIO *io, ut64 vaddr);
R_API ut64 r_io_section_offset_to_vaddr(RIO *io, ut64 offset);

/* undo api */
// track seeks and writes
// TODO: needs cleanup..kinda big?
R_API int r_io_undo_init(RIO *io);
R_API void r_io_undo_enable(RIO *io, int seek, int write);
/* seek undo */
R_API int r_io_sundo(RIO *io);
R_API ut64 r_io_sundo_last(RIO *io);
R_API int r_io_sundo_redo(RIO *io);
R_API void r_io_sundo_push(RIO *io);
R_API void r_io_sundo_reset(RIO *io);
R_API void r_io_sundo_list(RIO *io);
/* write undo */
R_API void r_io_wundo_new(RIO *io, ut64 off, const ut8 *data, int len);
R_API void r_io_wundo_clear(RIO *io);
R_API int r_io_wundo_size(RIO *io);
R_API void r_io_wundo_list(RIO *io);
R_API int r_io_wundo_set_t(RIO *io, struct r_io_undo_w_t *u, int set) ;
R_API void r_io_wundo_set_all(RIO *io, int set);
R_API int r_io_wundo_set(RIO *io, int n, int set);

/* io/desc.c */
R_API int r_io_desc_init(RIO *io);
R_API int r_io_desc_add(RIO *io, int fd, const char *file, int flags, struct r_io_plugin_t *plugin);
R_API int r_io_desc_del(RIO *io, int fd);
R_API struct r_io_desc_t *r_io_desc_get(RIO *io, int fd);
R_API int r_io_desc_generate(RIO *io);


/* plugins */
extern struct r_io_plugin_t r_io_plugin_procpid;
extern struct r_io_plugin_t r_io_plugin_malloc;
extern struct r_io_plugin_t r_io_plugin_ptrace;
extern struct r_io_plugin_t r_io_plugin_w32dbg;
extern struct r_io_plugin_t r_io_plugin_mach;
extern struct r_io_plugin_t r_io_plugin_debug;
extern struct r_io_plugin_t r_io_plugin_shm;
#endif

#if 0
#define CB_READ int (*cb_read)(RIO *user, int pid, ut64 addr, ut8 *buf, int len)
#define CB_WRITE int (*cb_write)(RIO *user, int pid, ut64 addr, const ut8 *buf, int len)
#define CB_IO int (*cb_io)(void *user, CB_READ, CB_WRITE)
R_API int r_io_hook(RIO *io, CB_IO);
#endif

#endif
