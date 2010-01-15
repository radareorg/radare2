#ifndef _LIB_R_IO_H_
#define _LIB_R_IO_H_

#include "r_types.h"
#include "list.h"

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
} rIoMap;

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
} rIoUndo;

typedef struct r_io_undo_w_t {
	int set;
	ut64 off;
	ut8 *o;   /* old data */
	ut8 *n;   /* new data */
	int len;  /* length */
	struct list_head list;
} rIoUndoWrite;

typedef struct r_io_t {
	int fd;
	int enforce_rwx;
	int enforce_seek;
	int cached;
	int cached_read;
	ut64 seek;
	char *redirect;
	/* write mask */
	void (*printf)(const char *str, ...);
	int write_mask_fd;
	ut8 *write_mask_buf;
	int write_mask_len;
	struct r_io_handle_t *plugin;
	struct r_io_undo_t undo;
	struct list_head io_list;
	ut64 last_align;
	struct list_head sections;
	/* maps */
	struct list_head maps;
        struct list_head desc;
	struct list_head cache;
} rIo;

//struct r_io_handle_fd_t {
// ... store io changes here
//};

typedef struct r_io_handle_t {
        void *handle;
        char *name;
        char *desc;
        void *widget;
        int (*init)();
	struct r_io_undo_t undo;
        struct debug_t *debug; // ???
        int (*system)(struct r_io_t *io, int fd, const char *);
        int (*open)(struct r_io_t *io, const char *, int rw, int mode);
        int (*read)(struct r_io_t *io, int fd, ut8 *buf, int count);
        ut64 (*lseek)(struct r_io_t *io, int fildes, ut64 offset, int whence);
        int (*write)(struct r_io_t *io, int fd, const ut8 *buf, int count);
        int (*close)(struct r_io_t *io, int fd);
        int (*resize)(struct r_io_t *io, int fd, ut64 size);
        int (*handle_open)(struct r_io_t *io, const char *);
        //int (*handle_fd)(struct r_io_t *, int);
	int fds[R_IO_NFDS];
} rIoHandle;

typedef struct r_io_list_t {
	struct r_io_handle_t *plugin;
	struct list_head list;
} rIoList;

/* compile time dependency */
typedef struct r_io_bind_t {
	int init;
	//int fd;
	struct r_io_t *io;
	int (*set_fd)(struct r_io_t *io, int fd);
	int (*read_at)(struct r_io_t *io, ut64 addr, ut8 *buf, int size);
	int (*write_at)(struct r_io_t *io, ut64 addr, const ut8 *buf, int size);
} rIoBind;

/* sections */
struct r_io_section_t {
	char name[256];
	ut64 from;
	ut64 to;
	ut64 vaddr;
	ut64 paddr; // offset on disk
	int rwx;
	struct list_head list;
};

struct r_io_cache_t {
	ut64 from;
	ut64 to;
	int size;
	ut8 *data;
	struct list_head list;
};

typedef struct r_io_desc_t {
	int fd;
	int flags;
        char name[4096];
	struct r_io_handle_t *handle;
        struct list_head list;
} rIoDesc;

#ifdef R_API
#define r_io_bind_init(x) memset(&x,0,sizeof(x))
/* io/handle.c */
R_API struct r_io_t *r_io_new();
R_API struct r_io_t *r_io_free(struct r_io_t *io);
R_API int r_io_handle_init(struct r_io_t *io);
R_API int r_io_handle_open(struct r_io_t *io, int fd, struct r_io_handle_t *plugin);
R_API int r_io_handle_close(struct r_io_t *io, int fd, struct r_io_handle_t *plugin);
R_API int r_io_handle_generate(struct r_io_t *io);
R_API int r_io_handle_add(struct r_io_t *io, struct r_io_handle_t *plugin);
R_API int r_io_handle_list(struct r_io_t *io);
// TODO: _del ??
R_API struct r_io_handle_t *r_io_handle_resolve(struct r_io_t *io, const char *filename);
R_API struct r_io_handle_t *r_io_handle_resolve_fd(struct r_io_t *io, int fd);

/* io/io.c */
R_API struct r_io_t* r_io_init(struct r_io_t *io);
R_API int r_io_set_write_mask(struct r_io_t *io, const ut8 *buf, int len);
R_API int r_io_open(struct r_io_t *io, const char *file, int flags, int mode);
R_API int r_io_open_as(struct r_io_t *io, const char *urihandler, const char *file, int flags, int mode);
R_API int r_io_redirect(struct r_io_t *io, const char *file);
R_API int r_io_set_fd(struct r_io_t *io, int fd);
R_API struct r_buf_t *r_io_read_buf(struct r_io_t *io, ut64 addr, int len);
R_API int r_io_read(struct r_io_t *io, ut8 *buf, int len);
R_API int r_io_read_at(struct r_io_t *io, ut64 addr, ut8 *buf, int len);
R_API ut64 r_io_read_i(struct r_io_t *io, ut64 addr, int sz, int endian);
R_API int r_io_write(struct r_io_t *io, const ut8 *buf, int len);
R_API int r_io_write_at(struct r_io_t *io, ut64 addr, const ut8 *buf, int len);
R_API ut64 r_io_seek(struct r_io_t *io, ut64 offset, int whence);
R_API int r_io_system(struct r_io_t *io,  const char *cmd);
R_API int r_io_close(struct r_io_t *io, int fd);
R_API ut64 r_io_size(struct r_io_t *io, int fd);

/* io/cache.c */
R_API void r_io_cache_enable(struct r_io_t *io, int read, int write);
R_API void r_io_cache_init(struct r_io_t *io);
R_API int r_io_cache_write(struct r_io_t *io, ut64 addr, const ut8 *buf, int len);
R_API int r_io_cache_read(struct r_io_t *io, ut64 addr, ut8 *buf, int len);

/* io/bind.c */
R_API int r_io_bind(struct r_io_t *io, struct r_io_bind_t *bnd);

/* io/map.c */
R_API void r_io_map_init(struct r_io_t *io);
R_API int r_io_map_add(struct r_io_t *io, int fd, int flags, ut64 delta, ut64 offset, ut64 size);
R_API int r_io_map_del(struct r_io_t *io, int fd);
R_API int r_io_map_list(struct r_io_t *io);
R_API int r_io_map(struct r_io_t *io, const char *file, ut64 offset);
R_API int r_io_map_read_at(struct r_io_t *io, ut64 off, ut8 *buf, int len);
//R_API int r_io_map_read_rest(struct r_io_t *io, ut64 off, ut8 *buf, ut64 len);
R_API int r_io_map_write_at(struct r_io_t *io, ut64 off, const ut8 *buf, int len);

R_API int r_io_section_rm(struct r_io_t *io, int idx);
R_API void r_io_section_add(struct r_io_t *io, ut64 from, ut64 to, ut64 vaddr, ut64 physical, int rwx, const char *comment);
R_API void r_io_section_set(struct r_io_t *io, ut64 from, ut64 to, ut64 vaddr, ut64 physical, int rwx, const char *comment);
R_API void r_io_section_list(struct r_io_t *io, ut64 addr, int rad);
R_API struct r_io_section_t * r_io_section_get(struct r_io_t *io, ut64 addr);
R_API void r_io_section_list_visual(struct r_io_t *io, ut64 seek, ut64 len);
R_API ut64 r_io_section_get_vaddr(struct r_io_t *io, ut64 addr);
R_API ut64 r_io_section_get_paddr(struct r_io_t *io, ut64 addr);
R_API int r_io_section_get_rwx(struct r_io_t *io, ut64 addr);
R_API struct r_io_section_t * r_io_section_get_i(struct r_io_t *io, int idx);
R_API void r_io_section_init(struct r_io_t *io);
R_API int r_io_section_overlaps(struct r_io_t *io, struct r_io_section_t *s);
R_API ut64 r_io_section_align(struct r_io_t *io, ut64 addr, ut64 vaddr, ut64 paddr);

R_API int r_io_desc_init(struct r_io_t *io);
R_API int r_io_desc_add(struct r_io_t *io, int fd, const char *file, int flags, struct r_io_handle_t *handle);
R_API int r_io_desc_del(struct r_io_t *io, int fd);
R_API struct r_io_desc_t *r_io_desc_get(struct r_io_t *io, int fd);
R_API int r_io_desc_generate(struct r_io_t *io);

/* undo api */
// track seeks and writes
// TODO: needs cleanup..kinda big?
R_API int r_io_undo_init(struct r_io_t *io);
R_API void r_io_undo_enable(struct r_io_t *io, int seek, int write);
/* seek undo */
R_API void r_io_sundo(struct r_io_t *io);
R_API ut64 r_io_sundo_last(struct r_io_t *io);
R_API void r_io_sundo_redo(struct r_io_t *io);
R_API void r_io_sundo_push(struct r_io_t *io);
R_API void r_io_sundo_reset(struct r_io_t *io);
R_API void r_io_sundo_list(struct r_io_t *io);
/* write undo */
R_API void r_io_wundo_new(struct r_io_t *io, ut64 off, const ut8 *data, int len);
R_API void r_io_wundo_clear(struct r_io_t *io);
R_API int r_io_wundo_size(struct r_io_t *io);
R_API void r_io_wundo_list(struct r_io_t *io);
R_API int r_io_wundo_set_t(struct r_io_t *io, struct r_io_undo_w_t *u, int set) ;
R_API void r_io_wundo_set_all(struct r_io_t *io, int set);
R_API int r_io_wundo_set(struct r_io_t *io, int n, int set);
#endif

#if 0
#define CB_READ int (*cb_read)(struct r_io_t *user, int pid, ut64 addr, ut8 *buf, int len)
#define CB_WRITE int (*cb_write)(struct r_io_t *user, int pid, ut64 addr, const ut8 *buf, int len)
#define CB_IO int (*cb_io)(void *user, CB_READ, CB_WRITE)
R_API int r_io_hook(struct r_io_t *io, CB_IO);
#endif
/* plugins */
extern struct r_io_handle_t r_io_plugin_malloc;
extern struct r_io_handle_t r_io_plugin_ptrace;
extern struct r_io_handle_t r_io_plugin_debug;
extern struct r_io_handle_t r_io_plugin_shm;

#endif
