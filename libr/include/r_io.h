#ifndef _LIB_R_IO_H_
#define _LIB_R_IO_H_

#include <r_types.h>
#include <r_util.h>
#include <r_socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#define R_IO_READ  4
#define R_IO_WRITE 2
#define R_IO_EXEC  1
#define R_IO_RW R_IO_READ | R_IO_WRITE

#define R_IO_SEEK_SET 0
#define R_IO_SEEK_CUR 1
#define R_IO_SEEK_END 2

#define R_IO_NFDS 32

#define RMT_MAX    4096
#define RMT_OPEN   0x01
#define RMT_READ   0x02
#define RMT_WRITE  0x03
#define RMT_SEEK   0x04
#define RMT_CLOSE  0x05
#define RMT_SYSTEM 0x06
#define RMT_CMD    0x07
#define RMT_REPLY  0x80

R_LIB_VERSION_HEADER (r_io);
// #define RMT_DLDIR "/tmp/$USER/r2"
// #define RMT_UPLOAD 0x08
// #define RMT_DOWNLOAD 0x09
// - upload a file giving a chksum

#define IO_MAP_N 128
typedef struct r_io_map_t {
	int fd;
	int flags;
	ut64 delta;
	ut64 from;
	ut64 to;
} RIOMap;

typedef struct r_io_section_t {
	char name[64]; // use strpool
	ut64 offset;
	ut64 vaddr;
	ut64 size;
	ut64 vsize;
	int rwx;
	int id;
	/* */
	int arch;
	int bits;
} RIOSection;

typedef struct r_io_desc_t {
	int fd;
	int flags;
	int state;
	char *name;
	void *data;
	struct r_io_plugin_t *plugin;
} RIODesc;

typedef struct {
	RSocket *fd;
	RSocket *client;
	int listener;
} RIORap;

// enum?
#define R_IO_DESC_TYPE_OPENED 1
#define R_IO_DESC_TYPE_CLOSED 0

/* stores write and seek changes */
#define R_IO_UNDOS 64
typedef struct r_io_undo_t {
	int s_enable;
	int w_enable;
	/* write stuff */
	RList *w_list;
	int w_init;
	/* seek stuff */
	int idx;
	int undos; /* available undos */
	int redos; /* available redos */
	ut64 seek[R_IO_UNDOS];
	/*int fd[R_IO_UNDOS]; // XXX: Must be RIODesc* */
} RIOUndo;

typedef struct r_io_undo_w_t {
	int set;
	ut64 off;
	ut8 *o;   /* old data */
	ut8 *n;   /* new data */
	int len;  /* length */
} RIOUndoWrite;

typedef struct r_io_t {
	RIODesc *fd;
	int enforce_rwx;
	int enforce_seek;
	int cached;
	int bits;
	int cached_read;
	ut64 off;
	int debug;
	int raised;
	int va;
	char *redirect;
	/* write mask */
	void (*printf)(const char *str, ...);
	int write_mask_fd;
	ut8 *write_mask_buf;
	int write_mask_len;
	struct r_io_plugin_t *plugin;
	RIOUndo undo;
	//RList *iolist;
	struct list_head io_list;
	RList *sections;
	int next_section_id;
	RIOSection *section; /* current section (cache) */
	/* maps */
	RList *maps; /*<RIOMap>*/
	RList *desc;
	RList *cache;
	int zeromap;
	//XXX: Need by rap
	void *user;
	int (*core_cmd_cb)(void *user, const char *str);
	RCache *buffer;
	int buffer_enabled;
} RIO;

typedef struct r_io_plugin_t {
        void *plugin;
        char *name;
        char *desc;
        void *widget;
	int (*listener)(RIODesc *io);
        int (*init)();
	RIOUndo undo;
        struct r_debug_t *debug;
        int (*is_file_opened)(RIO *io, RIODesc *fd, const char *);
        int (*system)(RIO *io, RIODesc *fd, const char *);
        RIODesc* (*open)(RIO *io, const char *, int rw, int mode);
        int (*read)(RIO *io, RIODesc *fd, ut8 *buf, int count);
        ut64 (*lseek)(RIO *io, RIODesc *fd, ut64 offset, int whence);
        int (*write)(RIO *io, RIODesc *fd, const ut8 *buf, int count);
        int (*close)(RIODesc *desc);
        int (*resize)(RIO *io, RIODesc *fd, ut64 size);
        int (*accept)(RIO *io, RIODesc *desc, int fd);
        int (*create)(RIO *io, const char *file, int mode, int type);
        int (*plugin_open)(RIO *io, const char *);
} RIOPlugin;

typedef struct r_io_list_t {
	RIOPlugin *plugin;
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
	RIOSetFd set_fd; // XXX : this is conceptually broken with the new RIODesc foo
	RIOReadAt read_at;
	RIOWriteAt write_at;
} RIOBind;

typedef struct r_io_cache_t {
	ut64 from;
	ut64 to;
	int size;
	ut8 *data;
} RIOCache;

// XXX: HACK this must be io->desc_new() maybe?
#define RETURN_IO_DESC_NEW(fplugin,ffd,fname,fflags,mode,fdata) { \
	if (!fname) return NULL; \
	RIODesc *desc = R_NEW (RIODesc); \
	if (desc != NULL) { \
		desc->state = R_IO_DESC_TYPE_OPENED; \
		desc->name = strdup (fname); \
		if (desc->name != NULL) { \
			desc->plugin = fplugin; \
			desc->flags = fflags; \
			if (ffd == -2) { \
				desc->fd = ((size_t)desc)&0xffffff; \
			} else \
			if (ffd == -1) { \
				desc->fd = ((size_t)&desc)&0xffffff; \
			} else desc->fd = ffd; \
			desc->data = fdata; \
		} else { \
			free (desc); \
			desc = NULL; \
		} \
	} \
	/* free (fname); */ \
	return desc; \
}

#ifdef R_API
#define r_io_bind_init(x) memset(&x,0,sizeof(x))

/* io/plugin.c */
R_API RIO *r_io_new();
R_API RIO *r_io_free(RIO *io);
R_API int r_io_plugin_init(RIO *io);
R_API void r_io_raise (RIO *io, int fd);
R_API int r_io_plugin_open(RIO *io, int fd, RIOPlugin *plugin);
R_API int r_io_plugin_close(RIO *io, int fd, RIOPlugin *plugin);
R_API int r_io_plugin_generate(RIO *io);
R_API int r_io_plugin_add(RIO *io, RIOPlugin *plugin);
R_API int r_io_plugin_list(RIO *io);
R_API int r_io_is_listener(RIO *io);
// TODO: _del ??
R_API RIOPlugin *r_io_plugin_resolve(RIO *io, const char *filename);
R_API RIOPlugin *r_io_plugin_resolve_fd(RIO *io, int fd);

/* io/io.c */
R_API int r_io_set_write_mask(RIO *io, const ut8 *buf, int len);
R_API RIODesc *r_io_open(RIO *io, const char *file, int flags, int mode);
R_API RIODesc *r_io_open_as(RIO *io, const char *urihandler, const char *file, int flags, int mode);
R_API int r_io_redirect(RIO *io, const char *file);
R_API int r_io_set_fd(RIO *io, RIODesc *fd);
R_API int r_io_set_fdn(RIO *io, int fd);
R_API const ut8* r_io_get_raw (RIO *io, ut64 addr, int *len);
R_API RBuffer *r_io_read_buf(RIO *io, ut64 addr, int len);
R_API int r_io_read(RIO *io, ut8 *buf, int len);
R_API int r_io_read_at(RIO *io, ut64 addr, ut8 *buf, int len);
R_API ut64 r_io_read_i(RIO *io, ut64 addr, int sz, int endian);
R_API int r_io_write(RIO *io, const ut8 *buf, int len);
R_API int r_io_write_at(RIO *io, ut64 addr, const ut8 *buf, int len);
R_API ut64 r_io_seek(RIO *io, ut64 offset, int whence);
R_API int r_io_system(RIO *io,  const char *cmd);
R_API int r_io_close(RIO *io, RIODesc *fd);
R_API ut64 r_io_size(RIO *io); //, int fd);
R_API int r_io_resize(RIO *io, ut64 newsize);
R_API int r_io_accept(RIO *io, int fd);
R_API int r_io_shift(RIO *io, ut64 start, ut64 end, st64 move);
R_API int r_io_create (RIO *io, const char *file, int mode, int type);

/* io/cache.c */
R_API int r_io_cache_invalidate(RIO *io, ut64 from, ut64 to);
R_API void r_io_cache_commit(RIO *io);
R_API void r_io_cache_enable(RIO *io, int read, int write);
R_API void r_io_cache_init(RIO *io);
R_API int r_io_cache_list(RIO *io, int rad);
R_API void r_io_cache_reset(RIO *io, int set);
R_API int r_io_cache_write(RIO *io, ut64 addr, const ut8 *buf, int len);
R_API int r_io_cache_read(RIO *io, ut64 addr, ut8 *buf, int len);

/* io/bind.c */
R_API int r_io_bind(RIO *io, RIOBind *bnd);

/* io/map.c */
R_API void r_io_map_init(RIO *io);
R_API ut64 r_io_map_next(RIO *io, ut64 addr);
R_API RIOMap *r_io_map_add(RIO *io, int fd, int flags, ut64 delta, ut64 offset, ut64 size);
R_API int r_io_map_del_at(RIO *io, ut64 addr);
R_API RIOMap *r_io_map_get(RIO *io, ut64 addr);
R_API int r_io_map_del(RIO *io, int fd);
R_API int r_io_map(RIO *io, const char *file, ut64 offset);
R_API ut64 r_io_map_select(RIO *io, ut64 off);
//R_API int r_io_map_read_rest(RIO *io, ut64 off, ut8 *buf, ut64 len);
R_API RIOMap *r_io_map_resolve(RIO *io, int fd);

/* io/section.c */
R_API void r_io_section_init(RIO *io);
R_API void r_io_section_add(RIO *io, ut64 offset, ut64 vaddr, ut64 size, ut64 vsize, int rwx, const char *name);
R_API RIOSection *r_io_section_get_name(RIO *io, const char *name);
R_API RIOSection *r_io_section_get_i(RIO *io, int idx);
R_API RIOSection *r_io_section_getv(RIO *io, ut64 vaddr);
R_API RIOSection *r_io_section_vget(RIO *io, ut64 addr);
R_API int r_io_section_set_archbits(RIO *io, ut64 addr, const char *arch, int bits);
R_API const char *r_io_section_get_archbits(RIO* io, ut64 addr, int *bits);
R_API int r_io_section_rm(RIO *io, int idx);
R_API void r_io_section_list(RIO *io, ut64 offset, int rad);
R_API void r_io_section_list_visual(RIO *io, ut64 seek, ut64 len);
R_API RIOSection *r_io_section_get(RIO *io, ut64 offset);
R_API ut64 r_io_section_get_offset(RIO *io, ut64 offset);
R_API ut64 r_io_section_get_vaddr(RIO *io, ut64 offset);
R_API int r_io_section_get_rwx(RIO *io, ut64 offset);
R_API int r_io_section_overlaps(RIO *io, RIOSection *s);
R_API ut64 r_io_section_vaddr_to_offset(RIO *io, ut64 vaddr);
R_API ut64 r_io_section_offset_to_vaddr(RIO *io, ut64 offset);
R_API ut64 r_io_section_next(RIO *io, ut64 o);

/* undo api */
// track seeks and writes
// TODO: needs cleanup..kinda big?
R_API int r_io_undo_init(RIO *io);
R_API void r_io_undo_enable(RIO *io, int seek, int write);
/* seek undo */
R_API ut64 r_io_sundo(RIO *io, ut64 offset);
R_API ut64 r_io_sundo_redo(RIO *io);
R_API void r_io_sundo_push(RIO *io, ut64 off);
R_API void r_io_sundo_reset(RIO *io);
R_API void r_io_sundo_list(RIO *io);
/* write undo */
R_API void r_io_wundo_new(RIO *io, ut64 off, const ut8 *data, int len);
R_API void r_io_wundo_clear(RIO *io);
R_API int r_io_wundo_size(RIO *io);
R_API void r_io_wundo_list(RIO *io);
R_API int r_io_wundo_set_t(RIO *io, RIOUndoWrite *u, int set) ;
R_API void r_io_wundo_set_all(RIO *io, int set);
R_API int r_io_wundo_set(RIO *io, int n, int set);

/* io/desc.c */
R_API void r_io_desc_init(RIO *io);
R_API void r_io_desc_fini(RIO *io);
R_API RIODesc *r_io_desc_new(RIOPlugin *plugin, int fd, const char *name, int flags, int mode, void *data);
R_API void r_io_desc_free(RIODesc *desc);
R_API int r_io_desc_del(RIO *io, int fd);
R_API RIODesc *r_io_desc_get(RIO *io, int fd);
R_API int r_io_desc_add(RIO *io, RIODesc *desc);
R_API int r_io_desc_del(RIO *io, int fd);
R_API RIODesc *r_io_desc_get(RIO *io, int fd);
R_API ut64 r_io_desc_size(RIO *io, RIODesc *desc);
R_API ut64 r_io_fd_size(RIO *io, int fd);
//R_API int r_io_desc_generate(RIO *io);

/* buffer.c */
R_API void r_io_buffer_close(RIO* io);
R_API int r_io_buffer_load(RIO* io, ut64 addr, int len);
R_API const ut8* r_io_buffer_get (RIO *io, ut64 addr, int *len);
R_API int r_io_buffer_read (RIO *io, ut64 addr, ut8* buf, int len);

/* plugins */
extern RIOPlugin r_io_plugin_procpid;
extern RIOPlugin r_io_plugin_malloc;
extern RIOPlugin r_io_plugin_ptrace;
extern RIOPlugin r_io_plugin_w32dbg;
extern RIOPlugin r_io_plugin_mach;
extern RIOPlugin r_io_plugin_debug;
extern RIOPlugin r_io_plugin_shm;
extern RIOPlugin r_io_plugin_gdb;
extern RIOPlugin r_io_plugin_rap;
extern RIOPlugin r_io_plugin_http;
extern RIOPlugin r_io_plugin_haret;
extern RIOPlugin r_io_plugin_bfdbg;
extern RIOPlugin r_io_plugin_w32;
extern RIOPlugin r_io_plugin_ewf;
extern RIOPlugin r_io_plugin_zip;
extern RIOPlugin r_io_plugin_mmap;
extern RIOPlugin r_io_plugin_ihex;
#endif

#ifdef __cplusplus
}
#endif

#endif
