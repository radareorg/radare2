#ifndef _LIB_R_IO_H_
#define _LIB_R_IO_H_

#include "r_types.h"
#include "list.h"

#define R_IO_READ 0
#define R_IO_WRITE 1
#define R_IO_RDWR 2

#define R_IO_NFDS 32

#define R_IO_SEEK_SET 0
#define R_IO_SEEK_CUR 1
#define R_IO_SEEK_END 2

#define IO_MAP_N 32
struct r_io_maps_t {
        int fd;
        char file[128];
        ut64 from;
        ut64 to;
        struct list_head list;
};

/* stores write and seek changes */
#define R_IO_UNDOS 64
struct r_io_undo_t {
	struct list_head undo_w_list;
	int w_init;
	int w_lock;
	ut64 seek[R_IO_UNDOS];
	int fd[R_IO_UNDOS];
	int idx;
	int lim;
};

struct r_io_t {
	int fd;
	ut64 seek;
	char *redirect;
	/* write mask */
	int write_mask_fd;
	ut8 *write_mask_buf;
	int write_mask_len;
	struct r_io_handle_t *plugin;
	struct list_head io_list;
	ut64 last_align;
	struct list_head sections;
	struct list_head maps;
};

//struct r_io_handle_fd_t {
// ... store io changes here
//};

struct r_io_handle_t {
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
        int (*handle_open)(struct r_io_t *io, const char *);
        int (*handle_fd)(struct r_io_t *, int);
	int fds[R_IO_NFDS];
};

struct r_io_list_t {
	struct r_io_handle_t *plugin;
	struct list_head list;
};

/* io/handle.c */
struct r_io_t *r_io_new();
R_API struct r_io_t *r_io_free(struct r_io_t *io);
int r_io_handle_init(struct r_io_t *io);
int r_io_handle_open(struct r_io_t *io, int fd, struct r_io_handle_t *plugin);
int r_io_handle_close(struct r_io_t *io, int fd, struct r_io_handle_t *plugin);
int r_io_handle_generate(struct r_io_t *io);
int r_io_handle_add(struct r_io_t *io, struct r_io_handle_t *plugin);
int r_io_handle_list(struct r_io_t *io);
// TODO: _del ??
struct r_io_handle_t *r_io_handle_resolve(struct r_io_t *io, const char *filename);
struct r_io_handle_t *r_io_handle_resolve_fd(struct r_io_t *io, int fd);

/* io/io.c */
int r_io_init(struct r_io_t *io);
int r_io_set_write_mask(struct r_io_t *io, int fd, const ut8 *buf, int len);
int r_io_open(struct r_io_t *io, const char *file, int flags, int mode);
int r_io_redirect(struct r_io_t *io, const char *file);
int r_io_read(struct r_io_t *io, int fd, ut8 *buf, int len);
int r_io_write(struct r_io_t *io, int fd, const ut8 *buf, int len);
ut64 r_io_lseek(struct r_io_t *io, int fd, ut64 offset, int whence);
int r_io_system(struct r_io_t *io, int fd, const char *cmd);
int r_io_close(struct r_io_t *io, int fd);
ut64 r_io_size(struct r_io_t *io, int fd);

/* io/map.c */
void r_io_map_init(struct r_io_t *io);
int r_io_map_rm(struct r_io_t *io, int fd);
int r_io_map_list(struct r_io_t *io);
int r_io_map(struct r_io_t *io, const char *file, ut64 offset);
int r_io_map_read_at(struct r_io_t *io, ut64 off, ut8 *buf, ut64 len);
int r_io_map_read_rest(struct r_io_t *io, ut64 off, ut8 *buf, ut64 len);
int r_io_map_write_at(struct r_io_t *io, ut64 off, const ut8 *buf, ut64 len);

/* sections */
struct r_io_section_t {
	char comment[256];
	ut64 from;
	ut64 to;
	ut64 vaddr;
	ut64 paddr; // offset on disk
	int rwx;
	struct list_head list;
};

enum {
	R_IO_SECTION_R = 4,
	R_IO_SECTION_W = 2,
	R_IO_SECTION_X = 1,
};

int r_io_section_rm(struct r_io_t *io, int idx);
void r_io_section_add(struct r_io_t *io, ut64 from, ut64 to, ut64 vaddr, ut64 physical, int rwx, const char *comment);
void r_io_section_set(struct r_io_t *io, ut64 from, ut64 to, ut64 vaddr, ut64 physical, int rwx, const char *comment);
void r_io_section_list(struct r_io_t *io, ut64 addr, int rad);
struct r_io_section_t * r_io_section_get(struct r_io_t *io, ut64 addr);
void r_io_section_list_visual(struct r_io_t *io, ut64 seek, ut64 len);
ut64 r_io_section_get_vaddr(struct r_io_t *io, ut64 addr);
struct r_io_section_t * r_io_section_get_i(struct r_io_t *io, int idx);
void r_io_section_init(struct r_io_t *io);
int r_io_section_overlaps(struct r_io_t *io, struct r_io_section_t *s);
ut64 r_io_section_align(struct r_io_t *io, ut64 addr, ut64 vaddr, ut64 paddr);

#if 0
#define CB_READ int (*cb_read)(struct r_io_t *user, int pid, ut64 addr, ut8 *buf, int len)
#define CB_WRITE int (*cb_write)(struct r_io_t *user, int pid, ut64 addr, const ut8 *buf, int len)
#define CB_IO int (*cb_io)(void *user, CB_READ, CB_WRITE)
R_API int r_io_hook(struct r_io_t *io, CB_IO);
#endif
/* plugins */
struct r_io_handle_t r_io_plugin_dbg;
struct r_io_handle_t r_io_plugin_ptrace;

#endif
