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

#define IO_MAP_N 10
struct r_io_maps_t {
        int fd;
        char file[128];
        u64 from;
        u64 to;
        struct list_head list;
};

struct r_io_t {
	int fd;
	u64 seek;
	char *redirect;
	/* write mask */
	int write_mask_fd;
	u8 *write_mask_buf;
	int write_mask_len;
	struct r_io_handle_t *plugin;
	struct list_head io_list;
	u64 last_align;
	struct list_head sections;
	struct list_head maps;
};

struct r_io_handle_t {
        void *handle;
        char *name;
        char *desc;
        void *widget;
        int (*init)();
        struct debug_t *debug;
        int (*system)(struct r_io_t *io, int fd, const char *);
        int (*open)(struct r_io_t *io, const char *, int rw, int mode);
        int (*read)(struct r_io_t *io, int fd, u8 *buf, int count);
        u64 (*lseek)(struct r_io_t *io, int fildes, u64 offset, int whence);
        int (*write)(struct r_io_t *io, int fd, const u8 *buf, int count);
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
int r_io_handle_init(struct r_io_t *io);
int r_io_handle_open(struct r_io_t *io, int fd, struct r_io_handle_t *plugin);
int r_io_handle_close(struct r_io_t *io, int fd, struct r_io_handle_t *plugin);
int r_io_handle_generate(struct r_io_t *io);
int r_io_handle_add(struct r_io_t *io, struct r_io_handle_t *plugin);
// TODO: _del ??
struct r_io_handle_t *r_io_handle_resolve(struct r_io_t *io, const char *filename);
struct r_io_handle_t *r_io_handle_resolve_fd(struct r_io_t *io, int fd);

/* io/io.c */
int r_io_init(struct r_io_t *io);
int r_io_set_write_mask(struct r_io_t *io, int fd, const u8 *buf, int len);
int r_io_open(struct r_io_t *io, const char *file, int flags, int mode);
int r_io_redirect(struct r_io_t *io, const char *file);
int r_io_read(struct r_io_t *io, int fd, u8 *buf, int len);
int r_io_write(struct r_io_t *io, int fd, const u8 *buf, int len);
u64 r_io_lseek(struct r_io_t *io, int fd, u64 offset, int whence);
int r_io_system(struct r_io_t *io, int fd, const char *cmd);
int r_io_close(struct r_io_t *io, int fd);
u64 r_io_size(struct r_io_t *io, int fd);

/* io/map.c */
void r_io_map_init(struct r_io_t *io);
int r_io_map_rm(struct r_io_t *io, int fd);
int r_io_map_list(struct r_io_t *io);
int r_io_map(struct r_io_t *io, const char *file, u64 offset);
int r_io_map_read_at(struct r_io_t *io, u64 off, u8 *buf, u64 len);
int r_io_map_read_rest(struct r_io_t *io, u64 off, u8 *buf, u64 len);
int r_io_map_write_at(struct r_io_t *io, u64 off, const u8 *buf, u64 len);

/* sections */
struct r_io_section_t {
	char comment[256];
	u64 from;
	u64 to;
	u64 vaddr;
	u64 paddr; // offset on disk
	int rwx;
	struct list_head list;
};

enum {
	R_IO_SECTION_R = 4,
	R_IO_SECTION_W = 2,
	R_IO_SECTION_X = 1,
};

int r_io_section_rm(struct r_io_t *io, int idx);
void r_io_section_add(struct r_io_t *io, u64 from, u64 to, u64 vaddr, u64 physical, int rwx, const char *comment);
void r_io_section_set(struct r_io_t *io, u64 from, u64 to, u64 vaddr, u64 physical, int rwx, const char *comment);
void r_io_section_list(struct r_io_t *io, u64 addr, int rad);
struct r_io_section_t * r_io_section_get(struct r_io_t *io, u64 addr);
void r_io_section_list_visual(struct r_io_t *io, u64 seek, u64 len);
u64 r_io_section_get_vaddr(struct r_io_t *io, u64 addr);
struct r_io_section_t * r_io_section_get_i(struct r_io_t *io, int idx);
void r_io_section_init(struct r_io_t *io);
int r_io_section_overlaps(struct r_io_t *io, struct r_io_section_t *s);
u64 r_io_section_align(struct r_io_t *io, u64 addr, u64 vaddr, u64 paddr);

#endif
