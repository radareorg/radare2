#ifndef R_IO_API
#define R_IO_API

#include <sdb.h>
#include <r_types.h>

#define R_IO_READ	4
#define R_IO_WRITE	2
#define R_IO_EXEC	1
#define R_IO_RW		R_IO_READ|R_IO_WRITE

#define R_IO_SEEK_SET	0
#define R_IO_SEEK_CUR	1
#define R_IO_SEEK_END	2

typedef struct r_io_t {
	struct r_io_desc_t *desc;
	ut64 off;
	int va;
	int ff;
	int autofd;
	ut32 map_id;
	SdbList *freed_map_ids;
	SdbList *maps;
	//SdbList *cache;
	Sdb *files;
} RIO;

//RIOCbs instances should be predefined and not generated to prevent memleaks
typedef struct r_io_callbacks_t {
	struct r_io_desc_t *(*open)(RIO *io, const char *uri, int flags, int mode);
	int (*read)(RIO *io, struct r_io_desc_t *desc, ut8 *buf, int len);
	ut64 (*lseek)(RIO *io, struct r_io_desc_t *desc, ut64 offset, int whence);
	int (*write)(RIO *io, struct r_io_desc_t *desc, const ut8 *buf, int len);
	int (*close)(struct r_io_desc_t *desc);
} RIOCbs;

typedef struct r_io_map_t {
	int fd;
	int flags;
	ut32 id;
	ut64 from;
	ut64 to;
	ut64 delta;
	char *name;
} RIOMap;

typedef struct r_io_desc_t {
	int fd;
	int flags;
	char *uri;
	void *data;
	RIOCbs *cbs;
	RIO *io;
} RIODesc;

//desc.c
R_API int r_io_desc_init (RIO *io);
R_API RIODesc *r_io_desc_new (RIOCbs *cbs, int fd, char *uri, int flags, void *data);
R_API void r_io_desc_free (RIODesc *desc);
R_API int r_io_desc_add (RIO *io, RIODesc *desc);
R_API int r_io_desc_del (RIO *io, int fd);
R_API RIODesc *r_io_desc_get (RIO *io, int fd);
R_API int r_io_desc_use (RIO *io, int fd);
R_API ut64 r_io_desc_seek (RIODesc *desc, ut64 offset, int whence);
R_API ut64 r_io_desc_size (RIODesc *desc);
R_API int r_io_desc_fini (RIO *io);

//map.c
R_API RIOMap *r_io_map_new (RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size);
R_API void r_io_map_init (RIO *io);
R_API int r_io_map_exists (RIO *io, RIOMap *map);
R_API int r_io_map_exists_for_id (RIO *io, ut32 id);
R_API RIOMap *r_io_map_add (RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size);
R_API RIOMap *r_io_map_get (RIO *io, ut64 addr);
R_API int r_io_map_del (RIO *io, ut32 id);
R_API int r_io_map_del_for_fd (RIO *io, int fd);
R_API int r_io_map_priorize (RIO *io, ut32 id);
R_API void r_io_map_cleanup (RIO *io);
R_API void r_io_map_fini (RIO *io);
R_API int r_io_map_is_in_range (RIOMap *map, ut64 from, ut64 to);
R_API void r_io_map_set_name (RIOMap *map, const char *name);
R_API void r_io_map_del_name (RIOMap *map);

//io.c
R_API RIO *r_io_new ();
R_API RIO *r_io_init (RIO *io);
R_API RIODesc *r_io_open_nomap (RIO *io, RIOCbs *cbs, char *uri, int flags, int mode);
R_API RIODesc *r_io_open (RIO *io, RIOCbs *cbs, char *uri, int flags, int mode);
R_API RIODesc *r_io_open_at (RIO *io, RIOCbs *cbs, char *uri, int flags, int mode, ut64 at);
R_API int r_io_close (RIO *io, int fd);
R_API int r_io_pread_at (RIO *io, ut64 paddr, ut8 *buf, int len);
R_API int r_io_pwrite_at (RIO *io, ut64 paddr, ut8 *buf, int len);
R_API int r_io_vread_at (RIO *io, ut64 paddr, ut8 *buf, int len);
R_API int r_io_vwrite_at (RIO *io, ut64 paddr, ut8 *buf, int len);
R_API int r_io_read_at (RIO *io, ut64 paddr, ut8 *buf, int len);
R_API int r_io_write_at (RIO *io, ut64 paddr, ut8 *buf, int len);
R_API int r_io_fini (RIO *io);
R_API void r_io_free (RIO *io);

#endif