#ifndef R_IO_API
#define R_IO_API

#include <r_db.h>
#include <r_types.h>
#include <r_list.h>

#define R_IO_READ	4
#define R_IO_WRITE	2
#define R_IO_EXEC	1
#define R_IO_RW		R_IO_READ|R_IO_WRITE

#define R_IO_SEEK_SET	0
#define R_IO_SEEK_CUR	1
#define R_IO_SEEK_END	2

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
	RIOUndos seek[R_IO_UNDOS];
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
	struct r_io_desc_t *desc;
	ut64 off;
	int va;		//all of this config stuff must be in 1 int
	int ff;
	int autofd;
	int cached;
	int cached_read;
	ut32 map_id;
	ut32 sec_id;
	SdbList *freed_map_ids;
	SdbList *freed_sec_ids;
	SdbList *maps;
	SdbList *sections;
	RList *cache;	//sdblist?
	Sdb *files;
	RIOUndo undo;
} RIO;

typedef struct r_io_desc_t {
	int fd;
	int flags;
	char *uri;
	char *name;
	void *data;
	struct r_io_plugin_t *plugin;
	RIO *io;
} RIODesc;

typedef struct r_io_plugin_t {
//	void *plugin;
	char *name;
	char *desc;
	char *license;
	void *widget;
	int (*listener)(RIODesc *io);
	int (*init)();
	RIOUndo undo;
	bool isdbg;
	// int (*is_file_opened)(RIO *io, RIODesc *fd, const char *);
	int (*system)(RIO *io, RIODesc *fd, const char *);
	RIODesc* (*open)(RIO *io, const char *, int rw, int mode);
	RList* /*RIODesc* */ (*open_many)(RIO *io, const char *, int rw, int mode);
	int (*read)(RIO *io, RIODesc *fd, ut8 *buf, int count);
	ut64 (*lseek)(RIO *io, RIODesc *fd, ut64 offset, int whence);
	int (*write)(RIO *io, RIODesc *fd, const ut8 *buf, int count);
	int (*close)(RIODesc *desc);
	bool (*resize)(RIO *io, RIODesc *fd, ut64 size);
	int (*extend)(RIO *io, RIODesc *fd, ut64 size);
	int (*accept)(RIO *io, RIODesc *desc, int fd);
	int (*create)(RIO *io, const char *file, int mode, int type);
	bool (*check)(RIO *io, const char *, bool many);
} RIOPlugin;

typedef struct r_io_map_t {
	int fd;
	int flags;
	ut32 id;
	ut64 from;
	ut64 to;
	ut64 delta;
	char *name;
} RIOMap;

typedef struct r_io_section_t {
	char *name;
	ut64 addr;
	ut64 size;
	ut64 vaddr;
	ut64 vsize;
	int rwx;
	ut32 id;
	ut32 bin_id;
	int arch;
	int bits;
	int fd;
	ut32 filemap;
	ut32 memmap;
} RIOSection:

typedef enum {
	R_IO_SECTION_APPLY_FOR_PATCHING,
	R_IO_SECTION_APPLY_AS_MAPPING,
} RIOSectionApplyMethod;

typedef struct r_io_cache_t {
	ut64 from;
	ut64 to;
	int size;
	ut8 *data;
	ut8 *odata;
	int written;
} RIOCache;

//desc.c
R_API int r_io_desc_init (RIO *io);
R_API RIODesc *r_io_desc_new (RIOPlugin *plugin, int fd, char *uri, int flags, void *data);
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
R_API RIODesc *r_io_open_nomap (RIO *io, char *uri, int flags, int mode);
R_API RIODesc *r_io_open (RIO *io, char *uri, int flags, int mode);
R_API RIODesc *r_io_open_at (RIO *io, char *uri, int flags, int mode, ut64 at);
R_API int r_io_close (RIO *io, int fd);
R_API int r_io_pread_at (RIO *io, ut64 paddr, ut8 *buf, int len);
R_API int r_io_pwrite_at (RIO *io, ut64 paddr, ut8 *buf, int len);
R_API int r_io_vread_at (RIO *io, ut64 paddr, ut8 *buf, int len);
R_API int r_io_vwrite_at (RIO *io, ut64 paddr, ut8 *buf, int len);
R_API int r_io_read_at (RIO *io, ut64 paddr, ut8 *buf, int len);
R_API int r_io_write_at (RIO *io, ut64 paddr, ut8 *buf, int len);
R_API int r_io_fini (RIO *io);
R_API void r_io_free (RIO *io);

R_API int r_io_plugin_init(RIO *io);
R_API int r_io_plugin_open(RIO *io, int fd, RIOPlugin *plugin);
R_API int r_io_plugin_close(RIO *io, int fd, RIOPlugin *plugin);
R_API int r_io_plugin_generate(RIO *io);
R_API bool r_io_plugin_add(RIO *io, RIOPlugin *plugin);
R_API int r_io_plugin_list(RIO *io);
R_API RIOPlugin *r_io_plugin_resolve(RIO *io, const char *filename, ut8 many);
R_API RIOPlugin *r_io_plugin_resolve_fd(RIO *io, int fd);
R_API RIOPlugin *r_io_plugin_get_default(RIO *io, const char *filename, bool many);

/* undo api */
// track seeks and writes
// TODO: needs cleanup..kinda big?
R_API int r_io_undo_init(RIO *io);
R_API void r_io_undo_enable(RIO *io, int seek, int write);
/* seek undo */
R_API RIOUndos *r_io_sundo(RIO *io, ut64 offset);
R_API RIOUndos *r_io_sundo_redo(RIO *io);
R_API void r_io_sundo_push(RIO *io, ut64 off, int cursor);
R_API void r_io_sundo_reset(RIO *io);
R_API void r_io_sundo_list(RIO *io, int mode);
/* write undo */
R_API void r_io_wundo_new(RIO *io, ut64 off, const ut8 *data, int len);
R_API void r_io_wundo_apply_all(RIO *io, int set);
R_API int r_io_wundo_apply(RIO *io, struct r_io_undo_w_t *u, int set);
R_API void r_io_wundo_clear(RIO *io);
R_API int r_io_wundo_size(RIO *io);
R_API void r_io_wundo_list(RIO *io);
R_API int r_io_wundo_set_t(RIO *io, RIOUndoWrite *u, int set) ;
R_API void r_io_wundo_set_all(RIO *io, int set);
R_API int r_io_wundo_set(RIO *io, int n, int set);

/* io/cache.c */
R_API int r_io_cache_invalidate(RIO *io, ut64 from, ut64 to);
R_API void r_io_cache_commit(RIO *io, ut64 from, ut64 to);
R_API void r_io_cache_enable(RIO *io, int read, int write);
R_API void r_io_cache_init(RIO *io);
R_API int r_io_cache_list(RIO *io, int rad);
R_API void r_io_cache_reset(RIO *io, int set);
R_API int r_io_cache_write(RIO *io, ut64 addr, const ut8 *buf, int len);
R_API int r_io_cache_read(RIO *io, ut64 addr, ut8 *buf, int len);

/* io/section.c */
R_API void r_io_section_init (RIO *io);
R_API void r_io_section_fini (RIO *io);
R_API int r_io_section_exists_for_id (RIO *io, ut32 id);
R_API RIOSection *r_io_section_add (RIO *io, ut64 addr, ut64 vaddr, ut64 size, ut64 vsize, int rwx, const char *name, ut32 bin_id, int fd);
R_API RIOSection *r_io_section_get_i (RIO *io, ut32 id);
R_API int r_io_section_rm (RIO *io, ut32 id);
R_API SdbList *r_io_section_bin_get (RIO *io, ut32 bin_id);
R_API int r_io_section_bin_rm (RIO *io, ut32 bin_id);
R_API int r_io_section_set_archbits (RIO *io, ut32 id, const char *arch, int bits);
R_API char *r_io_section_get_archbits (RIO *io, ut32 id, int *bits);
R_API int r_io_section_bin_set_archbits (RIO *io, ut32 bin_id, const char *arch, int bits);
R_API int r_io_section_apply (RIO *io, ut32 id, RIOSectionApplyMethod method);

#endif
