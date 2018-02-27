/* radare2 - LGPL - Copyright 2017 - condret, pancake, alvaro */

#ifndef R2_IO_H
#define R2_IO_H

#include "r_list.h"
#include <r_util/r_id_storage.h>
#include <r_util/r_cache.h>
#include <r_util/r_buf.h>
#include "r_socket.h"
#include "r_util.h"
#include "r_vector.h"

#define R_IO_READ	4
#define R_IO_WRITE	2
#define R_IO_EXEC	1
#define R_IO_RW		(R_IO_READ|R_IO_WRITE)
#define R_IO_RWX	(R_IO_READ|R_IO_WRITE|R_IO_EXEC)
#define R_IO_PRIV	16
#define R_IO_SHAR	32	//wtf is this

#define R_IO_SEEK_SET	0
#define R_IO_SEEK_CUR	1
#define R_IO_SEEK_END	2

#define R_IO_UNDOS 64

#if __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_io);

typedef struct r_io_undos_t {
	ut64 off;
	int cursor;
} RIOUndos;

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
	int bits;
	int va;		//all of this config stuff must be in 1 int
	int ff;
	int Oxff;
	int addrbytes;
	int aslr;
	int autofd;
	int cached;
	bool cachemode; // write in cache all the read operations (EXPERIMENTAL)
	int p_cache;
	int buffer_enabled;
	int debug;
//#warning remove debug from RIO
	RIDPool *sec_ids;
	RIDPool *map_ids;
	SdbList *maps; //from tail backwards maps with higher priority are found
	RVector map_skyline; // map parts that are not covered by others
	SdbList *sections;
	RIDStorage *files;
	RCache *buffer;
	RList *cache;	//sdblist?
	RBNode cacheTree;
	ut8 *write_mask;
	int write_mask_len;
	RIOUndo undo;
	SdbList *plugins;
	char *runprofile;
	char *args;
	void *user;
	void (*cb_printf)(const char *str, ...);
	int (*cb_core_cmd)(void *user, const char *str);
	char* (*cb_core_cmdstr)(void *user, const char *str);
	void (*cb_core_post_write)(void *user, ut64 maddr, ut8 *orig_bytes, int orig_len);
} RIO;

typedef struct r_io_desc_t {
	int fd;
	int flags;
	int obsz;	//optimal blocksize// do we really need this here?
	char *uri;
	char *name;
	char *referer;
	Sdb *cache;
	void *data;
	struct r_io_plugin_t *plugin;
	RIO *io;
} RIODesc;

typedef struct {
	ut32 magic;
	int pid;
	int tid;
	void *data;
} RIODescData;

// #warning move RIORap somewhere else
typedef struct {
	RSocket *fd;
	RSocket *client;
	int listener;
} RIORap;

#define RMT_MAX    4096
#define RMT_OPEN   0x01
#define RMT_READ   0x02
#define RMT_WRITE  0x03
#define RMT_SEEK   0x04
#define RMT_CLOSE  0x05
#define RMT_SYSTEM 0x06
#define RMT_CMD    0x07
#define RMT_REPLY  0x80

typedef struct r_io_plugin_t {
	char *name;
	char *desc;
	char *version;
	char *author;
	char *license;
	void *widget;
	int (*listener)(RIODesc *io);
	int (*init)(void);
	RIOUndo undo;
	bool isdbg;
	// int (*is_file_opened)(RIO *io, RIODesc *fd, const char *);
	char *(*system)(RIO *io, RIODesc *fd, const char *);
	RIODesc* (*open)(RIO *io, const char *, int rw, int mode);
	RList* /*RIODesc* */ (*open_many)(RIO *io, const char *, int rw, int mode);
	int (*read)(RIO *io, RIODesc *fd, ut8 *buf, int count);
	ut64 (*lseek)(RIO *io, RIODesc *fd, ut64 offset, int whence);
	int (*write)(RIO *io, RIODesc *fd, const ut8 *buf, int count);
	int (*close)(RIODesc *desc);
	bool (*is_blockdevice)(RIODesc *desc);
	int (*getpid)(RIODesc *desc);
	int (*gettid)(RIODesc *desc);
	bool (*getbase)(RIODesc *desc, ut64 *base);
	bool (*resize)(RIO *io, RIODesc *fd, ut64 size);
	int (*extend)(RIO *io, RIODesc *fd, ut64 size);
	bool (*accept)(RIO *io, RIODesc *desc, int fd);
	int (*create)(RIO *io, const char *file, int mode, int type);
	bool (*check)(RIO *io, const char *, bool many);
} RIOPlugin;

typedef struct r_io_map_t {
	int fd;
	int flags;
	ut32 id;
	RInterval itv;
	ut64 delta; //this delta means paddr when talking about section
	char *name;
} RIOMap;

typedef struct r_io_map_skyline_t {
	RIOMap *map;
	RInterval itv;
} RIOMapSkyline;

typedef struct r_io_section_t {
	char *name;
	ut64 paddr;
	ut64 size;
	ut64 vaddr;
	ut64 vsize;
	int flags;
	ut32 id;
	ut32 bin_id;
	int arch;
	int bits;
	int fd;
	ut32 filemap;
	ut32 memmap;
} RIOSection;

typedef enum {
	R_IO_SECTION_APPLY_FOR_PATCH,
	R_IO_SECTION_APPLY_FOR_ANALYSIS,
	R_IO_SECTION_APPLY_FOR_EMULATOR
} RIOSectionApplyMethod;

typedef struct r_io_cache_t {
	RInterval itv;
	ut8 *data;
	ut8 *odata;
	int written;
} RIOCache;

#define R_IO_DESC_CACHE_SIZE (sizeof(ut64) * 8)
typedef struct r_io_desc_cache_t {
	ut64 cached;
	ut8 cdata[R_IO_DESC_CACHE_SIZE];
} RIODescCache;

typedef struct r_io_access_log_element_t {
	ut64 vaddr;
	ut64 paddr;
	int buf_idx;
	int expect_len;
	int len;
	int fd;
	int mapid;
	int flags;
} RIOAccessLogElement;

typedef struct r_io_access_log_t {
	bool allocation_failed;
	ut8 *buf;
	RList *log;
} RIOAccessLog;

struct r_io_bind_t;

typedef bool (*RIODescUse) (RIO *io, int fd);
typedef RIODesc *(*RIODescGet) (RIO *io, int fd);
typedef ut64 (*RIODescSize) (RIODesc *desc);
typedef RIODesc *(*RIOOpen) (RIO *io, const char *uri, int flags, int mode);
typedef RIODesc *(*RIOOpenAt) (RIO *io, const  char *uri, int flags, int mode, ut64 at);
typedef bool (*RIOClose) (RIO *io, int fd);
typedef bool (*RIOReadAt) (RIO *io, ut64 addr, ut8 *buf, int len);
typedef RIOAccessLog *(*RIOAlReadAt) (RIO *io, ut64 addr, ut8 *buf, int len);
typedef bool (*RIOWriteAt) (RIO *io, ut64 addr, const ut8 *buf, int len);
typedef char *(*RIOSystem) (RIO *io, const char* cmd);
typedef int (*RIOFdOpen) (RIO *io, const char *uri, int flags, int mode);
typedef bool (*RIOFdClose) (RIO *io, int fd);
typedef ut64 (*RIOFdSeek) (RIO *io, int fd, ut64 addr, int whence);
typedef ut64 (*RIOFdSize) (RIO *io, int fd);
typedef int (*RIOFdRead) (RIO *io, int fd, ut8 *buf, int len);
typedef int (*RIOFdWrite) (RIO *io, int fd, const ut8 *buf, int len);
typedef int (*RIOFdReadAt) (RIO *io, int fd, ut64 addr, ut8 *buf, int len);
typedef int (*RIOFdWriteAt) (RIO *io, int fd, ut64 addr, const ut8 *buf, int len);
typedef bool (*RIOFdIsDbg) (RIO *io, int fd);
typedef const char *(*RIOFdGetName) (RIO *io, int fd);
typedef bool (*RIOFdRemap) (RIO *io, int fd, ut64 addr);
typedef void (*RIOAlSort) (RIOAccessLog *log);
typedef void (*RIOAlFree) (RIOAccessLog *log);
typedef ut8 *(*RIOAlGetFbufByflags) (RIOAccessLog *log, int flags, ut64 *addr, int *len);
typedef bool (*RIOIsValidOff) (RIO *io, ut64 addr, int hasperm);
typedef bool (*RIOAddrIsMapped) (RIO *io, ut64 addr);
typedef SdbList *(*RIOSectionVgetSecsAt) (RIO *io, ut64 vaddr);
typedef RIOSection *(*RIOSectionVgetSec) (RIO *io, ut64 vaddr);
typedef RIOSection *(*RIOSectionAdd) (RIO *io, ut64 addr, ut64 vaddr, ut64 size, ut64 vsize, int rwx, const char *name, ut32 bin_id, int fd);

typedef struct r_io_bind_t {
	int init;
	RIO *io;
	RIODescUse desc_use;
	RIODescGet desc_get;
	RIODescSize desc_size;
	RIOOpen open;
	RIOOpenAt open_at;
	RIOClose close;
	RIOReadAt read_at;
	RIOAlReadAt al_read_at;	//needed for esil
	RIOWriteAt write_at;
	RIOSystem system;
	RIOFdOpen fd_open;
	RIOFdClose fd_close;
	RIOFdSeek fd_seek;	//needed for esil
	RIOFdSize fd_size;
	RIOFdRead fd_read;	//needed for esil
	RIOFdWrite fd_write;	//needed for esil
	RIOFdReadAt fd_read_at;
	RIOFdWriteAt fd_write_at;
	RIOFdIsDbg fd_is_dbg;
	RIOFdGetName fd_get_name;
	RIOFdRemap fd_remap;
	RIOAlSort al_sort;	//needed for esil
	RIOAlFree al_free;	//needed for esil
	RIOAlGetFbufByflags al_buf_byflags;	//needed for esil
	RIOIsValidOff is_valid_offset;
	RIOAddrIsMapped addr_is_mapped;
	RIOSectionVgetSecsAt sections_vget;
	RIOSectionVgetSec sect_vget;
	RIOSectionAdd section_add;
} RIOBind;

//map.c
R_API RIOMap *r_io_map_new (RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size, bool do_skyline);
R_API void r_io_map_init (RIO *io);
R_API bool r_io_map_remap (RIO *io, ut32 id, ut64 addr);
R_API bool r_io_map_remap_fd (RIO *io, int fd, ut64 addr);
R_API bool r_io_map_exists (RIO *io, RIOMap *map);
R_API bool r_io_map_exists_for_id (RIO *io, ut32 id);
R_API RIOMap *r_io_map_resolve (RIO *io, ut32 id);
R_API RIOMap *r_io_map_add (RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size, bool do_skyline);
R_API RIOMap *r_io_map_get (RIO *io, ut64 addr);		//returns the map at vaddr with the highest priority
R_API RIOMap *r_io_map_get_paddr (RIO *io, ut64 paddr);		//returns the map at paddr with the highest priority
R_API void r_io_map_reset(RIO* io);
R_API bool r_io_map_del (RIO *io, ut32 id);
R_API bool r_io_map_del_for_fd (RIO *io, int fd);
R_API bool r_io_map_priorize (RIO *io, ut32 id);
R_API bool r_io_map_priorize_for_fd (RIO *io, int fd);
R_API void r_io_map_cleanup (RIO *io);
R_API void r_io_map_fini (RIO *io);
R_API bool r_io_map_is_in_range (RIOMap *map, ut64 from, ut64 to);
R_API void r_io_map_set_name (RIOMap *map, const char *name);
R_API void r_io_map_del_name (RIOMap *map);
R_API RIOMap *r_io_map_add_next_available(RIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size, ut64 load_align);
R_API void r_io_map_calculate_skyline(RIO *io);
R_API RList* r_io_map_get_for_fd(RIO *io, int fd);
R_API bool r_io_map_resize(RIO *io, ut32 id, ut64 newsize);

//io.c
R_API RIO *r_io_new (void);
R_API RIO *r_io_init (RIO *io);
R_API RIODesc *r_io_open_nomap (RIO *io, const char *uri, int flags, int mode);		//should return int
R_API RIODesc *r_io_open (RIO *io, const char *uri, int flags, int mode);
R_API RIODesc *r_io_open_at (RIO *io, const char *uri, int flags, int mode, ut64 at);
R_API RList *r_io_open_many (RIO *io, const char *uri, int flags, int mode);
R_API RIODesc* r_io_open_buffer (RIO *io, RBuffer *b, int flags, int mode);
R_API bool r_io_close (RIO *io);
R_API bool r_io_reopen (RIO *io, int fd, int flags, int mode);
R_API int r_io_close_all (RIO *io);
R_API int r_io_pread_at (RIO *io, ut64 paddr, ut8 *buf, int len);
R_API int r_io_pwrite_at (RIO *io, ut64 paddr, const ut8 *buf, int len);
R_API bool r_io_vread_at_mapped(RIO* io, ut64 vaddr, ut8* buf, int len);
R_API RIOAccessLog *r_io_al_vread_at (RIO *io, ut64 vaddr, ut8 *buf, int len);
R_API RIOAccessLog *r_io_al_vwrite_at (RIO *io, ut64 vaddr, const ut8 *buf, int len);
R_API bool r_io_read_at (RIO *io, ut64 addr, ut8 *buf, int len);
R_API bool r_io_read_at_mapped(RIO *io, ut64 addr, ut8 *buf, int len);
R_API int r_io_nread_at (RIO *io, ut64 addr, ut8 *buf, int len);
R_API RIOAccessLog *r_io_al_read_at (RIO *io, ut64 addr, ut8 *buf, int len);
R_API void r_io_alprint(RList *ls);
R_API bool r_io_write_at (RIO *io, ut64 addr, const ut8 *buf, int len);
R_API bool r_io_read (RIO *io, ut8 *buf, int len);
R_API bool r_io_write (RIO *io, ut8 *buf, int len);
R_API ut64 r_io_size (RIO *io);
R_API bool r_io_is_listener (RIO *io);
R_API char *r_io_system (RIO *io, const char* cmd);
R_API bool r_io_resize (RIO *io, ut64 newsize);
R_API int r_io_extend_at (RIO *io, ut64 addr, ut64 size);
R_API bool r_io_set_write_mask (RIO *io, const ut8 *mask, int len);
R_API int r_io_bind (RIO *io, RIOBind *bnd);
R_API int r_io_shift (RIO *io, ut64 start, ut64 end, st64 move);
R_API int r_io_create (RIO *io, const char *file, int mode, int type);
R_API ut64 r_io_seek (RIO *io, ut64 offset, int whence);
R_API int r_io_fini (RIO *io);
R_API void r_io_free (RIO *io);
#define r_io_bind_init(x) memset(&x,0,sizeof(x))

R_API bool r_io_plugin_init(RIO *io);
R_API int r_io_plugin_open(RIO *io, int fd, RIOPlugin *plugin);
R_API int r_io_plugin_close(RIO *io, int fd, RIOPlugin *plugin);
R_API int r_io_plugin_generate(RIO *io);
R_API bool r_io_plugin_add(RIO *io, RIOPlugin *plugin);
R_API int r_io_plugin_list(RIO *io);
R_API int r_io_plugin_list_json(RIO *io);
R_API RIOPlugin *r_io_plugin_resolve(RIO *io, const char *filename, bool many);
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
R_API RList *r_io_sundo_list(RIO *io, int mode);
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

//desc.c
R_API bool r_io_desc_init (RIO *io);
R_API RIODesc *r_io_desc_new (RIO *io, RIOPlugin *plugin, const char *uri, int flags, int mode, void *data);
R_API RIODesc *r_io_desc_open (RIO *io, const char *uri, int flags, int mode);
R_API bool r_io_desc_close (RIODesc *desc);
R_API int r_io_desc_read (RIODesc *desc, ut8 *buf, int count);
R_API int r_io_desc_write (RIODesc *desc, const ut8 *buf, int count);
R_API void r_io_desc_free (RIODesc *desc);
R_API bool r_io_desc_add (RIO *io, RIODesc *desc);
R_API bool r_io_desc_del (RIO *io, int fd);
R_API RIODesc *r_io_desc_get (RIO *io, int fd);
R_API ut64 r_io_desc_seek (RIODesc *desc, ut64 offset, int whence);
R_API bool r_io_desc_resize (RIODesc *desc, ut64 newsize);
R_API ut64 r_io_desc_size (RIODesc *desc);
R_API bool r_io_desc_is_blockdevice (RIODesc *desc);
R_API bool r_io_desc_exchange (RIO *io, int fd, int fdx);	//this should get 2 descs
R_API bool r_io_desc_is_dbg (RIODesc *desc);
R_API int r_io_desc_get_pid (RIODesc *desc);
R_API int r_io_desc_get_tid (RIODesc *desc);
R_API bool r_io_desc_get_base (RIODesc *desc, ut64 *base);
R_API int r_io_desc_read_at (RIODesc *desc, ut64 addr, ut8 *buf, int len);
R_API int r_io_desc_write_at (RIODesc *desc, ut64 addr, const ut8 *buf, int len);
R_API bool r_io_desc_fini (RIO *io);

/* io/cache.c */
R_API int r_io_cache_invalidate(RIO *io, ut64 from, ut64 to);
R_API bool r_io_cache_at(RIO *io, ut64 addr);
R_API void r_io_cache_commit(RIO *io, ut64 from, ut64 to);
R_API void r_io_cache_init(RIO *io);
R_API int r_io_cache_list(RIO *io, int rad);
R_API void r_io_cache_reset(RIO *io, int set);
R_API bool r_io_cache_write(RIO *io, ut64 addr, const ut8 *buf, int len);
R_API bool r_io_cache_read(RIO *io, ut64 addr, ut8 *buf, int len);

/* io/section.c */
R_API void r_io_section_init (RIO *io);
R_API void r_io_section_fini (RIO *io);
R_API int r_io_section_exists_for_id (RIO *io, ut32 id);
R_API RIOSection *r_io_section_add (RIO *io, ut64 addr, ut64 vaddr, ut64 size, ut64 vsize, int rwx, const char *name, ut32 bin_id, int fd);
R_API RIOSection *r_io_section_get_i (RIO *io, ut32 id);
R_API int r_io_section_rm (RIO *io, ut32 id);
R_API SdbList *r_io_section_bin_get (RIO *io, ut32 bin_id);
R_API bool r_io_section_bin_rm (RIO *io, ut32 bin_id);
R_API RIOSection *r_io_section_get_name (RIO *io, const char *name);
R_API void r_io_section_cleanup (RIO *io);
R_API SdbList *r_io_sections_get (RIO *io, ut64 addr);
R_API SdbList *r_io_sections_vget (RIO *io, ut64 vaddr);
R_API int r_io_section_set_archbits (RIO *io, ut32 id, const char *arch, int bits);
R_API const char *r_io_section_get_archbits (RIO *io, ut64 vaddr, int *bits);
R_API int r_io_section_bin_set_archbits (RIO *io, ut32 bin_id, const char *arch, int bits);
R_API bool r_io_section_priorize (RIO *io, ut32 id);
R_API bool r_io_section_priorize_bin (RIO *io, ut32 bin_id);
R_API bool r_io_section_apply (RIO *io, ut32 id, RIOSectionApplyMethod method);
R_API bool r_io_section_reapply (RIO *io, ut32 id, RIOSectionApplyMethod method);
R_API bool r_io_section_apply_bin (RIO *io, ut32 bin_id, RIOSectionApplyMethod method);
R_API bool r_io_section_reapply_bin (RIO *io, ut32 bin_id, RIOSectionApplyMethod method);
R_API RIOSection* r_io_section_get(RIO *io, ut64 paddr);
R_API RIOSection* r_io_section_vget(RIO *io, ut64 vaddr);
R_API ut64 r_io_section_get_paddr_at(RIO *io, ut64 addr);
R_API ut64 r_io_section_get_vaddr_at(RIO *io, ut64 addr);

/* io/p_cache.c */
R_API bool r_io_desc_cache_init (RIODesc *desc);
R_API int r_io_desc_cache_write (RIODesc *desc, ut64 paddr, const ut8 *buf, int len);
R_API int r_io_desc_cache_read (RIODesc *desc, ut64 paddr, ut8 *buf, int len);
R_API bool r_io_desc_cache_commit (RIODesc *desc);
R_API void r_io_desc_cache_cleanup (RIODesc *desc);
R_API void r_io_desc_cache_fini (RIODesc *desc);
R_API void r_io_desc_cache_fini_all (RIO *io);
R_API RList *r_io_desc_cache_list (RIODesc *desc);
R_API int r_io_desc_extend(RIODesc *desc, ut64 size);

/* io/buffer.c */
R_API int r_io_buffer_read (RIO* io, ut64 addr, ut8* buf, int len);
R_API int r_io_buffer_load (RIO* io, ut64 addr, int len);
R_API void r_io_buffer_close (RIO* io);

/* io/fd.c */
R_API int r_io_fd_open (RIO *io, const char *uri, int flags, int mode);
R_API bool r_io_fd_close (RIO *io, int fd);
R_API int r_io_fd_read (RIO *io, int fd, ut8 *buf, int len);
R_API int r_io_fd_write (RIO *io, int fd, const ut8 *buf, int len);
R_API ut64 r_io_fd_seek (RIO *io, int fd, ut64 addr, int whence);
R_API ut64 r_io_fd_size (RIO *io, int fd);
R_API bool r_io_fd_resize (RIO *io, int fd, ut64 newsize);
R_API bool r_io_fd_is_blockdevice (RIO *io, int fd);
R_API int r_io_fd_read_at (RIO *io, int fd, ut64 addr, ut8 *buf, int len);
R_API int r_io_fd_write_at (RIO *io, int fd, ut64 addr, const ut8 *buf, int len);
R_API bool r_io_fd_is_dbg (RIO *io, int fd);
R_API int r_io_fd_get_pid (RIO *io, int fd);
R_API int r_io_fd_get_tid (RIO *io, int fd);
R_API bool r_io_fd_get_base (RIO *io, int fd, ut64 *base);
R_API const char *r_io_fd_get_name (RIO *io, int fd);
R_API int r_io_fd_get_current(RIO *io);
R_API bool r_io_use_fd (RIO *io, int fd);


#define r_io_range_new()	R_NEW0(RIORange)
#define r_io_range_free(x)	free(x)

/* io/ioutils.c */
R_API bool r_io_create_mem_map(RIO *io, RIOSection *sec, ut64 at, bool null, bool do_skyline);
R_API bool r_io_create_file_map(RIO *io, RIOSection *sec, ut64 size, bool patch, bool do_skyline);
R_API bool r_io_create_mem_for_section(RIO *io, RIOSection *sec);
R_API bool r_io_is_valid_offset (RIO *io, ut64 offset, int hasperm);
R_API bool r_io_addr_is_mapped(RIO *io, ut64 vaddr);
R_API bool r_io_read_i (RIO* io, ut64 addr, ut64 *val, int size, bool endian);
R_API bool r_io_write_i (RIO* io, ut64 addr, ut64 *val, int size, bool endian);
R_API RIOAccessLog *r_io_accesslog_new (void);
R_API void r_io_accesslog_free (RIOAccessLog *log);
R_API void r_io_accesslog_sort (RIOAccessLog *log);
R_API void r_io_accesslog_sqash_ignore_gaps (RIOAccessLog *log);
R_API void r_io_accesslog_sqash_byflags (RIOAccessLog *log, int flags);
R_API ut8 *r_io_accesslog_getf_buf_byflags (RIOAccessLog *log, int flags, ut64 *addr, int *len);

extern RIOPlugin r_io_plugin_procpid;
extern RIOPlugin r_io_plugin_malloc;
extern RIOPlugin r_io_plugin_sparse;
extern RIOPlugin r_io_plugin_ptrace;
extern RIOPlugin r_io_plugin_w32dbg;
extern RIOPlugin r_io_plugin_mach;
extern RIOPlugin r_io_plugin_debug;
extern RIOPlugin r_io_plugin_shm;
extern RIOPlugin r_io_plugin_gdb;
extern RIOPlugin r_io_plugin_rap;
extern RIOPlugin r_io_plugin_http;
extern RIOPlugin r_io_plugin_bfdbg;
extern RIOPlugin r_io_plugin_w32;
extern RIOPlugin r_io_plugin_zip;
extern RIOPlugin r_io_plugin_mmap;
extern RIOPlugin r_io_plugin_default;
extern RIOPlugin r_io_plugin_ihex;
extern RIOPlugin r_io_plugin_self;
extern RIOPlugin r_io_plugin_gzip;
extern RIOPlugin r_io_plugin_windbg;
extern RIOPlugin r_io_plugin_r2pipe;
extern RIOPlugin r_io_plugin_r2web;
extern RIOPlugin r_io_plugin_qnx;
extern RIOPlugin r_io_plugin_r2k;
extern RIOPlugin r_io_plugin_tcp;
extern RIOPlugin r_io_plugin_bochs;
extern RIOPlugin r_io_plugin_null;
extern RIOPlugin r_io_plugin_ar;
extern RIOPlugin r_io_plugin_rbuf;
extern RIOPlugin r_io_plugin_winedbg;

#if __cplusplus
}
#endif

#endif
