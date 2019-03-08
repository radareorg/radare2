#ifndef R_BUF_H
#define R_BUF_H
#include <r_util/r_mem.h>

#ifdef __cplusplus
extern "C" {
#endif

#define R_BUF_CUR 0
#define R_BUF_SET 1
#define R_BUF_END 2

typedef struct r_buf_t RBuffer;

typedef bool (*RBufferInit)(RBuffer *b, const void *user);
typedef bool (*RBufferFini)(RBuffer *b);
typedef bool (*RBufferSetBytes)(RBuffer *b, const ut8 *buf, ut64 length);
typedef bool (*RBufferSetBytesSteal)(RBuffer *b, const ut8 *buf, ut64 length);
typedef bool (*RBufferPrependBytes)(RBuffer *b, const ut8 *buf, ut64 length);
typedef bool (*RBufferPrependBuf)(RBuffer *b, RBuffer *o);
typedef bool (*RBufferAppendBytes)(RBuffer *b, const ut8 *buf, ut64 length);
typedef bool (*RBufferAppendBuf)(RBuffer *b, RBuffer *o);
typedef bool (*RBufferExtend)(RBuffer *b, ut64 add_length);
typedef bool (*RBufferToString)(RBuffer *b);
typedef ut8 *(*RBufferGetAt)(RBuffer *b, ut64 addr, int *len);
typedef int (*RBufferRead)(RBuffer *b, ut8 *buf, size_t len);
typedef int (*RBufferWrite)(RBuffer *b, const ut8 *buf, size_t len);
typedef int (*RBufferReadAt)(RBuffer *b, ut64 addr, ut8 *buf, int len);
typedef int (*RBufferWriteAt)(RBuffer *b, ut64 addr, const ut8 *buf, int len);
typedef int (*RBufferFReadAt)(RBuffer *b, ut64 addr, const ut8 *buf, const char *fmt, int n);
typedef int (*RBufferFWriteAt)(RBuffer *b, ut64 addr, const ut8 *buf, const char *fmt, int n);
typedef ut64 (*RBufferGetSize)(RBuffer *b);
typedef bool (*RBufferResize)(RBuffer *b, ut64 newsize);
typedef int (*RBufferSeek)(RBuffer *b, st64 addr, int whence);

typedef struct r_buffer_methods_t {
	RBufferInit init;
	RBufferFini fini;
	RBufferGetAt get_at;
	RBufferRead read;
	RBufferWrite write;
	RBufferGetSize get_size;
	RBufferResize resize;
	RBufferSeek seek;
} RBufferMethods;

typedef struct r_buf_t {
	const RBufferMethods *methods;
	void *priv;

	ut8 *buf;
	ut64 length;
	st64 cur;
	ut64 base;
	RMmap *mmap;
	bool empty;
	bool ro; // read-only
	int fd;
	int Oxff;
	RList *sparse;
	int refctr;
	// RIOBind *iob;
	// forward declaration
	void *iob;
	ut64 offset;
	ut64 limit;
} RBuffer;

// XXX: this should not be public
typedef struct r_buf_cache_t {
	ut64 from;
	ut64 to;
	int size;
	ut8 *data;
	int written;
} RBufferSparse;

/* constructors */
R_API RBuffer *r_buf_new(void);
R_API RBuffer *r_buf_new_with_io(void *iob, int fd);
R_API RBuffer *r_buf_new_with_bytes(const ut8* bytes, ut64 len);
R_API RBuffer *r_buf_new_with_string(const char *msg);
R_API RBuffer *r_buf_new_with_pointers(const ut8 *bytes, ut64 len);
R_API RBuffer *r_buf_new_with_buf(RBuffer *b);
R_API RBuffer *r_buf_new_with_bufref(RBuffer *b);
R_API RBuffer *r_buf_new_file(const char *file, int perm, int mode);
R_API RBuffer *r_buf_new_slurp(const char *file);
R_API RBuffer *r_buf_new_empty(ut64 len);
R_API RBuffer *r_buf_mmap(const char *file, int flags);
R_API RBuffer *r_buf_new_sparse(ut8 Oxff);
R_API bool r_buf_dump(RBuffer *buf, const char *file);
R_API RBuffer *r_buf_ref(RBuffer *b);

/* methods */
R_API bool r_buf_set_bytes(RBuffer *b, const ut8 *buf, ut64 length);
R_API int r_buf_set_bytes_steal(RBuffer *b, const ut8 *buf, ut64 length);
R_API int r_buf_append_string(RBuffer *b, const char *str);
R_API bool r_buf_append_buf(RBuffer *b, RBuffer *a);
R_API bool r_buf_append_bytes(RBuffer *b, const ut8 *buf, size_t length);
R_API bool r_buf_append_nbytes(RBuffer *b, size_t length);
R_API bool r_buf_append_ut32(RBuffer *b, ut32 n);
R_API bool r_buf_append_ut64(RBuffer *b, ut64 n);
R_API bool r_buf_append_ut16(RBuffer *b, ut16 n);
R_API bool r_buf_prepend_bytes(RBuffer *b, const ut8 *buf, size_t length);
R_API int r_buf_insert_bytes(RBuffer *b, ut64 addr, const ut8 *buf, size_t length);
R_API char *r_buf_to_string(RBuffer *b);
R_API ut8 *r_buf_get_at(RBuffer *b, ut64 addr, int *len);
R_API int r_buf_read(RBuffer *b, ut8 *buf, size_t len);
R_API int r_buf_fread(RBuffer *b, ut8 *buf, const char *fmt, int n);
R_API int r_buf_read_at(RBuffer *b, ut64 addr, ut8 *buf, int len);
R_API int r_buf_fread_at(RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n);
R_API int r_buf_write(RBuffer *b, const ut8 *buf, size_t len);
R_API int r_buf_fwrite(RBuffer *b, const ut8 *buf, const char *fmt, int n);
R_API int r_buf_write_at(RBuffer *b, ut64 addr, const ut8 *buf, int len);
R_API int r_buf_fwrite_at(RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n);
R_API int r_buf_seek(RBuffer *b, st64 addr, int whence);
R_API void r_buf_free(RBuffer *b);
R_API bool r_buf_fini(RBuffer *b);
R_API char *r_buf_free_to_string(RBuffer *b);
R_API const ut8 *r_buf_buffer(RBuffer *b);
R_API ut64 r_buf_size(RBuffer *b);
R_API bool r_buf_resize(RBuffer *b, ut64 newsize);

#ifdef __cplusplus
}
#endif

#endif //  R_BUF_H
