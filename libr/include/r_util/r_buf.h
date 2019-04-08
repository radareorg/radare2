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
typedef ut8 *(*RBufferGetWholeBuf)(RBuffer *b, ut64 *sz);
typedef void (*RBufferFreeWholeBuf)(RBuffer *b);

typedef struct r_buffer_methods_t {
	RBufferInit init;
	RBufferFini fini;
	RBufferRead read;
	RBufferWrite write;
	RBufferGetSize get_size;
	RBufferResize resize;
	RBufferSeek seek;
	RBufferGetWholeBuf get_whole_buf;
	RBufferFreeWholeBuf free_whole_buf;
} RBufferMethods;

typedef struct r_buf_t {
	const RBufferMethods *methods;
	void *priv;
	ut8 tmp[8];
	ut8 *whole_buf;

	ut8 *buf_priv;
	ut64 length_priv;
	st64 cur_priv;
	// FIXME: some direct accesses to base_priv still exist unfortunately
	ut64 base_priv;
	RMmap *mmap_priv;
	bool empty_priv;
	bool ro_priv; // read-only
	int fd_priv;
	int Oxff_priv;
	RList *sparse_priv;
	int refctr;
	// RIOBind *iob;
	// forward declaration
	void *iob;
	ut64 offset_priv;
	ut64 limit_priv;
	struct r_buf_t *parent_priv;
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
R_API RBuffer *r_buf_new_with_pointers(const ut8 *bytes, ut64 len, bool steal);
R_API RBuffer *r_buf_new_file(const char *file, int perm, int mode);
R_API RBuffer *r_buf_new_with_buf(RBuffer *b);
R_API RBuffer *r_buf_new_with_bufref(RBuffer *b);
R_API RBuffer *r_buf_new_slurp(const char *file);
R_API RBuffer *r_buf_new_slice(RBuffer *b, ut64 offset, ut64 size);
R_API RBuffer *r_buf_new_empty(ut64 len);
R_API RBuffer *r_buf_new_mmap(const char *file, int flags);
R_API RBuffer *r_buf_new_sparse(ut8 Oxff);

/* methods */
R_API bool r_buf_dump(RBuffer *buf, const char *file);
R_API bool r_buf_set_bytes(RBuffer *b, const ut8 *buf, ut64 length);
R_API int r_buf_append_string(RBuffer *b, const char *str);
R_API bool r_buf_append_buf(RBuffer *b, RBuffer *a);
R_API bool r_buf_append_bytes(RBuffer *b, const ut8 *buf, size_t length);
R_API bool r_buf_append_nbytes(RBuffer *b, size_t length);
R_API bool r_buf_append_ut16(RBuffer *b, ut16 n);
R_API bool r_buf_append_buf_slice(RBuffer *b, RBuffer *a, ut64 offset, int size);
R_API bool r_buf_append_ut32(RBuffer *b, ut32 n);
R_API bool r_buf_append_ut64(RBuffer *b, ut64 n);
R_API bool r_buf_prepend_bytes(RBuffer *b, const ut8 *buf, size_t length);
R_API int r_buf_insert_bytes(RBuffer *b, ut64 addr, const ut8 *buf, size_t length);
R_API char *r_buf_to_string(RBuffer *b);
R_API ut8 *r_buf_get_at(RBuffer *b, ut64 addr, int *len);
R_API int r_buf_read(RBuffer *b, ut8 *buf, size_t len);
R_API ut8 r_buf_read8(RBuffer *b);
R_API int r_buf_fread(RBuffer *b, ut8 *buf, const char *fmt, int n);
R_API int r_buf_read_at(RBuffer *b, ut64 addr, ut8 *buf, int len);
R_API ut8 r_buf_read8_at(RBuffer *b, ut64 addr);
R_API ut64 r_buf_tell(RBuffer *b);
R_API int r_buf_seek(RBuffer *b, st64 addr, int whence);
R_API int r_buf_fread_at(RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n);
R_API int r_buf_write(RBuffer *b, const ut8 *buf, size_t len);
R_API int r_buf_fwrite(RBuffer *b, const ut8 *buf, const char *fmt, int n);
R_API int r_buf_write_at(RBuffer *b, ut64 addr, const ut8 *buf, int len);
R_API int r_buf_fwrite_at(RBuffer *b, ut64 addr, const ut8 *buf, const char *fmt, int n);
// TODO change all uses to use R_BUF_{SET,CUR,END}
R_API const ut8 *r_buf_buffer(RBuffer *b, ut64 *size);
R_API ut64 r_buf_size(RBuffer *b);
R_API bool r_buf_resize(RBuffer *b, ut64 newsize);
R_API RBuffer *r_buf_ref(RBuffer *b);
R_API void r_buf_free(RBuffer *b);
R_API bool r_buf_fini(RBuffer *b);
R_API RList *r_buf_nonempty_list(RBuffer *b);

static inline ut16 r_buf_read_be16(RBuffer *b) {
	ut8 buf[sizeof (ut16)];
	int r = r_buf_read (b, buf, sizeof (buf));
	return r == sizeof (buf)? r_read_be16 (buf): UT16_MAX;
}

static inline ut16 r_buf_read_be16_at(RBuffer *b, ut64 addr) {
	ut8 buf[sizeof (ut16)];
	int r = r_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? r_read_be16 (buf): UT16_MAX;
}

static inline ut32 r_buf_read_be32(RBuffer *b) {
	ut8 buf[sizeof (ut32)];
	int r = r_buf_read (b, buf, sizeof (buf));
	return r == sizeof (buf)? r_read_be32 (buf): UT32_MAX;
}

static inline ut32 r_buf_read_be32_at(RBuffer *b, ut64 addr) {
	ut8 buf[sizeof (ut32)];
	int r = r_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? r_read_be32 (buf): UT32_MAX;
}

static inline ut64 r_buf_read_be64(RBuffer *b) {
	ut8 buf[sizeof (ut64)];
	int r = r_buf_read (b, buf, sizeof (buf));
	return r == sizeof (buf)? r_read_be64 (buf): UT64_MAX;
}

static inline ut64 r_buf_read_be64_at(RBuffer *b, ut64 addr) {
	ut8 buf[sizeof (ut64)];
	int r = r_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? r_read_be64 (buf): UT64_MAX;
}

static inline ut16 r_buf_read_le16(RBuffer *b) {
	ut8 buf[sizeof (ut16)];
	int r = r_buf_read (b, buf, sizeof (buf));
	return r == sizeof (buf)? r_read_le16 (buf): UT16_MAX;
}

static inline ut16 r_buf_read_le16_at(RBuffer *b, ut64 addr) {
	ut8 buf[sizeof (ut16)];
	int r = r_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? r_read_le16 (buf): UT16_MAX;
}

static inline ut32 r_buf_read_le32(RBuffer *b) {
	ut8 buf[sizeof (ut32)];
	int r = r_buf_read (b, buf, sizeof (buf));
	return r == sizeof (buf)? r_read_le32 (buf): UT32_MAX;
}

static inline ut32 r_buf_read_le32_at(RBuffer *b, ut64 addr) {
	ut8 buf[sizeof (ut32)];
	int r = r_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? r_read_le32 (buf): UT32_MAX;
}

static inline ut64 r_buf_read_le64(RBuffer *b) {
	ut8 buf[sizeof (ut64)];
	int r = r_buf_read (b, buf, sizeof (buf));
	return r == sizeof (buf)? r_read_le64 (buf): UT64_MAX;
}

static inline ut64 r_buf_read_le64_at(RBuffer *b, ut64 addr) {
	ut8 buf[sizeof (ut64)];
	int r = r_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? r_read_le64 (buf): UT64_MAX;
}

static inline ut16 r_buf_read_ble16_at(RBuffer *b, ut64 addr, bool big_endian) {
	ut8 buf[sizeof (ut16)];
	int r = r_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? r_read_ble16 (buf, big_endian): UT16_MAX;
}

static inline ut32 r_buf_read_ble32_at(RBuffer *b, ut64 addr, bool big_endian) {
	ut8 buf[sizeof (ut32)];
	int r = r_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? r_read_ble32 (buf, big_endian): UT32_MAX;
}

static inline ut64 r_buf_read_ble64_at(RBuffer *b, ut64 addr, bool big_endian) {
	ut8 buf[sizeof (ut64)];
	int r = r_buf_read_at (b, addr, buf, sizeof (buf));
	return r == sizeof (buf)? r_read_ble64 (buf, big_endian): UT64_MAX;
}

#ifdef __cplusplus
}
#endif

#endif //  R_BUF_H
