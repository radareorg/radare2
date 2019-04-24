#ifndef R_BUF_H
#define R_BUF_H
#include <r_util/r_mem.h>

#ifdef __cplusplus
extern "C" {
#endif

#define R_BUF_CUR UT64_MAX

typedef struct r_buf_t {
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
R_API RBuffer *r_buf_new_file(const char *file, bool newFile);
R_API RBuffer *r_buf_new_slurp(const char *file);
R_API RBuffer *r_buf_new_empty (ut64 len);
R_API RBuffer *r_buf_mmap(const char *file, int flags);
R_API RBuffer *r_buf_new_sparse(ut8 Oxff);
R_API RBuffer *r_buf_new_slice(RBuffer *b, ut64 offset, ut64 size);
R_API bool r_buf_dump (RBuffer *buf, const char *file);
R_API RBuffer *r_buf_ref(RBuffer *b);
/* methods */
R_API bool r_buf_set_bits(RBuffer *b, ut64 at, const ut8* buf, int bitoff, int count);
R_API int r_buf_set_bytes(RBuffer *b, const ut8 *buf, ut64 length);
R_API int r_buf_set_bytes_steal(RBuffer *b, const ut8 *buf, ut64 length);
R_API int r_buf_append_string(RBuffer *b, const char *str);
R_API bool r_buf_append_buf(RBuffer *b, RBuffer *a);
R_API bool r_buf_append_buf_slice(RBuffer *b, RBuffer *a, ut64 offset, ut64 size);
R_API bool r_buf_append_bytes(RBuffer *b, const ut8 *buf, int length);
R_API bool r_buf_append_nbytes(RBuffer *b, int length);
R_API bool r_buf_append_ut32(RBuffer *b, ut32 n);
R_API bool r_buf_append_ut64(RBuffer *b, ut64 n);
R_API bool r_buf_append_ut16(RBuffer *b, ut16 n);
R_API bool r_buf_prepend_bytes(RBuffer *b, const ut8 *buf, int length);
R_API char *r_buf_to_string(RBuffer *b);
R_API ut8 *r_buf_get_at(RBuffer *b, ut64 addr, int *len);
#define r_buf_read(a,b,c) r_buf_read_at(a,R_BUF_CUR,b,c)
#define r_buf_write(a,b,c) r_buf_write_at(a,R_BUF_CUR,b,c)
#define r_buf_read8(b) r_buf_read8_at(b,R_BUF_CUR)
R_API int r_buf_read_at(RBuffer *b, ut64 addr, ut8 *buf, int len);
R_API ut8 r_buf_read8_at(RBuffer *b, ut64 addr);
R_API ut64 r_buf_tell(RBuffer *b);
R_API int r_buf_seek(RBuffer *b, st64 addr, int whence);
R_API int r_buf_fread_at(RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n);
R_API int r_buf_write_at(RBuffer *b, ut64 addr, const ut8 *buf, int len);
R_API int r_buf_fwrite_at(RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n);
R_API void r_buf_free(RBuffer *b);
R_API bool r_buf_fini(RBuffer *b);
R_API char *r_buf_free_to_string(RBuffer *b);
R_API const ut8 *r_buf_buffer(RBuffer *b);
R_API ut64 r_buf_size(RBuffer *b);
R_API bool r_buf_resize(RBuffer *b, ut64 newsize);
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
