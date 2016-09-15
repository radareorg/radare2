#ifndef R_BUF_H
#define R_BUF_H
#include <r_util/r_mem.h>

#define R_BUF_CUR UT64_MAX

typedef struct r_buf_t {
	ut8 *buf;
	ut64 length;
	st64 cur;
	ut64 base;
	RMmap *mmap;
	bool empty;
	bool ro; // read-only
	int fd;
	RList *sparse;
} RBuffer;

typedef struct r_buf_cache_t {
        ut64 from;
        ut64 to;
        int size;
        ut8 *data;
        ut8 *odata;
        int written;
} RBufferSparse;

/* constructors */
R_API RBuffer *r_buf_new(void);
R_API RBuffer *r_buf_new_with_bytes(const ut8* bytes, ut64 len);
R_API RBuffer *r_buf_new_with_pointers(const ut8 *bytes, ut64 len);
R_API RBuffer *r_buf_new_with_buf(RBuffer *b);
R_API RBuffer *r_buf_new_file(const char *file, bool newFile);
R_API RBuffer *r_buf_new_slurp(const char *file);
R_API RBuffer *r_buf_mmap(const char *file, int flags);
R_API RBuffer *r_buf_new_sparse();
R_API bool r_buf_dump (RBuffer *buf, const char *file);
/* methods */
R_API int r_buf_set_bits(RBuffer *b, int bitoff, int bitsize, ut64 value);
R_API int r_buf_set_bytes(RBuffer *b, const ut8 *buf, ut64 length);
R_API int r_buf_append_string(RBuffer *b, const char *str);
R_API bool r_buf_append_buf(RBuffer *b, RBuffer *a);
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
R_API int r_buf_read_at(RBuffer *b, ut64 addr, ut8 *buf, int len);
R_API int r_buf_seek(RBuffer *b, st64 addr, int whence);
R_API int r_buf_fread_at(RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n);
R_API int r_buf_write_at(RBuffer *b, ut64 addr, const ut8 *buf, int len);
R_API int r_buf_fwrite_at(RBuffer *b, ut64 addr, ut8 *buf, const char *fmt, int n);
R_API void r_buf_free(RBuffer *b);
R_API char *r_buf_free_to_string(RBuffer *b);
R_API const ut8 *r_buf_buffer(RBuffer *b);
R_API ut64 r_buf_size(RBuffer *b);
R_API bool r_buf_resize(RBuffer *b, ut64 newsize);
#endif //  R_BUF_H
