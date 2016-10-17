#ifndef R_FILE_H
#define R_FILE_H
#include <r_util/r_mem.h>

R_API int r_file_is_abspath(const char *file);
R_API bool r_file_truncate(const char *filename, ut64 newsize);
R_API ut64 r_file_size(const char *str);
R_API char *r_file_root(const char *root, const char *path);
R_API bool r_file_is_directory(const char *str);
R_API bool r_file_is_regular(const char *str);
R_API RMmap *r_file_mmap(const char *file, bool rw, ut64 base);
R_API int r_file_mmap_read(const char *file, ut64 addr, ut8 *buf, int len);
R_API int r_file_mmap_write(const char *file, ut64 addr, const ut8 *buf, int len);
R_API void r_file_mmap_free(RMmap *m);
R_API int r_file_chmod(const char *file, const char *mod, int recursive);
R_API char *r_file_temp(const char *prefix);
R_API char *r_file_path(const char *bin);
R_API const char *r_file_basename(const char *path);
R_API char *r_file_dirname(const char *path);
R_API char *r_file_abspath(const char *file);
R_API ut8 *r_inflate(const ut8 *src, int srcLen, int *srcConsumed, int *dstLen);
R_API ut8 *r_file_gzslurp(const char *str, int *outlen, int origonfail);
R_API char *r_stdin_slurp(int *sz);
R_API char *r_file_slurp(const char *str, int *usz);
//R_API char *r_file_slurp_range(const char *str, ut64 off, ut64 sz);
R_API char *r_file_slurp_range(const char *str, ut64 off, int sz, int *osz);
R_API char *r_file_slurp_random_line(const char *file);
R_API char *r_file_slurp_random_line_count(const char *file, int *linecount);
R_API ut8 *r_file_slurp_hexpairs(const char *str, int *usz);
R_API bool r_file_dump(const char *file, const ut8 *buf, int len, int append);
R_API bool r_file_rm(const char *file);
R_API bool r_file_exists(const char *str);
R_API bool r_file_fexists(const char *fmt, ...);
R_API char *r_file_slurp_line(const char *file, int line, int context);
R_API int r_file_mkstemp(const char *prefix, char **oname);
R_API char *r_file_tmpdir(void);
R_API char *r_file_readlink(const char *path);
R_API bool r_file_copy (const char *src, const char *dst);

#endif //  R_FILE_H
