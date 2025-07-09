#ifndef R_FILE_H
#define R_FILE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <r_util/r_mem.h>

#ifndef SHELL_PATH
#if TERMUX_BUILD
#define SHELL_PATH "/data/data/com.termux/files/usr/bin/sh"
#else
#define SHELL_PATH "/bin/sh"
#endif
#endif

#ifndef TERMUX_PREFIX
#define TERMUX_PREFIX "/data/data/com.termux/files/usr"
#endif

/* is */
R_API bool r_file_is_abspath(const char *file);
R_API bool r_file_is_c(const char *file);
R_API bool r_file_is_directory(const char *str);
R_API bool r_file_is_regular(const char *str);
R_API bool r_file_is_executable(const char *file);

R_API bool r_file_truncate(const char *filename, ut64 newsize);
R_API char *r_file_new(const char *root, ...);
R_API ut64 r_file_size(const char *str);
R_API char *r_file_root(const char *root, const char *path);

// mmap
R_API bool r_file_mmap_fd(RMmap *map, const char *filename, int fd);
R_API RMmap *r_file_mmap(const char *file, bool rw, ut64 base);
R_API int r_file_mmap_read(RMmap *m, ut64 addr, ut8 *buf, int len);
R_API bool r_file_mmap_resize(RMmap *m, ut64 newsize);
// TODO: make mmap_write work with msync
R_API int r_file_mmap_write(const char *file, ut64 addr, const ut8 *buf, int len);
R_API ut64 r_file_mmap_size(RMmap *m);
R_API void r_file_mmap_free(RMmap *m);

R_API bool r_file_chmod(const char *file, const char *mod, int recursive);
R_API char *r_file_temp(const char *prefix);
R_API char *r_file_path(const char *bin);
R_API char *r_file_binsh(void);
R_API const char *r_file_basename(const char *path);
R_API char *r_file_dirname(const char *path);
R_API char *r_file_abspath_rel(const char *cwd, const char *file);
R_API char *r_file_abspath(const char *file);
R_API ut8 *r_inflate(const ut8 *src, int srcLen, int *srcConsumed, int *dstLen);
R_API ut8 *r_inflate_raw(const ut8 *src, int srcLen, int *srcConsumed, int *dstLen);
R_API ut8 *r_inflate_lz4(const ut8 *src, int srcLen, int *consumed, int *dstLen);
R_API ut8 *r_file_gzslurp(const char *str, int *outlen, int origonfail);
R_API char *r_stdin_slurp(int *sz);
R_API char *r_stdin_readline(int *sz);
R_API char *r_file_slurp(const char *str, size_t * R_NULLABLE usz);
R_API char *r_file_slurp_range(const char *str, ut64 off, int sz, int *osz);
R_API char *r_file_slurp_random_line(const char *file);
R_API char *r_file_slurp_random_line_count(const char *file, int *linecount);
R_API int r_file_slurp_mmap(const char *file, ut64 addr, ut8 *buf, int len);
R_API ut8 *r_file_slurp_hexpairs(const char *str, int *usz);
R_API bool r_file_dump(const char *file, const ut8 *buf, int len, bool append);
R_API bool r_file_dump_line(const char *file, int line, const char *msg, bool replace);
R_API bool r_file_touch(const char *file);
R_API bool r_file_hexdump(const char *file, const ut8 *buf, int len, int append);
R_API bool r_file_rm(const char *file);
R_API bool r_file_exists(const char *str);
R_API const char *r_file_extension(const char *str);
R_API bool r_file_fexists(const char *fmt, ...) R_PRINTF_CHECK(1, 2);
R_API char *r_file_slurp_line(const char *file, int line, int context);
R_API char *r_file_slurp_lines(const char *file, int line, int count);
R_API char *r_file_slurp_lines_from_bottom(const char *file, int line);
R_API char *r_file_temp_ex(const char * R_NULLABLE prefix, const char * R_NULLABLE ex);
R_API int r_file_mkstemp(const char *prefix, char **oname);
R_API char *r_file_tmpdir(void);
R_API char *r_file_readlink(const char *path);
R_API bool r_file_copy(const char *src, const char *dst);
R_API bool r_file_move(const char *src, const char *dst);
R_API RList* r_file_glob(const char *globbed_path, int maxdepth);
R_API RList *r_file_lsrf(const char *dir);
R_API bool r_file_is_newer(const char *f1, const char *f2);
R_API bool r_file_rm_rf(const char *dir);
R_API R_MUSTUSE char *r_file_home(const char *str);
R_API R_MUSTUSE char *r_file_homef(const char *fmt, ...);

// XDG
R_API char * R_NULLABLE r_xdg_configdir(const char *s);
R_API char * R_NULLABLE r_xdg_datadir(const char *s);
R_API char * R_NULLABLE r_xdg_cachedir(const char *s);

#ifdef __cplusplus
}
#endif

#endif //  R_FILE_H
