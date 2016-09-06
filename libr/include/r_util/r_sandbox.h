#ifndef R_SANDBOX_H
#define R_SANDBOX_H

/**
 * This function verifies that the given path is allowed. Paths are allowed only if they don't
 * contain .. components (which would indicate directory traversal) and they are relative.
 * Paths pointing into the webroot are an exception: For reaching the webroot, .. and absolute
 * path are ok.
 */
R_API DIR* r_sandbox_opendir(const char *path);
R_API int r_sandbox_lseek(int fd, ut64 addr, int mode);
R_API int r_sandbox_close(int fd);
R_API int r_sandbox_read(int fd, ut8 *buf, int len);
R_API int r_sandbox_write(int fd, const ut8 *buf, int len);
R_API bool r_sandbox_enable(bool e);
R_API bool r_sandbox_disable(bool e);
R_API int r_sandbox_system(const char *x, int fork);
R_API bool r_sandbox_creat(const char *path, int mode);
R_API int r_sandbox_open(const char *path, int mode, int perm);
R_API FILE *r_sandbox_fopen(const char *path, const char *mode);
R_API int r_sandbox_chdir(const char *path);
R_API int r_sandbox_check_path(const char *path);
R_API int r_sandbox_kill(int pid, int sig);
#endif //  R_SANDBOX_H
