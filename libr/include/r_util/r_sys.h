#ifndef R_SYS_H
#define R_SYS_H

#include <r_list.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	R_SYS_BITS_8 = 1,
	R_SYS_BITS_16 = 2,
	R_SYS_BITS_32 = 4,
	R_SYS_BITS_64 = 8,
};

R_API char **r_sys_get_environ(void);
R_API void r_sys_set_environ(char **e);
R_API ut64 r_sys_now(void);
R_API int r_sys_fork(void);
R_API bool r_sys_stop(void);
R_API char *r_sys_pid_to_path(int pid);
R_API int r_sys_run(const ut8 *buf, int len);
R_API int r_sys_getpid(void);
R_API int r_sys_crash_handler(const char *cmd);
R_API const char *r_sys_arch_str(int arch);
R_API int r_sys_arch_id(const char *arch);
R_API bool r_sys_arch_match(const char *archstr, const char *arch);
R_API RList *r_sys_dir(const char *path);
R_API void r_sys_perror_str(const char *fun);
#if __WINDOWS__ && !defined(__CYGWIN__)
#define r_sys_mkdir_failed() (GetLastError () != ERROR_ALREADY_EXISTS)
#else
#define r_sys_mkdir_failed() (errno != EEXIST)
#endif
R_API bool r_sys_mkdir(const char *dir);
R_API bool r_sys_mkdirp(const char *dir);
R_API int r_sys_sleep(int secs);
R_API int r_sys_usleep(int usecs);
R_API char *r_sys_getenv(const char *key);
R_API int r_sys_setenv(const char *key, const char *value);
R_API int r_sys_clearenv(void);
R_API char *r_sys_whoami(char *buf);
R_API char *r_sys_getdir(void);
R_API int r_sys_chdir(const char *s);
R_API int r_sys_cmd_str_full(const char *cmd, const char *input, char **output, int *len, char **sterr);
#if __WINDOWS__
R_API int r_sys_get_src_dir_w32(char *buf);
R_API char *r_sys_cmd_str_w32(const char *cmd);
#endif
R_API int r_sys_truncate(const char *file, int sz);
R_API int r_sys_cmd(const char *cmd);
R_API int r_sys_cmdbg(const char *cmd);
R_API int r_sys_cmdf(const char *fmt, ...);
R_API char *r_sys_cmd_str(const char *cmd, const char *input, int *len);
R_API char *r_sys_cmd_strf(const char *cmd, ...);
//#define r_sys_cmd_str(cmd, input, len) r_sys_cmd_str_full(cmd, input, len, 0)
R_API void r_sys_backtrace(void);
R_API bool r_sys_tts(const char *txt, bool bg);

/* syscmd */
R_API char *r_syscmd_ls(const char *input);
R_API char *r_syscmd_cat(const char *file);
R_API char *r_syscmd_mkdir(const char *dir);
R_API bool r_syscmd_mv(const char *input);

#ifdef __cplusplus
}
#endif

#endif //  R_SYS_H
