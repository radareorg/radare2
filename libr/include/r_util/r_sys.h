#ifndef R_SYS_H
#define R_SYS_H

#include <r_list.h>

#if __WINDOWS__ && !__CYGWIN__
#define R_SYS_DEVNULL "nul"
#else
#define R_SYS_DEVNULL "/dev/null"
#endif

#if __linux__ || (__FreeBSD__ && __FreeBSD_version >= 1101000) || (__NetBSD__ && __NetBSD_Version__ >= 700000000)
#define HAS_CLOCK_NANOSLEEP 1
#else
#define HAS_CLOCK_NANOSLEEP 0
#endif

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
R_API const char *r_time_to_string (ut64 ts);
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
R_API const char *r_sys_prefix(const char *pfx);
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
#if UNICODE
#define W32_TCHAR_FSTR "%S"
#define W32_TCALL(name) name"W"
#define r_sys_conv_utf8_to_utf16(buf) r_utf8_to_utf16 ((buf))
#define r_sys_conv_utf8_to_utf16_l(buf, len) r_utf8_to_utf16_l (buf, len) 
#define r_sys_conv_utf16_to_utf8(buf) r_utf16_to_utf8 ((buf))
#define r_sys_conv_utf16_to_utf8_l(buf, len) r_utf16_to_utf8_l (buf, len) 
#else
#define W32_TCHAR_FSTR "%s"
#define W32_TCALL(name) name"A"
#define r_sys_conv_utf8_to_utf16(buf) r_str_new (buf)
#define r_sys_conv_utf16_to_utf8(buf) r_sys_conv_utf8_to_utf16 (buf)
#define r_sys_conv_utf16_to_utf8_l(buf, len) r_str_newlen (buf, len)
#endif
R_API int r_sys_get_src_dir_w32(char *buf);
R_API char *r_sys_cmd_str_w32(const char *cmd);
R_API bool r_sys_create_child_proc_w32(const char *cmdline, HANDLE out);
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

#if __WINDOWS__
#include <intrin.h>
#define r_sys_breakpoint() { __debugbreak(); }
#else
#if __i386__ || __x86_64__
#define r_sys_breakpoint() __asm__ volatile ("int3");
#elif __arm64__ || __aarch64__
#define r_sys_breakpoint() __asm__ volatile ("brk 0");
#elif __arm__ || __thumb__
#define r_sys_breakpoint() __asm__ volatile ("bkpt $0");
#else
#warning r_sys_breakpoint not implemented for this platform
#define r_sys_breakpoint() { char *a = NULL; *a = 0; }
#endif
#endif

/* syscmd */
R_API char *r_syscmd_ls(const char *input);
R_API char *r_syscmd_cat(const char *file);
R_API char *r_syscmd_mkdir(const char *dir);
R_API bool r_syscmd_mv(const char *input);

#ifdef __cplusplus
}
#endif

#endif //  R_SYS_H
