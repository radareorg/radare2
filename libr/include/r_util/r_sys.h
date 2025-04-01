#ifndef R_SYS_H
#define R_SYS_H

#include <r_list.h>

#if R2__WINDOWS__
#define R_SYS_DEVNULL "nul"
#else
#include <errno.h>
#define R_SYS_DEVNULL "/dev/null"
#endif


#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	char *sysname;
	char *nodename;
	char *release;
	char *version;
	char *machine;
} RSysInfo;

R_API RSysInfo *r_sys_info(void);
R_API void r_sys_info_free(RSysInfo *si);

R_API int r_sys_sigaction(int *sig, void(*handler)(int));
R_API int r_sys_signal(int sig, void(*handler)(int));
R_API void r_sys_signable(bool v);
R_API void r_sys_env_init(void);
R_API char **r_sys_get_environ(void);
R_API void r_sys_set_environ(char **e);

R_API int r_sys_fork(void);
// nocleanup = false => exit(); true => _exit()
R_API void r_sys_exit(int status, bool nocleanup);
R_API bool r_sys_stop(void);
R_API char *r_sys_pid_to_path(int pid);
R_API int r_sys_run(const ut8 *buf, int len);
R_API int r_sys_run_rop(const ut8 *buf, int len);
R_API int r_sys_getpid(void);
R_API bool r_sys_crash_handler(const char *cmd);
R_API const char *r_sys_arch_str(int arch);
R_API int r_sys_arch_id(const char *arch);
R_API bool r_sys_arch_match(const char *archstr, const char *arch);
R_API RList *r_sys_dir(const char *path);
R_API void r_sys_perror_str(const char *fun);
#if R2__WINDOWS__
#define r_sys_mkdir_failed() (GetLastError () != ERROR_ALREADY_EXISTS)
#else
#define r_sys_mkdir_failed() (errno != EEXIST)
#endif
R_API int r_sys_tem(const char *s);
R_API const char *r_sys_prefix(const char *pfx);
R_API bool r_sys_mktemp(const char *dir);
R_API bool r_sys_mkdir(const char *dir);
R_API bool r_sys_mkdirp(const char *dir);
R_API int r_sys_sleep(int secs);
R_API int r_sys_usleep(int usecs);
R_API char *r_sys_getenv(const char *key);
R_API bool r_sys_getenv_asbool(const char *key);
R_API int r_sys_getenv_asint(const char *key);
R_API ut64 r_sys_getenv_asut64(const char *key);
R_API int r_sys_setenv(const char *key, const char *value);
R_API int r_sys_setenv_sep(const char *key, const char *value, bool prefix);
R_API void r_sys_setenv_asbool(const char *key, bool v);
R_API void r_sys_setenv_asut64(const char *key, ut64 n);
R_API int r_sys_clearenv(void);
R_API char *r_sys_whoami(void);
R_API int r_sys_uid(void);
R_API char *r_sys_getdir(void);
R_API bool r_sys_chdir(const char *s);
R_API bool r_sys_aslr(int val);
R_API int r_sys_thp_mode(void);
R_API int r_sys_cmd_str_full(const char *cmd, const char *input, int ilen, char **output, int *len, char **sterr);
#if R2__WINDOWS__
#ifdef UNICODE
#define W32_TCHAR_FSTR "%S"
#define W32_TCALL(name) name"W"
#define r_sys_conv_utf8_to_win(buf) r_utf8_to_utf16 (buf)
#define r_sys_conv_utf8_to_win_l(buf, len) r_utf8_to_utf16_l (buf, len)
#define r_sys_conv_win_to_utf8(buf) r_utf16_to_utf8 (buf)
#define r_sys_conv_win_to_utf8_l(buf, len) r_utf16_to_utf8_l ((wchar_t *)buf, len)
#else
#define W32_TCHAR_FSTR "%s"
#define W32_TCALL(name) name"A"
#define r_sys_conv_utf8_to_win(buf) r_utf8_to_acp (buf)
#define r_sys_conv_utf8_to_win_l(buf, len) r_utf8_to_acp_l (buf, len)
#define r_sys_conv_win_to_utf8(buf) r_acp_to_utf8 (buf)
#define r_sys_conv_win_to_utf8_l(buf, len) r_acp_to_utf8_l (buf, len)
#endif
R_API char *r_sys_get_src_dir_w32(void);
R_API bool r_sys_cmd_str_full_w32(const char *cmd, const char *input, int ilen, char **output, int *outlen, char **sterr);
R_API bool r_sys_create_child_proc_w32(const char *cmdline, HANDLE in, HANDLE out, HANDLE err);
#endif
R_API int r_sys_truncate(const char *file, int sz);
R_API int r_sys_cmd(const char *cmd);
R_API int r_sys_cmdbg(const char *cmd);
R_API int r_sys_cmdf(const char *fmt, ...) R_PRINTF_CHECK(1, 2);
R_API char *r_sys_cmd_str(const char *cmd, const char *input, int *len);
R_API char *r_sys_cmd_strf(const char *cmd, ...) R_PRINTF_CHECK(1, 2);
//#define r_sys_cmd_str(cmd, input, len) r_sys_cmd_str_full(cmd, input, len, 0)
R_API void r_sys_backtrace(void);
R_API bool r_sys_tts(const char *txt, bool bg);

#define R_DUMP(x) __builtin_dump_struct(x, &printf)

#if R2__WINDOWS__
#  define r_sys_breakpoint() { __debugbreak  (); }
#else
#if __i386__ || __x86_64__
#   define r_sys_breakpoint() __asm__ volatile ("int3");
#elif __arm64__ || __aarch64__ || __arm64e__
#  define r_sys_breakpoint() __asm__ volatile ("brk 0");
// #define r_sys_breakpoint() __asm__ volatile ("brk #1");
#elif __GNUC__ && !defined(__TINYC__)
#  define r_sys_breakpoint() __builtin_trap()
#elif (__arm__ || __thumb__)
#  if __ARM_ARCH > 5
#    define r_sys_breakpoint() __asm__ volatile ("bkpt $0");
#  else
#    define r_sys_breakpoint() __asm__ volatile ("svc $1");
#  endif
#elif __mips__
#  define r_sys_breakpoint() __asm__ volatile ("break");
#elif __loongarch__
#  define r_sys_breakpoint() __asm__ volatile ("break");
// #  define r_sys_breakpoint() __asm__ volatile ("teq $0, $0");
#elif __EMSCRIPTEN__
// TODO: cannot find a better way to breakpoint in wasm/asm.js
#  define r_sys_breakpoint() { char *a = NULL; *a = 0; }
#else
#  warning r_sys_breakpoint not implemented for this platform
#  define r_sys_trap() __asm__ __volatile__ (".word 0");
#   define r_sys_breakpoint() { char *a = NULL; *a = 0; }
#endif
#endif

/* syscmd */
R_API char *r_syscmd_ls(const char *input, int w);
R_API char *r_syscmd_cat(const char *file);
R_API bool r_syscmd_pushd(const char *dir);
R_API bool r_syscmd_popd(void);
R_API bool r_syscmd_popalld(void);
R_API bool r_syscmd_mkdir(const char *dir);
R_API char *r_syscmd_mktemp(const char *dir);
R_API bool r_syscmd_mv(const char *input);
R_API char *r_syscmd_uniq(const char *file);
R_API char *r_syscmd_head(const char *file, int count);
R_API char *r_syscmd_tail(const char *file, int count);
R_API char *r_syscmd_join(const char *file1, const char *file2);
R_API char *r_syscmd_sort(const char *file);

R_API ut8 *r_sys_unxz(const ut8 *data, size_t len, size_t *olen);
R_API bool r_w32_init(void);

#ifdef __cplusplus
}
#endif

#endif //  R_SYS_H
