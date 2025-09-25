/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_userconf.h>
#include <stdlib.h>
#include <string.h>
#if defined(__NetBSD__)
# include <sys/param.h>
# include <sys/sysctl.h>
# if __NetBSD_Prereq__(7,0,0)
#  define NETBSD_WITH_BACKTRACE
# endif
#endif
#if defined(__FreeBSD__)
# include <sys/param.h>
# include <sys/sysctl.h>
# if __FreeBSD_version >= 1000000
#  define FREEBSD_WITH_BACKTRACE
# endif
#endif
#if defined(__DragonFly__)
# include <sys/param.h>
# include <sys/sysctl.h>
#endif
#if defined(__HAIKU__)
# include <kernel/image.h>
# include <sys/param.h>
extern int backtrace(void**, size_t);
extern int backtrace_symbols_fd(void**, size_t, int);
#endif
#include <sys/types.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>

static R_TH_LOCAL char** Genv = NULL;
static R_TH_LOCAL char *Gprefix = NULL;
static R_TH_LOCAL char *Gr2prefix = NULL;
static R_TH_LOCAL bool Gunsignable = false; // OK

#if (__linux__ && __GNU_LIBRARY__) || defined(NETBSD_WITH_BACKTRACE) || \
  defined(FREEBSD_WITH_BACKTRACE) || __DragonFly__ || __sun
# include <execinfo.h>
#endif
#if __APPLE__
#include <errno.h>
#include <TargetConditionals.h>
// iOS don't have this
#if !TARGET_OS_IPHONE
#define HAVE_ENVIRON 1
#else
#define HAVE_ENVIRON 0
#endif

// _NSGetEnviron is used on both macOS and iOS paths
#if defined(__has_include)
# if __has_include(<crt_externs.h>)
#  include <crt_externs.h>
# endif
#else
# include <crt_externs.h>
#endif
// Fallback declaration if header is unavailable
#ifndef _NSGetEnviron
extern char ***_NSGetEnviron(void);
#endif

// Provide environ via _NSGetEnviron when available
#if HAVE_ENVIRON
#define environ (*_NSGetEnviron())
#endif

# ifndef PROC_PIDPATHINFO_MAXSIZE
#  define PROC_PIDPATHINFO_MAXSIZE 1024
int proc_pidpath(int pid, void * buffer, ut32 buffersize);
//#  include <libproc.h>
# endif
#endif
#if R2__UNIX__
# include <sys/utsname.h>
# include <sys/stat.h>
# include <errno.h>
#ifndef __wasi__
# include <pwd.h>
# include <sys/wait.h>
#endif
# include <signal.h>
#ifndef __APPLE__
extern char **environ;
#endif

#ifdef __HAIKU__
# define Sleep sleep
#endif
#endif
#if R2__WINDOWS__
# include <io.h>
# include <winbase.h>
# include <signal.h>
#define TMP_BUFSIZE	4096
#ifdef _MSC_VER
#include <psapi.h>
#include <process.h>  // to allow getpid under windows msvc compilation
#include <direct.h>  // to allow getcwd under windows msvc compilation
#endif
#endif

R_LIB_VERSION (r_util);

#ifdef __x86_64__
# ifdef _MSC_VER
#  define R_SYS_ASM_START_ROP() \
	 eprintf ("r_sys_run_rop: Unsupported arch\n");
# else
#  define R_SYS_ASM_START_ROP() \
	 __asm__ __volatile__ ("leaq %0, %%rsp; ret" \
				: \
				: "m" (*bufptr));
# endif
#elif __i386__
# ifdef _MSC_VER
#  define R_SYS_ASM_START_ROP() \
	__asm \
	{ \
		__asm lea esp, bufptr\
		__asm ret\
	}
# else
#  define R_SYS_ASM_START_ROP() \
	__asm__ __volatile__ ("leal %0, %%esp; ret" \
				: \
				: "m" (*bufptr));
# endif
#else
# define R_SYS_ASM_START_ROP() \
	eprintf ("r_sys_run_rop: Unsupported arch\n");
#endif

static const struct {const char* name; ut64 bit;} arch_bit_array[] = {
	{ "x86", R_SYS_ARCH_X86},
	{ "arm", R_SYS_ARCH_ARM},
	{ "ppc", R_SYS_ARCH_PPC},
	{ "m68k", R_SYS_ARCH_M68K},
	{ "java", R_SYS_ARCH_JAVA},
	{ "mips", R_SYS_ARCH_MIPS},
	{ "sparc", R_SYS_ARCH_SPARC},
	{ "xap", R_SYS_ARCH_XAP},
	{ "tms320", R_SYS_ARCH_TMS320},
	{ "msil", R_SYS_ARCH_MSIL},
	{ "objd", R_SYS_ARCH_OBJD},
	{ "bf", R_SYS_ARCH_BF},
	{ "sh", R_SYS_ARCH_SH},
	{ "avr", R_SYS_ARCH_AVR},
	{ "dalvik", R_SYS_ARCH_DALVIK},
	{ "z80", R_SYS_ARCH_Z80},
	{ "arc", R_SYS_ARCH_ARC},
	{ "i8080", R_SYS_ARCH_I8080},
	{ "rar", R_SYS_ARCH_RAR},
	{ "lm32", R_SYS_ARCH_LM32},
	{ "v850", R_SYS_ARCH_V850},
	{ "bpf", R_SYS_ARCH_BPF},
	{ "sbpf", R_SYS_ARCH_SBPF},
	{NULL, 0}
};

R_API void r_sys_signable(bool v) {
	Gunsignable = !v;
}

R_API int r_sys_fork(void) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_EXEC)) {
		return false;
	}
#if HAVE_FORK
#if R2__WINDOWS__
	return -1;
#else
	return fork ();
#endif
#else
	return -1;
#endif
}

#if R2__WINDOWS__
R_API int r_sys_sigaction(int *sig, void(*handler)(int)) {
	return -1;
}
#elif __wasi__
R_API int r_sys_sigaction(int *sig, void(*handler)(int)) {
	return 0;
}
#elif HAVE_SIGACTION
R_API int r_sys_sigaction(int *sig, void(*handler)(int)) {
#if WANT_DEBUGSTUFF
	struct sigaction sigact = { };
	int ret, i;
	if (Gunsignable) {
		return -1;
	}

	if (!sig) {
		return -EINVAL;
	}

	sigact.sa_handler = handler;
	sigemptyset (&sigact.sa_mask);

	for (i = 0; sig[i] != 0; i++) {
		sigaddset (&sigact.sa_mask, sig[i]);
	}

	for (i = 0; sig[i] != 0; i++) {
		ret = sigaction (sig[i], &sigact, NULL);
		if (ret) {
			R_LOG_ERROR ("Failed to set signal handler for signal '%d': %s", sig[i], strerror(errno));
			return ret;
		}
	}
#endif
	return 0;
}
#else
R_API int r_sys_sigaction(int *sig, void(*handler)(int)) {
	if (Gunsignable) {
		return -1;
	}
	if (!sig) {
		return -EINVAL;
	}
	size_t i;
	for (i = 0; sig[i] != 0; i++) {
		void (*ret)(int) = signal (sig[i], handler);
		if (ret == SIG_ERR) {
			R_LOG_ERROR ("Failed to set signal handler for signal '%d': %s", sig[i], strerror(errno));
			return -1;
		}
	}
	return 0;
}
#endif

R_API int r_sys_signal(int sig, void(*handler)(int)) {
	int s[2] = { sig, 0 };
	return r_sys_sigaction (s, handler);
}

R_API void r_sys_exit(int status, bool nocleanup) {
	if (nocleanup) {
		_exit (status);
	} else {
		exit (status);
	}
}

R_API int r_sys_truncate(const char *file, int sz) {
#if R2__WINDOWS__
	int fd = r_sandbox_open (file, O_RDWR, 0644);
	if (fd == -1) {
		return false;
	}
	int r = _chsize (fd, sz);
	if (r != 0) {
		R_LOG_ERROR ("Could not resize '%s' file", file);
		close (fd);
		return false;
	}
	close (fd);
	return true;
#else
	if (r_sandbox_enable (0)) {
		return false;
	}
	return truncate (file, sz) == 0;
#endif
}

R_API RList *r_sys_dir(const char *path) {
	RList *list = NULL;
#if R2__WINDOWS__
	WIN32_FIND_DATAW entry;
	char *cfname;
	HANDLE fh = r_sandbox_opendir (path, &entry);
	if (fh == INVALID_HANDLE_VALUE) {
		//IFDGB R_LOG_ERROR ("Cannot open directory %ls", wcpath);
		return list;
	}
	list = r_list_newf (free);
	if (list) {
		do {
			if ((cfname = r_utf16_to_utf8 (entry.cFileName))) {
				r_list_append (list, strdup (cfname));
				free (cfname);
			}
		} while (FindNextFileW (fh, &entry));
	}
	FindClose (fh);
#else
	struct dirent *entry;
	DIR *dir = r_sandbox_opendir (path);
	if (dir) {
		list = r_list_newf (free);
		if (list) {
			list->free = free;
			while ((entry = readdir (dir))) {
				r_list_append (list, strdup (entry->d_name));
			}
		}
		closedir (dir);
	}
#endif
	return list;
}

R_API char *r_sys_cmd_strf(const char *fmt, ...) {
	char *ret, cmd[4096];
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (cmd, sizeof (cmd), fmt, ap);
	ret = r_sys_cmd_str (cmd, NULL, NULL);
	va_end (ap);
	return ret;
}

R_API ut8 *r_sys_unxz(const ut8 *buf, size_t len, size_t *olen) {
	char *err = NULL;
	ut8 *out = NULL;
	int _olen = 0;
	int rc = r_sys_cmd_str_full ("xz -d", (const char *)buf, (int)len, (char **)&out, &_olen, &err);
	if (rc == 0 || rc == 1) {
		if (olen) {
			*olen = (size_t)_olen;
		}
		free (err);
		return out;
	}
	free (out);
	free (err);
	return NULL;
}

#ifdef __MAC_10_7
#define APPLE_WITH_BACKTRACE 1
#endif
#ifdef __IPHONE_4_0
#define APPLE_WITH_BACKTRACE 1
#endif

#if (__linux__ && __GNU_LIBRARY__) || (__APPLE__ && APPLE_WITH_BACKTRACE) || \
  defined(NETBSD_WITH_BACKTRACE) || defined(FREEBSD_WITH_BACKTRACE) || \
  __DragonFly__ || __sun || __HAIKU__
#define HAVE_BACKTRACE 1
#endif

// Ensure backtrace() declarations are visible on Apple when supported
#if defined(__APPLE__) && defined(APPLE_WITH_BACKTRACE)
# if defined(__has_include)
#  if __has_include(<execinfo.h>)
#   include <execinfo.h>
#  endif
# else
// Older SDKs may not have execinfo.h; include only when available above
# endif
#endif

R_API void r_sys_backtrace(void) {
#if WANT_DEBUGSTUFF
#ifdef HAVE_BACKTRACE
	void *array[10];
	size_t size = backtrace (array, 10);
	R_LOG_ERROR ("Backtrace %d stack frames", (int)size);
	backtrace_symbols_fd (array, size, 2);
#elif __APPLE__
	void **fp = (void **) __builtin_frame_address (0);
	void *saved_pc = __builtin_return_address (0);
	void *saved_fp = __builtin_frame_address (1);
	int depth = 0;

	printf ("[%d] pc == %p fp == %p\n", depth++, saved_pc, saved_fp);
	fp = saved_fp;
	while (fp) {
		saved_fp = *fp;
		fp = saved_fp;
		if (!*fp) {
			break;
		}
		saved_pc = *(fp + 2);
		printf ("[%d] pc == %p fp == %p\n", depth++, saved_pc, saved_fp);
	}
#else
#pragma message ("TODO: r_sys_bt : unimplemented")
#endif
#endif
}

R_API int r_sys_sleep(int secs) {
#if HAS_CLOCK_NANOSLEEP
	struct timespec rqtp;
	rqtp.tv_sec = secs;
	rqtp.tv_nsec = 0;
	return clock_nanosleep (CLOCK_MONOTONIC, 0, &rqtp, NULL);
#elif R2__UNIX__
	return sleep (secs);
#else
	Sleep (secs * 1000); // W32
	return 0;
#endif
}

R_API int r_sys_usleep(int usecs) {
#if HAS_CLOCK_NANOSLEEP
	struct timespec rqtp;
	rqtp.tv_sec = usecs / 1000000;
	rqtp.tv_nsec = (usecs - (rqtp.tv_sec * 1000000)) * 1000;
	return clock_nanosleep (CLOCK_MONOTONIC, 0, &rqtp, NULL);
#elif R2__UNIX__
#if defined(__GLIBC__) && defined(__GLIBC_MINOR__) && (__GLIBC__ <= 2) && (__GLIBC_MINOR__ <= 2)
	// Old versions of GNU libc return void for usleep
	usleep (usecs);
	return 0;
#else
	return usleep (usecs);
#endif
#else
	// w32 api uses milliseconds
	usecs /= 1000;
	Sleep (usecs); // W32
	return 0;
#endif
}

R_API bool r_sys_clearenv(void) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_ENVIRON)) {
		return false;
	}
#if R2__UNIX__
#if __APPLE__ && !HAVE_ENVIRON
	/* do nothing */
	if (!Genv) {
		r_sys_env_init ();
		return true;
	}
	char **e = Genv;
	if (e) {
		while (*e) {
			*e++ = NULL;
		}
	}
#else
	if (!environ) {
		return false;
	}
	while (*environ) {
		*environ++ = NULL;
	}
#endif
	return true;
#else
#pragma message ("r_sys_clearenv : unimplemented for this platform")
	return false;
#endif
}

R_API int r_sys_setenv(const char *key, const char *value) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_ENVIRON)) {
		return -1;
	}
	if (!key) {
		return 0;
	}
#if R2__UNIX__
	if (!value) {
		unsetenv (key);
		return 0;
	}
	return setenv (key, value, 1);
#elif R2__WINDOWS__
	if (!value) {
		SetEnvironmentVariableA(key, NULL);
		return 0;
	}
	LPTSTR key_ = r_sys_conv_utf8_to_win (key);
	LPTSTR value_ = r_sys_conv_utf8_to_win (value);
	int ret = SetEnvironmentVariable (key_, value_);
	if (!ret) {
		r_sys_perror ("r_sys_setenv/SetEnvironmentVariable");
	}
	free (key_);
	free (value_);
	return ret ? 0 : -1;
#else
#pragma message("r_sys_setenv : unimplemented for this platform")
	return 0;
#endif
}

R_API int r_sys_setenv2(const char *key, const ut8 *value, size_t len) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_ENVIRON)) {
		return -1;
	}
	if (!key) {
		return 0;
	}
	if (!value) {
		r_sys_setenv (key, NULL);
		return 0;
	}
	ut8 *buf = malloc (len + 1);
	ut8 *zeroes = calloc (1, len);
	memcpy (buf, value, len);
	size_t i = 0;
	bool nullbytes = false;
	for (i = 0; i < len; i++) {
		if (!buf[i]) {
			buf[i] = 'X';
			zeroes[i] = 1;
			nullbytes = true;
		}
	}
	buf[len] = 0;
	if (r_sys_setenv (key, (char *)buf) != 0) {
		free (zeroes);
		free (buf);
		return -1;
	}
	if (nullbytes) {
		R_LOG_WARN ("Environment corrupted after null bytes injected via r_sys_setenv2");
	}
	char *p = getenv (key);
	for (i = 0; i < len; i++) {
		if (zeroes[i]) {
			p[i] = 0;
		}
	}
	free (zeroes);
	free (buf);
	return 0;
}

R_API int r_sys_setenv_sep(const char *key, const char *value, bool prefix) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_ENVIRON)) {
		return false;
	}
	char *o = r_sys_getenv (key);
	if (R_STR_ISEMPTY (o)) {
		int res = r_sys_setenv (key, value);
		free (o);
		return res;
	}
	char *v = prefix
		? r_str_newf ("%s" R_SYS_ENVSEP "%s", o, value)
		: r_str_newf ("%s" R_SYS_ENVSEP "%s", value, o);
	int res = r_sys_setenv (key, v);
	free (v);
	free (o);
	return res;
}

#if WANT_DEBUGSTUFF
#if R2__UNIX__
static char *crash_handler_cmd = NULL;

static void signal_handler(int signum) {
	if (!crash_handler_cmd) {
		return;
	}
#if __wasi__ || EMSCRIPTEN
	char *cmd = r_str_newf ("%s %d", crash_handler_cmd, 0);
#else
	char *cmd = r_str_newf ("%s %d", crash_handler_cmd, r_sys_getpid ());
#endif
	int rc = 1;
	if (cmd) {
		r_sys_backtrace ();
		rc = r_sys_cmd (cmd);
		free (cmd);
	}
	exit (rc);
}

static int checkcmd(const char *c) {
	char oc = 0;
	for (; *c; c++) {
		if (oc == '%') {
			if (*c != 'd' && *c != '%') {
				return 0;
			}
		}
		oc = *c;
	}
	return 1;
}
#endif

R_API bool r_sys_crash_handler(const char *cmd) {
#ifndef R2__WINDOWS__
	int sig[] = { SIGINT, SIGSEGV, SIGBUS, SIGQUIT, SIGHUP, 0 };
	if (!checkcmd (cmd)) {
		return false;
	}
#ifdef HAVE_BACKTRACE
	void *array[1];
	/* call this outside of the signal handler to init it safely */
	backtrace (array, 1);
#endif
	free (crash_handler_cmd);
	crash_handler_cmd = strdup (cmd);
	r_sys_sigaction (sig, signal_handler);
#else
#pragma message ("r_sys_crash_handler : unimplemented for this platform")
#endif
	return true;
}
#else
R_API bool r_sys_crash_handler(const char *cmd) {
	return true;
}
#endif

R_API char *r_sys_getenv(const char *key) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_ENVIRON)) {
		return false;
	}
#if R2__WINDOWS__
	DWORD dwRet;
	LPTSTR envbuf = NULL, key_ = NULL, tmp_ptr;
	char *val = NULL;

	if (!key) {
		return NULL;
	}
	envbuf = (LPTSTR)calloc (sizeof (TCHAR), TMP_BUFSIZE);
	if (!envbuf) {
		goto err_r_sys_get_env;
	}
	key_ = r_sys_conv_utf8_to_win (key);
	dwRet = GetEnvironmentVariable (key_, envbuf, TMP_BUFSIZE);
	if (dwRet == 0) {
		if (GetLastError () == ERROR_ENVVAR_NOT_FOUND) {
			goto err_r_sys_get_env;
		}
	} else if (TMP_BUFSIZE < dwRet) {
		tmp_ptr = (LPTSTR)realloc (envbuf, dwRet * sizeof (TCHAR));
		if (!tmp_ptr) {
			goto err_r_sys_get_env;
		}
		envbuf = tmp_ptr;
		dwRet = GetEnvironmentVariable (key_, envbuf, dwRet);
		if (!dwRet) {
			goto err_r_sys_get_env;
		}
	}
	val = r_sys_conv_win_to_utf8_l (envbuf, (int)dwRet);
err_r_sys_get_env:
	free (key_);
	free (envbuf);
	return val;
#else
	char *b;
	if (!key) {
		return NULL;
	}
	b = getenv (key);
	return b? strdup (b): NULL;
#endif
}

R_API void r_sys_setenv_asbool(const char *key, bool v) {
	R_RETURN_IF_FAIL (key);
	r_sys_setenv (key, v? "1": "0");
}

R_API void r_sys_setenv_asut64(const char *key, ut64 n) {
	R_RETURN_IF_FAIL (key);
	char *env = r_str_newf ("%"PFMT64d, n);
	r_sys_setenv (key, env);
	free (env);
}

R_API bool r_sys_getenv_asbool(const char *key) {
	R_RETURN_VAL_IF_FAIL (key, false);
	char *env = r_sys_getenv (key);
	const bool res = env && r_str_is_true (env);
	free (env);
	return res;
}

R_API ut64 r_sys_getenv_asut64(const char *key) {
	R_RETURN_VAL_IF_FAIL (key, false);
	char *env = r_sys_getenv (key);
	const ut64 res = env? r_num_math (NULL, env): 0;
	free (env);
	return res;
}

R_API int r_sys_getenv_asint(const char *key) {
	R_RETURN_VAL_IF_FAIL (key, false);
	char *env = r_sys_getenv (key);
	const int res = env? atoi (env): 0;
	free (env);
	return res;
}

R_API char *r_sys_getdir(void) {
#if R2__WINDOWS__
	return _getcwd (NULL, 0);
#else
#ifdef __GLIBC__
	return getcwd (NULL, 0);
#else
	const size_t maxpathlen = 4096;
	char *res = calloc (maxpathlen, 1);
	char *cwd = getcwd (res, maxpathlen);
	if (!cwd) {
		free (res);
	}
	return cwd;
#endif
#endif
}

R_API bool r_sys_chdir(const char *s) {
	return r_sandbox_chdir (s) == 0;
}

R_API bool r_sys_aslr(int val) {
	bool ret = true;
#if __linux__
	const char *rva = "/proc/sys/kernel/randomize_va_space";
	char buf[3] = {0};
	snprintf(buf, sizeof (buf), "%d\n", val != 0 ? 2 : 0);
	int fd = r_sandbox_open (rva, O_WRONLY, 0644);
	if (fd != -1) {
		if (r_sandbox_write (fd, (ut8 *)buf, sizeof (buf)) != sizeof (buf)) {
			R_LOG_ERROR ("Failed to set RVA");
			ret = false;
		}
		close (fd);
	}
#elif __FreeBSD__ && __FreeBSD_version >= 1300000
	size_t vlen = sizeof (val);
	if (sysctlbyname ("kern.elf32.aslr.enable", NULL, 0, &val, vlen) == -1) {
		R_LOG_ERROR ("Failed to set RVA 32 bits");
		return false;
	}

#if __LP64__
	if (sysctlbyname ("kern.elf64.aslr.enable", NULL, 0, &val, vlen) == -1) {
		R_LOG_ERROR ("Failed to set RVA 64 bits");
		ret = false;
	}
#endif
#elif __NetBSD__
	size_t vlen = sizeof (val);
	if (sysctlbyname ("security.pax.aslr.enabled", NULL, 0, &val, vlen) == -1) {
		R_LOG_ERROR ("Failed to set RVA");
		ret = false;
	}
#elif __DragonFly__
	size_t vlen = sizeof (val);
	if (sysctlbyname ("vm.randomize_mmap", NULL, 0, &val, vlen) == -1) {
		R_LOG_ERROR ("Failed to set RVA");
		ret = false;
	}
#endif
	return ret;
}

#if R2__UNIX__ && HAVE_SYSTEM
R_API int r_sys_cmd_str_full(const char *cmd, const char *input, int ilen, char **output, int *len, char **sterr) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_EXEC)) {
		return false;
	}

	char *mysterr = NULL;
	if (!sterr) {
		sterr = &mysterr;
	}
	ut8 buffer[1024];
	char *outputptr = NULL;
	char *inputptr = (char *)input;
	int pid, bytes = 0, status;
	int sh_in[2], sh_out[2], sh_err[2];

	if (len) {
		*len = 0;
	}
	if (ilen == -1 && inputptr) {
		ilen = strlen (inputptr);
	}
	if (pipe (sh_in)) {
		return false;
	}
	if (output) {
		if (pipe (sh_out)) {
			close (sh_in[0]);
			close (sh_in[1]);
			close (sh_out[0]);
			close (sh_out[1]);
			return false;
		}
	}
	if (pipe (sh_err)) {
		close (sh_in[0]);
		close (sh_in[1]);
		return false;
	}

	switch ((pid = r_sys_fork ())) {
	case -1:
		return false;
	case 0:
		dup2 (sh_in[0], 0);
		close (sh_in[0]);
		close (sh_in[1]);
		if (output) {
			dup2 (sh_out[1], 1);
			close (sh_out[0]);
			close (sh_out[1]);
		}
		if (sterr) {
			dup2 (sh_err[1], 2);
		} else {
			close (2);
		}
		close (sh_err[0]);
		close (sh_err[1]);
		exit (r_sandbox_system (cmd, 0));
	default:
		outputptr = strdup ("");
		if (!outputptr) {
			return false;
		}
		if (sterr) {
			*sterr = strdup ("");
			if (!*sterr) {
				free (outputptr);
				return false;
			}
		}
		if (output) {
			close (sh_out[1]);
		}
		close (sh_err[1]);
		close (sh_in[0]);
		if (R_STR_ISEMPTY (inputptr)) {
			close (sh_in[1]);
		}
		// we should handle broken pipes somehow better
		r_sys_signal (SIGPIPE, SIG_IGN);
		size_t err_len = 0, out_len = 0;
		size_t written = 0;
		for (;;) {
			fd_set rfds, wfds;
			int nfd;
			FD_ZERO (&rfds);
			FD_ZERO (&wfds);
			if (output) {
				FD_SET (sh_out[0], &rfds);
			}
			if (sterr) {
				FD_SET (sh_err[0], &rfds);
			}
			if (inputptr && *inputptr) {
				FD_SET (sh_in[1], &wfds);
			}
			memset (buffer, 0, sizeof (buffer));
			nfd = select (sh_err[0] + 1, &rfds, &wfds, NULL, NULL);
			if (nfd < 0) {
				// eprintf ("nfd %d 2%c", nfd, 10);
			}
			if (output && FD_ISSET (sh_out[0], &rfds)) {
				if ((bytes = read (sh_out[0], buffer, sizeof (buffer))) < 1) {
					break;
				}
				char *tmp = realloc (outputptr, out_len + bytes + 1);
				if (!tmp) {
					R_FREE (outputptr);
					break;
				}
				outputptr = tmp;
				memcpy (outputptr + out_len, buffer, bytes);
				out_len += bytes;
			} else if (FD_ISSET (sh_err[0], &rfds) && sterr) {
				if ((bytes = read (sh_err[0], buffer, sizeof (buffer))) < 1) {
					break;
				}
				char *tmp = realloc (*sterr, err_len + bytes + 1);
				if (!tmp) {
					R_FREE (*sterr);
					break;
				}
				*sterr = tmp;
				memcpy (*sterr + err_len, buffer, bytes);
				err_len += bytes;
			} else if (FD_ISSET (sh_in[1], &wfds) && written < ilen) {
				int inputptr_len = ilen >= 0? ilen - written: strlen (inputptr + written);
				inputptr_len = R_MIN (inputptr_len, sizeof (buffer));
				bytes = write (sh_in[1], inputptr + written, inputptr_len);
				written += bytes;
				if (written >= ilen) {
					close (sh_in[1]);
					// break;
				}
			}
		}
		if (output) {
			close (sh_out[0]);
		}
		close (sh_err[0]);
		close (sh_in[1]);
		waitpid (pid, &status, 0);
		bool ret = true;
		if (status) {
			// char *escmd = r_str_escape (cmd);
			// R_LOG_ERROR ("error code %d (%s): %s", WEXITSTATUS (status), escmd, *sterr);
			// eprintf ("(%s)\n", output);
			R_LOG_DEBUG ("command failed: %s", cmd);
			// free (escmd);
			ret = false;
		}
		if (len) {
			*len = out_len;
		}
		if (*sterr) {
			(*sterr)[err_len] = 0;
		}
		if (outputptr) {
			outputptr[out_len] = 0;
		}
		if (output) {
			*output = outputptr;
		} else {
			free (outputptr);
		}
		free (mysterr);
		return ret;
	}
	return false;
}
#elif R2__WINDOWS__
R_API int r_sys_cmd_str_full(const char *cmd, const char *input, int ilen, char **output, int *len, char **sterr) {
	return r_sys_cmd_str_full_w32 (cmd, input, ilen, output, len, sterr);
}
#else
R_API int r_sys_cmd_str_full(const char *cmd, const char *input, int ilen, char **output, int *len, char **sterr) {
	R_LOG_ERROR ("RSyscmd.strFull() is not yet implemented for this platform");
	return false;
}
#endif

R_API int r_sys_cmdf(const char *fmt, ...) {
	int ret;
	char cmd[4096];
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (cmd, sizeof (cmd), fmt, ap);
	ret = r_sys_cmd (cmd);
	va_end (ap);
	return ret;
}

R_API int r_sys_cmdbg(const char *str) {
#if R2__UNIX__
	int pid = r_sys_fork ();
	if (pid == -1) {
		return -1;
	}
	if (pid > 0) {
		return pid;
	}
	int ret = r_sandbox_system (str, 0);
	PJ *pj = pj_new ();
	pj_kn (pj, "exit", ret);
	pj_kn (pj, "pid", pid);
	pj_ks (pj, "cmd", str);
	char *s = pj_drain (pj);
	eprintf ("%s\n", s);
	free (s);
	exit (0);
	return -1;
#else
#pragma message ("r_sys_cmdbg is not implemented for this platform")
	return -1;
#endif
}

R_API int r_sys_cmd(const char *str) {
	if (r_sandbox_enable (0)) {
		return false;
	}
	// setvbuf (stdout, NULL, _IONBF, 0);
	return r_sandbox_system (str, 1);
}

R_API char *r_sys_cmd_str(const char *cmd, const char *input, int *len) {
	char *output = NULL;
	if (r_sys_cmd_str_full (cmd, input, -1, &output, len, NULL)) {
		return output;
	}
	free (output);
	return NULL;
}

R_API bool r_sys_mkdir(const char *dir) {
	bool ret;

	if (r_sandbox_enable (0)) {
		return false;
	}
#if R2__WINDOWS__
	LPTSTR dir_ = r_sys_conv_utf8_to_win (dir);

	ret = CreateDirectory (dir_, NULL) != 0;
	free (dir_);
#else
	ret = mkdir (dir, 0755) != -1;
#endif
	return ret;
}

R_API bool r_sys_mkdirp(const char *dir) {
	bool ret = true;
	char slash = R_SYS_DIR[0];
	char *path = strdup (dir), *ptr = path;
	if (!path) {
		R_LOG_ERROR ("Unable to allocate memory");
		return false;
	}
	if (*ptr == slash) {
		ptr++;
	}
#if R2__WINDOWS__
	{
		char *p = strstr (ptr, ":\\");
		if (p) {
			ptr = p + 3;
		}
	}
#endif
	for (;;) {
		// find next slash
		for (; *ptr; ptr++) {
			if (*ptr == '/' || *ptr == '\\') {
				slash = *ptr;
				break;
			}
		}
		if (!*ptr) {
			break;
		}
		*ptr = 0;
		if (!r_sys_mkdir (path) && r_sys_mkdir_failed ()) {
#if 0
			if (!r_sandbox_check (R_SANDBOX_GRAIN_FILES)) {
				R_LOG_ERROR ("fail '%s' of '%s'", path, dir);
			}
#endif
			free (path);
			return false;
		}
		*ptr = slash;
		ptr++;
	}
	if (!r_sys_mkdir (path) && r_sys_mkdir_failed ()) {
		ret = false;
	}
	free (path);
	return ret;
}

R_API void r_sys_perror_str(const char *fun) {
#if R2__UNIX__
#pragma push_macro("perror")
#undef perror
	perror (fun);
#pragma pop_macro("perror")
#elif R2__WINDOWS__
	LPTSTR lpMsgBuf;
	DWORD dw = GetLastError();

	if (FormatMessage (FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dw,
			MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&lpMsgBuf,
			0, NULL )) {
		char *err = r_sys_conv_win_to_utf8 (lpMsgBuf);
		if (err) {
			R_LOG_WARN ("%s: (%#lx) %s%s", fun, dw, err,
				r_str_endswith (err, "\n") ? "" : "\n");
			free (err);
		}
		LocalFree (lpMsgBuf);
	} else {
		R_LOG_INFO ("%s", fun);
	}
#endif
}

R_API bool r_sys_arch_match(const char *archstr, const char *arch) {
	char *ptr;
	if (!archstr || !arch || !*archstr || !*arch) {
		return true;
	}
	if (!strcmp (archstr, "*") || !strcmp (archstr, "any")) {
		return true;
	}
	if (!strcmp (archstr, arch)) {
		return true;
	}
	if ((ptr = strstr (archstr, arch))) {
		char p = ptr[strlen (arch)];
		if (!p || p == ',') {
			return true;
		}
	}
	return false;
}

R_API int r_sys_arch_id(const char *arch) {
	R_RETURN_VAL_IF_FAIL (arch, 0);
	int i;
	for (i = 0; arch_bit_array[i].name; i++) {
		if (!strcmp (arch, arch_bit_array[i].name)) {
			return arch_bit_array[i].bit;
		}
	}
	return 0;
}

R_API const char *r_sys_arch_str(int arch) {
	int i;
	for (i = 0; arch_bit_array[i].name; i++) {
		if (arch & arch_bit_array[i].bit) {
			return arch_bit_array[i].name;
		}
	}
	return "none";
}

#define USE_FORK 0
R_API int r_sys_run(const ut8 *buf, int len) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_EXEC)) {
		return -1;
	}
	const int sz = 4096;
	int pdelta, ret, (*cb)();
// TODO: define R_SYS_ALIGN_FORWARD in r_util.h
	ut8 *ptr, *p = malloc ((sz + len) << 1);
	ptr = p;
	pdelta = ((size_t)(p)) & (4096 - 1);
	if (pdelta) {
		ptr += (4096 - pdelta);
	}
	if (!p || !ptr || !buf) {
		R_LOG_ERROR ("Cannot run empty buffer");
		free (p);
		return false;
	}
	memcpy (ptr, buf, len);
	r_mem_protect (ptr, sz, "rx"); // rwx ?
	cb = (int (*)())ptr;
#if USE_FORK
	int pid = r_sys_fork ();
	if (pid < 0) {
		return cb ();
	}
	if (!pid) {
		ret = cb ();
		exit (ret);
		return ret;
	}
	int st = 0;
	waitpid (pid, &st, 0);
	if (WIFSIGNALED (st)) {
		const int num = WTERMSIG (st);
		R_LOG_INFO ("Child process received signal %d", num);
		ret = num;
	} else {
		ret = WEXITSTATUS (st);
	}
#else
	ret = (*cb) ();
#endif
	free (p);
	return ret;
}

// TODO. maybe this should be moved into socket/run?
R_API int r_sys_run_rop(const ut8 *buf, int len) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_EXEC)) {
		return -1;
	}
#if USE_FORK
	int st;
#endif
	// TODO: define R_SYS_ALIGN_FORWARD in r_util.h
	ut8 *bufptr = malloc (len);
	if (!bufptr) {
		R_LOG_ERROR ("Cannot allocate %d byte buffer", len);
		return false;
	}
	if (!buf) {
		R_LOG_ERROR ("Cannot execute empty rop chain");
		free (bufptr);
		return false;
	}
	memcpy (bufptr, buf, len);
#if USE_FORK
#if R2__UNIX__
	pid_t pid = r_sys_fork ();
#else
	pid = -1;
#endif
	if (pid < 0) {
		R_SYS_ASM_START_ROP ();
	} else {
		R_SYS_ASM_START_ROP ();
		exit (0);
		return 0;
	}
	st = 0;
	if (waitpid (pid, &st, 0) == -1) {
		R_LOG_ERROR ("waitpid failed");
		free (bufptr);
		return -1;
	}
	if (WIFSIGNALED (st)) {
		int num = WTERMSIG (st);
		R_LOG_INFO ("Got signal %d", num);
		ret = num;
	} else {
		ret = WEXITSTATUS (st);
	}
#else
	R_SYS_ASM_START_ROP ();
#endif
	free (bufptr);
	return 0;
}

#if R2__WINDOWS__
// w32 specific API
R_API char *r_w32_handle_to_path(HANDLE processHandle) {
	const DWORD maxlength = MAX_PATH;
	char *filename = calloc ((MAX_PATH * 2) + 2, 1);
	char *result = NULL;
	DWORD length = r_w32_GetModuleFileNameEx (processHandle, NULL, (LPSTR)filename, maxlength);
	if (length == 0) {
		// Upon failure fallback to GetProcessImageFileName
		length = r_w32_GetProcessImageFileName (processHandle, filename, maxlength);
		if (length == 0) {
			R_LOG_ERROR ("calling GetProcessImageFileName failed");
			return NULL;
		}
		// Convert NT path to win32 path
		char *name = r_sys_conv_win_to_utf8 (filename);
		if (!name) {
			R_LOG_ERROR ("Error converting filepath to utf8");
			return NULL;
		}
		char *tmp = strchr (name + 1, '\\');
		if (!tmp) {
			free (name);
			R_LOG_ERROR ("Malformed NT path");
			return NULL;
		}
		tmp = strchr (tmp + 1, '\\');
		if (!tmp) {
			free (name);
			R_LOG_ERROR ("Malformed NT path");
			return NULL;
		}
		length = tmp - name;
		tmp = malloc (length + 1);
		if (!tmp) {
			free (name);
			R_LOG_ERROR ("Error allocating memory");
			return NULL;
		}
		r_str_ncpy (tmp, name, length);
		TCHAR device[MAX_PATH];
		TCHAR drv[3] = {'A',':', 0};
		for (; drv[0] <= 'Z'; drv[0]++) {
			if (QueryDosDevice (drv, device, maxlength) > 0) {
				char *dvc = r_sys_conv_win_to_utf8 (device);
				if (!dvc) {
					free (name);
					free (tmp);
					R_LOG_ERROR ("Cannot convert to utf8");
					return NULL;
				}
				if (!strcmp (tmp, dvc)) {
					free (tmp);
					free (dvc);
					char *d = r_sys_conv_win_to_utf8 (drv);
					if (!d) {
						free (name);
						R_LOG_ERROR ("Cannot convert to utf8");
						return NULL;
					}
					tmp = r_str_newf ("%s%s", d, &name[length]);
					free (d);
					if (!tmp) {
						free (name);
						return NULL;
					}
					result = strdup (tmp);
					break;
				}
				free (dvc);
			}
		}
		free (name);
		free (tmp);
	} else {
		result = r_sys_conv_win_to_utf8 (filename);
	}
	free (filename);
	return result;
}
#endif

R_API char *r_sys_pid_to_path(int pid) {
#if R2__WINDOWS__
	HANDLE processHandle = OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!processHandle) {
		// R_LOG_ERROR ("r_sys_pid_to_path: Cannot open process");
		return NULL;
	}
	char *filename = r_w32_handle_to_path (processHandle);
	CloseHandle (processHandle);
	return filename;
#elif __APPLE__
#if __POWERPC__
#pragma message("TODO getpidproc")
	return NULL;
#else
	char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
	pathbuf[0] = 0;
	int ret = proc_pidpath (pid, pathbuf, sizeof (pathbuf));
	if (ret <= 0) {
		return NULL;
	}
	return strdup (pathbuf);
#endif
#else
#if __FreeBSD__ || __DragonFly__
	char pathbuf[PATH_MAX];
	size_t pathbufl = sizeof (pathbuf);
	int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, pid};
	int ret = sysctl (mib, 4, pathbuf, &pathbufl, NULL, 0);
	if (ret != 0) {
		return NULL;
	}
#elif __HAIKU__
	char pathbuf[MAXPATHLEN];
	int32 group = 0;
	image_info ii;

	while (get_next_image_info ((team_id)pid, &group, &ii) == B_OK) {
		if (ii.type == B_APP_IMAGE) {
			break;
		}
	}

	if (ii.type == B_APP_IMAGE) {
		r_str_ncpy (pathbuf, ii.name, MAXPATHLEN);
	} else {
		pathbuf[0] = '\0';
	}
#else
	char buf[128], pathbuf[1024];
	snprintf (buf, sizeof (buf), "/proc/%d/exe", pid);
	int ret = readlink (buf, pathbuf, sizeof (pathbuf)-1);
	if (ret < 1) {
		return NULL;
	}
	pathbuf[ret] = 0;
#endif
	return strdup (pathbuf);
#endif
}

R_API void r_sys_env_init(void) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_ENVIRON)) {
		return;
	}
	char **envp = r_sys_get_environ ();
	if (envp) {
		r_sys_set_environ (envp);
	}
}

R_API char **r_sys_get_environ(void) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_ENVIRON)) {
		return NULL;
	}
#if __APPLE__ && !HAVE_ENVIRON
	Genv = *_NSGetEnviron();
#else
	Genv = environ;
#endif
	// return environ if available??
	if (!Genv) {
		Genv = r_lib_dl_sym (NULL, "environ");
	}
	return Genv;
}

R_API void r_sys_set_environ(char **e) {
	if (!r_sandbox_check (R_SANDBOX_GRAIN_ENVIRON)) {
		return;
	}
	Genv = e;
}

R_API char *r_sys_whoami(void) {
#if R2__WINDOWS__
	char buf[256];
	DWORD buf_sz = sizeof (buf);
	if (!GetUserName ((LPSTR)buf, (LPDWORD)&buf_sz) ) {
		return strdup ("?");
	}
	return strdup (buf);
#elif __wasi__
	return strdup ("user");
#elif HAVE_TH_LOCAL
	char *user = r_sys_getenv ("USER");
	return user? user: r_str_newf ("uid%d", getuid ());
#else
	char buf[32];
	// XXX this is not thread safe and getpwuid_r is not available
	struct passwd *pw = getpwuid (getuid ());
	if (pw) {
		return strdup (pw->pw_name);
	}
	int uid = getuid ();
	snprintf (buf, sizeof (buf), "uid%d", uid);
	return strdup (buf);
#endif
}

R_API int r_sys_uid(void) {
#if R2__WINDOWS__
#pragma message ("r_sys_uid not implemented for windows")
	char buf[32];
	DWORD buf_sz = sizeof (buf);
	// TODO
	if (!GetUserName ((LPSTR)buf, (LPDWORD)&buf_sz) ) {
		return 1; //
	}
	return 0;
#elif __wasi__
	return 0;
#else
	return getuid ();
#endif
}

R_API int r_sys_getpid(void) {
#if __wasi__
	return 0;
#elif R2__UNIX__
	return getpid ();
#elif R2__WINDOWS__
	return (int)GetCurrentProcessId ();
#else
#pragma message ("r_sys_getpid not implemented for this platform")
	return -1;
#endif
}

R_API bool r_sys_tts(const char *txt, bool bg) {
	int i;
	R_RETURN_VAL_IF_FAIL (txt, false);
	const char *says[] = {
		"say", "termux-tts-speak", NULL
	};
	for (i = 0; says[i]; i++) {
		char *sayPath = r_file_path (says[i]);
		if (sayPath) {
			char *line = r_str_replace (strdup (txt), "'", "\"", 1);
			r_sys_cmdf ("\"%s\" '%s'%s", sayPath, line, bg? " &": "");
			free (line);
			free (sayPath);
			return true;
		}
	}
	return false;
}

R_API const char *r_sys_prefix(const char *pfx) {
	if (!Gr2prefix) {
		Gr2prefix = r_sys_getenv ("R2_PREFIX");
		if (R_STR_ISEMPTY (Gr2prefix)) {
			free (Gr2prefix);
			Gr2prefix = strdup (R2_PREFIX);
		}
	}
	if (!Gprefix) {
#if R2__WINDOWS__
		Gprefix = r_sys_get_src_dir_w32 ();
		if (!Gprefix) {
			Gprefix = strdup (Gr2prefix);
		}
#else
		Gprefix = strdup (Gr2prefix);
#endif
	}
	if (pfx) {
		free (Gprefix);
		Gprefix = strdup (pfx);
	}
	return Gprefix;
}

R_API RSysInfo *r_sys_info(void) {
#if R2__UNIX__
	struct utsname un = {{0}};
	if (uname (&un) != -1) {
		RSysInfo *si = R_NEW0 (RSysInfo);
		si->sysname  = strdup (un.sysname);
		si->nodename = strdup (un.nodename);
		si->release  = strdup (un.release);
		si->version  = strdup (un.version);
		si->machine  = strdup (un.machine);
		return si;
	}
#elif R2__WINDOWS__
	HKEY key;
	DWORD type;
	DWORD size;
	DWORD major;
	DWORD minor;
	char tmp[256] = {0};
	RSysInfo *si = R_NEW0 (RSysInfo);
	if (RegOpenKeyExA (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
		KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
		r_sys_perror ("r_sys_info/RegOpenKeyExA");
		r_sys_info_free (si);
		return NULL;
	}

	size = sizeof (tmp);
	if (RegQueryValueExA (key, "ProductName", NULL, &type,
		(LPBYTE)&tmp, &size) != ERROR_SUCCESS
		|| type != REG_SZ) {
		goto beach;
	}
	si->sysname = strdup (tmp);

	size = sizeof (major);
	if (RegQueryValueExA (key, "CurrentMajorVersionNumber", NULL, &type,
		(LPBYTE)&major, &size) != ERROR_SUCCESS
		|| type != REG_DWORD) {
		goto beach;
	}
	size = sizeof (minor);
	if (RegQueryValueExA (key, "CurrentMinorVersionNumber", NULL, &type,
		(LPBYTE)&minor, &size) != ERROR_SUCCESS
		|| type != REG_DWORD) {
		goto beach;
	}

	size = sizeof (tmp);
	if (RegQueryValueExA (key, "CurrentBuild", NULL, &type,
		(LPBYTE)&tmp, &size) != ERROR_SUCCESS
		|| type != REG_SZ) {
		goto beach;
	}
	si->version = r_str_newf ("%lu.%lu.%s", major, minor, tmp);

	size = sizeof (tmp);
	if (RegQueryValueExA (key, "ReleaseId", NULL, &type,
		(LPBYTE)tmp, &size) != ERROR_SUCCESS
		|| type != REG_SZ) {
		goto beach;
	}
	si->release = strdup (tmp);
beach:
	RegCloseKey (key);
	return si;
#endif
	return NULL;
}

R_API void r_sys_info_free(RSysInfo *si) {
	if (si) {
		free (si->sysname);
		free (si->nodename);
		free (si->release);
		free (si->version);
		free (si->machine);
		free (si);
	}
}

// R2_590 r_sys_endian_tostring() // endian == R_SYS_ENDIAN_BIG "big" .. R_ARCH_CONFIG_IS_BIG_ENDIAN (core->rasm->config)? "big": "little"

R_API R_MUSTUSE char *r_file_home(const char *str) {
	char *dst, *home = r_sys_getenv (R_SYS_HOME);
	size_t length;
	if (!home) {
		home = r_file_tmpdir ();
		if (!home) {
			return NULL;
		}
	}
	length = strlen (home) + 1;
	if (R_STR_ISNOTEMPTY (str)) {
		length += strlen (R_SYS_DIR) + strlen (str);
	}
	dst = (char *)calloc (1, length);
	if (!dst) {
		goto fail;
	}
	int home_len = strlen (home);
	memcpy (dst, home, home_len + 1);
	if (R_STR_ISNOTEMPTY (str)) {
		dst[home_len] = R_SYS_DIR[0];
		strcpy (dst + home_len + 1, str);
	}
fail:
	free (home);
	return dst;
}

R_API R_MUSTUSE char *r_file_homef(const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	char *r = r_str_newvf (fmt, ap);
	char *s = r_file_home (r);
	free (r);
	va_end (ap);
	return s;
}
