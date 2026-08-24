/* radare2 UEFI libc compatibility - LGPL - Copyright 2026 - pancake */

#ifndef R2_UEFI_COMPAT_H
#define R2_UEFI_COMPAT_H 1

#include <ctype.h>
#include <errno.h>
#include <fenv.h>
#include <fcntl.h>
#include <grp.h>
#include <locale.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <wctype.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

FILE *r_uefi_stdio(int fd);

#undef stdin
#undef stdout
#undef stderr
#define stdin r_uefi_stdio (0)
#define stdout r_uefi_stdio (1)
#define stderr r_uefi_stdio (2)

static inline unsigned int r2_uefi_arc4random_uniform(unsigned int upper) {
	return upper? (unsigned int)rand () % upper: 0;
}
#define arc4random_uniform r2_uefi_arc4random_uniform

static inline size_t r2_uefi_strlcpy(char *dst, const char *src, size_t size) {
	size_t len = strlen (src);
	if (size) {
		size_t copy = len < size - 1? len: size - 1;
		memcpy (dst, src, copy);
		dst[copy] = 0;
	}
	return len;
}
#define strlcpy r2_uefi_strlcpy

static inline size_t r2_uefi_strlcat(char *dst, const char *src, size_t size) {
	size_t len = strnlen (dst, size);
	return len + r2_uefi_strlcpy (dst + len, src, len < size? size - len: 0);
}
#define strlcat r2_uefi_strlcat

#define R2_UEFI_CTYPE(name, expression) \
	static inline int r2_uefi_##name(int c) { return (expression); }
R2_UEFI_CTYPE (isdigit, c >= '0' && c <= '9')
R2_UEFI_CTYPE (isupper, c >= 'A' && c <= 'Z')
R2_UEFI_CTYPE (islower, c >= 'a' && c <= 'z')
R2_UEFI_CTYPE (isalpha, r2_uefi_isupper (c) || r2_uefi_islower (c))
R2_UEFI_CTYPE (isalnum, r2_uefi_isalpha (c) || r2_uefi_isdigit (c))
R2_UEFI_CTYPE (isxdigit, r2_uefi_isdigit (c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
R2_UEFI_CTYPE (isspace, c == ' ' || (c >= '\t' && c <= '\r'))
R2_UEFI_CTYPE (isblank, c == ' ' || c == '\t')
R2_UEFI_CTYPE (iscntrl, (c >= 0 && c < 0x20) || c == 0x7f)
R2_UEFI_CTYPE (isprint, c >= 0x20 && c < 0x7f)
R2_UEFI_CTYPE (isgraph, c > 0x20 && c < 0x7f)
R2_UEFI_CTYPE (ispunct, r2_uefi_isgraph (c) && !r2_uefi_isalnum (c))
R2_UEFI_CTYPE (isascii, c >= 0 && c < 0x80)
R2_UEFI_CTYPE (toupper, r2_uefi_islower (c)? c - 0x20: c)
R2_UEFI_CTYPE (tolower, r2_uefi_isupper (c)? c + 0x20: c)
#undef R2_UEFI_CTYPE

#undef isdigit
#undef isupper
#undef islower
#undef isalpha
#undef isalnum
#undef isxdigit
#undef isspace
#undef isblank
#undef iscntrl
#undef isprint
#undef isgraph
#undef ispunct
#undef isascii
#undef toupper
#undef tolower
#define isdigit r2_uefi_isdigit
#define isupper r2_uefi_isupper
#define islower r2_uefi_islower
#define isalpha r2_uefi_isalpha
#define isalnum r2_uefi_isalnum
#define isxdigit r2_uefi_isxdigit
#define isspace r2_uefi_isspace
#define isblank r2_uefi_isblank
#define iscntrl r2_uefi_iscntrl
#define isprint r2_uefi_isprint
#define isgraph r2_uefi_isgraph
#define ispunct r2_uefi_ispunct
#define isascii r2_uefi_isascii
#define toupper r2_uefi_toupper
#define tolower r2_uefi_tolower

static inline int r2_uefi_iswspace(wint_t c) { return c < 0x80 && r2_uefi_isspace ((int)c); }
static inline int r2_uefi_iswdigit(wint_t c) { return c < 0x80 && r2_uefi_isdigit ((int)c); }
static inline int r2_uefi_iswalpha(wint_t c) { return c < 0x80 && r2_uefi_isalpha ((int)c); }
static inline int r2_uefi_iswalnum(wint_t c) { return c < 0x80 && r2_uefi_isalnum ((int)c); }
static inline int r2_uefi_iswxdigit(wint_t c) { return c < 0x80 && r2_uefi_isxdigit ((int)c); }
static inline int r2_uefi_iswprint(wint_t c) { return c < 0x80 && r2_uefi_isprint ((int)c); }
static inline int r2_uefi_iswgraph(wint_t c) { return c < 0x80 && r2_uefi_isgraph ((int)c); }
static inline int r2_uefi_iswpunct(wint_t c) { return c < 0x80 && r2_uefi_ispunct ((int)c); }
static inline int r2_uefi_iswcntrl(wint_t c) { return c < 0x80 && r2_uefi_iscntrl ((int)c); }
static inline int r2_uefi_iswblank(wint_t c) { return c < 0x80 && r2_uefi_isblank ((int)c); }
static inline int r2_uefi_iswupper(wint_t c) { return c < 0x80 && r2_uefi_isupper ((int)c); }
static inline int r2_uefi_iswlower(wint_t c) { return c < 0x80 && r2_uefi_islower ((int)c); }
static inline wint_t r2_uefi_towupper(wint_t c) { return c < 0x80? (wint_t)r2_uefi_toupper ((int)c): c; }
static inline wint_t r2_uefi_towlower(wint_t c) { return c < 0x80? (wint_t)r2_uefi_tolower ((int)c): c; }

#undef iswspace
#undef iswdigit
#undef iswalpha
#undef iswalnum
#undef iswxdigit
#undef iswprint
#undef iswgraph
#undef iswpunct
#undef iswcntrl
#undef iswblank
#undef iswupper
#undef iswlower
#undef towupper
#undef towlower
#define iswspace r2_uefi_iswspace
#define iswdigit r2_uefi_iswdigit
#define iswalpha r2_uefi_iswalpha
#define iswalnum r2_uefi_iswalnum
#define iswxdigit r2_uefi_iswxdigit
#define iswprint r2_uefi_iswprint
#define iswgraph r2_uefi_iswgraph
#define iswpunct r2_uefi_iswpunct
#define iswcntrl r2_uefi_iswcntrl
#define iswblank r2_uefi_iswblank
#define iswupper r2_uefi_iswupper
#define iswlower r2_uefi_iswlower
#define towupper r2_uefi_towupper
#define towlower r2_uefi_towlower

static inline int r2_uefi_unsupported(void) {
	errno = ENOSYS;
	return -1;
}

static inline int r2_uefi_fscanf(FILE *stream, const char *format, ...) { (void)stream; (void)format; return 0; }
static inline int r2_uefi_scanf(const char *format, ...) { (void)format; return 0; }
static inline FILE *r2_uefi_popen(const char *command, const char *type) { (void)command; (void)type; errno = ENOSYS; return NULL; }
static inline int r2_uefi_pclose(FILE *stream) { (void)stream; return r2_uefi_unsupported (); }
static inline int r2_uefi_rename(const char *oldpath, const char *newpath) { (void)oldpath; (void)newpath; return r2_uefi_unsupported (); }
#define fscanf r2_uefi_fscanf
#define scanf r2_uefi_scanf
#define popen r2_uefi_popen
#define pclose r2_uefi_pclose
#define rename r2_uefi_rename

/* there are no signals on firmware, so pretend the handlers are installed */
typedef void (*r2_uefi_sighandler)(int);
static inline r2_uefi_sighandler r2_uefi_signal(int sig, r2_uefi_sighandler handler) { (void)sig; (void)handler; return SIG_DFL; }
static inline int r2_uefi_sigemptyset(sigset_t *set) { if (set) { memset (set, 0, sizeof (*set)); } return 0; }
static inline int r2_uefi_sigsetop(sigset_t *set, int sig) { (void)set; (void)sig; return 0; }
#define signal r2_uefi_signal
#define sigemptyset r2_uefi_sigemptyset
#define sigaddset r2_uefi_sigsetop
#define sigdelset r2_uefi_sigsetop

static inline int r2_uefi_system(const char *command) { (void)command; return r2_uefi_unsupported (); }
static inline pid_t r2_uefi_fork(void) { return (pid_t)r2_uefi_unsupported (); }
static inline pid_t r2_uefi_waitpid(pid_t pid, int *status, int options) { (void)pid; (void)status; (void)options; return (pid_t)r2_uefi_unsupported (); }
static inline int r2_uefi_kill(pid_t pid, int sig) { (void)pid; (void)sig; return r2_uefi_unsupported (); }
static inline int r2_uefi_raise(int sig) { (void)sig; return r2_uefi_unsupported (); }
static inline int r2_uefi_exec(const char *path, ...) { (void)path; return r2_uefi_unsupported (); }
static inline pid_t r2_uefi_getpid(void) { return 1; }
static inline pid_t r2_uefi_getppid(void) { return 0; }
static inline uid_t r2_uefi_getuid(void) { return 0; }
static inline uid_t r2_uefi_geteuid(void) { return 0; }
static inline gid_t r2_uefi_getgid(void) { return 0; }
static inline gid_t r2_uefi_getegid(void) { return 0; }
static inline int r2_uefi_setid(unsigned int id) { (void)id; return 0; }
static inline int r2_uefi_setsid(void) { return r2_uefi_unsupported (); }
static inline int r2_uefi_pause(void) { return r2_uefi_unsupported (); }
static inline int r2_uefi_nice(int inc) { (void)inc; return 0; }
#define system r2_uefi_system
#define fork r2_uefi_fork
#define waitpid r2_uefi_waitpid
#define kill r2_uefi_kill
#define raise r2_uefi_raise
#define execl r2_uefi_exec
#define execle r2_uefi_exec
#define execlp r2_uefi_exec
#define execv r2_uefi_exec
#define execve r2_uefi_exec
#define execvp r2_uefi_exec
#define getpid r2_uefi_getpid
#define getppid r2_uefi_getppid
#define getuid r2_uefi_getuid
#define geteuid r2_uefi_geteuid
#define getgid r2_uefi_getgid
#define getegid r2_uefi_getegid
#define setuid r2_uefi_setid
#define seteuid r2_uefi_setid
#define setgid r2_uefi_setid
#define setegid r2_uefi_setid
#define setsid r2_uefi_setsid
#define pause r2_uefi_pause
#define nice r2_uefi_nice

static inline int r2_uefi_dup(int fd) { (void)fd; return r2_uefi_unsupported (); }
static inline int r2_uefi_dup2(int oldfd, int newfd) { (void)oldfd; (void)newfd; return r2_uefi_unsupported (); }
static inline int r2_uefi_pipe(int pipefd[2]) { (void)pipefd; return r2_uefi_unsupported (); }
static inline int r2_uefi_fcntl(int fd, int command, ...) { (void)fd; (void)command; return r2_uefi_unsupported (); }
static inline int r2_uefi_flock(int fd, int operation) { (void)fd; (void)operation; return r2_uefi_unsupported (); }
static inline int r2_uefi_ftruncate(int fd, off_t length) { (void)fd; (void)length; return r2_uefi_unsupported (); }
static inline int r2_uefi_truncate(const char *path, off_t length) { (void)path; (void)length; return r2_uefi_unsupported (); }
static inline ssize_t r2_uefi_readlink(const char *path, char *buf, size_t size) { (void)path; (void)buf; (void)size; return r2_uefi_unsupported (); }
static inline unsigned int r2_uefi_alarm(unsigned int seconds) { (void)seconds; return 0; }
static inline int r2_uefi_chroot(const char *path) { (void)path; return r2_uefi_unsupported (); }
static inline int r2_uefi_setgroups(size_t size, const gid_t *list) { (void)size; (void)list; return 0; }
static inline int r2_uefi_getpagesize(void) { return 4096; }
#define dup r2_uefi_dup
#define dup2 r2_uefi_dup2
#define pipe r2_uefi_pipe
#define fcntl r2_uefi_fcntl
#define flock r2_uefi_flock
#define ftruncate r2_uefi_ftruncate
#define truncate r2_uefi_truncate
#define readlink r2_uefi_readlink
#define alarm r2_uefi_alarm
#define chroot r2_uefi_chroot
#define setgroups r2_uefi_setgroups
#define getpagesize r2_uefi_getpagesize

static inline int r2_uefi_chmod(const char *path, mode_t mode) { (void)path; (void)mode; return 0; }
static inline int r2_uefi_fchmod(int fd, mode_t mode) { (void)fd; (void)mode; return 0; }
static inline mode_t r2_uefi_umask(mode_t mask) { (void)mask; return 022; }
static inline int r2_uefi_mkfifo(const char *path, mode_t mode) { (void)path; (void)mode; return r2_uefi_unsupported (); }
#define chmod r2_uefi_chmod
#define fchmod r2_uefi_fchmod
#define umask r2_uefi_umask
#define mkfifo r2_uefi_mkfifo

static inline void *r2_uefi_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) { (void)addr; (void)length; (void)prot; (void)flags; (void)fd; (void)offset; errno = ENOSYS; return MAP_FAILED; }
static inline int r2_uefi_munmap(void *addr, size_t length) { (void)addr; (void)length; return r2_uefi_unsupported (); }
static inline int r2_uefi_mprotect(void *addr, size_t length, int prot) { (void)addr; (void)length; (void)prot; return 0; }
static inline int r2_uefi_msync(void *addr, size_t length, int flags) { (void)addr; (void)length; (void)flags; return 0; }
#define mmap r2_uefi_mmap
#define munmap r2_uefi_munmap
#define mprotect r2_uefi_mprotect
#define msync r2_uefi_msync

static inline int r2_uefi_socket(int domain, int type, int protocol) { (void)domain; (void)type; (void)protocol; errno = EAFNOSUPPORT; return -1; }
static inline int r2_uefi_socketpair(int domain, int type, int protocol, int sv[2]) { (void)domain; (void)type; (void)protocol; (void)sv; errno = EAFNOSUPPORT; return -1; }
static inline int r2_uefi_sockop(int fd, ...) { (void)fd; errno = EAFNOSUPPORT; return -1; }
static inline ssize_t r2_uefi_sockio(int fd, ...) { (void)fd; errno = EAFNOSUPPORT; return -1; }
#define socket r2_uefi_socket
#define socketpair r2_uefi_socketpair
#define bind r2_uefi_sockop
#define listen r2_uefi_sockop
#define accept r2_uefi_sockop
#define connect r2_uefi_sockop
#define shutdown r2_uefi_sockop
#define getsockopt r2_uefi_sockop
#define setsockopt r2_uefi_sockop
#define getsockname r2_uefi_sockop
#define getpeername r2_uefi_sockop
#define send r2_uefi_sockio
#define recv r2_uefi_sockio
#define sendto r2_uefi_sockio
#define recvfrom r2_uefi_sockio

/* the console read blocks in the firmware until a key arrives, so report
 * the descriptors as ready instead of implementing the select machinery */
static inline int r2_uefi_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) { (void)nfds; (void)readfds; (void)writefds; (void)exceptfds; (void)timeout; return 1; }
static inline int r2_uefi_pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask) { (void)nfds; (void)readfds; (void)writefds; (void)exceptfds; (void)timeout; (void)sigmask; return 1; }
#define select r2_uefi_select
#define pselect r2_uefi_pselect

/* efi only runs little endian */
static inline unsigned short r2_uefi_bswap16(unsigned short x) { return __builtin_bswap16 (x); }
static inline unsigned int r2_uefi_bswap32(unsigned int x) { return __builtin_bswap32 (x); }
#define htons r2_uefi_bswap16
#define ntohs r2_uefi_bswap16
#define htonl r2_uefi_bswap32
#define ntohl r2_uefi_bswap32

static inline int r2_uefi_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result) { (void)node; (void)service; (void)hints; (void)result; return EAI_FAIL; }
static inline void r2_uefi_freeaddrinfo(struct addrinfo *result) { (void)result; }
static inline const char *r2_uefi_gai_strerror(int error) { (void)error; return "networking is unavailable on UEFI"; }
static inline struct hostent *r2_uefi_gethostbyname(const char *name) { (void)name; return NULL; }
static inline struct servent *r2_uefi_getservbyname(const char *name, const char *protocol) { (void)name; (void)protocol; return NULL; }
#define getaddrinfo r2_uefi_getaddrinfo
#define freeaddrinfo r2_uefi_freeaddrinfo
#define gai_strerror r2_uefi_gai_strerror
#define gethostbyname r2_uefi_gethostbyname
#define getservbyname r2_uefi_getservbyname

static inline int r2_uefi_getrlimit(int resource, struct rlimit *limits) { (void)resource; limits->rlim_cur = RLIM_INFINITY; limits->rlim_max = RLIM_INFINITY; return 0; }
static inline int r2_uefi_setrlimit(int resource, const struct rlimit *limits) { (void)resource; (void)limits; return 0; }
static inline struct passwd *r2_uefi_getpwuid(uid_t uid) { (void)uid; return NULL; }
static inline struct passwd *r2_uefi_getpwnam(const char *name) { (void)name; return NULL; }
#define getrlimit r2_uefi_getrlimit
#define setrlimit r2_uefi_setrlimit
#define getpwuid r2_uefi_getpwuid
#define getpwnam r2_uefi_getpwnam

static inline int r2_uefi_tcgetattr(int fd, struct termios *termios) { (void)fd; memset (termios, 0, sizeof (*termios)); return 0; }
static inline int r2_uefi_tcsetattr(int fd, int action, const struct termios *termios) { (void)fd; (void)action; (void)termios; return 0; }
static inline int r2_uefi_tcsimple(int fd, ...) { (void)fd; return 0; }
static inline int r2_uefi_cfsetspeed(struct termios *termios, speed_t speed) { (void)termios; (void)speed; return 0; }
static inline speed_t r2_uefi_cfgetspeed(const struct termios *termios) { (void)termios; return 0; }
static inline void r2_uefi_cfmakeraw(struct termios *termios) { if (termios) { memset (termios, 0, sizeof (*termios)); } }
#define tcgetattr r2_uefi_tcgetattr
#define tcsetattr r2_uefi_tcsetattr
#define tcsendbreak r2_uefi_tcsimple
#define tcdrain r2_uefi_tcsimple
#define tcflush r2_uefi_tcsimple
#define cfsetispeed r2_uefi_cfsetspeed
#define cfsetospeed r2_uefi_cfsetspeed
#define cfgetispeed r2_uefi_cfgetspeed
#define cfgetospeed r2_uefi_cfgetspeed
#define cfmakeraw r2_uefi_cfmakeraw

static inline long double r2_uefi_fmaxl(long double a, long double b) { return a > b? a: b; }
#define fmaxl r2_uefi_fmaxl

static inline int r2_uefi_feclearexcept(int exceptions) { (void)exceptions; return 0; }
static inline int r2_uefi_fetestexcept(int exceptions) { (void)exceptions; return 0; }
static inline int r2_uefi_fegetround(void) { return FE_TONEAREST; }
static inline int r2_uefi_fesetround(int round) { (void)round; return 0; }
#define feclearexcept r2_uefi_feclearexcept
#define fetestexcept r2_uefi_fetestexcept
#define fegetround r2_uefi_fegetround
#define fesetround r2_uefi_fesetround

static inline char *r2_uefi_setlocale(int category, const char *locale) { (void)category; (void)locale; static char name[] = "C"; return name; }
static inline struct lconv *r2_uefi_localeconv(void) { static char dot[] = "."; static struct lconv value = { .decimal_point = dot }; return &value; }
#define setlocale r2_uefi_setlocale
#define localeconv r2_uefi_localeconv

#undef sigsetjmp
#undef siglongjmp
#define sigsetjmp(env, save) setjmp (env)
#define siglongjmp longjmp

#endif
