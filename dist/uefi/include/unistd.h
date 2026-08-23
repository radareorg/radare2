/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _UNISTD_H
#define _UNISTD_H

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#define F_OK 0
#define X_OK 1
#define W_OK 2
#define R_OK 4

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#endif

#define _SC_PAGESIZE 30
#define _SC_PAGE_SIZE _SC_PAGESIZE
#define _SC_NPROCESSORS_ONLN 84

extern char **environ;

ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
ssize_t pread(int fd, void *buf, size_t count, off_t offset);
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);
int close(int fd);
off_t lseek(int fd, off_t offset, int whence);
#define lseek64 lseek
int unlink(const char *pathname);
int rmdir(const char *pathname);
int access(const char *pathname, int mode);
char *getcwd(char *buf, size_t size);
int chdir(const char *path);
int fchdir(int fd);
int dup(int oldfd);
int dup2(int oldfd, int newfd);
int pipe(int pipefd[2]);
int isatty(int fd);
char *ttyname(int fd);
int ttyname_r(int fd, char *buf, size_t buflen);
int ftruncate(int fd, off_t length);
int truncate(const char *path, off_t length);
ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
int symlink(const char *target, const char *linkpath);
int link(const char *oldpath, const char *newpath);
int chown(const char *pathname, uid_t owner, gid_t group);
int fsync(int fd);

pid_t getpid(void);
pid_t getppid(void);
uid_t getuid(void);
uid_t geteuid(void);
gid_t getgid(void);
gid_t getegid(void);
int setuid(uid_t uid);
int seteuid(uid_t euid);
int setgid(gid_t gid);
pid_t fork(void);
pid_t vfork(void);
int execv(const char *pathname, char *const argv[]);
int execve(const char *pathname, char *const argv[], char *const envp[]);
int execvp(const char *file, char *const argv[]);
int execl(const char *pathname, const char *arg, ...);
int execlp(const char *file, const char *arg, ...);
pid_t setsid(void);
int nice(int inc);
void _exit(int status) __attribute__((noreturn));
int chroot(const char *path);
int setgroups(size_t size, const gid_t *list);
int getgroups(int size, gid_t list[]);
int pause(void);
int daemon(int nochdir, int noclose);

unsigned int sleep(unsigned int seconds);
int usleep(useconds_t usec);
unsigned int alarm(unsigned int seconds);
long sysconf(int name);
int gethostname(char *name, size_t len);
int getpagesize(void);
char *getlogin(void);
int getopt(int argc, char *const argv[], const char *optstring);
extern char *optarg;
extern int optind, opterr, optopt;

#ifdef __cplusplus
}
#endif

#endif /* _UNISTD_H */
