/* sdb - LGPLv3 - Copyright 2012-2013 - pancake */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "sdb.h"
#if WINDOWS
#include <windows.h>
#endif

SDB_API const char *sdb_lockfile(const char *f) {
	static char buf[128];
	size_t len;
	if (!f || !*f)
		return NULL;
	len = strlen (f);
	if (len+10>sizeof buf)
		return NULL;
	memcpy (buf, f, len);
	strcpy (buf+len, ".lock");
	return buf;
}

#define os_getpid() getpid()

SDB_API int sdb_lock(const char *s) {
	int ret;
	char pidstr[64];
	if (!s) return 0;
	ret = open (s, O_CREAT | O_TRUNC | O_WRONLY | O_EXCL, 0644);
	char *pid = sdb_itoa (getpid(), pidstr, 10);
	if (ret==-1)
		return 0;
	if (pid) {
		write (1, pid, strlen (pid));
		write (1, "\n", 1);
	}
	close (ret);
	return 1;
}

SDB_API void sdb_lock_wait(const char *s UNUSED) {
	// TODO use flock() here
 	while (!sdb_lock (s)) {
#if WINDOWS
	 	Sleep (500); // hack
#else
	// TODO use lockf() here .. flock is not much useful (fd, LOCK_EX);
	// 	usleep (100); // hack
#endif
 	}
}

SDB_API void sdb_unlock(const char *s) {
	//flock (fd, LOCK_UN);
	unlink (s);
}

#if TEST
main () {
	int r;
	r = sdb_lock (".lock");
	printf ("%d\n", r);
	r = sdb_lock (".lock");
	printf ("%d\n", r);
	sdb_unlock (".lock");
	r = sdb_lock (".lock");
	printf ("%d\n", r);
}
#endif
