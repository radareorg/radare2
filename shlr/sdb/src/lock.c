/* sdb - LGPLv3 - Copyright 2012-2014 - pancake */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "sdb.h"
#if WINDOWS
#include <windows.h>
#endif

SDB_API const char *sdb_lock_file(const char *f) {
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
	int fd;
	char *pid, pidstr[64];
	if (!s) return 0;
	fd = open (s, O_CREAT | O_TRUNC | O_WRONLY | O_EXCL, SDB_MODE);
	if (fd==-1)
		return 0;
	pid = sdb_itoa (getpid(), pidstr, 10);
	if (pid) {
		if ((write (fd, pid, strlen (pid)) < 0)
			|| (write (fd, "\n", 1) < 0)) {
			close (fd);
			return 0;
		}
	}
	close (fd);
	return 1;
}

SDB_API int sdb_lock_wait(const char *s) {
	// TODO use flock() here
	// wait forever here?
 	while (!sdb_lock (s)) {
		// TODO: if waiting too much return 0
#if WINDOWS
	 	Sleep (500); // hack
#else
	// TODO use lockf() here .. flock is not much useful (fd, LOCK_EX);
	 	sleep (1); // hack
#endif
 	}
	return 1;
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
