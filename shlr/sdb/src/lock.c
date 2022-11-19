/* sdb - MIT - Copyright 2012-2022 - pancake */

#include <fcntl.h>
#include "sdb/sdb.h"

SDB_API bool sdb_lock_file(const char *f, char *buf, size_t buf_size) {
	size_t len;
	if (!f || !*f || !buf || !buf_size) {
		return false;
	}
	len = strlen (f);
	if (len + 10 > buf_size) {
		return false;
	}
	memcpy (buf, f, len);
	strcpy (buf + len, ".lock");
	return true;
}

SDB_API bool sdb_lock(const char *s) {
	char pidstr[64];
	if (!s) {
		return false;
	}
	int fd = open (s, O_CREAT | O_TRUNC | O_WRONLY | O_EXCL, SDB_MODE);
	if (fd == -1) {
		return false;
	}
#if __wasi__ || EMSCRIPTEN || __MINGW32__
	char *pid = sdb_itoa (rand (), 10, pidstr, sizeof (pidstr));
#else
	char *pid = sdb_itoa (getpid (), 10, pidstr, sizeof (pidstr));
#endif
	if (pid) {
		if ((write (fd, pid, strlen (pid)) < 0)
			|| (write (fd, "\n", 1) < 0)) {
			close (fd);
			return false;
		}
	}
	close (fd);
	return true;
}

SDB_API int sdb_lock_wait(const char *s) {
	// TODO use flock() here
	// wait forever here?
 	while (!sdb_lock (s)) {
		// TODO: if waiting too much return 0
#if __SDB_WINDOWS__
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
