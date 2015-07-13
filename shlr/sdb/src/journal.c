/* sdb - MIT - Copyright 2011-2015 - pancake */

#include "sdb.h"
#include <unistd.h>
#include <fcntl.h>

static const char *sdb_journal_filename (Sdb *s) {
	if (!s || !s->name)
		return NULL;
	return sdb_fmt (0, "%s.journal", s->name);
}

SDB_API int sdb_journal_close(Sdb *s) {
	const char *filename;
	if (s->journal == -1) {
		return 0;
	}
	close (s->journal);
	s->journal = -1;
	filename = sdb_journal_filename (s);
	unlink (filename);
	return 1;
}

SDB_API int sdb_journal_open(Sdb *s) {
	const char *filename;
	if (!s || !s->name) {
		return -1;
	}
	filename = sdb_journal_filename (s);
	if (!filename) {
		return -1;
	}
	close (s->journal);
	s->journal = -1;
	return s->journal = open (filename, O_CREAT | O_RDWR | O_APPEND, 0600);
}

SDB_API int sdb_journal_load(Sdb *s) {
	int rr, sz, fd, changes = 0;
	char *eq, *str, *cur, *ptr = NULL;
	if (!s) {
		return 0;
	}
	fd = s->journal;
	if (fd == -1) {
		return 0;
	}
	sz = lseek (fd, 0, SEEK_END);
	if (sz<1) {
		return 0;
	}
	lseek (fd, 0, SEEK_SET);
	str = malloc (sz+1);
	if (!str) {
		return 0;
	}
	rr = read (fd, str, sz);
	if (rr <0) {
		free (str);
		return 0;
	}
	str[sz] = 0;
	for (cur = str; ;) {
		ptr = strchr (cur, '\n');
		if (ptr) {
			*ptr = 0;
			eq = strchr (cur, '=');
			if (eq) {
				*eq++ = 0;
				sdb_set (s, cur, eq, 0);
				changes ++;
			}
			cur = ptr+1;
		} else break;
	}
	free (str);
	return changes;
}

SDB_API int sdb_journal_log(Sdb *s, const char *key, const char *val) {
	const char *str;
	if (s->journal == -1) {
		return 0;
	}
	str = sdb_fmt (0, "%s=%s\n", key, val);
	write (s->journal, str, strlen (str));
#if USE_MMAN
	fsync (s->journal);
#endif
	return 1;
}

SDB_API int sdb_journal_clear(Sdb *s) {
	if (s->journal != -1) {
		ftruncate (s->journal, 0);
		return 1;
	}
	return 1;
}

SDB_API int sdb_journal_unlink(Sdb *s) {
	const char *filename = sdb_journal_filename (s);
	sdb_journal_close (s);
	if (filename) {
		return unlink (filename) != -1;
	}
	return 0;
}
