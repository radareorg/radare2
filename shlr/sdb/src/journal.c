/* sdb - MIT - Copyright 2011-2023 - pancake */

#include "sdb/sdb.h"
#include <fcntl.h>
#if R2__UNIX__ || __UNIX__ || __MINGW32__
#include <unistd.h>
#endif

static bool sdb_journal_filename(Sdb *s, char *path, size_t path_size) {
	if (!s || !s->name) {
		return false;
	}

	int res = snprintf (path, path_size, "%s.journal", s->name);
	if (res < 0 || (size_t)res >= path_size) {
		return false;
	}

	return true;
}

SDB_API bool sdb_journal_close(Sdb *s) {
	char filename[SDB_MAX_PATH];
	if (s->journal == -1) {
		return false;
	}
	close (s->journal);
	s->journal = -1;
	if (!sdb_journal_filename (s, filename, sizeof (filename))) {
		return false;
	}
	unlink (filename);
	return true;
}

SDB_API bool sdb_journal_open(Sdb *s) {
	char filename[SDB_MAX_PATH];
	if (!s || !s->name) {
		return false;
	}
	if (!sdb_journal_filename (s, filename, sizeof (filename))) {
		return false;
	}
	close (s->journal);
	s->journal = open (filename, O_CREAT | O_RDWR | O_APPEND, 0600);
	return s->journal != -1;
}

// TODO boolify and save changes somewhere else? or just dont count that?
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
	if (sz < 1) {
		return 0;
	}
	if (lseek (fd, 0, SEEK_SET) == (off_t) -1) {
		return 0;
	}
	str = (char *)sdb_gh_malloc (sz + 1);
	if (!str) {
		return 0;
	}
	rr = read (fd, str, sz);
	if (rr < 0) {
		sdb_gh_free (str);
		return 0;
	}
	str[sz] = 0;
	for (cur = str; ; ) {
		ptr = strchr (cur, '\n');
		if (!ptr) {
			break;
		}
		*ptr = 0;
		eq = strchr (cur, '=');
		if (eq) {
			*eq++ = 0;
			sdb_set (s, cur, eq, 0);
			changes ++;
		}
		cur = ptr + 1;
	}
	sdb_gh_free (str);
	return changes;
}

SDB_API bool sdb_journal_log(Sdb *s, const char *key, const char *val) {
	char str[SDB_MAX_PATH];
	if (s->journal == -1) {
		return false;
	}
	if (snprintf (str, sizeof (str), "%s=%s\n", key, val) < 0) {
		return false;
	}
	int len = strlen (str);
	if (write (s->journal, str, len) != len) {
		return false;
	}
#if USE_MMAN
	(void)fsync (s->journal);
#endif
	return true;
}

SDB_API bool sdb_journal_clear(Sdb *s) {
	if (s->journal != -1) {
		return !ftruncate (s->journal, 0);
	}
	return false;
}

SDB_API bool sdb_journal_unlink(Sdb *s) {
	char filename[SDB_MAX_PATH];
	if (!sdb_journal_filename (s, filename, sizeof (filename))) {
		return false;
	}
	sdb_journal_close (s);
	return !unlink (filename);
}
