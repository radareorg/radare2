/* sdb - MIT - Copyright 2011-2016 - pancake */

#include "sdb.h"
#include <fcntl.h>

static const char *sdb_journal_filename(Sdb *s) {
	return (s && s->name)
		? sdb_fmt ("%s.journal", s->name)
		: NULL;
}

SDB_API bool sdb_journal_close(Sdb *s) {
	if (s->journal == -1) {
		return false;
	}
	close (s->journal);
	s->journal = -1;
	unlink (sdb_journal_filename (s));
	return true;
}

SDB_API bool sdb_journal_open(Sdb *s) {
	const char *filename;
	if (!s || !s->name) {
		return false;
	}
	filename = sdb_journal_filename (s);
	if (!filename) {
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
	lseek (fd, 0, SEEK_SET);
	str = malloc (sz + 1);
	if (!str) {
		return 0;
	}
	rr = read (fd, str, sz);
	if (rr < 0) {
		free (str);
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
	free (str);
	return changes;
}

SDB_API bool sdb_journal_log(Sdb *s, const char *key, const char *val) {
	if (s->journal == -1) {
		return false;
	}
	const char *str = sdb_fmt ("%s=%s\n", key, val);
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
	const char *filename = sdb_journal_filename (s);
	sdb_journal_close (s);
	if (filename) {
		return !unlink (filename);
	}
	return false;
}
