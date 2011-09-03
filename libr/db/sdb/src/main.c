/* Public domain -- pancake @ 2011 */

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "sdb.h"

static int save = 0;
static Sdb *s = NULL;

static void terminate(int sig) {
	if (!s) return;
	if (save) sdb_sync (s);
	sdb_free (s);
	exit (0);
}

static void syncronize(int sig) {
	// TODO: must be in sdb_sync() or wat?
	Sdb *n;
	sdb_sync (s);
	n = sdb_new (s->dir, s->lock);
	sdb_free (s);
	s = n;
}

static int sdb_dump (const char *db) {
	char k[SDB_KEYSIZE];
	char v[SDB_VALUESIZE];
	Sdb *s = sdb_new (db, 0);
	if (!s) return 1;
	sdb_dump_begin (s);
	while (sdb_dump_next (s, k, v))
		printf ("%s=%s\n", k, v);
	sdb_free (s);
	s = NULL;
	return 0;
}

static void createdb(const char *f) {
	char line[SDB_VALUESIZE];
	struct cdb_make c;
	char *eq, *ftmp = malloc (strlen (f)+5);
	sprintf (ftmp, "%s.tmp", f);
	int fd = open (ftmp, O_RDWR|O_CREAT|O_TRUNC, 0644);
	if (fd == -1) {
		printf ("cannot create %s\n", ftmp);
		exit (1);
	}
	cdb_make_start (&c, fd);
	for (;;) {
		fgets (line, sizeof line, stdin);
		if (feof (stdin))
			break;
		line[strlen (line)-1] = 0;
		if ((eq = strchr (line, '='))) {
			*eq = 0;
			sdb_add (&c, line, eq+1);
		}
	}
	cdb_make_finish (&c);
	//fsync (fd);
	close (fd);
	rename (ftmp, f);
	free (ftmp);
}

static void runline (Sdb *s, const char *cmd) {
	ut64 n;
	char *p, *eq;
	switch (*cmd) {
	case '+': // inc
		n = sdb_inc (s, cmd, 1);
		save = 1;
		printf ("%lld\n", n);
		break;
	case '-': // dec
		n = sdb_inc (s, cmd, -1);
		save = 1;
		printf ("%lld\n", n);
		break;
	default:
		if ((eq = strchr (cmd, '='))) {
			save = 1;
			*eq = 0;
			sdb_set (s, cmd, eq+1);
		} else
		if ((p = sdb_get (s, cmd))) {
			printf ("%s\n", p);
			free (p);
		}
	}
}

static void showusage(int o) {
	printf ("usage: sdb [-v|-h] [db[.lock]] [-=]|[key[=value] ..]\n");
	exit (o);
}

static void showversion() {
	printf ("sdb "VERSION"\n");
	exit (0);
}

int main(int argc, char **argv) {
	int i;
	if (argc<2)
		showusage (1);
	if (!strcmp (argv[1], "-v"))
		showversion ();
	if (!strcmp (argv[1], "-h"))
		showusage (0);
	if (argc == 2)
		return sdb_dump (argv[1]);

	signal (SIGINT, terminate);
	signal (SIGHUP, syncronize);

	if (!strcmp (argv[2], "=")) {
		createdb (argv[1]);
	} else
	if (!strcmp (argv[2], "-")) {
		char line[SDB_VALUESIZE];
		if ((s = sdb_new (argv[1], 0)))
			for (;;) {
				fgets (line, sizeof line, stdin);
				if (feof (stdin))
					break;
				line[strlen (line)-1] = 0;
				runline (s, line);
			}
	} else
	if ((s = sdb_new (argv[1], 0)))
		for (i=2; i<argc; i++)
			runline (s, argv[i]);
	terminate (0);
	return 0;
}
