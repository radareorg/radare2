/* Public domain -- pancake @ 2011-2012 */

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

#if USE_MMAN
static void syncronize(int sig) {
	// TODO: must be in sdb_sync() or wat?
	Sdb *n;
	sdb_sync (s);
	n = sdb_new (s->dir, s->lock);
	sdb_free (s);
	s = n;
}
#endif

static int sdb_dump (const char *db) {
	char k[SDB_KSZ];
	char v[SDB_VSZ];
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
	char line[SDB_VSZ];
	char *eq;
	s = sdb_new (f, 0);
	if (!sdb_create (s)) {
		printf ("Cannot create database\n");
		exit (1);
	}
	for (;;) {
		fgets (line, sizeof line, stdin);
		if (feof (stdin))
			break;
		line[strlen (line)-1] = 0;
		if ((eq = strchr (line, '='))) {
			*eq = 0;
			sdb_append (s, line, eq+1);
		}
	}
	sdb_finish (s);
}

static void runline (Sdb *s, const char *cmd) {
	ut64 n;
	char *p, *eq;
	switch (*cmd) {
	case '+': // inc
		if ((eq = strchr (cmd+1, '?'))) {
			*eq = 0;
			n = sdb_json_inc (s, cmd+1, eq+1, 1, 0);
			save = 1;
			printf ("%"ULLFMT"d\n", n);
		} else {
			n = sdb_inc (s, cmd+1, 1, 0);
			save = 1;
			printf ("%"ULLFMT"d\n", n);
		}
		break;
	case '-': // dec
		if ((eq = strchr (cmd+1, '?'))) {
			*eq = 0;
			n = sdb_json_dec (s, cmd+1, eq+1, 1, 0);
			save = 1;
			printf ("%"ULLFMT"d\n", n);
		} else {
			n = sdb_inc (s, cmd+1, -1, 0);
			save = 1;
			printf ("%"ULLFMT"d\n", n);
		}
		break;
	default:
		/* spaghetti */
		if ((eq = strchr (cmd, '?'))) {
			char *path = eq+1;
			*eq = 0;
			if ((eq = strchr (path+1, '='))) {
				save = 1;
				*eq = 0;
				sdb_json_set (s, cmd, path, eq+1, 0);
			} else
			if ((p = sdb_json_get (s, cmd, path, 0))) {
				printf ("%s\n", p);
				free (p);
			}
		} else {
			if ((eq = strchr (cmd, '='))) {
				save = 1;
				*eq = 0;
				sdb_set (s, cmd, eq+1, 0);
			} else
			if ((p = sdb_get (s, cmd, 0))) {
				printf ("%s\n", p);
				free (p);
			}
		}
	}
}

static void showusage(int o) {
	printf ("usage: sdb [-v|-h] [file.db] [-=]|[key[=value] ..]\n");
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
	if (!strcmp (argv[1], "-")) {
		argv[1] = "";
		if (argc == 2) {
			argv[2] = "-";
			argc++;
		}
	}
	if (argc == 2)
		return sdb_dump (argv[1]);
#if USE_MMAN
	signal (SIGINT, terminate);
	signal (SIGHUP, syncronize);
#endif
	if (!strcmp (argv[2], "=")) {
		createdb (argv[1]);
	} else
	if (!strcmp (argv[2], "-")) {
		char line[SDB_VSZ+SDB_KSZ]; // XXX can overflow stack
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
