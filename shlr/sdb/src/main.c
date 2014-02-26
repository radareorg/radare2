/* sdb - LGPLv3 - Copyright 2011-2014 - pancake */

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "sdb.h"

static int save = 0;
static Sdb *s = NULL;

static void terminate(int sig UNUSED) {
	if (!s) return;
	if (save && !sdb_sync (s))
		exit (1);
	sdb_free (s);
	exit (0);
}

static char *stdin_gets() {
	static char buf[96096];
	fgets (buf, sizeof (buf)-1, stdin);
	if (feof (stdin)) return NULL;
	buf[strlen (buf)-1] = 0;
	return strdup (buf);
}

#if USE_MMAN
static void syncronize(int sig UNUSED) {
	// TODO: must be in sdb_sync() or wat?
	Sdb *n;
	sdb_sync (s);
	n = sdb_new (s->path, s->name, s->lock);
	if (n) {
		sdb_config (n, SDB_OPTION_FS | SDB_OPTION_NOSTAMP);
		sdb_free (s);
		s = n;
	}
}
#endif

static int sdb_dump (const char *db, int qf) {
	char *k, *v;
	Sdb *s = sdb_new (NULL, db, 0);
	if (!s) return 1;
	sdb_config (s, SDB_OPTION_FS | SDB_OPTION_NOSTAMP);
	sdb_dump_begin (s);
	while (sdb_dump_dupnext (s, &k, &v)) {
		printf ("%s=%s\n", k, v);
#if 0
		if (qf && strchr (v, SDB_RS)) {
			for (p=v; *p; p++)
				if (*p==SDB_RS)
					*p = ',';
			printf ("[]%s=%s\n", k, v);
		} else {
			printf ("%s=%s\n", k, v);
		}
#endif
		free (k);
		free (v);
	}
	sdb_free (s);
	return 0;
}

static int createdb(const char *f) {
	char *line, *eq;
	s = sdb_new (NULL, f, 0);
	if (!s || !sdb_disk_create (s)) {
		fprintf (stderr, "Cannot create database\n");
		return 1;
	}
	sdb_config (s, SDB_OPTION_FS | SDB_OPTION_NOSTAMP);
	for (;(line = stdin_gets ());) {
		if ((eq = strchr (line, '='))) {
			*eq = 0;
			sdb_disk_insert (s, line, eq+1);
		}
		free (line);
	}
	sdb_disk_finish (s);
	return 0;
}

static void showusage(int o) {
	printf ("usage: sdb [-hv|-d A B] [-|db] []|[.file]|[-=]|[-+][(idx)key[:json|=value] ..]\n");
	exit (o);
}

static void showversion(void) {
	printf ("sdb "SDB_VERSION"\n");
	exit (0);
}

static int dbdiff (const char *a, const char *b) {
	int n = 0;
	char *k, *v;
	const char *v2;
	Sdb *A = sdb_new (NULL, a, 0);
	Sdb *B = sdb_new (NULL, b, 0);
	sdb_dump_begin (A);
	while (sdb_dump_dupnext (A, &k, &v)) {
		v2 = sdb_const_get (B, k, 0);
		if (!v2) {
			printf ("%s=\n", k);
			n = 1;
		}
	}
	sdb_dump_begin (B);
	while (sdb_dump_dupnext (B, &k, &v)) {
		if (!v || !*v) continue;
		v2 = sdb_const_get (A, k, 0);
		if (!v2 || strcmp (v, v2)) {
			printf ("%s=%s\n", k, v2);
			n = 1;
		}
	}
	sdb_free (A);
	sdb_free (B);
	return n;
}

int main(int argc, const char **argv) {
	char *line;
	int i;

	if (argc<2) showusage (1);
	if (!strcmp (argv[1], "-d")) {
		if (argc == 4)
			return dbdiff (argv[2], argv[3]);
		showusage(0);
	} else
	if (!strcmp (argv[1], "-v")) showversion ();
	if (!strcmp (argv[1], "-h")) showusage (0);
	if (!strcmp (argv[1], "-")) {
		argv[1] = "";
		if (argc == 2) {
			argv[2] = "-";
			argc++;
		}
	}
	if (argc == 2)
		return sdb_dump (argv[1], 0);
#if USE_MMAN
	signal (SIGINT, terminate);
	signal (SIGHUP, syncronize);
#endif
	if (!strcmp (argv[2], "[]")) {
		return sdb_dump (argv[1], 1);
	} if (!strcmp (argv[2], "="))
		return createdb (argv[1]);
	else if (!strcmp (argv[2], "-")) {
		if ((s = sdb_new (NULL, argv[1], 0))) {
			sdb_config (s, SDB_OPTION_FS | SDB_OPTION_NOSTAMP);
			for (;(line = stdin_gets ());) {
				save = sdb_query (s, line);
				free (line);
			}
		}
	} else {
		s = sdb_new (NULL, argv[1], 0);
		if (!s) return 1;
		sdb_config (s, SDB_OPTION_FS | SDB_OPTION_NOSTAMP);
		for (i=2; i<argc; i++)
			save = sdb_query (s, argv[i]);
	}
	terminate (0);
	return 0;
}
