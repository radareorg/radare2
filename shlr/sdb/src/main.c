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
	if (save) sdb_sync (s);
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
	n = sdb_new (s->dir, s->lock);
	sdb_free (s);
	s = n;
}
#endif

static int sdb_dump (const char *db) {
	char *k, *v;
	Sdb *s = sdb_new (db, 0);
	if (!s) return 1;
	sdb_dump_begin (s);
	while (sdb_dump_dupnext (s, &k, &v)) {
		printf ("%s=%s\n", k, v);
		free (k);
		free (v);
	}
	sdb_free (s);
	return 0;
}

static void createdb(const char *f) {
	char *line, *eq;
	s = sdb_new (f, 0);
	if (!sdb_create (s)) {
		printf ("Cannot create database\n");
		exit (1);
	}
	for (;(line = stdin_gets ());) {
		if ((eq = strchr (line, '='))) {
			*eq = 0;
			sdb_append (s, line, eq+1);
		}
		free (line);
	}
	sdb_finish (s);
}

static void showusage(int o) {
	printf ("usage: sdb [-hv] [-|db] [<script]|[-=]|[-+][(idx)key[?path|=value] ..]\n");
	exit (o);
}

static void showversion(void) {
	printf ("sdb "SDB_VERSION"\n");
	exit (0);
}

int main(int argc, const char **argv) {
	char *line;
	int i;

	if (argc<2) showusage (1);
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
		return sdb_dump (argv[1]);
#if USE_MMAN
	signal (SIGINT, terminate);
	signal (SIGHUP, syncronize);
#endif
	if (!strcmp (argv[2], "="))
		createdb (argv[1]);
	else if (!strcmp (argv[2], "-")) {
		if ((s = sdb_new (argv[1], 0))) {
			for (;(line = stdin_gets ());) {
				save = sdb_query (s, line);
				free (line);
			}
		}
	} else if ((s = sdb_new (argv[1], 0))) {
		for (i=2; i<argc; i++)
			save = sdb_query (s, argv[i]);
	}
	terminate (0);
	return 0;
}
