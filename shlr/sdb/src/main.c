/* sdb - LGPLv3 - Copyright 2011-2014 - pancake */

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "sdb.h"

#define MODE_ZERO '0'
#define MODE_JSON 'j'
#define MODE_DFLT 0

static int save = 0;
static Sdb *s = NULL;

static void terminate(int sig UNUSED) {
	if (!s) return;
	if (save && !sdb_sync (s)) {
		sdb_free (s);
		exit (1);
	}
	sdb_free (s);
	exit (0);
}

static char *stdin_gets() {
	static char buf[96096]; // MAGIC NUMBERS CO.
	if (!fgets (buf, sizeof (buf)-1, stdin))
		return NULL;;
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

static int sdb_dump (const char *db, int fmt) {
	char *k, *v;
	const char *comma = "";
	Sdb *s = sdb_new (NULL, db, 0);
	if (!s) return 1;
	sdb_config (s, SDB_OPTION_FS | SDB_OPTION_NOSTAMP);
	sdb_dump_begin (s);
	if (fmt==MODE_JSON)
		printf ("{");
	while (sdb_dump_dupnext (s, &k, &v, NULL)) {
		switch (fmt) {
		case MODE_JSON:
			if (!strcmp (v, "true") || !strcmp (v, "false")) {
				printf ("%s\"%s\":%s", comma, k, v);
			} else if (sdb_isnum (v)) {
				printf ("%s\"%s\":%llu", comma, k, sdb_atoi (v));
			} else if (*v=='{' || *v=='[') {
				printf ("%s\"%s\":%s", comma, k, v);
			} else printf ("%s\"%s\":\"%s\"", comma, k, v);
			comma = ",";
			break;
		case MODE_ZERO:
			printf ("%s=%s", k, v);
			break;
		default:
			printf ("%s=%s\n", k, v);
			break;
		}
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
	switch (fmt) {
	case MODE_ZERO:
		fflush (stdout);
		write (1, "", 1);
		break;
	case MODE_JSON:
		printf ("}\n");
		break;
	}
	sdb_free (s);
	return 0;
}

static int insertkeys(Sdb *s, const char **args, int nargs, int mode) {
	int must_save = 0;
	if (args && nargs>0) {
		int i;
		for (i=0; i<nargs; i++) {
			switch (mode) {
			case '-':
				must_save |= sdb_query (s, args[i]);
				break;
			case '=':
				if (strchr (args[i], '=')) {
					char *v, *kv = strdup (args[i]);
					v = strchr (kv, '=');
					if (v) {
						*v++ = 0;
						sdb_disk_insert (s, kv, v);
					}
					free (kv);
				}
				break;
			}
		}
	}
	return must_save;
}

static int createdb(const char *f, const char **args, int nargs) {
	char *line, *eq;
	s = sdb_new (NULL, f, 0);
	if (!s || !sdb_disk_create (s)) {
		eprintf ("Cannot create database\n");
		return 1;
	}
	insertkeys (s, args, nargs, '=');
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
	printf ("usage: sdb [-0hjv|-d A B] [-|db] "
		"[.file]|[-=]|[-+][(idx)key[:json|=value] ..]\n");
	if (o==2) {
		printf ("  -0      terminate results with \\x00\n");
		printf ("  -j      output in json\n");
		exit (0);
	}
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
	while (sdb_dump_dupnext (A, &k, &v, NULL)) {
		v2 = sdb_const_get (B, k, 0);
		if (!v2) {
			printf ("%s=\n", k);
			n = 1;
		}
	}
	sdb_dump_begin (B);
	while (sdb_dump_dupnext (B, &k, &v, NULL)) {
		if (!v || !*v) continue;
		v2 = sdb_const_get (A, k, 0);
		if (!v2 || strcmp (v, v2)) {
			printf ("%s=%s\n", k, v2);
			n = 1;
		}
	}
	sdb_free (A);
	sdb_free (B);
	free (k);
	free (v);
	return n;
}

int main(int argc, const char **argv) {
	char *line;
	int i, ret, fmt = MODE_DFLT;
	int db0 = 1, argi = 1;
	int interactive = 0;

	/* terminate flags */
	if (argc<2) showusage (1);
	if (!strcmp (argv[1], "-d")) {
		if (argc == 4)
			return dbdiff (argv[2], argv[3]);
		showusage (0);
	}
	if (!strcmp (argv[1], "-v")) showversion ();
	if (!strcmp (argv[1], "-h")) showusage (2);
	if (!strcmp (argv[1], "-j")) {
		if (argc>2)
			return sdb_dump (argv[db0+1], MODE_JSON);
		eprintf ("Missing database filename after -j\n");
		return 1;
	}

	/* flags */
	if (!strcmp (argv[argi], "-0")) {
		fmt = MODE_ZERO;
		db0++;
		argi++;
	}
	if (!strcmp (argv[argi], "-")) {
		/* no database */
		argv[argi] = "";
		if (argc == db0+1) {
			interactive = 1;
			/* if no argument passed */
			argv[argi] = "-";
			argc++;
			argi++;
		}
	}
	if (argc-1 == db0)
		return sdb_dump (argv[db0], fmt);
#if USE_MMAN
	signal (SIGINT, terminate);
	signal (SIGHUP, syncronize);
#endif
	ret = 0;
	if (interactive || !strcmp (argv[db0+1], "-")) {
		if ((s = sdb_new (NULL, argv[db0], 0))) {
			save |= insertkeys (s, argv+3, argc-3, '-');
			sdb_config (s, SDB_OPTION_FS | SDB_OPTION_NOSTAMP);
			for (;(line = stdin_gets ());) {
				save |= sdb_query (s, line);
				if (fmt) {
					fflush (stdout);
					write (1, "", 1);
				}
				free (line);
			}
		}
	} else if (!strcmp (argv[db0+1], "=")) {
		ret = createdb (argv[db0], argv+db0+2, argc-(db0+2));
	} else {
		s = sdb_new (NULL, argv[db0], 0);
		if (!s) return 1;
		sdb_config (s, SDB_OPTION_FS | SDB_OPTION_NOSTAMP);
		for (i=db0+1; i<argc; i++) {
			save |= sdb_query (s, argv[i]);
			if (fmt) {
				fflush (stdout);
				write (1, "", 1);
			}
		}
	}
	terminate (0);
	return ret;
}
