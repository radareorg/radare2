/* sdb - MIT - Copyright 2011-2021 - pancake */

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include "sdb.h"

#define MODE_ZERO '0'
#define MODE_JSON 'j'
#define MODE_CGEN 'c'
#define MODE_DFLT 0

static int save = 0;
static Sdb *s = NULL;
static ut32 options = SDB_OPTION_FS | SDB_OPTION_NOSTAMP;

static void terminate(int sig UNUSED) {
	if (!s) {
		return;
	}
	if (save && !sdb_sync (s)) {
		sdb_free (s);
		s = NULL;
		exit (1);
	}
	sdb_free (s);
	exit (sig<2?sig:0);
}

static void write_null(void) {
	(void)write (1, "", 1);
}

#define BS 128
#define USE_SLURPIN 1

static char *slurp(FILE *f, size_t *sz) {
	int blocksize = BS;
	static int bufsize = BS;
	static char *next = NULL;
	static size_t nextlen = 0;
	size_t len, rr, rr2;
	char *tmp, *buf = NULL;
	if (sz) {
		*sz = 0;
	}
#if USE_SLURPIN
	if (!sz) {
		/* this is faster but have limits */
		/* run test/add10k.sh script to benchmark */
		const int buf_size = 96096;

		buf = calloc (1, buf_size);
		if (!buf) {
			return NULL;
		}

		if (!fgets (buf, buf_size, f)) {
			free (buf);
			return NULL;
		}
		if (feof (f)) {
			free (buf);
			return NULL;
		}

		size_t buf_len = strlen (buf);
		if (buf_len > 0) {
			buf[buf_len - 1] = '\0';
		}

		char *newbuf = realloc (buf, buf_len + 1);
		// realloc behaves like free if buf_len is 0
		if (!newbuf) {
			return buf;
		}
		return newbuf;
	}
#endif
	buf = calloc (BS + 1, 1);
	if (!buf) {
		return NULL;
	}

	len = 0;
	for (;;) {
		if (next) {
			free (buf);
			buf = next;
			bufsize = nextlen + blocksize;
			//len = nextlen;
			rr = nextlen;
			rr2 = fread (buf + nextlen, 1, blocksize, f);
			if (rr2 > 0) {
				rr += rr2;
				bufsize += rr2;
			}
			next = NULL;
			nextlen = 0;
		} else {
			rr = fread (buf + len, 1, blocksize, f);
		}
		if (rr < 1) { // EOF
			buf[len] = 0;
			next = NULL;
			break;
		}
		len += rr;
		//buf[len] = 0;
#if !USE_SLURPIN
		if (!sz) {
			char *nl = strchr (buf, '\n');
			if (nl) {
				*nl++ = 0;
				int nlen = nl - buf;
				nextlen = len - nlen;
				if (nextlen > 0) {
					next = malloc (nextlen + blocksize + 1);
					if (!next) {
						eprintf ("Cannot malloc %d\n", nextlen);
						break;
					}
					memcpy (next, nl, nextlen);
					if (!*next) {
						next = NULL;
					} else {
						//	continue;
					}
				} else {
					next = NULL;
					nextlen = 0; //strlen (next);;
				}
				break;
			}
		}
#endif
		bufsize += blocksize;
		tmp = realloc (buf, bufsize + 1);
		if (!tmp) {
			bufsize -= blocksize;
			break;
		}
		memset (tmp + bufsize - blocksize, 0, blocksize);
		buf = tmp;
	}
	if (sz) {
		*sz = len;
	}
	if (len < 1) {
		free (buf);
		return buf = NULL;
	}
	buf[len] = 0;
	return buf;
}

#if USE_MMAN
static void synchronize(int sig UNUSED) {
	// TODO: must be in sdb_sync() or wat?
	sdb_sync (s);
	Sdb *n = sdb_new (s->path, s->name, s->lock);
	if (n) {
		sdb_config (n, options);
		sdb_free (s);
		s = n;
	}
}
#endif

static int sdb_grep_dump(const char *dbname, int fmt, bool grep,
                         const char *expgrep) {
	char cname[SDB_MAX_KEY];
	char *v, k[SDB_MAX_KEY] = { 0 };
	char *d = cname;
	const char *comma = "";
	// local db beacuse is readonly and we dont need to finalize in case of ^C
	for (v=(char*)dbname;*v;v++) {
		if (*v == '.') {
			break;
		}
		*d++ = *v;
	}
	*d++ = 0;
	Sdb *db = sdb_new (NULL, dbname, 0);
	if (!db) {
		return 1;
	}
	sdb_config (db, options);
	sdb_dump_begin (db);
	switch (fmt) {
	case MODE_JSON:
		printf ("{");
		break;
	case MODE_CGEN:
		printf ("%%{\n");
		printf ("// gperf -aclEDCIG --null-strings -H sdb_hash_c_%s -N sdb_get_c_%s -t %s.gperf > %s.c\n", cname, cname, cname, cname);
		printf ("// gcc -DMAIN=1 %s.c ; ./a.out > %s.h\n", cname, cname);
		printf ("#include <stdio.h>\n");
		printf ("#include <ctype.h>\n");
		printf ("%%}\n");
		printf ("\n");
		printf ("struct kv { const char *name; const char *value; };\n");
		printf ("%%%%\n");
		break;
	}
	while (sdb_dump_dupnext (db, k, &v, NULL)) {
		if (grep && !strstr (k, expgrep) && !strstr (v, expgrep)) {
			free (v);
			continue;
		}
		switch (fmt) {
		case MODE_JSON:
			if (!strcmp (v, "true") || !strcmp (v, "false")) {
				printf ("%s\"%s\":%s", comma, k, v);
			} else if (sdb_isnum (v)) {
				printf ("%s\"%s\":%llu", comma, k, sdb_atoi (v));
			} else if (*v == '{' || *v == '[') {
				printf ("%s\"%s\":%s", comma, k, v);
			} else {
				printf ("%s\"%s\":\"%s\"", comma, k, v);
			}
			comma = ",";
			break;
		case MODE_CGEN:
			printf ("%s,\"%s\"\n", k, v);
			break;
		case MODE_ZERO:
			printf ("%s=%s", k, v);
			break;
		default:
			printf ("%s=%s\n", k, v);
			break;
		}
		free (v);
	}
	switch (fmt) {
	case MODE_ZERO:
		fflush (stdout);
		write_null ();
		break;
	case MODE_CGEN:
		printf ("%%%%\n");
		printf ("// SDB-CGEN V"SDB_VERSION"\n");
		printf ("const char* %s_get(const char *s) {\n", cname);
		printf ("\tconst struct kv *o = sdb_get_c_%s (s, strlen(s));\n", cname);
		printf ("\treturn o? o->value: NULL;\n");
		printf ("}\n");
		printf ("const unsigned int %s_hash(const char *s) {\n", cname);
		printf ("\treturn sdb_hash_c_%s(s, strlen (s));\n", cname);
		printf ("}\n");
printf (
"#if MAIN\n"
"int main () {\n"
"	char line[1024];\n"
"	FILE *fd = fopen (\"%s.gperf\", \"r\");\n"
"	int mode = 0;\n"
"	printf (\"#ifndef INCLUDE_%s_H\\n\");\n"
"	printf (\"#define INCLUDE_%s_H 1\\n\");\n"
"	while (!feof (fd)) {\n"
"		*line = 0;\n"
"		fgets(line,sizeof(line),fd);\n"
"		if (mode == 1) {\n"
"			char *comma = strchr (line, ',');\n"
"			if(comma) {\n"
"				*comma = 0;\n"
"				char *up = strdup(line);\n"
"				char *p = up;while(*p){*p=toupper(*p);p++;}\n"
"				printf (\"#define %s_%%s %%d\\n\",\n"
"					line, sdb_hash_c_%s (line, comma-line));\n"
"			}\n"
"		}\n"
"		if (*line == '%%' && line[1] == '%%')\n"
"			mode++;\n"
"	}\n"
"	printf (\"#endif\\n\");\n"
"}\n"
"#endif\n",
cname, cname,
cname, cname,
cname
);
		printf ("\n");
		break;
	case MODE_JSON:
		printf ("}\n");
		break;
	}
	sdb_free (db);
	return 0;
}

static int sdb_grep(const char *db, int fmt, const char *grep) {
	return sdb_grep_dump (db, fmt, true, grep);
}

static int sdb_dump(const char *db, int fmt) {
	return sdb_grep_dump (db, fmt, false, NULL);
}

static int insertkeys(Sdb *s, const char **args, int nargs, int mode) {
	int must_save = 0;
	if (args && nargs > 0) {
		int i;
		for (i = 0; i < nargs; i++) {
			switch (mode) {
			case '-':
				must_save |= sdb_query (s, args[i]);
				break;
			case '=':
				if (strchr (args[i], '=')) {
					char *v, *kv = (char *) strdup (args[i]);
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
	s = sdb_new (NULL, f, 0);
	if (!s) {
		eprintf ("Cannot create database\n");
		return 1;
	}
	sdb_config (s, options);
	int ret = 0;
	if (args) {
		int i;
		for (i = 0; i < nargs; i++) {
			if (!sdb_text_load (s, args[i])) {
				eprintf ("Failed to load text sdb from %s\n", args[i]);
			}
		}
	} else {
		size_t len;
		char *in = slurp (stdin, &len);
		if (!in) {
			return 0;
		}
		if (!sdb_text_load_buf (s, in, len)) {
			eprintf ("Failed to read text sdb from stdin\n");
		}
		free (in);
	}
	sdb_sync (s);
	return ret;
}

static int showusage(int o) {
	printf ("usage: sdb [-0cCdDehjJv|-D A B] [-|db] "
		"[.file]|[-=]|==||[-+][(idx)key[:json|=value] ..]\n");
	if (o == 2) {
		printf ("  -0      terminate results with \\x00\n"
			"  -c      count the number of keys database\n"
			"  -C      create foo.c and foo.h for sdb embedding\n"
			"  -G      output database for gperf processing\n"
			"  -d      decode base64 from stdin\n"
			"  -D      diff two databases\n"
			"  -e      encode stdin as base64\n"
			"  -h      show this help\n"
			"  -j      output in json\n"
			"  -J      enable journaling\n"
			"  -v      show version information\n");
		return 0;
	}
	return o;
}

static int showversion(void) {
	printf ("sdb "SDB_VERSION "\n");
	fflush (stdout);
	return 0;
}

static int jsonIndent(void) {
	size_t len;
	char *out;
	char *in = slurp (stdin, &len);
	if (!in) {
		return 0;
	}
	out = sdb_json_indent (in, "  ");
	if (!out) {
		free (in);
		return 1;
	}
	puts (out);
	free (out);
	free (in);
	return 0;
}

static int base64encode(void) {
	char *out;
	size_t len = 0;
	ut8 *in = (ut8 *) slurp (stdin, &len);
	if (!in) {
		return 0;
	}
	out = sdb_encode (in, (int)len);
	if (!out) {
		free (in);
		return 1;
	}
	puts (out);
	free (out);
	free (in);
	return 0;
}

static int base64decode(void) {
	ut8 *out;
	size_t len, ret = 1;
	char *in = slurp (stdin, &len);
	if (in) {
		int declen;
		out = sdb_decode (in, &declen);
		if (out && declen >= 0) {
			(void)write (1, out, declen);
			ret = 0;
		}
		free (out);
		free (in);
	}
	return ret;
}

static void dbdiff_cb(const SdbDiff *diff, void *user) {
	char sbuf[512];
	int r = sdb_diff_format (sbuf, sizeof(sbuf), diff);
	if (r < 0) {
		return;
	}
	char *buf = sbuf;
	char *hbuf = NULL;
	if ((size_t)r >= sizeof (sbuf)) {
		hbuf = malloc (r + 1);
		if (!hbuf) {
			return;
		}
		r = sdb_diff_format (hbuf, r + 1, diff);
		if (r < 0) {
			goto beach;
		}
	}
	printf ("\x1b[%sm%s\x1b[0m\n", diff->add ? "32" : "31", buf);
beach:
	free (hbuf);
}

static bool dbdiff(const char *a, const char *b) {
	Sdb *A = sdb_new (NULL, a, 0);
	Sdb *B = sdb_new (NULL, b, 0);
	bool equal = sdb_diff (A, B, dbdiff_cb, NULL);
	sdb_free (A);
	sdb_free (B);
	return equal;
}

static int showcount(const char *db) {
	ut32 d;
	s = sdb_new (NULL, db, 0);
	if (sdb_stats (s, &d, NULL)) {
		printf ("%d\n", d);
	}
	// TODO: show version, timestamp information
	sdb_free (s);
	return 0;
}

static int gen_gperf(const char *file, const char *name) {
	const size_t bufsz = 4096;
	char *buf = malloc (bufsz);
	
	char *out = malloc (strlen (file) +32);
	snprintf(out, strlen (file) + 32, "%s.gperf", name);
	int wd = open (out, O_RDWR);
	ftruncate (wd, 0);
	int rc = 0;
	if (wd != -1) {
		dup2 (1, 999);
		dup2 (wd, 1);
		rc = sdb_dump (file, MODE_CGEN);
		fflush (stdout);
		close (wd);
		dup2 (999, 1);
	} else {
		snprintf (buf, bufsz, "sdb -G %s > %s.gperf\n", file, name);
		rc = system (buf);
	}
	if (rc == 0) {
		snprintf (buf, bufsz, "gperf -aclEDCIG --null-strings -H sdb_hash_c_%s"
				" -N sdb_get_c_%s -t %s.gperf > %s.c\n", name, name, name, name);
		rc = system (buf);
		if (rc == 0) {
			snprintf (buf, bufsz, "gcc -DMAIN=1 %s.c ; ./a.out > %s.h\n", name, name);
			rc = system (buf);
			if (rc == 0) {
				eprintf ("Generated %s.c and %s.h\n", name, name);
			}
		} else {
			eprintf ("%s\n", buf);
			eprintf ("Cannot run gperf\n");
		}
	} else {
		eprintf ("Outdated sdb binary in PATH?\n");
	}
	free (buf);
	return rc;
}

int main(int argc, const char **argv) {
	char *line;
	const char *arg, *grep = NULL;
	int i, fmt = MODE_DFLT;
	int db0 = 1, argi = 1;
	bool interactive = false;

	/* terminate flags */
	if (argc < 2) {
		return showusage (1);
	}
	arg = argv[1];

	if (arg[0] == '-') {// && arg[1] && arg[2]==0) {
		switch (arg[1]) {
		case 0:
			/* no-op */
			break;
		case '0':
			fmt = MODE_ZERO;
			db0++;
			argi++;
			if (db0 >= argc) {
				return showusage (1);
			}
			break;
		case 'g':
			db0 += 2;
			if (db0 >= argc) {
				return showusage (1);
			}
			grep = argv[2];
			argi += 2;
			break;
		case 'J':
			options |= SDB_OPTION_JOURNAL;
			db0++;
			argi++;
			if (db0 >= argc) {
				return showusage (1);
			}
			break;
		case 'G':
			if (argc > 2) {
				return sdb_dump (argv[db0 + 1], MODE_CGEN);
			}
			return showusage (1);
		case 'c':
			return (argc < 3)? showusage (1): showcount (argv[2]);
		case 'C':
			if (argc > 2) {
				const char *file = argv[db0 + 1];
				char *name = strdup (file);
				char *p = strchr (name, '.');
				if (p) *p = 0;
				int rc = gen_gperf (file, name);
				free (name);
				return rc;
			}
			return showusage (1);
		case 'v': return showversion ();
		case 'h': return showusage (2);
		case 'e': return base64encode ();
		case 'd': return base64decode ();
		case 'D':
			if (argc == 4) {
				return dbdiff (argv[2], argv[3]) ? 0 : 1;
			}
			return showusage (0);
		case 'j':
			if (argc > 2) {
				return sdb_dump (argv[db0 + 1], MODE_JSON);
			}
			return jsonIndent ();
		default:
			eprintf ("Invalid flag %s\n", arg);
			break;
		}
	}

	/* sdb - */
	if (argi == 1 && !strcmp (argv[argi], "-")) {
		/* no database */
		argv[argi] = "";
		if (argc == db0 + 1) {
			interactive = true;
			/* if no argument passed */
			argv[argi] = "-";
			argc++;
			argi++;
		}
	}
	/* sdb dbname */
	if (argc - 1 == db0) {
		if (grep) {
			return sdb_grep (argv[db0], fmt, grep);
		}
		return sdb_dump (argv[db0], fmt);
	}
#if USE_MMAN
	signal (SIGINT, terminate);
	signal (SIGHUP, synchronize);
#endif
	int ret = 0;
	if (interactive || !strcmp (argv[db0 + 1], "-")) {
		if ((s = sdb_new (NULL, argv[db0], 0))) {
			sdb_config (s, options);
			int kvs = db0 + 2;
			if (kvs < argc) {
				save |= insertkeys (s, argv + argi + 2, argc - kvs, '-');
			}
			for (; (line = slurp (stdin, NULL));) {
				save |= sdb_query (s, line);
				if (fmt) {
					fflush (stdout);
					write_null ();
				}
				free (line);
			}
		}
	} else if (!strcmp (argv[db0 + 1], "=")) {
		ret = createdb (argv[db0], NULL, 0);
	} else if (!strcmp (argv[db0 + 1], "==")) {
		ret = createdb (argv[db0], argv + db0 + 2, argc - (db0 + 2));
	} else {
		s = sdb_new (NULL, argv[db0], 0);
		if (!s) {
			return 1;
		}
		sdb_config (s, options);
		for (i = db0 + 1; i < argc; i++) {
			save |= sdb_query (s, argv[i]);
			if (fmt) {
				fflush (stdout);
				write_null ();
			}
		}
	}
	terminate (ret);
	return ret;
}
