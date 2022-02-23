/* sdb - MIT - Copyright 2011-2022 - pancake */

#include <signal.h>
#include <fcntl.h>
#ifndef HAVE_SYSTEM
#define HAVE_SYSTEM 1
#endif
#if USE_DLSYSTEM
#include <dlfcn.h>
#endif
#include "sdb.h"

typedef enum {
	text,
	zero,
	json,
	cgen,
	diff,
	perf
} MainFormat;

typedef enum {
	nope = 0,
	dash,
	eqeq,
	dobl
} MainCreate;

typedef struct {
	int argc;
	const char **argv;
	int argi;
	int db0;
	bool failed;
	const char *db;
	const char *outfile;
	const char *db2;
	const char *grep;
	ut32 options;
	bool textmode;
	MainCreate create;
	MainFormat format;
} MainOptions;

static bool save = false;
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
	exit (sig < 2? sig: 0);
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

		buf = (char *)calloc (1, buf_size);
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

		char *newbuf = (char *)realloc (buf, buf_len + 1);
		// realloc behaves like free if buf_len is 0
		if (!newbuf) {
			return buf;
		}
		return newbuf;
	}
#endif
	buf = (char *)calloc (BS + 1, 1);
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
					next = (char *)malloc (nextlen + blocksize + 1);
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
		tmp = (char *)realloc (buf, bufsize + 1);
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

static char* get_name(const char*name) {
	if (!name || !*name) {
		return NULL;
	}
	const char *l = name + strlen (name) - 1;
	while (*l && l > name) {
		if (*l == '/') {
			name = l + 1;
			break;
		}
		l--;
	}
	char *n = strdup (name);
	char *v, *d = n;
	for (v = (char*)n; *v; v++) {
		if (*v == '.') {
			break;
		}
		*d++ = *v;
	}
	*d++ = 0;
	return n;
}

static char* get_cname(const char*name) {
	if (!name || !*name) {
		return NULL;
	}
	const char *l = name + strlen (name) - 1;
	while (*l && l > name) {
		if (*l == '/') {
			name = l + 1;
			break;
		}
		l--;
	}
	char *n = strdup (name);
	char *v, *d = n;
	for (v = (char*)n; *v; v++) {
		if (*v == '/' || *v == '-') {
			*d++ = '_';
			continue;
		}
		if (*v == '.') {
			break;
		}
		*d++ = *v;
	}
	*d++ = 0;
	return n;
}

static char *escape(const char *b, int ch) {
	char *a = (char *)calloc ((1 + strlen (b)), 4);
	char *c = a;
	while (*b) {
		if (*b == ch) {
			*c = '_';
		} else
		switch (*b) {
		case '"':
			*c++ = '\\';
			*c++ = '"';
			break;
		case '\\':
			*c++ = '\\';
			*c++ = '\\';
			break;
		case '\r':
			*c++ = '\\';
			*c++ = 'r';
			break;
		case '\n':
			*c++ = '\\';
			*c++ = 'n';
			break;
		default:
			*c = *b;
			break;
		}
		b++;
		c++;
	}
	return a;
}

static void sdb_dump_cb(MainOptions *mo, const char *k, const char *v, const char *comma) {
	switch (mo->format) {
	case json:
		if (!strcmp (v, "true") || !strcmp (v, "false")) {
			printf ("%s\"%s\":%s", comma, k, v);
		} else if (sdb_isnum (v)) {
			printf ("%s\"%s\":%" ULLFMT "u", comma, k, sdb_atoi (v));
		} else if (*v == '{' || *v == '[') {
			printf ("%s\"%s\":%s", comma, k, v);
		} else {
			printf ("%s\"%s\":\"%s\"", comma, k, v);
		}
		break;
	case perf:
	case cgen:
		{
			char *a = escape (k, ',');
			char *b = escape (v, 0);
			if (mo->textmode) {
				printf ("  {\"%s\",\"%s\"}, \n", a, b);
			} else {
				printf ("%s,\"%s\"\n", a, b);
			}
			free (a);
			free (b);
		}
		break;
	case zero:
		printf ("%s=%s", k, v);
		break;
	default:
		printf ("%s=%s\n", k, v);
		break;
	}
}

static void cgen_header(MainOptions *mo, const char *cname) {
	if (mo->textmode) {
		printf ("// SDB-CGEN V" SDB_VERSION "\n");
		printf ("// gcc -DMAIN=1 %s.c ; ./a.out > %s.h\n", cname, cname);
		printf ("#include <ctype.h>\n");
		printf ("#include <stdio.h>\n");
		printf ("#include <string.h>\n");
		printf ("\n");
		printf ("struct kv { const char *name; const char *value; };\n");
		printf ("static struct kv kvs[] = {\n");
	} else {
		printf ("%%{\n");
		printf ("// gperf -aclEDCIG --null-strings -H sdb_hash_c_%s -N sdb_get_c_%s -t %s.gperf > %s.c\n", cname, cname, cname, cname);
		printf ("// gcc -DMAIN=1 %s.c ; ./a.out > %s.h\n", cname, cname);
		printf ("#include <stdio.h>\n");
		printf ("#include <string.h>\n");
		printf ("#include <ctype.h>\n");
		printf ("%%}\n");
		printf ("\n");
		printf ("struct kv { const char *name; const char *value; };\n");
		printf ("%%%%\n");
	}
}

// TODO rename gperf with cgen
static void cgen_footer(MainOptions *mo, const char *name, const char *cname) {
	if (mo->textmode) {
		printf ("  {NULL, NULL}\n");
		printf ("};\n");
		printf ("// %p\n", cname);
		printf ("// TODO\n");
		printf ("typedef int (*GperfForeachCallback)(void *user, const char *k, const char *v);\n");
		printf ("int gperf_%s_foreach(GperfForeachCallback cb, void *user) {\n", cname);
		printf ("  int i = 0; while (kvs[i].name) {\n");
		printf ("  cb (user, kvs[i].name, kvs[i].value);\n");
		printf ("  i++;}\n");
		printf ("  return 0;\n");
		printf ("}\n");
		printf ("const char *gperf_%s_get(const char *s) {\n", cname);
		printf ("  int i = 0; while (kvs[i].name) {\n");
		printf ("  if (!strcmp (s, kvs[i].name)) return kvs[i].value;\n");
		printf ("  i++;}\n");
		printf ("  return NULL;\n");
		printf ("}\n");
		printf ("#define sdb_hash_c_%s(x,y) gperf_%s_hash(x)\n", cname, cname);
		printf ("const unsigned int gperf_%s_hash(const char *s) {\n", cname);
		printf ("  int sum = strlen (s);\n");
		printf ("  while (*s) { sum += *s; s++; }\n");
		printf ("  return sum;\n");
		printf ("}\n");
		printf (
			"struct {const char *name;void *get;void *hash;void *foreach;} gperf_%s = {\n"
			"  .name = \"%s\",\n"
			"  .get = &gperf_%s_get,\n"
			"  .hash = &gperf_%s_hash,\n"
			"  .foreach = &gperf_%s_foreach\n"
			"};\n", cname, name, cname, cname, cname);
		printf (
			"\n"
			"#if MAIN\n"
			"int main () {\n"
			"	const char *s = ((char*(*)(char*))gperf_%s.get)(\"foo\");\n"
			"	printf (\"%%s\\n\", s);\n"
			"}\n"
			"#endif\n", cname);
		return;
	}
	printf ("%%%%\n");
	printf ("// SDB-CGEN V" SDB_VERSION "\n");
	printf ("// %p\n", cname);
	printf ("typedef int (*GperfForeachCallback)(void *user, const char *k, const char *v);\n");
	printf ("int gperf_%s_foreach(GperfForeachCallback cb, void *user) {\n", cname);
	printf ("\tint i;for (i=0;i<TOTAL_KEYWORDS;i++) {\n");
	printf ("\tconst struct kv *w = &wordlist[i];\n");
	printf ("\tif (!cb (user, w->name, w->value)) return 0;\n");
	printf ("}\n");
	printf ("return 1;}\n");
	printf ("const char* gperf_%s_get(const char *s) {\n", cname);
	printf ("\tconst struct kv *o = sdb_get_c_%s (s, strlen(s));\n", cname);
	printf ("\treturn o? o->value: NULL;\n");
	printf ("}\n");
	printf ("const unsigned int gperf_%s_hash(const char *s) {\n", cname);
	printf ("\treturn sdb_hash_c_%s(s, strlen (s));\n", cname);
	printf ("}\n");
	printf (
		"struct {const char*name;void*get;void*hash;void *foreach;} gperf_%s = {\n"
		"\t.name = \"%s\",\n"
		"\t.get = &gperf_%s_get,\n"
		"\t.hash = &gperf_%s_hash,\n"
		"\t.foreach = &gperf_%s_foreach\n"
		"};\n"
		"\n"
		"#if MAIN\n"
		"int main () {\n"
		"	char line[1024];\n"
		"	FILE *fd = fopen (\"%s.gperf\", \"r\");\n"
		"	if (!fd) {\n"
		"		fprintf (stderr, \"Cannot open %s.gperf\\n\");\n"
		"		return 1;\n"
		"	}\n"
		"	int mode = 0;\n"
		"	printf (\"#ifndef INCLUDE_%s_H\\n\");\n"
		"	printf (\"#define INCLUDE_%s_H 1\\n\");\n"
		"	while (!feof (fd)) {\n"
		"		*line = 0;\n"
		"		fgets (line, sizeof (line), fd);\n"
		"		if (mode == 1) {\n"
		"			char *comma = strchr (line, ',');\n"
		"			if (comma) {\n"
		"				*comma = 0;\n"
		"				char *up = strdup (line);\n"
		"				char *p = up; while (*p) { *p = toupper (*p); p++; }\n"
		"				printf (\"#define GPERF_%s_%%s %%d\\n\",\n"
		"					line, sdb_hash_c_%s (line, comma - line));\n"
		"			}\n"
		"		}\n"
		"		if (*line == '%%' && line[1] == '%%')\n"
		"			mode++;\n"
		"	}\n"
		"	printf (\"#endif\\n\");\n"
		"}\n"
		"#endif\n",
		cname, cname, cname, cname, cname,
		name, name,
		cname, cname, cname, cname
	);
	printf ("\n");
}

static int sdb_dump(MainOptions *mo) {
	const char *dbname = mo->db;
	const char *expgrep = mo->grep;
	const bool grep = mo->grep;

	char *v = NULL;
	char k[SDB_MAX_KEY] = { 0 };
	const char *comma = "";
	Sdb *db = sdb_new (NULL, dbname, 0);
	if (!db) {
		return 1;
	}
	char *cname = get_cname (dbname);
	char *name = get_name (dbname);
	sdb_config (db, options);
	sdb_dump_begin (db);
	switch (mo->format) {
	case cgen:
	case perf:
		cgen_header (mo, cname);
		break;
	case json:
		printf ("{");
		break;
	default:
		break;
	}

	if (db->fd == -1) {
		SdbList *l = sdb_foreach_list (db, true);
		if (!mo->textmode && mo->format == cgen && ls_length (l) > SDB_MAX_GPERF_KEYS) {
			ls_free (l);
			eprintf ("Error: gperf doesn't work with datasets with more than 15.000 keys.\n");
			free (name);
			free (cname);
			return -1;
		}
		SdbKv *kv;
		SdbListIter *it;
		ls_foreach_cast (l, it, SdbKv*, kv) {
			const char *k = sdbkv_key (kv);
			const char *v = sdbkv_value (kv);
			if (v && *v && grep && !strstr (k, expgrep) && !strstr (v, expgrep)) {
				continue;
			}
			sdb_dump_cb (mo, k, v, comma);
			comma = ",";
		}
		ls_free (l);
	} else {
		int count = 0;
		while (sdb_dump_dupnext (db, k, &v, NULL)) {
			if (v && *v && grep && !strstr (k, expgrep) && !strstr (v, expgrep)) {
				free (v);
				continue;
			}
			sdb_dump_cb (mo, k, v, comma);
			comma = ",";
			free (v);
			if (!mo->textmode && mo->format == cgen && count++ > SDB_MAX_GPERF_KEYS) {
				eprintf ("Error: gperf doesn't work with datasets with more than 15.000 keys.\n");
				free (name);
				free (cname);
				return -1;
			}
		}
	}
	switch (mo->format) {
	case zero:
		fflush (stdout);
		write_null ();
		break;
	case perf:
	case cgen:
		cgen_footer (mo, name, cname);
		break;
	case json:
		printf ("}\n");
		break;
	default:
		break;
	}
	sdb_free (db);
	free (cname);
	free (name);
	return 0;
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
	printf ("usage: sdb [-0cCdDehjJtv|-D A B] [-|db] "
		"[.file]|[-=]|==||[-+][(idx)key[:json|=value] ..]\n");
	if (o == 2) {
		printf ("  -0      terminate results with \\x00\n"
			"  -c      count the number of keys database\n"
			"  -C      create foo.{c,h} for embedding (uses gperf)\n"
			"  -d      decode base64 from stdin\n"
			"  -D      diff two databases\n"
			"  -e      encode stdin as base64\n"
			"  -g [..] grep expression\n"
			"  -G      print database in gperf format\n"
			"  -h      show this help\n"
			"  -j      output in json\n"
			"  -o [f]  output file name for -C -t\n"
			"  -J      enable journaling\n"
			"  -t      use textmode (for -C)\n"
			"  -v      show version information\n");
		return 0;
	}
	return o;
}

static int showversion(void) {
	printf ("sdb " SDB_VERSION "\n");
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
		hbuf = (char *)malloc (r + 1);
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

static int sdb_system(const char *cmd) {
	static int (*sys)(const char *cmd) = NULL;
	if (!sys) {
#if HAVE_SYSTEM
#if USE_DLSYSTEM
		sys = dlsym (NULL, "system");
		if (!sys) {
			sys = puts;
			return -1;
		}
#else
		sys = system;
#endif
#endif
	}
	return sys (cmd);
}

static int gen_gperf(MainOptions *mo, const char *file, const char *name) {
	const size_t buf_size = 4096;
	char *buf = (char *)malloc (buf_size);
	if (!buf) {
		return -1;
	}
	size_t out_size = strlen (file) + 32;
	char *out = (char *)malloc (out_size);
	if (!out) {
		free (buf);
		return -1;
	}
	if (mo->outfile) {
		snprintf (out, out_size, "%s", mo->outfile);
	} else {
		snprintf (out, out_size, "%s.%s", name, (mo->textmode)? "c": "gperf");
	}
	int wd = open (out, O_RDWR, 0644);
	if (wd == -1) {
		wd = open (out, O_RDWR | O_CREAT, 0644);
	} else {
		ftruncate (wd, 0);
	}
	int rc = -1;
	if (wd != -1) {
#if __wasi__ || EMSCRIPTEN
		rc = sdb_dump (mo); // file, MODE_CGEN, false, NULL);
		fflush (stdout);
#else
		dup2 (1, 999);
		dup2 (wd, 1);
		rc = sdb_dump (mo); // file, MODE_CGEN, false, NULL);
		fflush (stdout);
		close (wd);
		dup2 (999, 1);
#endif
	} else {
		eprintf ("Cannot create .%s\n", out);
	}
	if (mo->textmode) {
		// dont do much
	} else {
		if (rc == 0) {
			char *cname = get_cname (name);
			snprintf (buf, buf_size, "gperf -aclEDCIG --null-strings -H sdb_hash_c_%s"
					" -N sdb_get_c_%s -t %s.gperf > %s.c\n", cname, cname, name, name);
			free (cname);
			rc = sdb_system (buf);
			if (rc == 0) {
				snprintf (buf, buf_size, "gcc -DMAIN=1 %s.c ; ./a.out > %s.h\n", name, name);
				rc = sdb_system (buf);
				if (rc == 0) {
					eprintf ("Generated %s.c and %s.h\n", name, name);
				}
			} else {
				eprintf ("Cannot run gperf\n");
				eprintf ("%s\n", buf);
			}
		} else {
			eprintf ("Outdated sdb binary in PATH?\n");
		}
	}
	free (out);
	free (buf);
	return rc;
}

static const char *main_argparse_getarg(MainOptions *mo) {
	int cur = mo->argi;
	if (mo->argi + 1>= mo->argc) {
		return NULL;
	}
	mo->argi++;
	mo->db0++;
	return mo->argv[cur];
}

static bool main_argparse_flag(MainOptions *mo, char flag) {
	mo->argi++;
	switch (flag) {
	case '0':
		mo->format = zero;
		break;
	case 'h':
		return showusage (2);
	case 'o':
		mo->outfile = main_argparse_getarg (mo);
		break;
	case 'v':
		return showversion ();
	case 'e':
		return base64encode ();
	case 'd':
		return base64decode ();
	case 'j':
		mo->format = json;
		if (mo->argi >= mo->argc) {
			return jsonIndent ();
		}
		break;
	case 'c':
		if (mo->argc <= 3) {
			return showusage (1);
		} else {
			const char *db = main_argparse_getarg (mo);
			if (!db) {
				return showusage (1);
			}
			return showcount (db);
		}
		break;
	case 'g':
		mo->grep = main_argparse_getarg (mo);
		if (!mo->grep) {
			eprintf ("Missing argument for -g\n");
			return false;
		}
		break;
	case 'D':
		if (mo->argi + 1 >=  mo->argc) {
			return showusage (0);
		}
		mo->format = diff;
		break;
	case 'G':
		mo->format = perf;
		break;
	case 'C':
		mo->format = cgen;
		break;
	case 't':
		mo->textmode = true;
		break;
	case 'J':
		mo->options |= SDB_OPTION_JOURNAL;
		// expect argument
		break;
	default:
		return false;
	}
	return true;
}

static MainOptions *main_argparse(MainOptions *mo, int argc, const char **argv) {
	if (!mo) {
		return NULL;
	}
	mo->argc = argc;
	mo->argv = argv;
	mo->options = SDB_OPTION_FS | SDB_OPTION_NOSTAMP;
	mo->failed = true;
	int i;
	mo->argi = 1;
	for (i = 1; i < argc; i++) {
		mo->db0++;
		i = mo->argi;
		if (argv[i][0] == '-' && argv[i][1]) {
			int j = 1;
			while (argv[i][j]) {
				if (!main_argparse_flag (mo, argv[i][j])) {
					mo->db = argv[mo->argi];
					mo->db0 = i + 1;
					// invalid flag
					break; // return NULL;
				}
				if (i != mo->argi) {
					break;
				}
				j++;
			}
		} else {
			mo->db = argv[mo->db0];
			if (i + 1 < argc) {
				switch (argv[i + 1][0]) {
				case '-':
					if (!argv[i + 1][1]) {
						mo->create = dash;
					}
					break;
				case '=':
					if (argv[i + 1][1]) {
						mo->create = dobl;
					} else {
						mo->create = eqeq;
					}
					break;
				default:
					mo->db2 = argv[i];
					break;
				}
			}
			break;
		}
	}
	// mo->db = mo->argv[mo->db0 + 1];
	mo->db = argv[mo->db0];
	return mo;
}

int main(int argc, const char **argv) {
	char *line;
	int i;

	/* terminate flags */
	if (argc < 2) {
		return showusage (1);
	}

	MainOptions _mo = {0};
	MainOptions *mo = &_mo;
	main_argparse (mo, argc, argv);
	// -j json return sdb_dump (argv[db0 + 1], MODE_JSON);
	// -G sdb_dump (argv[db0 + 1], MODE_CGEN); // gperf
	// -C print C/H files
	// -t text
	switch (mo->format) {
	case diff:
		if (mo->db && mo->db2) {
			return dbdiff (mo->db, mo->db2)? 0: 1;
		}
		return showusage (1);
	case perf:
		return sdb_dump (mo);
	case cgen:
		{
			if (mo->db0 >= argc) {
				return showusage (1);
			}
			const char *file = mo->argv[mo->db0];
			char *name = strdup (file);
			char *p = strchr (name, '.');
			if (p) {
				*p = 0;
			}
			int rc = gen_gperf (mo, file, name);
			free (name);
			return rc;
		}
	default:
		break;
	}

	if (!mo->db && !mo->create) {
		return showusage (1);
	}
	if (!mo->create && mo->db) {
		if (!strcmp (mo->db, "-")) {
			mo->create = dash;
			mo->db = NULL;
			mo->argi--;
			mo->db0 = mo->argi;
		}
	}
#if USE_MMAN
	signal (SIGINT, terminate);
	signal (SIGHUP, synchronize);
#endif
	int ret = 0;
	switch (mo->create) {
	case dash: // "-"
		if ((s = sdb_new (NULL, mo->db, 0))) {
			sdb_config (s, options);
			int kvs = mo->db0 + 2;
			if (mo->argi + 2 < mo->argc) {
				for (i = mo->argi + 2; i < argc; i++) {
					save |= sdb_query (s, mo->argv[i]);
					if (mo->format) {
						fflush (stdout);
						write_null ();
					}
				}
			} else {
				if (kvs < argc) {
					save |= insertkeys (s, argv + mo->argi + 2, argc - kvs, '-');
				}
				for (; (line = slurp (stdin, NULL));) {
					save |= sdb_query (s, line);
					if (mo->format) {
						fflush (stdout);
						write_null ();
					}
					free (line);
				}
			}
		}
		break;
	case eqeq: // "="
		ret = createdb (mo->db, NULL, 0);
		break;
	case dobl: // "=="
		{
			int delta = mo->db0 + 2;
			ret = createdb (mo->db, mo->argv + delta, mo->argc - delta);
		}
		break;
	default:
		// "sdb test.db"
		s = sdb_new (NULL, mo->db, 0);
		if (!s) {
			return 1;
		}
		sdb_config (s, options);
		if (mo->argi + 1 < mo->argc) {
			for (i = mo->db0 + 1; i < argc; i++) {
				save |= sdb_query (s, mo->argv[i]);
				if (mo->format) {
					fflush (stdout);
					write_null ();
				}
			}
		} else {
			return sdb_dump (mo);
		}
		break;
	}
	terminate (ret);
	return ret;
}
