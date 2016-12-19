/* MIT (C) pancake (at) nopcode (dot) org - 2009-2016 */

#include "spp.h"
#include "config.h"

// TODO: avoid globals

static char *lbuf = NULL;
static int lbuf_s = 1024;
static int lbuf_n = 0;
static int incmd = 0;
static int printed = 0;
static char *tag_pre, *tag_post, *token = NULL;

int lineno = 1;
int tag_begin, echo[MAXIFL];
int ifl = 0; /* conditional nest level */

int spp_run(char *buf, Output *out) {
	int i, ret = 0;
	char *tok;

	D fprintf (stderr, "SPP_RUN(%s)\n", buf);
	if (proc->chop) {
		for (; IS_SPACE (*buf); buf++);
		for (tok = buf + strlen(buf) - 1; IS_SPACE (*tok); tok--) {
			*tok = '\0';
		}
	}

	if (token) {
		tok = strstr (buf, token);
		if (tok) {
			*tok = '\0';
			tok = tok + 1;
		} else {
			tok = buf;
		}
	} else {
		tok = buf;
	}
	for (i = 0; tags[i].callback; i++) {
		D fprintf (stderr, "NAME=(%s)\n", tok);
		if ((!tags[i].name) || (!strcmp (buf, tags[i].name))) {
			if (out->fout) {
				fflush (out->fout);
			}
			ret = tags[i].callback (tok, out);
			if (ret == -1) {
				break;
			}
			if (ret) {
				ifl += ret;
				if (ifl < 0 || ifl >= MAXIFL) {
					fprintf (stderr, "Nested conditionals parsing error.\n");
					break;
				}
			}
			break;
		}
	}
	return ret;
}

static char *spp_run_str(char *buf, int *rv) {
	char *b;
	Output tmp;
	tmp.fout = NULL;
	tmp.cout = r_strbuf_new ("");
	int rc = spp_run (buf, &tmp);
	b = strdup (r_strbuf_get (tmp.cout));
	r_strbuf_free (tmp.cout);
	if (rv) {
		*rv = rc;
	}
	return b;
}

void lbuf_strcat(char *dst, char *src) {
	int len = strlen (src);
	if (!lbuf || (len + lbuf_n) > lbuf_s) {
		lbuf = realloc (lbuf, lbuf_s << 1);
	}
	memcpy (lbuf + lbuf_n, src, len + 1);
	lbuf_n += len;
}

void do_printf(Output *out, char *str, ...) {
	va_list ap;
	va_start (ap, str);
	if (out->fout) {
		vfprintf (out->fout, str, ap);
	} else {
		char tmp[4096];
		vsnprintf (tmp, sizeof (tmp), str, ap);
		r_strbuf_append (out->cout, tmp);
	}
	va_end (ap);
}

void do_fputs(Output *out, char *str) {
	int i;
	for (i = 0; i <= ifl; i++) {
		if (!echo[i]) {
			return;
		}
	}
	if (str[0]) {
		printed = 1;
	}
	if (proc->fputs) {
		proc->fputs (out, str);
	} else {
		if (out->fout) {
			fprintf (out->fout, "%s", str);
		}
	}
}

void spp_eval(char *buf, Output *out) {
	char *ptr, *ptr2;
	char *ptrr = NULL;
	int delta;

	printed = 0;
retry:
	/* per word */
	if (!tag_pre && token) {
		do {
			ptr = strstr (buf, token);
			if (ptr) {
				*ptr = '\0';
			}
			delta = strlen (buf) - 1;
			if (buf[delta] == '\n') {
				buf[delta] = '\0';
			}
			if (*buf) {
				spp_run (buf, out);
			}
			buf = ptr + 1;
		} while (ptr);
		return;
	}

	if (!tag_post) {
		/* handle per line here ? */
		return;
	}

	// TODO: do it in scope!
	delta = strlen (tag_post);

	/* (pre) tag */
	ptr = tag_pre? strstr (buf, tag_pre): NULL;
	if (ptr) {
		D printf ("==> 0.0 (%s)\n", ptr);
		incmd = 1;
		if (!tag_begin || (tag_begin && ptr == buf)) {
			*ptr = '\0';
			ptr = ptr + strlen (tag_pre);
			do_fputs (out, buf);
			D printf ("==> 0 (%s)\n", ptr);
		}
		ptrr = strstr (ptr + strlen (tag_pre), tag_pre);
	}

	/* (post) tag */
	if (!ptr) {
		do_fputs (out, buf);
		return;
	}
	ptr2 = strstr (ptr, tag_post);
	if (ptr2) {
		*ptr2 = '\0';
		if (ptrr) {
			if (ptrr < ptr2) {
				char *p = strdup (ptr2 + 2);
				char *s = spp_run_str (ptrr + strlen (tag_pre), NULL);
				D fprintf (stderr, "strcpy(%s)(%s)\n", ptrr, s);
				strcpy (ptrr, s);
				free (s);
				ptr[-2] = tag_pre[0]; // XXX -2 check underflow?

				D fprintf (stderr, "strcat(%s)(%s)\n", ptrr, p);
				strcat (ptrr, p);
				buf = ptr - 2;
				D fprintf (stderr, "CONTINUE (%s)\n", buf);
				free (p);
				ptrr = NULL;
				goto retry;
			}
		}
		incmd = 0;
		if (lbuf && lbuf[0]) {
			D printf("==> 1 (%s)\n", lbuf);
			if (ptr) {
				lbuf_strcat (lbuf, buf);
				do_fputs (out, lbuf);
				spp_run (ptr, out);
			} else {
				lbuf_strcat (lbuf, buf);
				D printf ("=(1)=> spp_run(%s)\n", lbuf);
				spp_run (lbuf+delta, out);
				D printf ("=(1)=> spp_run(%s)\n", lbuf);
			}
			lbuf[0]='\0';
			lbuf_n = 0;
		} else {
			D printf ("==> 2 (%s)\n", ptr);
			if (ptr) {
				D printf (" ==> 2.1: run(%s)\n", ptr);
				spp_run (ptr, out);
				buf = ptr2 + delta;
				if (buf[0] == '\n' && printed) {
					buf++;
				}
				D printf (" ==> 2.1: continue(%s)\n", ptr2 + delta);
				goto retry;
			} else {
				do_fputs (out, "\n");
			}
		}
		do_fputs (out, ptr2 + delta);
	} else {
		D printf ("==> 3\n");
		if (ptr) {
			lbuf_strcat (lbuf, ptr);
		} else {
			if (!lbuf) {
				// XXX should never happen
				fprintf (stderr, "syntax error?\n");
				return;
			}
			if (buf[0]) {
				if (incmd) {
					lbuf_strcat (lbuf, buf);
				} else {
					do_fputs (out, buf);
				}
			} else {
				do_fputs (out, buf);
			}
		}
	}
}

/* TODO: detect nesting */
void spp_io(FILE *in, Output *out) {
	char buf[4096];
	int lines;
	if (!lbuf) {
		lbuf = calloc (1, 4096);
	}
	if (!lbuf) {
		fprintf (stderr, "Out of memory.\n");
		return;
	}
	lbuf[0] = '\0';
	while (!feof (in)) {
		buf[0] = '\0'; // ???
		fgets (buf, 1023, in);
		if (feof (in)) break;
		lines = 1;
		if (!memcmp (buf, "#!", 2)) {
			fgets (buf, 1023, in);
			if (feof (in)) break;
			lines++;
		}
		if (proc->multiline) {
			while (1) {
				char *eol = buf + strlen (buf) - strlen (proc->multiline);
				if (!strcmp (eol, proc->multiline)) {
					D fprintf (stderr, "Multiline detected!\n");
					fgets (eol, 1023, in);
					if (feof (in)) {
						break;
					}
					lines++;
				} else {
					break;
				}
			}
		}
		spp_eval (buf, out);
		lineno += lines;
	}
	do_fputs (out, lbuf);
}

int spp_file(const char *file, Output *out) {
	FILE *in = fopen (file, "r");
	D fprintf (stderr, "SPP-FILE(%s)\n", file);
	if (in) {
		spp_io (in, out);
		fclose (in);
		return 1;
	}
	fprintf (stderr, "Cannot find '%s'\n", file);
	return 0;
}

void spp_proc_list_kw() {
	int i;
	for (i = 0; tags[i].name; i++) {
		printf ("%s\n", tags[i].name);
	}
}

void spp_proc_list() {
	int i;
	for (i=0; procs[i]; i++) {
		printf ("%s\n", procs[i]->name);
	}
}

void spp_proc_set(struct Proc *p, char *arg, int fail) {
	int i, j;
	if (arg)
	for (j = 0; procs[j]; j++) {
		if (!strcmp (procs[j]->name, arg)) {
			proc = procs[j];
			D printf ("SET PROC:(%s)(%s)\n", arg, proc->name);
			break;
		}
	}
	if (arg && *arg && !procs[j] && fail) {
		fprintf (stderr, "Invalid preprocessor name '%s'\n", arg);
		return;
	}
	if (!proc) {
		proc = p;
	}
	if (proc) {
		// TODO: wtf!
		tag_pre = proc->tag_pre;
		tag_post = proc->tag_post;
		for (i = 0; i < MAXIFL; i++) {
			echo[i] = proc->default_echo;
		}
		token = proc->token;
		tag_begin = proc->tag_begin;
		args = (struct Arg*)proc->args;
		tags = (struct Tag*)proc->tags;
	}
}
