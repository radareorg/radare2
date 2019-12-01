/* Mini MCMS :: renamed to 'spp'? */

#if __UNIX__
#include <unistd.h>
#endif

static char *spp_var_get(char *var) {
	return r_sys_getenv (var);
}

static int spp_var_set(const char *var, const char *val) {
	return r_sys_setenv (var, val);
}

#if HAVE_SYSTEM
/* Should be dynamic buffer */
static char *cmd_to_str(const char *cmd) {
	char *out = (char *)calloc (4096, 1);
	char *tout;
	int ret = 0, len = 0, outlen = 4096;
	FILE *fd = popen (cmd, "r");
	while (fd) {
		len += ret;
		ret = fread (out + len, 1, 1023, fd);
		if (ret < 1) {
			pclose (fd);
			fd = NULL;
		}
		if (ret + 1024 > outlen) {
			outlen += 4096;
			tout = realloc (out, outlen);
			if (!tout) {
				if (fd) {
					pclose (fd);
					fd = NULL;
				}
				fprintf (stderr, "Out of memory.\n");
				break;
			}
			out = tout;
		}
	}
	out[len] = '\0';
	return out;
}
#endif

static TAG_CALLBACK(spp_set) {
	char *eq, *val = "";
	if (!state->echo[state->ifl]) {
		return 0;
	}
	for (eq=buf; eq[0]; eq++) {
		switch (eq[0]) {
		case '-':
		case '.':
			eq[0] = '_';
			break;
		}
	}
	eq = strchr (buf, ' ');
	if (eq) {
		*eq = '\0';
		val = eq + 1;
	}
	if (spp_var_set (buf, val) == -1) {
		fprintf (stderr, "Invalid variable name '%s' at line %d\n", buf, state->lineno);
	}
	return 0;
}

static TAG_CALLBACK(spp_get) {
	char *var;
	if (!state->echo[state->ifl]) {
		return 0;
	}
	var = spp_var_get (buf);
	if (var) {
		out_printf (out, "%s", var);
	}
	return 0;
}

static TAG_CALLBACK(spp_getrandom) {
	int max;
	if (!state->echo[state->ifl]) {
		return 0;
	}
	// XXX srsly? this is pretty bad random
	srandom (r_sys_getpid()); // TODO: change this to be portable
	max = atoi (buf);
	if (max > 0) {
		max = (int)(rand () % max);
	}
	out_printf (out, "%d", max);
	return 0;
}

static TAG_CALLBACK(spp_add) {
	char res[32];
	char *var, *eq = strchr (buf, ' ');
	int ret = 0;
	if (!state->echo[state->ifl]) {
		return 0;
	}
	if (eq) {
		*eq = '\0';
		var = spp_var_get (buf);
		if (var) {
			ret = atoi (var);
		}
		ret += atoi (eq + 1);
		snprintf (res, sizeof (res), "%d", ret);
		r_sys_setenv (buf, res);
	} else {
		/* syntax error */
	}
	return 0;
}

static TAG_CALLBACK(spp_sub) {
	char *eq = strchr(buf, ' ');
	char *var;
	int ret = 0;
	if (!state->echo[state->ifl]) {
		return 0;
	}
	if (eq) {
		*eq = '\0';
		var = spp_var_get (buf);
		ret = var? atoi (var): 0;
		ret -= atoi (eq + 1);
		r_sys_setenv (buf, eq + 1);
	} else {
		/* syntax error */
	}
	return ret;
}

static TAG_CALLBACK(spp_trace) {
	if (state->echo[state->ifl]) {
		fprintf (stderr, "%.1000s\n", buf);
	}
	return 0;
}

/* TODO: deprecate */
static TAG_CALLBACK(spp_echo) {
	if (state->echo[state->ifl]) {
		out_printf (out, "%s", buf);
	}
	// TODO: add variable replacement here?? not necessary, done by {{get}}
	return 0;
}

static TAG_CALLBACK(spp_error) {
	if (!state->echo[state->ifl]) {
		return 0;
	}
	fprintf (stderr, "ERROR: %s (line=%d)\n", buf, state->lineno);
	return -1;
}

static TAG_CALLBACK(spp_warning) {
	if (!state->echo[state->ifl]) {
		return 0;
	}
	fprintf (stderr, "WARNING: %s (line=%d)\n", buf, state->lineno);
	return 0;
}

static TAG_CALLBACK(spp_system) {
	if (!state->echo[state->ifl]) {
		return 0;
	}
#if HAVE_SYSTEM
	char *str = cmd_to_str (buf);
	out_printf (out, "%s", str);
	free(str);
#endif
	return 0;
}

static TAG_CALLBACK(spp_include) {
	char *incdir;
	if (!state->echo[state->ifl]) {
		return 0;
	}
	incdir = getenv("SPP_INCDIR");
	if (incdir) {
		char *b = strdup (incdir);
		char *p = realloc (b, strlen (b) + strlen (buf) + 3);
		if (p) {
			b = p;
			strcat (b, "/");
			strcat (b, buf);
			spp_file (b, out);
		}
		free (b);
	} else {
		spp_file(buf, out);
	}
	return 0;
}

static TAG_CALLBACK(spp_if) {
	char *var = spp_var_get(buf);
	state->echo[state->ifl + 1] = (var && *var != '0' && *var != '\0') ? 1 : 0;
	return 1;
}

/* {{ ifeq $path / }} */
static TAG_CALLBACK(spp_ifeq) {
	char *value = buf;
	char *eq = strchr(buf, ' ');
	if (eq) {
		*eq = '\0';
		value = spp_var_get(value);
		if (value && !strcmp(value, eq+1)) {
			state->echo[state->ifl + 1] = 1;
		} else state->echo[state->ifl + 1] = 0;
//fprintf(stderr, "IFEQ(%s)(%s)=%d\n", buf, eq+1, echo[ifl]);
	} else {
		value = spp_var_get(buf);
		if (!value || *value=='\0')
			state->echo[state->ifl + 1] = 1;
		else state->echo[state->ifl + 1] = 0;
//fprintf(stderr, "IFEQ(%s)(%s)=%d\n", buf, value, echo[ifl]);
	}
	return 1;
}

static TAG_CALLBACK(spp_hex) {
	int i;
	for(i = 0; buf[i]; i++) {
		if (buf[i] >= '0' && buf[i] <= '9') {
			int b;
			unsigned int ch;
			b = buf[i + 2];
			buf[i + 2] = '\0';
			sscanf(buf + i, "%02x", &ch);
			out_printf (out, "%c", ch);
			buf[i + 2] = b;
			buf = buf + 2;
		}
	}
	return 0;
}

static TAG_CALLBACK(spp_grepline) {
	FILE *fd;
	char b[1024];
	char *ptr;
	int line;

	if (!state->echo[state->ifl]) return 1;
	ptr = strchr(buf, ' ');
	if (ptr) {
		*ptr= '\0';
		fd = fopen (buf, "r");
		line = atoi (ptr+1);
		if (fd) {
			while (!feof (fd) && line--) {
				if (!fgets (b, 1023, fd)) {
					break;
				}
			}
			fclose (fd);
			out_printf (out, "%s", b);
		} else {
			fprintf(stderr, "Unable to open '%s'\n", buf);
		}
	}
	return 0;
}

static TAG_CALLBACK(spp_else) {
	state->echo[state->ifl] = state->echo[state->ifl] ? 0 : 1;
	return 0;
}

static TAG_CALLBACK(spp_ifnot) {
	spp_if (state, out, buf);
	spp_else (state, out, buf);
	return 1;
}

static TAG_CALLBACK(spp_ifin) {
	char *var, *ptr;
	if (!state->echo[state->ifl]) {
		return 1;
	}
	ptr = strchr (buf, ' ');
	state->echo[state->ifl + 1] = 0;
	if (ptr) {
		*ptr='\0';
		var = getenv(buf);
		if (strstr (ptr + 1, var)) {
			state->echo[state->ifl + 1] = 1;
		}
	}
	return 1;
}

static TAG_CALLBACK(spp_endif) {
	return -1;
}

static TAG_CALLBACK(spp_default) {
	if (!state->echo[state->ifl]) {
		return 0;
	}
	if (buf[-1] != ';') { /* commented tag */
		fprintf (stderr, "WARNING: invalid command: '%s' at line %d\n", buf, state->lineno);
	}
	return 0;
}

#if HAVE_SYSTEM
static FILE *spp_pipe_fd = NULL;
#endif

static TAG_CALLBACK(spp_pipe) {
#if HAVE_SYSTEM
	spp_pipe_fd = popen (buf, "w");
#endif
	return 0;
}

static char *spp_switch_str = NULL;

static TAG_CALLBACK(spp_switch) {
	char *var = spp_var_get (buf);
	if (var) {
		spp_switch_str = strdup (var);
	} else {
		spp_switch_str = strdup ("");
	}
	return 1;
}

static TAG_CALLBACK(spp_case) {
	state->echo[state->ifl] = strcmp (buf, spp_switch_str)?0:1;
	return 0;
}

static TAG_CALLBACK(spp_endswitch) {
	free (spp_switch_str);
	spp_switch_str = NULL;
	return -1;
}

static TAG_CALLBACK(spp_endpipe) {
#if HAVE_SYSTEM
	/* TODO: Get output here */
	int ret = 0, len = 0;
	int outlen = 4096;
	char *str = (char *)malloc (4096);
	char *tstr;
	do {
		len += ret;
		ret = fread (str + len, 1, 1023, spp_pipe_fd);
		if (ret + 1024 > outlen) {
			outlen += 4096;
			tstr = realloc (str, outlen);
			if (!tstr) {
				fprintf (stderr, "Out of memory.\n");
				break;
			}
			str = tstr;
		}
	} while (ret > 0);
	str[len] = '\0';
	out_printf (out, "%s", str);
	if (spp_pipe_fd) {
		pclose (spp_pipe_fd);
	}
	spp_pipe_fd = NULL;
	free (str);
#endif
	return 0;
}

static PUT_CALLBACK(spp_fputs) {
#if HAVE_SYSTEM
	if (spp_pipe_fd) {
		fprintf (spp_pipe_fd, "%s", buf);
	} else
#endif
	{
		out_printf (out, "%s", buf);
	}
	return 0;
}

static struct Tag spp_tags[] = {
	{ "get", spp_get },
	{ "hex", spp_hex },
	{ "getrandom", spp_getrandom },
	{ "grepline", spp_grepline },
	{ "set", spp_set },
	{ "add", spp_add },
	{ "sub", spp_sub },
	{ "switch", spp_switch },
	{ "case", spp_case },
	{ "endswitch", spp_endswitch },
	{ "echo", spp_echo },
	{ "error", spp_error },
	{ "warning", spp_warning },
	{ "trace", spp_trace },
	{ "ifin", spp_ifin },
	{ "ifnot", spp_ifnot },
	{ "ifeq", spp_ifeq },
	{ "if", spp_if },
	{ "else", spp_else },
	{ "endif", spp_endif },
	{ "pipe", spp_pipe },
	{ "endpipe", spp_endpipe },
	{ "include", spp_include },
	{ "system", spp_system },
	{ NULL, spp_default },
	{ NULL }
};

static ARG_CALLBACK(spp_arg_i) {
	r_sys_setenv ("SPP_INCDIR", arg);
	return 0;
}

static ARG_CALLBACK(spp_arg_d) {
	/* TODO: Handle error */
	char *eq = strchr (arg, '=');
	if (eq) {
		*eq = '\0';
		spp_var_set (arg, eq+1);
	} else {
		spp_var_set (arg, "");
	}
	return 0;
}

static struct Arg spp_args[] = {
	{ "-I", "add include directory", 1, spp_arg_i },
	{ "-D", "define value of variable", 1, spp_arg_d },
	{ NULL }
};

DLL_LOCAL struct Proc spp_proc = {
	.name = "spp",
	.tags = (struct Tag **)spp_tags,
	.args = (struct Arg **)spp_args,
	.token = " ",
	.eof = NULL,
	.tag_pre = "<{",
	.tag_post = "}>",
	.chop = 1,
	.fputs = spp_fputs,
	.multiline = NULL,
	.default_echo = 1,
	.tag_begin = 0,
};
