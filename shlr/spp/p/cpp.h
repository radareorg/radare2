/* CPP */

static TAG_CALLBACK(cpp_default) {
	out_printf (out, "DEFAULT: (%s)\n", buf);
	return 0;
}

static TAG_CALLBACK(cpp_error) {
	out_printf (out, "\n");
	if (state->echo[state->ifl] && buf) {
		out_printf (out, "ERROR: %s (line=%d)\n", buf, state->lineno);
		return -1;
	}
	return 0;
}

static TAG_CALLBACK(cpp_warning) {
	out_printf (out,"\n");
	if (state->echo[state->ifl] && buf != NULL) {
		out_printf (out, "WARNING: line %d: %s\n", state->lineno, buf);
	}
	return 0;
}

static TAG_CALLBACK(cpp_if) {
	char *var = getenv (buf + ((*buf == '!') ? 1 : 0));
	if (var && *var == '1') {
		state->echo[state->ifl + 1] = 1;
	} else {
		state->echo[state->ifl + 1] = 0;
	}
	if (*buf == '!') {
		state->echo[state->ifl + 1] = !!!state->echo[state->ifl + 1];
	}
	return 1;
}

static TAG_CALLBACK(cpp_ifdef) {
	char *var = getenv (buf);
	state->echo[state->ifl + 1] = var? 1: 0;
	return 1;
}

static TAG_CALLBACK(cpp_else) {
	state->echo[state->ifl] = state->echo[state->ifl]? 0: 1;
	return 0;
}

static TAG_CALLBACK(cpp_ifndef) {
	cpp_ifdef (state, out, buf);
	cpp_else (state, out, buf);
	return 1;
}

static struct cpp_macro_t {
	char *name;
	char *args;
	char *body;
} cpp_macros[10];

static int cpp_macros_n = 0;

static void cpp_macro_add(char *name, char *args, char *body) {
	char *ptr;
	cpp_macros[cpp_macros_n].args = strdup(args);
	cpp_macros[cpp_macros_n].body = strdup(body);
	ptr = strchr (name, '(');
	if (ptr) {
		ptr[1] = '\0';
	}
	cpp_macros[cpp_macros_n].name = strdup(name);
	cpp_macros_n++;
}

static PUT_CALLBACK(cpp_fputs) {
	int i;
	for (i = 0; i < cpp_macros_n; i++) {
		if (strstr(buf, cpp_macros[i].name)) {
			fprintf (stderr, "MACRO (%s) HIT\n",
				cpp_macros[i].name);
		}
	}
	out_printf (out, "%s", buf);
	return 0;
}

static TAG_CALLBACK(cpp_define) {
	char *eq = strchr (buf, ' ');
	if (eq) {
		char *ptr = eq + 1;
		char *macro = strchr(buf, '(');
		*eq = '\0';
		if (macro) {
			/*macro[0]='\0'; */
			ptr = strchr (macro + 1, ')');
			if (!ptr) {
				fprintf(stderr, "Invalid syntax\n");
				return 1;
			}
			ptr = ptr + 1;
			fprintf(stderr, "REGISTER MACRO:\n");
			fprintf(stderr, "  name: %s\n", buf);
			fprintf(stderr, "  args: %s\n", macro);
			fprintf(stderr, "  body: %s\n", ptr+1);
			cpp_macro_add(buf,macro,ptr+1);
			/* TODO: Name is "BUF(". for funny strstr */
		}
		r_sys_setenv (buf, ptr);
	} else r_sys_setenv (buf, "");
	return 0;
}

static TAG_CALLBACK(cpp_endif) {
	return -1;
}

static TAG_CALLBACK(cpp_include) {
	if (state->echo[state->ifl]) {
		spp_file (buf, out);
	}
	return 0;
}

DLL_LOCAL struct Tag cpp_tags[] = {
	{ "ifdef", cpp_ifdef },
	{ "ifndef", cpp_ifndef },
	{ "endif", cpp_endif },
	{ "if", cpp_if },
	{ "else", cpp_else },
	{ "include", cpp_include },
	{ "define", cpp_define },
	{ "error", cpp_error },
	{ "warning", cpp_warning },
	{ NULL, cpp_default },
	{ NULL }
};

/* arguments */

static ARG_CALLBACK(cpp_arg_i) {
	printf("INCLUDEDIR(%s)\n", arg);
	return 0;
}

static ARG_CALLBACK(cpp_arg_d) {
	// TODO: handle r_sys_setenv==-1
	char *eq = strchr(arg, '=');
	if (eq) {
		*eq = '\0';
		r_sys_setenv (arg, eq + 1);
	} else {
		r_sys_setenv (arg, "");
	}
	return 0;
}

static struct Arg cpp_args[] = {
	{ "-I", "add include directory", 1, cpp_arg_i },
	{ "-D", "define value of variable", 1, cpp_arg_d },
	{ NULL }
};

DLL_LOCAL struct Proc cpp_proc = {
	.name = "cpp",
	.tags = (struct Tag **)cpp_tags,
	.args = (struct Arg **)cpp_args,
	.token = " ",
	.eof = NULL,
	.tag_pre = "#",
	.tag_post = "\n",
	.multiline = "\\\n",
	.default_echo = 1,
	.fputs = cpp_fputs,
	.chop = 0,
	.tag_begin = 1,
};
