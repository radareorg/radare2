/* LGPLv2 - Tiny C Compiler - 2001-2004 fbellard, 2009-2024 pancake */

#include "tcc.h"

static void free_charptr(char **ptr) {
	free (*ptr);
}

R_VEC_TYPE_WITH_FINI (RVecCharPtr, char *, free_charptr);

#ifdef R2__WINDOWS__
// GCC appears to use '/' for relative paths and '\\' for absolute paths on Windows
static char *normalize_slashes(char *path) {
	char *p;
	if (path[1] == ':') {
		for (p = path + 2; *p; p++) {
			if (*p == '/') {
				*p = '\\';
			}
		}
	} else {
		for (p = path; *p; p++) {
			if (*p == '\\') {
				*p = '/';
			}
		}
	}
	return path;
}
#endif

/* strcat and truncate. */
R_API char *strcat2(char *buf, int buf_size, const char *s) {
	int len = strlen (buf);
	if (len < buf_size) {
		r_str_ncpy (buf + len, s, buf_size - len);
	}
	return buf;
}

/* extract the basename of a file */
R_API char *tcc_basename(const char *name) {
	char *p = strchr (name, 0);
	while (p && p > name && !IS_DIRSEP (p[-1])) {
		p--;
	}
	return p;
}

/* extract extension part of a file / (if no extension, return pointer to end-of-string) */
R_API char *tcc_fileextension(const char *name) {
	char *b = tcc_basename (name);
	char *e = strrchr (b, '.');
	return e? e: strchr (b, 0);
}

/* dynarrays */
ST_FUNC void dynarray_add(void ***ptab, int *nb_ptr, void *data) {
	int nb_alloc;
	int nb = *nb_ptr;
	void **pp = *ptab;
	/* every power of two we double array size */
	if ((nb & (nb - 1)) == 0) {
		if (!nb) {
			nb_alloc = 1;
		} else {
			nb_alloc = nb * 2;
		}
		pp = realloc (pp, nb_alloc * sizeof (void *));
		*ptab = pp;
	}
	pp[nb++] = data;
	*nb_ptr = nb;
}

ST_FUNC void dynarray_reset(void *pp, int *n) {
	void **p;
	for (p = *(void ***) pp; *n; p++, --*n) {
		if (*p) {
			free (*p);
		}
	}
	free (*(void **) pp);
	*(void **) pp = NULL;
}

static void tcc_split_path(TCCState *s, void ***p_ary, int *p_nb_ary, const char *in) {
	const char *p;
	do {
		int c;
		CString str;

		cstr_new (&str);
		for (p = in; c = *p, c != '\0' && c != *R_SYS_ENVSEP; p++) {
			if (c == '{' && p[1] && p[2] == '}') {
				c = p[1], p += 2;
				if (c == 'B') {
					cstr_cat (&str, s->tcc_lib_path);
				}
			} else {
				cstr_ccat (&str, c);
			}
		}
		cstr_ccat (&str, '\0');
		dynarray_add (p_ary, p_nb_ary, str.data);
		in = p + 1;
	} while (*p);
}

static void strcat_vprintf(char *buf, int buf_size, const char *fmt, va_list ap) {
	size_t len = strlen (buf);
	vsnprintf (buf + len, buf_size - len, fmt, ap);
}

R_API void strcat_printf(char *buf, int buf_size, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	strcat_vprintf (buf, buf_size, fmt, ap);
	va_end (ap);
}

static void error1(TCCState *s1, int is_warning, const char *fmt, va_list ap) {
	char buf[2048];
	BufferedFile **pf, *f;

	buf[0] = '\0';
	/* use upper file if inline ":asm:" or token ":paste:" */
	for (f = s1->file; f && f->filename[0] == ':'; f = f->prev) {
		;
	}
	if (f) {
		for (pf = s1->include_stack; pf < s1->include_stack_ptr; pf++) {
			strcat_printf (buf, sizeof (buf), "In file included from %s:%d:\n",
				(*pf)->filename, (*pf)->line_num);
		}
		if (f->line_num > 0) {
			strcat_printf (buf, sizeof (buf), "%s:%d: ",
				f->filename, f->line_num);
		} else {
			strcat_printf (buf, sizeof (buf), "%s: ",
				f->filename);
		}
	} else {
		strcat_printf (buf, sizeof (buf), "tcc: ");
	}
	if (is_warning) {
		strcat_printf (buf, sizeof (buf), "warning: ");
	} else {
		strcat_printf (buf, sizeof (buf), "error: ");
	}
	strcat_vprintf (buf, sizeof (buf), fmt, ap);
	if (!s1->error_func) {
		/* default case */
		eprintf ("%s\n", buf);
	} else {
		s1->error_func (s1->error_opaque, buf);
	}
	if (!is_warning || s1->warn_error) {
		s1->nb_errors++;
	}
}

R_API void tcc_set_error_func(TCCState *s, void *error_opaque, TccErrorCallback error_func) {
	s->error_opaque = error_opaque;
	s->error_func = error_func;
}

/* error without aborting current compilation */
R_API void tcc_error(TCCState *s1, const char *fmt, ...) {
	va_list ap;

	va_start (ap, fmt);
	error1 (s1, 0, fmt, ap);
	va_end (ap);
}

R_API void tcc_warning(TCCState *s1, const char *fmt, ...) {
	va_list ap;

	if (s1->warn_none) {
		return;
	}

	va_start (ap, fmt);
	error1 (s1, 1, fmt, ap);
	va_end (ap);
}

/* I/O layer */
ST_FUNC bool tcc_open_bf(TCCState *s1, const char *filename, int initlen) {
	const int buflen = initlen? initlen: IO_BUF_SIZE;
	BufferedFile *bf = malloc (sizeof (BufferedFile) + buflen);
	if (!bf) {
		R_LOG_ERROR ("too large buflen");
		return false;
	}
	bf->buf_ptr = bf->buffer;
	bf->buf_end = bf->buffer + initlen;
	bf->buf_end[0] = CH_EOB;/* put eob symbol */
	r_str_ncpy (bf->filename, filename, sizeof (bf->filename));
#ifdef R2__WINDOWS__
	normalize_slashes (bf->filename);
#endif
	bf->line_num = 1;
	bf->ifndef_macro = 0;
	bf->ifdef_stack_ptr = s1->ifdef_stack_ptr;
	bf->fd = -1;
	bf->prev = s1->file;
	s1->file = bf;
	return true;
}

ST_FUNC void tcc_close(TCCState *s1) {
	BufferedFile *bf = s1->file;
	if (bf->fd > 0) {
		close (bf->fd);
		s1->total_lines += bf->line_num;
	}
	s1->file = bf->prev;
	free (bf);
}

ST_FUNC int tcc_open(TCCState *s1, const char *filename) {
	int fd;
	if (!strcmp (filename, "-")) {
		filename = "stdin";
		fd = 0;
	} else {
		fd = open (filename, O_RDONLY | O_BINARY);
	}
	if ((s1->verbose == 2 && fd >= 0) || s1->verbose == 3) {
		printf ("%s %*s%s\n", fd < 0? "nf": "->",
			(int) (s1->include_stack_ptr - s1->include_stack), "", filename);
	}
	if (fd < 0) {
		return -1;
	}
	tcc_open_bf (s1, filename, 0);
	s1->file->fd = fd;
	return fd;
}

/* compile the C file opened in 'file'. Return non zero if errors. */
static int tcc_compile(TCCState *s1) {
	preprocess_init (s1);
	// define some often used types
	s1->funcname = "";
	s1->int8_type.t = VT_INT8;
	s1->int16_type.t = VT_INT16;
	s1->int32_type.t = VT_INT32;
	s1->int64_type.t = VT_INT64;
	s1->char_pointer_type.t = VT_INT8;
	mk_pointer (s1, &s1->char_pointer_type);
	if (s1->bits == 64) {
		s1->size_type.t = VT_INT64;
	} else {
		s1->size_type.t = VT_INT32;
	}
	s1->func_old_type.t = VT_FUNC;
	s1->func_old_type.ref = sym_push (s1, SYM_FIELD, &s1->int32_type, FUNC_CDECL, FUNC_OLD);
	Sym *define_start = s1->define_stack;
	s1->nocode_wanted = true;
	s1->nb_errors = 0;
	s1->error_set_jmp_enabled = true;
	s1->ch = s1->file->buf_ptr[0];
	s1->tok_flags = TOK_FLAG_BOL | TOK_FLAG_BOF;
	s1->parse_flags = PARSE_FLAG_PREPROCESS | PARSE_FLAG_TOK_NUM;
	// parse_flags = PARSE_FLAG_TOK_NUM;
	// pvtop = vtop;
	next (s1);
	tcc_decl0 (s1, VT_CONST, 0);
	if (s1->tok != TOK_EOF) {
		expect (s1, "declaration");
	}
	s1->error_set_jmp_enabled = false;

	/* reset define stack, but leave -Dsymbols (may be incorrect if they are undefined) */
	free_defines (s1, define_start);

	sym_pop (s1, &s1->global_stack, NULL);
	sym_pop (s1, &s1->local_stack, NULL);

	return s1->nb_errors != 0? -1: 0;
}

R_API int tcc_compile_string(TCCState *s1, const char *str) {
	int len = strlen (str);
	if (!tcc_open_bf (s1, "<string>", len)) {
		return false;
	}
	memcpy (s1->file->buffer, str, len);
	int ret = tcc_compile (s1);
	tcc_close (s1);
	return ret;
}

/* define a preprocessor symbol. A value can also be provided with the '=' operator */
R_API void tcc_define_symbol(TCCState *s1, const char *sym, const char *value) {
	/* default value */
	if (!value) {
		value = "1";
	}
	int len1 = strlen (sym);
	int len2 = strlen (value);

	/* init file structure */
	tcc_open_bf (s1, "<define>", len1 + len2 + 1);
	memcpy (s1->file->buffer, sym, len1);
	s1->file->buffer[len1] = ' ';
	memcpy (s1->file->buffer + len1 + 1, value, len2);

	/* parse with define parser */
	s1->ch = s1->file->buf_ptr[0];
	next_nomacro (s1);
	tcc_parse_define (s1);

	tcc_close (s1);
}

/* undefine a preprocessor symbol */
R_API void tcc_undefine_symbol(TCCState *s1, const char *sym) {
	TokenSym *ts = tok_alloc (s1, sym, strlen (sym));
	Sym *s = define_find (s1, ts->tok);
	/* undefine symbol by putting an invalid name */
	if (s) {
		define_undef (s1, s);
	}
}

/* cleanup all static data used during compilation */
static void tcc_cleanup(TCCState *s1) {
	int i, n;

	/* free -D defines */
	free_defines (s1, NULL);

	/* free tokens */
	n = s1->tok_ident - TOK_IDENT;
	for (i = 0; i < n; i++) {
		free (s1->table_ident[i]);
	}
	R_FREE (s1->table_ident);

	/* free sym_pools */
	dynarray_reset (&s1->sym_pools, &s1->nb_sym_pools);
	/* string buffer */
	cstr_free (&s1->tokcstr);
	/* reset symbol stack */
	s1->sym_free_first = NULL;
	/* cleanup from error/setjmp */
	s1->macro_ptr = NULL;
}

static void tcc_init_defines(TCCState *s) {
	char buffer[100];
	const char *arch = s->arch;
	const int bits = s->bits;
	const char *os = s->os;
	int a = 0, b = 0, c = 0;
	/* we add dummy defines for some special macros to speed up tests and to have working defined() */
	define_push (s, TOK___LINE__, MACRO_OBJ, NULL, NULL);
	define_push (s, TOK___FILE__, MACRO_OBJ, NULL, NULL);

	/* define __TINYC__ 92X  */
	sscanf (TCC_VERSION, "%d.%d.%d", &a, &b, &c);
	snprintf (buffer, sizeof (buffer), "%d", a * 10000 + b * 100 + c);
	tcc_define_symbol (s, "__TINYC__", buffer);
	tcc_define_symbol (s, "__R2TINYC__", buffer);

	// r2 specific defines
	tcc_define_symbol (s, "R_API", "");
	tcc_define_symbol (s, "R_IPI", "");
	tcc_define_symbol (s, "R_NULLABLE", "");
	tcc_define_symbol (s, "R_PRINTF_CHECK(a,b)", "");

	/* standard defines */
	tcc_define_symbol (s, "__STDC__", NULL);
	tcc_define_symbol (s, "__STDC_VERSION__", "199901L");
	tcc_define_symbol (s, "__STDC_HOSTED__", NULL);

	/* type defines */
	tcc_define_symbol (s, "ut8", "uint8_t");
	tcc_define_symbol (s, "ut16", "uint16_t");
	tcc_define_symbol (s, "ut32", "uint32_t");
	tcc_define_symbol (s, "ut64", "uint64_t");
	if (bits == 64) {
		tcc_define_symbol (s, "size_t", "uint64_t");
	} else {
		tcc_define_symbol (s, "size_t", "uint32_t");
	}

	tcc_define_symbol (s, "st8", "int8_t");
	tcc_define_symbol (s, "st16", "int16_t");
	tcc_define_symbol (s, "st32", "int32_t");
	tcc_define_symbol (s, "st64", "int64_t");

	/* target defines */
	if (r_str_startswith (arch, "x86")) {
		if (bits == 32 || bits == 16) {
			tcc_define_symbol (s, "__i386__", NULL);
			tcc_define_symbol (s, "__i386", NULL);
			tcc_define_symbol (s, "i386", NULL);
		} else {
			tcc_define_symbol (s, "__x86_64__", NULL);
		}
	} else if (r_str_startswith (arch, "arm")) {
		tcc_define_symbol (s, "__ARM_ARCH_4__", NULL);
		tcc_define_symbol (s, "__arm_elf__", NULL);
		tcc_define_symbol (s, "__arm_elf", NULL);
		tcc_define_symbol (s, "arm_elf", NULL);
		tcc_define_symbol (s, "__arm__", NULL);
		tcc_define_symbol (s, "__arm", NULL);
		tcc_define_symbol (s, "arm", NULL);
		tcc_define_symbol (s, "__APCS_32__", NULL);
	}
	// TODO: Add other architectures
	// TODO: Move that in SDB

	if (r_str_startswith (os, "windows")) {
		tcc_define_symbol (s, "__WCHAR_TYPE__", "unsigned short");
		tcc_define_symbol (s, "R2__WINDOWS__", NULL);
		if (bits == 64) {
			tcc_define_symbol (s, "_WIN64", NULL);
			tcc_define_symbol (s, "__SIZE_TYPE__", "unsigned long long");
			tcc_define_symbol (s, "__PTRDIFF_TYPE__", "long long");
		} else {
			tcc_define_symbol (s, "__SIZE_TYPE__", "unsigned long");
			tcc_define_symbol (s, "__PTRDIFF_TYPE__", "long");
		}
	} else {
		tcc_define_symbol (s, "__WCHAR_TYPE__", "int");
		/* glibc defines */
		tcc_define_symbol (s, "__REDIRECT(name, proto, alias)", "name proto __asm__(#alias)");
		tcc_define_symbol (s, "__REDIRECT_NTH(name, proto, alias)", "name proto __asm__(#alias) __THROW");

		tcc_define_symbol (s, "R2__UNIX__", NULL);
		tcc_define_symbol (s, "__unix__", NULL);
		tcc_define_symbol (s, "__unix", NULL);
		tcc_define_symbol (s, "unix", NULL);

		if (r_str_startswith (os, "linux")) {
			tcc_define_symbol (s, "__linux__", NULL);
			tcc_define_symbol (s, "__linux", NULL);
		}
#define str(s) #s
		if (r_str_startswith (os, "freebsd")) {
			tcc_define_symbol (s, "__FreeBSD__", str (__FreeBSD__));
		}
#undef str
	}
}

R_API TCCState *tcc_new(const char *arch, int bits, const char *os) {
	if (!arch || !os) {
		return NULL;
	}
	// tcc_cleanup (NULL); // wtf no globals anymore
	TCCState *s = R_NEW0 (TCCState);
	if (s) {
		s->arch = strdup (arch);
		s->bits = bits;
		s->os = strdup (os);
		s->anon_sym = SYM_FIRST_ANOM;
		s->output_type = TCC_OUTPUT_MEMORY;
		preprocess_new (s);
		s->include_stack_ptr = s->include_stack;
	}
	return s;
}

// TODO: rename to tcc_free
R_API void tcc_delete(TCCState *s1) {
	tcc_cleanup (s1);

	/* free include paths */
	dynarray_reset (&s1->cached_includes, &s1->nb_cached_includes);
	dynarray_reset (&s1->include_paths, &s1->nb_include_paths);
	dynarray_reset (&s1->sysinclude_paths, &s1->nb_sysinclude_paths);

	free (s1->tcc_lib_path);
	free (s1->deps_outfile);
	dynarray_reset (&s1->target_deps, &s1->nb_target_deps);

	/* target config */
	free (s1->arch);
	free (s1->os);
	free (s1);
}

R_API int tcc_add_include_path(TCCState *s, const char *pathname) {
	tcc_split_path (s, (void ***) &s->include_paths, &s->nb_include_paths, pathname);
	return 0;
}

R_API int tcc_add_sysinclude_path(TCCState *s, const char *pathname) {
	tcc_split_path (s, (void ***) &s->sysinclude_paths, &s->nb_sysinclude_paths, pathname);
	return 0;
}

ST_FUNC int tcc_add_file_internal(TCCState *s1, const char *filename, int flags) {
	/* find source file type with extension */
	const char *ext = tcc_fileextension (filename);
	if (ext[0]) {
		ext++;
	}

	/* open the file */
	int ret = tcc_open (s1, filename);
	if (ret < 0) {
		if (flags & AFF_PRINT_ERROR) {
			eprintf ("file '%s' not found\n", filename);
		}
		return ret;
	}

	/* update target deps */
	dynarray_add ((void ***) &s1->target_deps, &s1->nb_target_deps, strdup (filename));

	if (flags & AFF_PREPROCESS) {
		ret = tcc_preprocess (s1);
		goto the_end;
	}

	if (!ext[0] || !PATHCMP (ext, "c") || !PATHCMP (ext, "h") || !PATHCMP (ext, "cparse")) {
		/* C file assumed */
		ret = tcc_compile (s1);
		goto the_end;
	}
	if (ret < 0) {
		tcc_error (s1, "unrecognized file type");
	}

the_end:
	tcc_close (s1);
	return ret;
}

R_API int tcc_add_file(TCCState *s1, const char *filename, const char *directory) {
	if (directory) {
		free (s1->dir_name);
		s1->dir_name = strdup (directory);
	}

	int flags = AFF_PRINT_ERROR;
	if (s1->output_type == TCC_OUTPUT_PREPROCESS) {
		flags |= AFF_PREPROCESS;
	}
	return tcc_add_file_internal (s1, filename, flags);
}

R_API void tcc_set_callback(TCCState *s, TccCallback cb, char **p) {
	if (cb) {
		s->cb = cb;
		s->cb_user_data = p;
		tcc_init_defines (s);
	}
}

R_API void tcc_appendf(TCCState *s, const char *fmt, ...) {
	char b[1024];
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (b, sizeof (b), fmt, ap);
	if (s->cb) {
		s->cb (b, s->cb_user_data);
	} else {
		// eprintf ("Missing callback for tcc_cb\n");
	}
	va_end (ap);
}

R_API void tcc_typedef_appendf(TCCState *s, const char *fmt, ...) {
	if (!s->typedefs) {
		s->typedefs = RVecCharPtr_new ();
	}
	char typedefs_tail[1024];
	va_list ap;
	va_start (ap, fmt);
	if (vsnprintf (typedefs_tail, sizeof (typedefs_tail), fmt, ap) > 0) {
		char *value = strdup (typedefs_tail);
		if (value) {
			RVecCharPtr_push_back (s->typedefs, &value);
		}
	} // XXX else? how this should behave if sizeof (typedefs_tail) is not enough?
	va_end (ap);
}

R_API void tcc_typedef_alias_fields(TCCState *s, const char *alias) {
	if (s->typedefs) {
		char **it;
		R_VEC_FOREACH (s->typedefs, it) {
			tcc_appendf (s, *it, alias);
		}
		RVecCharPtr_free (s->typedefs);
		s->typedefs = NULL;
	}
}
