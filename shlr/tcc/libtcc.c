/*
 *  TCC - Tiny C Compiler
 *
 *  Copyright (c) 2001-2004 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <r_util.h>
#include "tcc.h"

/********************************************************/
/* global variables */
ST_DATA RPVector *tcc_typedefs;

/* use GNU C extensions */
ST_DATA int gnu_ext = 1;

/* use TinyCC extensions */
ST_DATA int tcc_ext = 1;

/* XXX: get rid of this ASAP */
ST_DATA struct TCCState *tcc_state;

/********************************************************/

#ifdef __WINDOWS__
// GCC appears to use '/' for relative paths and '\\' for absolute paths on Windows
static char *normalize_slashes(char *path)
{
	char *p;
	if (path[1] == ':') {
		for (p = path + 2; *p; ++p) {
			if (*p == '/') {
				*p = '\\';
			}
		}
	} else {
		for (p = path; *p; ++p) {
			if (*p == '\\') {
				*p = '/';
			}
		}
	}
	return path;
}
#endif

/********************************************************/
/* copy a string and truncate it. */
PUB_FUNC char *pstrcpy(char *buf, int buf_size, const char *s)
{
	char *q, *q_end;
	int c;

	if (buf_size > 0) {
		q = buf;
		q_end = buf + buf_size - 1;
		while (q < q_end) {
			c = *s++;
			if (c == '\0') {
				break;
			}
			*q++ = c;
		}
		*q = '\0';
	}
	return buf;
}

/* strcat and truncate. */
PUB_FUNC char *pstrcat(char *buf, int buf_size, const char *s)
{
	int len;
	len = strlen (buf);
	if (len < buf_size) {
		pstrcpy (buf + len, buf_size - len, s);
	}
	return buf;
}

PUB_FUNC char *pstrncpy(char *out, const char *in, size_t num)
{
	memcpy (out, in, num);
	out[num] = '\0';
	return out;
}

/* extract the basename of a file */
PUB_FUNC char *tcc_basename(const char *name)
{
	char *p = strchr (name, 0);
	while (p && p > name && !IS_DIRSEP (p[-1]))
		--p;
	return p;
}

/* extract extension part of a file
 *
 * (if no extension, return pointer to end-of-string)
 */
PUB_FUNC char *tcc_fileextension(const char *name)
{
	char *b = tcc_basename (name);
	char *e = strrchr (b, '.');
	return e? e: strchr (b, 0);
}

/********************************************************/
/* memory management */


PUB_FUNC void *tcc_mallocz(unsigned long size)
{
	void *ptr;
	ptr = malloc (size);
	memset (ptr, 0, size);
	return ptr;
}


PUB_FUNC void tcc_memstats(void)
{
#ifdef MEM_DEBUG
	printf ("memory: %d byte(s), max = %d byte(s)\n", mem_cur_size, mem_max_size);
#endif
}

/********************************************************/
/* dynarrays */

ST_FUNC void dynarray_add(void ***ptab, int *nb_ptr, void *data)
{
	int nb, nb_alloc;
	void **pp;

	nb = *nb_ptr;
	pp = *ptab;
	/* every power of two we double array size */
	if ((nb & (nb - 1)) == 0) {
		if (!nb) {
			nb_alloc = 1;
		} else {
			nb_alloc = nb * 2;
		}
		pp = realloc (pp, nb_alloc * sizeof(void *));
		*ptab = pp;
	}
	pp[nb++] = data;
	*nb_ptr = nb;
}

ST_FUNC void dynarray_reset(void *pp, int *n)
{
	void **p;
	for (p = *(void ***) pp; *n; ++p, --*n) {
		if (*p) {
			free (*p);
		}
	}
	free (*(void **) pp);
	*(void **) pp = NULL;
}

static void tcc_split_path(TCCState *s, void ***p_ary, int *p_nb_ary, const char *in)
{
	const char *p;
	do {
		int c;
		CString str;

		cstr_new (&str);
		for (p = in; c = *p, c != '\0' && c != PATHSEP; ++p) {
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

/********************************************************/

static void strcat_vprintf(char *buf, int buf_size, const char *fmt, va_list ap)
{
	int len;
	len = strlen (buf);
	vsnprintf (buf + len, buf_size - len, fmt, ap);
}

PUB_FUNC void strcat_printf(char *buf, int buf_size, const char *fmt, ...)
{
	va_list ap;
	va_start (ap, fmt);
	strcat_vprintf (buf, buf_size, fmt, ap);
	va_end (ap);
}

static void error1(TCCState *s1, int is_warning, const char *fmt, va_list ap)
{
	char buf[2048];
	BufferedFile **pf, *f;

	buf[0] = '\0';
	/* use upper file if inline ":asm:" or token ":paste:" */
	for (f = file; f && f->filename[0] == ':'; f = f->prev) {
		;
	}
	if (f) {
		for (pf = s1->include_stack; pf < s1->include_stack_ptr; pf++) {
			strcat_printf (buf, sizeof(buf), "In file included from %s:%d:\n",
				(*pf)->filename, (*pf)->line_num);
		}
		if (f->line_num > 0) {
			strcat_printf (buf, sizeof(buf), "%s:%d: ",
				f->filename, f->line_num);
		} else {
			strcat_printf (buf, sizeof(buf), "%s: ",
				f->filename);
		}
	} else {
		strcat_printf (buf, sizeof(buf), "tcc: ");
	}
	if (is_warning) {
		strcat_printf (buf, sizeof(buf), "warning: ");
	} else {
		strcat_printf (buf, sizeof(buf), "error: ");
	}
	strcat_vprintf (buf, sizeof(buf), fmt, ap);

	if (!s1->error_func) {
		/* default case: stderr */
		fprintf (stderr, "%s\n", buf);
	} else {
		s1->error_func (s1->error_opaque, buf);
	}
	if (!is_warning || s1->warn_error) {
		s1->nb_errors++;
	}
}

LIBTCCAPI void tcc_set_error_func(TCCState *s, void *error_opaque,
				  void (*error_func)(void *opaque, const char *msg))
{
	s->error_opaque = error_opaque;
	s->error_func = error_func;
}

/* error without aborting current compilation */
PUB_FUNC void tcc_error(const char *fmt, ...)
{
	TCCState *s1 = tcc_state;
	va_list ap;

	va_start (ap, fmt);
	error1 (s1, 0, fmt, ap);
	va_end (ap);
}

PUB_FUNC void tcc_warning(const char *fmt, ...)
{
	TCCState *s1 = tcc_state;
	va_list ap;

	if (s1->warn_none) {
		return;
	}

	va_start (ap, fmt);
	error1 (s1, 1, fmt, ap);
	va_end (ap);
}

/********************************************************/
/* I/O layer */

ST_FUNC void tcc_open_bf(TCCState *s1, const char *filename, int initlen)
{
	BufferedFile *bf;
	int buflen = initlen? initlen: IO_BUF_SIZE;

	bf = malloc (sizeof(BufferedFile) + buflen);
	bf->buf_ptr = bf->buffer;
	bf->buf_end = bf->buffer + initlen;
	bf->buf_end[0] = CH_EOB;/* put eob symbol */
	pstrcpy (bf->filename, sizeof(bf->filename), filename);
#ifdef __WINDOWS__
	normalize_slashes (bf->filename);
#endif
	bf->line_num = 1;
	bf->ifndef_macro = 0;
	bf->ifdef_stack_ptr = s1->ifdef_stack_ptr;
	bf->fd = -1;
	bf->prev = file;
	file = bf;
}

ST_FUNC void tcc_close(void)
{
	BufferedFile *bf = file;
	if (bf->fd > 0) {
		close (bf->fd);
		total_lines += bf->line_num;
	}
	file = bf->prev;
	free (bf);
}

ST_FUNC int tcc_open(TCCState *s1, const char *filename)
{
	int fd;
	if (strcmp (filename, "-") == 0) {
		fd = 0, filename = "stdin";
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
	file->fd = fd;
	return fd;
}

/* compile the C file opened in 'file'. Return non zero if errors. */
static int tcc_compile(TCCState *s1)
{
	Sym *define_start;

#ifdef INC_DEBUG
	printf ("%s: **** new file\n", file->filename);
#endif
	preprocess_init (s1);

	funcname = "";

	/* define some often used types */
	int8_type.t = VT_INT8;
	int16_type.t = VT_INT16;
	int32_type.t = VT_INT32;
	int64_type.t = VT_INT64;

	char_pointer_type.t = VT_INT8;
	mk_pointer (&char_pointer_type);

	if (tcc_state->bits != 64) {
		size_type.t = VT_INT32;
	} else {
		size_type.t = VT_INT64;
	}

	func_old_type.t = VT_FUNC;
	func_old_type.ref = sym_push (SYM_FIELD, &int32_type, FUNC_CDECL, FUNC_OLD);

// FIXME: Should depend on the target options too
#ifdef TCC_TARGET_ARM
	arm_init_types ();
#endif

#if 0
	/* define 'void *alloca(unsigned int)' builtin function */
	{
		Sym *s1;

		p = anon_sym++;
		sym = sym_push (p, mk_pointer (VT_VOID), FUNC_CDECL, FUNC_NEW);
		s1 = sym_push (SYM_FIELD, VT_UNSIGNED | VT_INT, 0, 0);
		s1->next = NULL;
		sym->next = s1;
		sym_push (TOK_alloca, VT_FUNC | (p << VT_STRUCT_SHIFT), VT_CONST, 0);
	}
#endif

	define_start = define_stack;
	nocode_wanted = 1;

	if (setjmp (s1->error_jmp_buf) == 0) {
		s1->nb_errors = 0;
		s1->error_set_jmp_enabled = 1;

		ch = file->buf_ptr[0];
		tok_flags = TOK_FLAG_BOL | TOK_FLAG_BOF;
		parse_flags = PARSE_FLAG_PREPROCESS | PARSE_FLAG_TOK_NUM;
		// pvtop = vtop;
		next ();
		decl (VT_CONST);
		if (tok != TOK_EOF) {
			expect ("declaration");
		}
#if 0
		if (pvtop != vtop) {
			fprintf (stderr, "internal compiler error:"
				" vstack leak? (%d)", vtop - pvtop);
		}
#endif
	}

	s1->error_set_jmp_enabled = 0;

	/* reset define stack, but leave -Dsymbols (may be incorrect if
	   they are undefined) */
	free_defines (define_start);

	sym_pop (&global_stack, NULL);
	sym_pop (&local_stack, NULL);

	return s1->nb_errors != 0? -1: 0;
}

LIBTCCAPI int tcc_compile_string(TCCState *s, const char *str)
{
	int len, ret;
	len = strlen (str);

	tcc_open_bf (s, "<string>", len);
	memcpy (file->buffer, str, len);
	ret = tcc_compile (s);
	tcc_close ();
	return ret;
}

/* define a preprocessor symbol. A value can also be provided with the '=' operator */
LIBTCCAPI void tcc_define_symbol(TCCState *s1, const char *sym, const char *value)
{
	int len1, len2;
	/* default value */
	if (!value) {
		value = "1";
	}
	len1 = strlen (sym);
	len2 = strlen (value);

	/* init file structure */
	tcc_open_bf (s1, "<define>", len1 + len2 + 1);
	memcpy (file->buffer, sym, len1);
	file->buffer[len1] = ' ';
	memcpy (file->buffer + len1 + 1, value, len2);

	/* parse with define parser */
	ch = file->buf_ptr[0];
	next_nomacro ();
	parse_define ();

	tcc_close ();
}

/* undefine a preprocessor symbol */
LIBTCCAPI void tcc_undefine_symbol(TCCState *s1, const char *sym)
{
	TokenSym *ts;
	Sym *s;
	ts = tok_alloc (sym, strlen (sym));
	s = define_find (ts->tok);
	/* undefine symbol by putting an invalid name */
	if (s) {
		define_undef (s);
	}
}

/* cleanup all static data used during compilation */
static void tcc_cleanup(void)
{
	int i, n;
	if (NULL == tcc_state) {
		return;
	}
	tcc_state = NULL;

	/* free -D defines */
	free_defines (NULL);

	/* free tokens */
	n = tok_ident - TOK_IDENT;
	for (i = 0; i < n; i++) {
		free (table_ident[i]);
	}
	free (table_ident);

	/* free sym_pools */
	dynarray_reset (&sym_pools, &nb_sym_pools);
	/* string buffer */
	cstr_free (&tokcstr);
	/* reset symbol stack */
	sym_free_first = NULL;
	/* cleanup from error/setjmp */
	macro_ptr = NULL;
}

LIBTCCAPI TCCState *tcc_new(const char *arch, int bits, const char *os)
{
	TCCState *s;
	char buffer[100];
	int a, b, c;

	if (!arch || !os) {
		return NULL;
	}
	tcc_cleanup ();
	s = tcc_mallocz (sizeof(TCCState));
	if (!s) {
		return NULL;
	}
	tcc_state = s;
	s->arch = strdup (arch);
	s->bits = bits;
	s->os = strdup (os);
	s->output_type = TCC_OUTPUT_MEMORY;
	preprocess_new ();
	s->include_stack_ptr = s->include_stack;

	/* we add dummy defines for some special macros to speed up tests
	   and to have working defined() */
	define_push (TOK___LINE__, MACRO_OBJ, NULL, NULL);
	define_push (TOK___FILE__, MACRO_OBJ, NULL, NULL);
	define_push (TOK___DATE__, MACRO_OBJ, NULL, NULL);
	define_push (TOK___TIME__, MACRO_OBJ, NULL, NULL);

	/* define __TINYC__ 92X  */
	sscanf (TCC_VERSION, "%d.%d.%d", &a, &b, &c);
	sprintf (buffer, "%d", a * 10000 + b * 100 + c);
	tcc_define_symbol (s, "__TINYC__", buffer);
	tcc_define_symbol (s, "__R2TINYC__", buffer);

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
	if (!strncmp (arch, "x86", 3)) {
		if (bits == 32 || bits == 16) {
			tcc_define_symbol (s, "__i386__", NULL);
			tcc_define_symbol (s, "__i386", NULL);
			tcc_define_symbol (s, "i386", NULL);
		} else {
			tcc_define_symbol (s, "__x86_64__", NULL);
		}
	} else if (!strncmp (arch, "arm", 3)) {
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

	if (!strncmp (os, "windows", 7)) {
		tcc_define_symbol (s, "__WINDOWS__", NULL);
		if (bits == 64) {
			tcc_define_symbol (s, "_WIN64", NULL);
		}
	} else {
		tcc_define_symbol (s, "__unix__", NULL);
		tcc_define_symbol (s, "__unix", NULL);
		tcc_define_symbol (s, "unix", NULL);

		if (!strncmp (os, "linux", 5)) {
			tcc_define_symbol (s, "__linux__", NULL);
			tcc_define_symbol (s, "__linux", NULL);
		}
#define str(s) #s
		if (!strncmp (os, "freebsd", 7)) {
			tcc_define_symbol (s, "__FreeBSD__", str ( __FreeBSD__));
		}
#undef str
	}

	/* TinyCC & gcc defines */
	if (!strncmp (os, "windows", 7) && (bits == 64)) {
		tcc_define_symbol (s, "__SIZE_TYPE__", "unsigned long long");
		tcc_define_symbol (s, "__PTRDIFF_TYPE__", "long long");
	} else {
		tcc_define_symbol (s, "__SIZE_TYPE__", "unsigned long");
		tcc_define_symbol (s, "__PTRDIFF_TYPE__", "long");
	}

	if (!strncmp (os, "windows", 7)) {
		tcc_define_symbol (s, "__WCHAR_TYPE__", "unsigned short");
	} else {
		tcc_define_symbol (s, "__WCHAR_TYPE__", "int");
		/* glibc defines */
		tcc_define_symbol (s, "__REDIRECT(name, proto, alias)", "name proto __asm__(#alias)");
		tcc_define_symbol (s, "__REDIRECT_NTH(name, proto, alias)", "name proto __asm__(#alias) __THROW");
	}

	s->alacarte_link = 1;
	s->nocommon = 1;

#ifdef CHAR_IS_UNSIGNED
	s->char_is_unsigned = 1;
#endif
	/* enable this if you want symbols with leading underscore on windows: */
#if 0	/* def TCC_TARGET_PE */
	s->leading_underscore = 1;
#endif
	if (!strncmp (arch, "x86", 3)) {
		// TODO: Set it to 16 for 16bit x86
		if (bits == 32 || bits == 16) {
			s->seg_size = 32;
		}
	}
	return s;
}

LIBTCCAPI void tcc_delete(TCCState *s1)
{
	tcc_cleanup ();

	/* free library paths */
	dynarray_reset (&s1->library_paths, &s1->nb_library_paths);
	dynarray_reset (&s1->crt_paths, &s1->nb_crt_paths);

	/* free include paths */
	dynarray_reset (&s1->cached_includes, &s1->nb_cached_includes);
	dynarray_reset (&s1->include_paths, &s1->nb_include_paths);
	dynarray_reset (&s1->sysinclude_paths, &s1->nb_sysinclude_paths);

	free (s1->tcc_lib_path);
	free (s1->soname);
	free (s1->rpath);
	free (s1->init_symbol);
	free (s1->fini_symbol);
	free (s1->outfile);
	free (s1->deps_outfile);
	dynarray_reset (&s1->files, &s1->nb_files);
	dynarray_reset (&s1->target_deps, &s1->nb_target_deps);

	/* target config */
	free (s1->arch);
	free (s1->os);

#ifdef TCC_IS_NATIVE
#ifdef HAVE_SELINUX
	munmap (s1->write_mem, s1->mem_size);
	munmap (s1->runtime_mem, s1->mem_size);
#else
	free (s1->runtime_mem);
#endif
#endif

	free (s1);
}

LIBTCCAPI int tcc_add_include_path(TCCState *s, const char *pathname)
{
	tcc_split_path (s, (void ***) &s->include_paths, &s->nb_include_paths, pathname);
	return 0;
}

LIBTCCAPI int tcc_add_sysinclude_path(TCCState *s, const char *pathname)
{
	tcc_split_path (s, (void ***) &s->sysinclude_paths, &s->nb_sysinclude_paths, pathname);
	return 0;
}

ST_FUNC int tcc_add_file_internal(TCCState *s1, const char *filename, int flags)
{
	const char *ext;
	int ret;

	/* find source file type with extension */
	ext = tcc_fileextension (filename);
	if (ext[0]) {
		ext++;
	}

	/* open the file */
	ret = tcc_open (s1, filename);
	if (ret < 0) {
		if (flags & AFF_PRINT_ERROR) {
			tcc_error ("file '%s' not found", filename);
		}
		return ret;
	}

	/* update target deps */
	dynarray_add ((void ***) &s1->target_deps, &s1->nb_target_deps,
		strdup (filename));

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
		tcc_error ("unrecognized file type");
	}

the_end:
	tcc_close ();
	return ret;
}

LIBTCCAPI int tcc_add_file(TCCState *s, const char *filename, const char *directory)
{
	if (directory) {
		dir_name = strdup (directory);
	}

	if (s->output_type == TCC_OUTPUT_PREPROCESS) {
		return tcc_add_file_internal (s, filename, AFF_PRINT_ERROR | AFF_PREPROCESS);
	} else {
		return tcc_add_file_internal (s, filename, AFF_PRINT_ERROR);
	}
}

#define WD_ALL    0x0001/* warning is activated when using -Wall */
#define FD_INVERT 0x0002/* invert value before storing */

typedef struct FlagDef {
	uint16_t offset;
	uint16_t flags;
	const char *name;
} FlagDef;

ST_FUNC int set_flag(TCCState *s, const FlagDef *flags, int nb_flags,
		     const char *name, int value)
{
	int i;
	const FlagDef *p;
	const char *r;

	r = name;
	if (r[0] == 'n' && r[1] == 'o' && r[2] == '-') {
		r += 3;
		value = !value;
	}
	for (i = 0, p = flags; i < nb_flags; i++, p++) {
		if (!strcmp (r, p->name)) {
			goto found;
		}
	}
	return -1;
found:
	if (p->flags & FD_INVERT) {
		value = !value;
	}
	*(int *) ((uint8_t *) s + p->offset) = value;
	return 0;
}

void (*tcc_cb)(const char *, char **);

PUB_FUNC void tcc_set_callback(TCCState *s, void (*cb)(const char *, char **), char **p) {
	tcc_cb = cb;
	tcc_cb_ptr = p;
}

PUB_FUNC void tcc_appendf(const char *fmt, ...) {
	char b[1024];
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (b, sizeof (b), fmt, ap);
	tcc_cb (b, tcc_cb_ptr);
	va_end (ap);
}

PUB_FUNC void tcc_typedef_appendf(const char *fmt, ...) {
	if (!tcc_typedefs) {
		tcc_typedefs = r_pvector_new ((RPVectorFree) free);
	}
	char typedefs_tail[1024];
	va_list ap;
	va_start (ap, fmt);
	if (vsnprintf (typedefs_tail, sizeof (typedefs_tail), fmt, ap) > 0) {
		r_pvector_push (tcc_typedefs, strdup (typedefs_tail));
	} // XXX else? how this should behave if sizeof (typedefs_tail) is not enough?
	va_end (ap);
}

PUB_FUNC void tcc_typedef_alias_fields(const char *alias) {
	if (tcc_typedefs) {
		void **it;
		r_pvector_foreach (tcc_typedefs, it) {
			tcc_appendf (*it, alias);
		}
		r_pvector_free (tcc_typedefs);
		tcc_typedefs = NULL;
	}
}
