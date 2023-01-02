/* sdb - MIT - Copyright 2020-2022 - pancake, thestr4ng3r */

#include "sdb/sdb.h"

#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#if USE_MMAN
#include <sys/mman.h>
#endif

/**
 * ********************
 * Plaintext SDB Format
 * ********************
 *
 * Files are UTF-8 and use '\n' line endings. Always.
 * 
 * Lines starting with '/' denote the path of the namespace for the following data:
 *
 *   /some/namespace
 * 
 * The default path is root, just a slash also means root.
 * These paths are always absolute from the root. Characters that must be escaped in a path are: '/', '\\', '\n', '\r':
 *
 *   /s\/ome/name\nspa\\ce
 *
 * SDB entries are written each as a single k=v line:
 *
 *   somekey=somevalue
 *
 * To distinguish these from path lines, if there is a leading '/' in the key, it must be escaped
 * (slashes later in the line don't have to be escaped):
 *
 *   \/slashedkey=somevalue
 *
 * Other than that, at any postion, '\\', '\n' and '\r' must be escaped:
 *   
 *   some\\key=some\nvalue
 *
 * In the key, '=' must also be escaped (not necessary in the value):
 *
 *   some\=key=some=value
 * 
 * --------
 * Example:
 *
 *   /
 *   key=intheroot
 *   \/slashedkey=somevalue
 *   some\\key=some\nvalue
 *   some\=key=some=value
 *
 *   /subns
 *   some=stuff in the sub-namespace
 *
 *   /subns/deeper
 *   this=is in /subns/deeper
 *
*/

static int cmp_ns(const void *a, const void *b) {
	const SdbNs *nsa = (const SdbNs *)a;
	const SdbNs *cia = (const SdbNs *)b;
	return strcmp (nsa->name, cia->name);
}


// n = position we are currently looking at
// p = position until we have already written everything
// flush a block of text that doesn't have to be escaped

static bool escape_flush(int fd, const char *p, const char *n) {
	if (p != n && write (fd, p, n - p) != n - p) {
		return false;
	}
	return true;
}

static bool escape_loop(int fd, const char *str, char ch) {
	const char *p = str;
	const char *n = p;
	bool ok = true;
	while (*n && ok) {
		ok = true;
		switch (*n) {
		case '\\':
			ok = escape_flush (fd, p, n) && write (fd, "\\\\", 2) == 2;
			p = n + 1;
			break;
		case '\r':
			ok = escape_flush (fd, p, n) && write (fd, "\\r", 2) == 2;
			p = n + 1;
			break;
		case '\n':
			ok = escape_flush (fd, p, n) && write (fd, "\\n", 2) == 2;
			p = n + 1;
			break;
		default:
			if (ch && *n == ch) {
				char pair[2] = { '\\', ch };
				ok = escape_flush (fd, p, n) && write (fd, &pair, 2) == 2;
				p = n + 1;
			}
			break;
		}
		n++;
	}
	return ok && escape_flush (fd, p, n);
}

static bool write_path(int fd, SdbList *path) {
	if (write (fd, "/", 1) != 1) { // always print a /, even if path is empty
		return false;
	}
	SdbListIter *it;
	const char *path_token;
	bool first = true;
	ls_foreach_cast (path, it, const char *, path_token) {
		if (first) {
			first = false;
		} else {
			if (write (fd, "/", 1) != 1) {
				return false;
			}
		}
		if (!escape_loop (fd, path_token, '/')) {
			return false;
		}
	}
	return true;
}

static bool write_key(int fd, const char *k) {
	// escape leading '/'
	if (*k == '/') {
		if (write (fd, "\\", 1) != 1) {
			return false;
		}
	}
	return escape_loop (fd, k, '=');
}

static bool write_value(int fd, const char *v) {
	return escape_loop (fd, v, 0);
}

static bool save_kv_cb(void *user, const char *k, const char *v) {
	int fd = *((int *)user);
	if (!write_key (fd, k) || write (fd, "=", 1) != 1) {
		return false;
	}
	if (!write_value (fd, v) || write (fd, "\n", 1) != 1) {
		return false;
	}
	return true;
}

static bool text_save(Sdb *s, int fd, bool sort, SdbList *path) {
	// path
	if (!write_path (fd, path) || write (fd, "\n", 1) != 1) {
		return false;
	}

	// k=v entries
	if (sort) {
		SdbList *l = sdb_foreach_list (s, true);
		SdbKv *kv;
		SdbListIter *it;
		ls_foreach_cast (l, it, SdbKv*, kv) {
			save_kv_cb (&fd, sdbkv_key (kv), sdbkv_value (kv));
		}
		ls_free (l);
	} else {
		// This is faster when sorting is not needed.
		sdb_foreach (s, save_kv_cb, &fd);
	}

	// sub-namespaces
	SdbList *l = s->ns;
	if (sort) {
		l = ls_clone (l);
		ls_sort (l, cmp_ns);
	}
	SdbNs *ns;
	SdbListIter *it;
	ls_foreach_cast (l, it, SdbNs*, ns) {
		if (write (fd, "\n", 1) != 1) {
			ls_free (l);
			return false;
		}
		ls_push (path, ns->name);
		text_save (ns->sdb, fd, sort, path);
		ls_pop (path);
	}
	if (l != s->ns) {
		ls_free (l);
	}

	return true;
}

SDB_API bool sdb_text_save_fd(Sdb *s, int fd, bool sort) {
	SdbList *path = ls_new ();
	if (!path) {
		return false;
	}
	bool r = text_save (s, fd, sort, path);
	ls_free (path);
	return r;
}

SDB_API bool sdb_text_save(Sdb *s, const char *file, bool sort) {
	int fd = open (file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
	if (fd < 0) {
		return false;
	}
	bool r = sdb_text_save_fd (s, fd, sort);
	close (fd);
	return r;
}

typedef enum {
	STATE_NEWLINE,
	STATE_PATH,
	STATE_KEY,
	STATE_VALUE
} LoadState;

typedef struct {
	bool eof;
	char *buf;
	size_t bufsz;
	Sdb *root_db;
	Sdb *cur_db; // current namespace, changes when encountering a path line
	size_t pos; // current processing position in the buffer
	size_t line_begin;
	size_t token_begin; // beginning of the currently processed token in the buffer
	size_t shift; // amount to shift chars to the left (from unescaping)
	SdbList/*<size_t>*/ *path;
	LoadState state;
	bool unescape; // whether the prev char was a backslash, i.e. the current one is escaped
} LoadCtx;

// to be called at the end of a line.
// save all the data processed from the line into the database.
// assumes that the ctx->buf is allocated until ctx->buf[ctx->pos] inclusive!
static void load_process_line(LoadCtx *ctx) {
	ctx->unescape = false;
	// finish up the line
	ctx->buf[ctx->pos - ctx->shift] = '\0';
	switch (ctx->state) {
	case STATE_PATH: {
		ls_push (ctx->path, (void *)ctx->token_begin);
		SdbListIter *it;
		void *token_off_tmp;
		ctx->cur_db = ctx->root_db;
		ls_foreach_cast (ctx->path, it, void*, token_off_tmp) {
			size_t token_off = (size_t)token_off_tmp;
			if (!ctx->buf[token_off]) {
				continue;
			}
			ctx->cur_db = sdb_ns (ctx->cur_db, ctx->buf + token_off, 1);
			if (!ctx->cur_db) {
				ctx->cur_db = ctx->root_db;
				break;
			}
		}
		ls_destroy (ctx->path);
		break;
	}
	case STATE_VALUE: {
		const char *k = ctx->buf + ctx->line_begin;
		const char *v = ctx->buf + ctx->token_begin;
		if (!*k || !*v) {
			break;
		}
		sdb_set (ctx->cur_db, k, v, 0);
		break;
	}
	default:
		break;
	}
	// prepare for next line
	ctx->shift = 0;
	ctx->state = STATE_NEWLINE;
}

static inline char unescape_raw_char(char c) {
	switch (c) {
	case 'n':
		return '\n';
	case 'r':
		return '\r';
	case 't':
		return '\t';
	default:
		return c;
	}
}

static void load_process_single_char(LoadCtx *ctx) {
	char c = ctx->buf[ctx->pos];
	if (c == '\n' || c == '\r') {
		load_process_line (ctx);
		ctx->pos++;
		return;
	}

	if (ctx->state == STATE_NEWLINE) {
		ctx->line_begin = ctx->pos;
		// at the start of a line, decide whether it's a path or a k=v
		// by whether there is a leading slash.
		if (c == '/') {
			ctx->state = STATE_PATH;
			ctx->token_begin = ctx->pos + 1;
			ctx->pos++;
			c = ctx->buf[ctx->pos];
			return;
		}
		ctx->state = STATE_KEY;
	}

	if (ctx->unescape) {
		ctx->buf[ctx->pos - ctx->shift] = unescape_raw_char (c);
		ctx->unescape = false;
	} else if (c == '\\') {
		// got a backslash, the next char, unescape in the next iteration or die!
		ctx->shift++;
		ctx->unescape = true;
	} else if (ctx->state == STATE_PATH && c == '/') {
		// new path token
		ctx->buf[ctx->pos - ctx->shift] = '\0';
		ls_push (ctx->path, (void *)ctx->token_begin);
		ctx->token_begin = ctx->pos + 1;
		ctx->shift = 0;
	} else if (ctx->state == STATE_KEY && c == '=') {
		// switch from key to value mode
		ctx->buf[ctx->pos - ctx->shift] = '\0';
		ctx->token_begin = ctx->pos + 1;
		ctx->shift = 0;
		ctx->state = STATE_VALUE;
	} else if (ctx->shift) {
		// just some char, shift it back if necessary
		ctx->buf[ctx->pos - ctx->shift] = c;
	}
	ctx->pos++;
}

static bool load_process_final_line(LoadCtx *ctx) {
	// load_process_line needs ctx.buf[ctx.pos] to be allocated!
	// so we need room for one additional byte after the buffer.
	size_t linesz = ctx->bufsz - ctx->line_begin;
	char *linebuf = (char *)sdb_gh_malloc (linesz + 1);
	if (!linebuf) {
		return false;
	}
	memcpy (linebuf, ctx->buf + ctx->line_begin, linesz);
	ctx->buf = linebuf;
	// shift everything by the size we skipped
	ctx->bufsz -= ctx->line_begin;
	ctx->pos = linesz;
	ctx->token_begin -= ctx->line_begin;
	SdbListIter *it;
	void *token_off_tmp;
	ls_foreach_cast (ctx->path, it, void*, token_off_tmp) {
		it->data = (void *)((size_t)token_off_tmp - ctx->line_begin);
	}
	ctx->line_begin = 0;
	load_process_line (ctx);
	free (linebuf);
	ctx->buf = NULL;
	return true;
}

static void load_ctx_fini(LoadCtx *ctx) {
	ls_free (ctx->path);
}

static bool load_ctx_init(LoadCtx *ctx, Sdb *s, char *buf, size_t sz) {
	ctx->eof = false;
	ctx->buf = buf;
	ctx->bufsz = sz;
	ctx->root_db = s;
	ctx->cur_db = s;
	ctx->pos = 0;
	ctx->line_begin = 0;
	ctx->token_begin = 0;
	ctx->shift = 0;
	ctx->path = ls_new ();
	ctx->state = STATE_NEWLINE;
	ctx->unescape = false;
	if (!ctx->buf || !ctx->path) {
		load_ctx_fini (ctx);
		return false;
	}
	return true;
}

SDB_API bool sdb_text_load_buf(Sdb *s, char *buf, size_t sz) {
	if (!sz) {
		return true;
	}
	LoadCtx ctx;
	if (!load_ctx_init (&ctx, s, buf, sz)) {
		return false;
	}
	bool ret = true;
	while (ctx.pos < ctx.bufsz) {
		load_process_single_char (&ctx);
	}
	if (ctx.line_begin < ctx.bufsz && ctx.state != STATE_NEWLINE) {
		load_process_final_line (&ctx);
	}
	load_ctx_fini (&ctx);
	return ret;
}

SDB_API bool sdb_text_load(Sdb *s, const char *file) {
	int fd = open (file, O_RDONLY | O_BINARY);
	if (fd < 0) {
		return false;
	}
	bool r = false;
	char *x = NULL;
	struct stat st;
	if (fstat (fd, &st) || !st.st_size) {
		goto beach;
	}
#if USE_MMAN
	x = (char *)mmap (0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (x == MAP_FAILED) {
		goto beach;
	}
#else
	x = (char *)sdb_gh_calloc (1, st.st_size);
	if (!x) {
		goto beach;
	}
	if (read (fd, x, st.st_size) != st.st_size) {
		sdb_gh_free (x);
		goto beach;
	}
#endif
	r = sdb_text_load_buf (s, x, st.st_size);
#if USE_MMAN
	munmap (x, st.st_size);
#else
	sdb_gh_free (x);
#endif
beach:
	close (fd);
	return r;
}

SDB_API bool sdb_text_check(Sdb *s, const char *file) {
	char buf[64] = {0};
	int fd = open (file, O_RDONLY | O_BINARY);
	if (fd < 0) {
		return false;
	}
	struct stat st;
	if (fstat (fd, &st) || !st.st_size) {
		close (fd);
		return false;
	}
	int count = read (fd, buf, R_MIN (st.st_size, (off_t)sizeof (buf)));
	close (fd);
	if (count < 1) {
		return false;
	}
	bool is_ascii = true;
	bool has_eq = false;
	bool has_nl = false;
	buf[sizeof (buf) - 1] = 0;
	char *p = buf;
	while (*p) {
		if (*p == '=') {
			has_eq = true;
		} else if (*p == '\n') {
			if (!has_eq) {
				break;
			}
			has_nl = true;
		} else if (!has_eq) {
			if (*p < 10 || *p > '~') {
				is_ascii = false;
			}
		}
		p++;
	}
	return count > 4 && is_ascii && has_nl && has_eq;
}
