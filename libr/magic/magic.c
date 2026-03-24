/* radare - Copyright 2011-2025 pancake<nopcode.org> */
/* $OpenBSD: magic.c,v 1.8 2009/10/27 23:59:37 deraadt Exp $ */

#include <r_userconf.h>
#include <r_magic.h>
#include <r_lib.h>
#include <r_util.h>
#include <limits.h>
#include <unistd.h>

R_LIB_VERSION(r_magic);

#if USE_LIB_MAGIC

// we keep this code just to make debian happy, but we should use
// our own magic implementation for consistency reasons
#include <magic.h>
#undef R_API
#define R_API

R_API RMagic *r_magic_new(int flags) {
	return magic_open (flags);
}
R_API void r_magic_free(RMagic *m) {
	R_RETURN_IF_FAIL (m);
	magic_close (m);
}
R_API const char *r_magic_buffer(RMagic *m, const void *b, size_t s) {
	R_RETURN_VAL_IF_FAIL (m, NULL);
	return magic_buffer (m, b, s);
}
R_API const char *r_magic_file(RMagic *m, const char *f) {
	R_RETURN_VAL_IF_FAIL (m, NULL);
	return magic_file (m, f);
}
R_API const char *r_magic_descriptor(RMagic *m, int fd) {
	R_RETURN_VAL_IF_FAIL (m && fd >= 0, NULL);
	return magic_descriptor (m, fd);
}
R_API const char *r_magic_error(RMagic *m) {
	R_RETURN_VAL_IF_FAIL (m, NULL);
	return magic_error (m);
}
R_API int r_magic_getflags(RMagic *m) {
	R_RETURN_VAL_IF_FAIL (m, -1);
	return magic_getflags (m);
}
R_API void r_magic_setflags(RMagic *m, int f) {
	R_RETURN_IF_FAIL (m);
	magic_setflags (m, f);
}
R_API char *r_magic_getpath(const char *magicfile, int action) {
	const char *path = magic_getpath (magicfile, action);
	return path? strdup (path): NULL;
}
R_API bool r_magic_load(RMagic *m, const char *f) {
	R_RETURN_VAL_IF_FAIL (m, false);
	return magic_load (m, f) != -1;
}
R_API bool r_magic_compile(RMagic *m, const char *x) {
	R_RETURN_VAL_IF_FAIL (m, false);
	return magic_compile (m, x) != -1;
}
R_API bool r_magic_check(RMagic *m, const char *x) {
	R_RETURN_VAL_IF_FAIL (m, false);
	return magic_check (m, x) != -1;
}
R_API bool r_magic_list(RMagic *m, const char *x) {
	R_RETURN_VAL_IF_FAIL (m, false);
	return magic_list (m, x) != -1;
}
R_API bool r_magic_load_buffers(RMagic *m, const void *const *buffers, const size_t *sizes, size_t nbuffers) {
	R_RETURN_VAL_IF_FAIL (m && buffers && sizes && nbuffers > 0, false);
	return magic_load_buffers (m, (void **)buffers, (size_t *)sizes, nbuffers) != -1;
}
R_API int r_magic_errno(RMagic *m) {
	R_RETURN_VAL_IF_FAIL (m, -1);
	return magic_errno (m);
}
R_API int r_magic_api_version(void) {
	return magic_version ();
}

#else

/* use embedded magic library */

#include "file.h"

static void free_mlist(struct mlist *mlist) {
	struct mlist *ml;
	if (!mlist) {
		return;
	}
	for (ml = mlist->next; ml != mlist;) {
		struct mlist *next = ml->next;
		struct r_magic *mg = ml->magic;
		free (ml->min_bytes);
		__magic_file_delmagic (mg, ml->mapped, ml->nmagic);
		free (ml);
		ml = next;
	}
	free (ml);
}

static void mlist_append(struct mlist *dst, struct mlist *src) {
	if (!dst || !src || src->next == src) {
		return;
	}
	struct mlist *first = src->next;
	struct mlist *last = src->prev;
	first->prev = dst->prev;
	dst->prev->next = first;
	last->next = dst;
	dst->prev = last;
	src->next = src->prev = src;
}

static size_t mlist_bytes_max(const struct mlist *mlist) {
	const struct mlist *ml;
	size_t max_bytes = 0;

	if (!mlist) {
		return 0;
	}
	for (ml = mlist->next; ml != mlist; ml = ml->next) {
		max_bytes = R_MAX (max_bytes, ml->bytes_max);
	}
	return max_bytes;
}

static char *magic_default_path(int action) {
	char *prefix = r_sys_prefix (NULL);
	char *system_magic = prefix? r_file_new (prefix, R2_SDB_MAGIC, NULL): NULL;
	char *user_magic = action == FILE_LOAD? r_xdg_datadir ("magic"): NULL;
	char *path = NULL;

	free (prefix);
	if (R_STR_ISNOTEMPTY (user_magic) && R_STR_ISNOTEMPTY (system_magic)) {
		path = r_str_newf ("%s%s%s", user_magic, R_SYS_ENVSEP, system_magic);
	} else if (R_STR_ISNOTEMPTY (user_magic)) {
		path = strdup (user_magic);
	} else if (R_STR_ISNOTEMPTY (system_magic)) {
		path = strdup (system_magic);
	}
	free (user_magic);
	free (system_magic);
	return path;
}

static struct mlist *magic_load_path(RMagic *ms, const char *magicfile, int action) {
	char *path = r_magic_getpath (magicfile, action);
	struct mlist *ml = NULL;
	if (R_STR_ISNOTEMPTY (path)) {
		ml = __magic_file_apprentice (ms, path, strlen (path), action);
	} else if (ms) {
		__magic_file_error (ms, 0, "could not find any magic files!");
	}
	free (path);
	return ml;
}

static const char *magic_buffer_from_mem(RMagic *ms, char *buf, size_t sz) {
	const char *res = r_magic_buffer (ms, buf, sz);
	free (buf);
	return res;
}

/* API */

extern void init_file_tables(RMagic *m);

// TODO: reinitialize all the time
R_API RMagic *r_magic_new(int flags) {
	RMagic *ms = R_NEW0 (RMagic);
	if (!ms) {
		return NULL;
	}
	init_file_tables (ms);
	r_magic_setflags (ms, flags);
	r_strbuf_init (&ms->o.sb);
	ms->o.pbuf = NULL;
	ms->c.li = malloc ((ms->c.len = 10) * sizeof (*ms->c.li));
	if (!ms->c.li) {
		free (ms);
		return NULL;
	}
	__magic_file_reset (ms);
	ms->mlist = NULL;
	ms->file = "unknown";
	ms->line = 0;
	ms->bytes_max = 0;
	return ms;
}

R_API void r_magic_free(RMagic *ms) {
	R_RETURN_IF_FAIL (ms);
	free_mlist (ms->mlist);
	free (ms->o.pbuf);
	r_strbuf_fini (&ms->o.sb);
	free (ms->c.li);
	free (ms);
}

R_API bool r_magic_load_buffer(RMagic *ms, const ut8 *magicdata, size_t magicdata_size) {
	R_RETURN_VAL_IF_FAIL (ms, false);
	if (magicdata && magicdata_size > 0) {
		struct mlist *ml = __magic_file_apprentice_buffer (ms, magicdata, magicdata_size, FILE_LOAD);
		if (ml) {
			free_mlist (ms->mlist);
			ms->mlist = ml;
			ms->bytes_max = mlist_bytes_max (ml);
			return true;
		}
	} else {
		__magic_file_error (ms, 0, "magic buffer is empty");
	}
	return false;
}

R_API bool r_magic_load(RMagic *ms, const char *magicfile) {
	R_RETURN_VAL_IF_FAIL (ms, false);
	struct mlist *ml = magic_load_path (ms, magicfile, FILE_LOAD);
	if (ml) {
		free_mlist (ms->mlist);
		ms->mlist = ml;
		ms->bytes_max = mlist_bytes_max (ml);
		return true;
	}
	return false;
}

R_API bool r_magic_compile(RMagic *ms, const char *magicfile) {
	R_RETURN_VAL_IF_FAIL (ms, false);
	struct mlist *ml = magic_load_path (ms, magicfile, FILE_COMPILE);
	free_mlist (ml);
	return ml;
}

R_API bool r_magic_check(RMagic *ms, const char *magicfile) {
	R_RETURN_VAL_IF_FAIL (ms, false);
	struct mlist *ml = magic_load_path (ms, magicfile, FILE_CHECK);
	free_mlist (ml);
	return ml;
}

R_API const char *r_magic_buffer(RMagic *ms, const void *buf, size_t nb) {
	R_RETURN_VAL_IF_FAIL (ms, NULL);
	if (__magic_file_reset (ms) == -1) {
		return NULL;
	}
	if (__magic_file_buffer (ms, -1, NULL, buf, nb) == -1) {
		return NULL;
	}
	return __magic_file_getbuffer (ms);
}

R_API const char *r_magic_file(RMagic *ms, const char *filename) {
	R_RETURN_VAL_IF_FAIL (ms && filename, NULL);
	size_t limit = ms->bytes_max? ms->bytes_max: HOWMANY;
	int osz = 0;
	char *buf = r_file_slurp_range (filename, 0, (int)R_MIN (limit, (size_t)INT_MAX), &osz);
	if (!buf) {
		__magic_file_error (ms, errno, "cannot read `%s'", filename);
		return NULL;
	}
	return magic_buffer_from_mem (ms, buf, (size_t)osz);
}

R_API const char *r_magic_descriptor(RMagic *ms, int fd) {
	R_RETURN_VAL_IF_FAIL (ms && fd >= 0, NULL);
	__magic_file_error (ms, 0, "descriptor lookups are not supported");
	return NULL;
}

R_API const char *r_magic_error(RMagic *ms) {
	R_RETURN_VAL_IF_FAIL (ms, NULL);
	if (ms->haderr) {
		return r_strbuf_get (&ms->o.sb);
	}
	return NULL;
}

R_API int r_magic_getflags(RMagic *ms) {
	R_RETURN_VAL_IF_FAIL (ms, -1);
	return ms->flags;
}

R_API int r_magic_errno(RMagic *ms) {
	R_RETURN_VAL_IF_FAIL (ms, -1);
	if (ms->haderr) {
		return ms->error;
	}
	return 0;
}

R_API void r_magic_setflags(RMagic *ms, int flags) {
	R_RETURN_IF_FAIL (ms);
	ms->flags = flags;
}

R_API char *r_magic_getpath(const char *magicfile, int action) {
	if (magicfile) {
		return strdup (magicfile);
	}
	char *env = r_sys_getenv ("MAGIC");
	if (R_STR_ISNOTEMPTY (env)) {
		return env;
	}
	free (env);
	return magic_default_path (action);
}

R_API bool r_magic_load_buffers(RMagic *ms, const void *const *buffers, const size_t *sizes, size_t nbuffers) {
	struct mlist *merged = NULL;
	size_t i;
	R_RETURN_VAL_IF_FAIL (ms && buffers && sizes && nbuffers > 0, false);
	for (i = 0; i < nbuffers; i++) {
		struct mlist *ml = __magic_file_apprentice_buffer (ms, (const ut8 *)buffers[i], sizes[i], FILE_LOAD);
		if (!ml) {
			free_mlist (merged);
			return false;
		}
		if (!merged) {
			merged = ml;
			continue;
		}
		mlist_append (merged, ml);
		free (ml);
	}
	free_mlist (ms->mlist);
	ms->mlist = merged;
	ms->bytes_max = mlist_bytes_max (merged);
	return true;
}

R_API bool r_magic_list(RMagic *ms, const char *magicfile) {
	struct mlist *ml;
	struct mlist *it;
	R_RETURN_VAL_IF_FAIL (ms, false);
	ml = magic_load_path (ms, magicfile, FILE_LOAD);
	if (!ml) {
		return false;
	}
	for (it = ml->next; it != ml; it = it->next) {
		ut32 i;
		for (i = 0; i < it->nmagic; i++) {
			char *line = __magic_file_mrender (ms, &it->magic[i]);
			if (!line) {
				free_mlist (ml);
				return false;
			}
			(void)fprintf (stdout, "%s\n", line);
			free (line);
		}
	}
	free_mlist (ml);
	return true;
}

R_API int r_magic_api_version(void) {
	return R_MAGIC_VERSION;
}
#endif
