/* radare - Copyright 2011-2025 pancake<nopcode.org> */
/* $OpenBSD: magic.c,v 1.8 2009/10/27 23:59:37 deraadt Exp $ */

#include <r_userconf.h>
#include <r_magic.h>
#include <r_lib.h>

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
	if (m) {
		magic_close (m);
	}
}
R_API const char *r_magic_buffer(RMagic *m, const void *b, size_t s) {
	return magic_buffer (m, b, s);
}
R_API const char *r_magic_error(RMagic *m) {
	return magic_error (m);
}
R_API void r_magic_setflags(RMagic *m, int f) {
	magic_setflags (m, f);
}
R_API bool r_magic_load(RMagic *m, const char *f) {
	return magic_load (m, f) != -1;
}
R_API bool r_magic_compile(RMagic *m, const char *x) {
	return magic_compile (m, x) != -1;
}
R_API bool r_magic_check(RMagic *m, const char *x) {
	return magic_check (m, x) != -1;
}
R_API int r_magic_errno(RMagic *m) {
	return magic_errno (m);
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
		__magic_file_delmagic (mg, ml->mapped, ml->nmagic);
		free (ml);
		ml = next;
	}
	free (ml);
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
	return ms;
}

R_API void r_magic_free(RMagic *ms) {
	if (ms) {
		free_mlist (ms->mlist);
		free (ms->o.pbuf);
		r_strbuf_fini (&ms->o.sb);
		free (ms->c.li);
		free (ms);
	}
}

R_API bool r_magic_load_buffer(RMagic *ms, const ut8 *magicdata, size_t magicdata_size) {
	if (magicdata && magicdata_size > 0) {
		struct mlist *ml = __magic_file_apprentice_buffer (ms, magicdata, magicdata_size, FILE_LOAD);
		if (ml) {
			free_mlist (ms->mlist);
			ms->mlist = ml;
			return true;
		}
	} else if (ms) {
		__magic_file_error (ms, 0, "magic buffer is empty");
	}
	return false;
}

R_API bool r_magic_load(RMagic *ms, const char *magicfile) {
	struct mlist *ml = __magic_file_apprentice (ms, magicfile, strlen (magicfile), FILE_LOAD);
	if (ml) {
		free_mlist (ms->mlist);
		ms->mlist = ml;
		return true;
	}
	return false;
}

R_API bool r_magic_compile(RMagic *ms, const char *magicfile) {
	struct mlist *ml = __magic_file_apprentice (ms, magicfile, strlen (magicfile), FILE_COMPILE);
	free_mlist (ml);
	return ml;
}

R_API bool r_magic_check(RMagic *ms, const char *magicfile) {
	struct mlist *ml = __magic_file_apprentice (ms, magicfile, strlen (magicfile), FILE_CHECK);
	free_mlist (ml);
	return ml;
}

R_API const char *r_magic_buffer(RMagic *ms, const void *buf, size_t nb) {
	if (__magic_file_reset (ms) == -1) {
		return NULL;
	}
	if (__magic_file_buffer (ms, -1, NULL, buf, nb) == -1) {
		return NULL;
	}
	return __magic_file_getbuffer (ms);
}

R_API const char *r_magic_error(RMagic *ms) {
	if (ms && ms->haderr) {
		return r_strbuf_get (&ms->o.sb);
	}
	return NULL;
}

R_API int r_magic_errno(RMagic *ms) {
	if (ms && ms->haderr) {
		return ms->error;
	}
	return 0;
}

R_API void r_magic_setflags(RMagic *ms, int flags) {
	if (ms) {
		ms->flags = flags;
	}
}
#endif
