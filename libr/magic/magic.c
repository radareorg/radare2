/* radare - Copyright 2011-2019 pancake<nopcode.org> */
/* $OpenBSD: magic.c,v 1.8 2009/10/27 23:59:37 deraadt Exp $ */

#include <r_userconf.h>
#include <r_magic.h>

R_LIB_VERSION (r_magic);

#ifdef _MSC_VER
# include <io.h>
# include <sys\stat.h>
# define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
# define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
# define S_IFIFO (-1)
# define S_ISFIFO(m) (((m) & S_IFIFO) == S_IFIFO)
# define MAXPATHLEN 255
#endif

#if USE_LIB_MAGIC

// we keep this code just to make debian happy, but we should use
// our own magic implementation for consistency reasons
#include <magic.h>
#undef R_API
#define R_API

R_API RMagic* r_magic_new(int flags) { return magic_open (flags); }
R_API void r_magic_free(RMagic* m) { if (m) { magic_close (m); } }
R_API const char *r_magic_file(RMagic* m, const char * f) { return magic_file (m, f); } 
R_API const char *r_magic_descriptor(RMagic* m, int fd) { return magic_descriptor (m, fd); }
R_API const char *r_magic_buffer(RMagic* m, const void *b, size_t s) { return magic_buffer (m, b, s); }
R_API const char *r_magic_error(RMagic* m) { return magic_error (m); }
R_API void r_magic_setflags(RMagic* m, int f) { magic_setflags (m, f); }
R_API bool r_magic_load(RMagic* m, const char *f) { return magic_load (m, f) != -1; }
R_API bool r_magic_compile(RMagic* m, const char *x) { return magic_compile (m, x) != -1; }
R_API bool r_magic_check(RMagic* m, const char *x) { return magic_check (m, x) != -1; }
R_API int r_magic_errno(RMagic* m) { return magic_errno (m); }

#else

/* use embedded magic library */

#include "file.h"

#ifndef PIPE_BUF 
/* Get the PIPE_BUF from pathconf */
#ifdef _PC_PIPE_BUF
#define PIPE_BUF pathconf(".", _PC_PIPE_BUF)
#else
#define PIPE_BUF 512
#endif
#endif

static void free_mlist(struct mlist *mlist) {
	struct mlist *ml;
	if (!mlist) {
		return;
	}
	for (ml = mlist->next; ml != mlist;) {
		struct mlist *next = ml->next;
		struct r_magic *mg = ml->magic;
		file_delmagic (mg, ml->mapped, ml->nmagic);
		free (ml);
		ml = next;
	}
	free (ml);
}

static int info_from_stat(RMagic *ms, unsigned short md) {
	/* We cannot open it, but we were able to stat it. */
	if (md & 0222) {
		if (file_printf (ms, "writable, ") == -1) {
			return -1;
		}
	}
	if (md & 0111) {
		if (file_printf (ms, "executable, ") == -1) {
			return -1;
		}
	}
	if (S_ISREG (md)) {
		if (file_printf (ms, "regular file, ") == -1) {
			return -1;
		}
	}
	if (file_printf (ms, "no read permission") == -1) {
		return -1;
	}
	return 0;
}

static void close_and_restore (const RMagic *ms, const char *name, int fd, const struct stat *sb) {
	if (fd >= 0) {
		close (fd);
	}
}

static const char *file_or_fd(RMagic *ms, const char *inname, int fd) {
	bool ispipe = false;
	int rv = -1;
	unsigned char *buf;
	struct stat sb;
	int nbytes = 0;	/* number of bytes read from a datafile */

	/*
	 * one extra for terminating '\0', and
	 * some overlapping space for matches near EOF
	 */
#define SLOP (1 + sizeof(union VALUETYPE))
	if (!(buf = malloc (HOWMANY + SLOP))) {
		return NULL;
	}

	if (file_reset (ms) == -1) {
		goto done;
	}

	switch (file_fsmagic (ms, inname, &sb)) {
	case -1: goto done;		/* error */
	case 0:	break;			/* nothing found */
	default: rv = 0; goto done;	/* matched it and printed type */
	}

	if (!inname) {
		if (fstat (fd, &sb) == 0 && S_ISFIFO (sb.st_mode)) {
			ispipe = true;
		}
	} else {
		int flags = O_RDONLY|O_BINARY;

		if (stat (inname, &sb) == 0 && S_ISFIFO (sb.st_mode)) {
#if O_NONBLOCK
			flags |= O_NONBLOCK;
#endif
			ispipe = true;
		}
		errno = 0;
		if ((fd = open (inname, flags)) < 0) {
			eprintf ("couldn't open file\n");
			if (info_from_stat (ms, sb.st_mode) == -1) {
				goto done;
			}
			rv = 0;
			goto done;
		}
#ifdef O_NONBLOCK
		if ((flags = fcntl (fd, F_GETFL)) != -1) {
			flags &= ~O_NONBLOCK;
			(void)fcntl (fd, F_SETFL, flags);
		}
#endif
	}

	/*
	 * try looking at the first HOWMANY bytes
	 */
#ifdef O_NONBLOCK
	if (ispipe) {
		ssize_t r = 0;

		//while ((r = sread(fd, (void *)&buf[nbytes],
		while ((r = read(fd, (void *)&buf[nbytes],
		    (size_t)(HOWMANY - nbytes))) > 0) {
			nbytes += r;
			if (r < PIPE_BUF) {
				break;
			}
		}

		if (nbytes == 0) {
			/* We can not read it, but we were able to stat it. */
			if (info_from_stat (ms, sb.st_mode) == -1) {
				goto done;
			}
			rv = 0;
			goto done;
		}
	} else {
#endif
		if ((nbytes = read(fd, (char *)buf, HOWMANY)) == -1) {
			file_error(ms, errno, "cannot read `%s'", inname);
			goto done;
		}
#ifdef O_NONBLOCK
	}
#endif

	(void)memset (buf + nbytes, 0, SLOP); /* NUL terminate */
	if (file_buffer (ms, fd, inname, buf, (size_t)nbytes) == -1) {
		goto done;
	}
	rv = 0;
done:
	free (buf);
	close_and_restore (ms, inname, fd, &sb);
	return rv == 0 ? file_getbuffer(ms) : NULL;
}

/* API */

// TODO: reinitialize all the time
R_API RMagic* r_magic_new(int flags) {
	RMagic *ms = R_NEW0 (RMagic);
	if (!ms) {
		return NULL;
	}
	r_magic_setflags (ms, flags);
	ms->o.buf = ms->o.pbuf = NULL;
	ms->c.li = malloc ((ms->c.len = 10) * sizeof (*ms->c.li));
	if (!ms->c.li) {
		free (ms);
		return NULL;
	}
	file_reset (ms);
	ms->mlist = NULL;
	ms->file = "unknown";
	ms->line = 0;
	return ms;
}

R_API void r_magic_free(RMagic *ms) {
	if (ms) {
		free_mlist (ms->mlist);
		free (ms->o.pbuf);
		free (ms->o.buf);
		free (ms->c.li);
		free (ms);
	}
}

R_API bool r_magic_load_buffer(RMagic* ms, const char *magicdata) {
	if (*magicdata == '#') {
		struct mlist *ml = file_apprentice (ms, magicdata, FILE_LOAD);
		if (ml) {
			free_mlist (ms->mlist);
			ms->mlist = ml;
			return true;
		}
	} else {
		eprintf ("Magic buffers should start with #\n");
	}
	return false;
}

R_API bool r_magic_load(RMagic* ms, const char *magicfile) {
	struct mlist *ml = file_apprentice (ms, magicfile, FILE_LOAD);
	if (ml) {
		free_mlist (ms->mlist);
		ms->mlist = ml;
		return true;
	}
	return false;
}

R_API bool r_magic_compile(RMagic *ms, const char *magicfile) {
	struct mlist *ml = file_apprentice (ms, magicfile, FILE_COMPILE);
	free_mlist (ml);
	return ml != NULL;
}

R_API bool r_magic_check(RMagic *ms, const char *magicfile) {
	struct mlist *ml = file_apprentice (ms, magicfile, FILE_CHECK);
	free_mlist (ml);
	return ml != NULL;
}

R_API const char* r_magic_descriptor(RMagic *ms, int fd) {
	return file_or_fd (ms, NULL, fd);
}

R_API const char * r_magic_file(RMagic *ms, const char *inname) {
	return file_or_fd (ms, inname, 0); // 0 = stdin
}

R_API const char * r_magic_buffer(RMagic *ms, const void *buf, size_t nb) {
	if (file_reset (ms) == -1) {
		return NULL;
	}
	if (file_buffer (ms, -1, NULL, buf, nb) == -1) {
		return NULL;
	}
	return file_getbuffer (ms);
}

R_API const char *r_magic_error(RMagic *ms) {
	if (ms && ms->haderr) {
		return ms->o.buf;
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
