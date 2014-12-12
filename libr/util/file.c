/* radare - LGPL - Copyright 2007-2014 - pancake */

#include "r_types.h"
#include "r_util.h"
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#if __UNIX__
#include <sys/mman.h>
#endif

R_API int r_what_os_am_i () {
#if __UNIX__
	return ON_NIX_OS;
#elif __WINDOWS__ || __CYGWIN__ || __MINGW32__ || MINGW32
	return ON_WINDOWS_OS;
#endif
}

R_API boolt r_file_truncate (const char *filename, ut64 newsize) {
	int fd;
	if (r_file_is_directory (filename))
		return R_FALSE;
	if (!r_file_exists (filename) || !r_file_is_regular (filename))
		return R_FALSE;
#if __WINDOWS__
	fd = r_sandbox_open (filename, O_RDWR, 0644);
#else
	fd = r_sandbox_open (filename, O_RDWR|O_SYNC, 0644);
#endif
	if (fd == -1)
		return R_FALSE;
	ftruncate (fd, newsize);
	close (fd);
	return R_TRUE;
}

/*
Example:
	str = r_file_basename ("home/inisider/Downloads/user32.dll");
	// str == user32.dll 
*/
R_API const char *r_file_basename (const char *path) {
	const char *ptr = r_str_rchr (path, NULL, '/');
	if (ptr) {
		path = ptr + 1;
	} else {
		ptr = r_str_rchr (path, NULL, '\\');
		if (ptr) path = ptr + 1;
	}
	return path;
}

/*
Example:
	str = r_file_basename ("home/inisider/Downloads");
	// str == "home/inisider/Downloads"
	free (str);
*/
R_API char *r_file_dirname (const char *path) {
	char *newpath = strdup (path);
	char *ptr = (char*)r_str_rchr (newpath, NULL, '/');
	if (ptr) {
		*ptr = 0;
	} else {
		ptr = (char*)r_str_rchr (newpath, NULL, '\\');
		if (ptr) *ptr = 0;
	}
	return newpath;
}

R_API boolt r_file_is_regular(const char *str) {
	struct stat buf = {0};
	if (!str||!*str)
		return R_FALSE;
	if (stat (str, &buf)==-1)
		return R_FALSE;
	return ((S_IFREG & buf.st_mode)==S_IFREG)? R_TRUE: R_FALSE;
}

R_API boolt r_file_is_directory(const char *str) {
	struct stat buf = {0};
	if (!str||!*str)
		return R_FALSE;
	if (stat (str, &buf)==-1)
		return R_FALSE;
	if ((S_IFBLK & buf.st_mode) == S_IFBLK)
		return R_FALSE;
	return (S_IFDIR==(S_IFDIR & buf.st_mode))? R_TRUE: R_FALSE;
}

R_API boolt r_file_fexists(const char *fmt, ...) {
	int ret;
	char string[1024];
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (string, sizeof (string), fmt, ap);
	ret = r_file_exists (string);
	va_end (ap);
	return ret;
}

R_API boolt r_file_exists(const char *str) {
	struct stat buf = {0};
	if (str && *str && stat (str, &buf)==-1)
		return R_FALSE;
	return (S_ISREG (buf.st_mode))? R_TRUE: R_FALSE;
}

R_API ut64 r_file_size(const char *str) {
	struct stat buf = {0};
	if (stat (str, &buf)==-1)
		return 0;
	return (ut64)buf.st_size;
}

R_API char *r_file_abspath(const char *file) {
	char *ret = NULL;
	char *cwd = r_sys_getdir ();
	if (!memcmp (file, "~/", 2))
		return r_str_home (file+2);
#if __UNIX__
	if (cwd && *file != '/')
		ret = r_str_newf ("%s/%s", cwd, file);
#elif __WINDOWS__
	if (cwd && !strchr (file, ':'))
		ret = r_str_newf ("%s\\%s", cwd, file);
#endif
	free (cwd);
// TODO: remove // and ./
	return ret? ret: strdup (file);
}

R_API char *r_file_path(const char *bin) {
	char file[1024];
	char *path_env = (char *)r_sys_getenv ("PATH");
	char *path = NULL;
	char *str, *ptr;
	if (path_env) {
		str = path = strdup (path_env);
		do {
			ptr = strchr (str, ':');
			if (ptr) {
				*ptr = '\0';
				snprintf (file, sizeof (file), "%s/%s", str, bin);
				if (r_file_exists (file)) {
					free (path);
					free (path_env);
					return strdup (file);
				}
				str = ptr + 1;
			}
		} while (ptr);
	}
	free (path_env);
	free (path);
	return strdup (bin);
}

R_API char *r_stdin_slurp (int *sz) {
#define BS 1024
#if __UNIX__
	int i, ret, newfd = dup(0);
	char *buf = malloc (BS);
	for (i=ret=0;;i+=ret) {
		buf = realloc (buf, i+BS);
		ret = read (0, buf+i, BS);
		if (ret<1)
			break;
	}
	buf[i] = 0;
	dup2 (newfd, 0);
	close (newfd);
	if (sz)
		*sz = i;
	if (i==0) {
		R_FREE (buf);
	}
	return buf;
#else
	#warning TODO r_stdin_slurp
	return NULL;
#endif
}

R_API char *r_file_slurp(const char *str, int *usz) {
	size_t rsz;
	char *ret;
	FILE *fd;
	long sz;
	if (!r_file_exists (str))
		return NULL;
	fd = r_sandbox_fopen (str, "rb");
	if (fd == NULL)
		return NULL;
	fseek (fd, 0, SEEK_END);
	sz = ftell (fd);
	if (sz==0)
		sz = 65536;
	if (sz <0) {
		fclose (fd);
		return NULL;
	}
	fseek (fd, 0, SEEK_SET);
	ret = (char *)calloc (sz+1, 1);
	rsz = fread (ret, 1, sz, fd);
	if (rsz != sz) {
		// eprintf ("r_file_slurp: fread: error\n");
		sz = rsz;
	}
	fclose (fd);
	ret[sz]='\0';
	if (usz)
		*usz = (ut32)sz;
	return ret;
}

R_API ut8 *r_file_gzslurp(const char *str, int *outlen, int origonfail) {
	int sz;
	ut8 *in, *out;
	if (outlen) *outlen = 0;
	in = (ut8*)r_file_slurp (str, &sz);
	if (!in) return NULL;
	out = r_inflate (in, sz, outlen);
	if (!out && origonfail) {
		// if uncompression fails, return orig buffer ?
		if (outlen)
			*outlen = sz;
		in[sz] = 0;
		return in;
	}
	free (in);
	return out;
}

R_API ut8 *r_file_slurp_hexpairs(const char *str, int *usz) {
	ut8 *ret;
	long sz;
	int c, bytes = 0;
	FILE *fd = r_sandbox_fopen (str, "r");
	if (fd == NULL)
		return NULL;
	fseek (fd, 0, SEEK_END);
	sz = ftell (fd);
	fseek (fd, 0, SEEK_SET);
	ret = (ut8*)malloc ((sz>>1)+1);
	if (!ret) {
		fclose (fd);
		return NULL;
	}
	for (;;) {
		if (fscanf (fd, " #%*[^\n]") == 1)
			continue;
		if (fscanf (fd, "%02x", &c) == 1) {
			ret[bytes++] = c;
			continue;
		}
		if (feof (fd))
			break;
		free (ret);
		fclose (fd);
		return NULL;
	}

	ret[bytes] = '\0';
	fclose (fd);
	if (usz) *usz = bytes;
	return ret;
}

R_API char *r_file_slurp_range(const char *str, ut64 off, int sz, int *osz) {
	char *ret;
	size_t read_items;
	FILE *fd = r_sandbox_fopen (str, "rb");
	if (fd == NULL)
		return NULL;
	// XXX handle out of bound reads (eof)
	if (fseek (fd, off, SEEK_SET) < 0) {
		fclose (fd);
		return NULL;
	}
	ret = (char *)malloc (sz+1);
	if (ret != NULL) {
		if (osz)
			*osz = (int)(size_t)fread (ret, 1, sz, fd);
		else {
			read_items = fread (ret, 1, sz, fd);
			if (!read_items) {
				fclose (fd);
				return ret;
			}
		}
		ret[sz] = '\0';
	}
	fclose (fd);
	return ret;
}

R_API char *r_file_slurp_random_line(const char *file) {
	char *ptr = NULL, *str;
	int sz, i, lines = 0;
	struct timeval tv;

	if ((str = r_file_slurp (file, &sz))) {
		gettimeofday (&tv,NULL);
		srand (getpid()+tv.tv_usec);
		for (i=0; str[i]; i++)
			if (str[i]=='\n')
				lines++;
		if (lines>0) {
			lines = (rand()%lines);
			for (i=0; str[i] && lines; i++)
				if (str[i]=='\n')
					lines--;
			ptr = str+i;
			for (i=0; ptr[i]; i++)
				if (ptr[i]=='\n') {
					ptr[i]='\0';
					break;
				}
			ptr = strdup (ptr);
		}
		free (str);
	}
	return ptr;
}

R_API char *r_file_slurp_line(const char *file, int line, int context) {
	int i, lines = 0;
	int sz;
	char *ptr = NULL, *str = r_file_slurp (file, &sz);
	// TODO: Implement context
	if (str) {
		for (i=0; str[i]; i++)
			if (str[i]=='\n')
				lines++;
		if (line > lines) {
			free (str);
			return NULL;
		}
		lines = line - 1;
		for (i=0; str[i]&&lines; i++)
			if (str[i]=='\n')
				lines--;
		ptr = str+i;
		for (i=0; ptr[i]; i++)
			if (ptr[i]=='\n') {
				ptr[i]='\0';
				break;
			}
		ptr = strdup (ptr);
		free (str);
	}
	return ptr;
}

R_API char *r_file_root(const char *root, const char *path) {
	char *ret, *s = r_str_replace (strdup (path), "..", "", 1);
	// XXX ugly hack
	while (strstr (s, "..")) s = r_str_replace (s, "..", "", 1);
	while (strstr (s, "./")) s = r_str_replace (s, "./", "", 1);
	while (strstr (s, "//")) s = r_str_replace (s, "//", "", 1);
	ret = r_str_concat (strdup (root), "/");
	ret = r_str_concat (ret, s);
	free (s);
	return ret;
}

R_API boolt r_file_dump(const char *file, const ut8 *buf, int len) {
	int ret;
	FILE *fd;
	if (!file || !*file || !buf)
		return R_FALSE;
	fd = r_sandbox_fopen (file, "wb");
	if (fd == NULL) {
		eprintf ("Cannot open '%s' for writing\n", file);
		return R_FALSE;
	}
	ret = fwrite (buf, 1, len, fd) == len;
	if (!ret) eprintf ("r_file_dump: fwrite: error\n");
	fclose (fd);
	return ret;
}

R_API boolt r_file_rm(const char *file) {
	if (r_sandbox_enable (0)) return R_FALSE;
#if __WINDOWS__
	return (DeleteFile (file)==0)? R_TRUE: R_FALSE;
#else
	return (unlink (file)==0)? R_TRUE: R_FALSE;
#endif
}

R_API boolt r_file_rmrf(const char *file) {
	if (r_sandbox_enable (0))
        return R_FALSE;
    else {
        char *nfile = strdup (file);
        nfile[ strlen (nfile)-1 ] = '_';
        nfile[ strlen (nfile)-2 ] = '_';
        if (rename (file, nfile)) {
            free (nfile);
		return R_FALSE;
	}
        eprintf ("mv %s %s\n", file, nfile);
        free (nfile);
        return R_TRUE;
    }
}

R_API int r_file_mmap_write(const char *file, ut64 addr, const ut8 *buf, int len) {
#if __WINDOWS__
	HANDLE fm, fh;
	if (r_sandbox_enable (0)) return -1;
	fh = CreateFile (file, GENERIC_READ|GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (fh == INVALID_HANDLE_VALUE) {
		r_sys_perror ("r_file_mmap_write: CreateFile");
		return -1;
	}
// no need to overengineer the file write more
#if 0
	fm = CreateFileMapping (fh, NULL,
		PAGE_READWRITE, 0, 0, NULL);
	if (fm == NULL) {
		r_sys_perror ("r_file_mmap_write: CreateFileMapping");
		CloseHandle (fh);
		return -1;
	}

	if (fm != INVALID_HANDLE_VALUE) {
		MEMORY_BASIC_INFORMATION info;
		ut8 *obuf = MapViewOfFile (fm,
			FILE_MAP_WRITE,
			0,0,
			0);
		VirtualQuery (obuf, &info, sizeof(info);
		memcpy (obuf+addr, buf, len);
		UnmapViewOfFile (obuf);
	}
	CloseHandle (fm);
#else
	SetFilePointer (fh, addr, NULL, FILE_BEGIN);
	if (!WriteFile (fh, buf, len, NULL, NULL)) {
		r_sys_perror ("WriteFile");
		len = -1;
	}
#endif
	CloseHandle (fh);
	return len;
#elif __UNIX__
	int fd = r_sandbox_open (file, O_RDWR|O_SYNC, 0644);
	const int pagesize = 4096;
	int mmlen = len+pagesize;
	int rest = addr%pagesize;
        ut8 *mmap_buf;
	if (fd == -1) return -1;
	mmap_buf = mmap (NULL, mmlen*2, PROT_READ|PROT_WRITE,
		MAP_SHARED, fd, (off_t)addr-rest);
        if (((int)(size_t)mmap_buf)==-1)
                return -1;
        memcpy (mmap_buf+rest, buf, len);
        munmap (mmap_buf, mmlen*2);
	close (fd);
	return len;
#else
	return -1;
#endif
}

R_API int r_file_mmap_read (const char *file, ut64 addr, ut8 *buf, int len) {
#if __WINDOWS__
	HANDLE fm, fh;

	if (r_sandbox_enable (0)) return -1;
	fh = CreateFile (file, GENERIC_READ,
		FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);

	if (fh == INVALID_HANDLE_VALUE) {
		r_sys_perror ("r_file_mmap_read: CreateFile");
		return -1;
	}

	fm = CreateFileMapping (fh, NULL,
		PAGE_READONLY, 0, 0, NULL);

	if (fm != INVALID_HANDLE_VALUE) {
		ut8 *obuf = MapViewOfFile (fm,
		    FILE_MAP_READ,
			0, 0, len);
		memcpy (obuf, buf, len);
		UnmapViewOfFile (obuf);
	} else {
		r_sys_perror ("r_file_mmap_read: CreateFileMapping");
		CloseHandle (fh);
		return -1;
	}
	CloseHandle (fh);
	CloseHandle (fm);
	return len;
#elif __UNIX__
	int fd = r_sandbox_open (file, O_RDONLY, 0644);
	const int pagesize = 4096;
	int mmlen = len+pagesize;
	int rest = addr%pagesize;
        ut8 *mmap_buf;
	if (fd == -1) return -1;
	mmap_buf = mmap (NULL, mmlen*2, PROT_READ,
		MAP_SHARED, fd, (off_t)addr-rest);
        if (((int)(size_t)mmap_buf)==-1)
                return -1;
        memcpy (buf, mmap_buf+rest, len);
        munmap (mmap_buf, mmlen*2);
	close (fd);
	return len;
#endif
	return 0;
}

#if __UNIX__
static RMmap *r_file_mmap_unix (RMmap *m, int fd) {
	ut8 empty = m->len == 0;
	m->buf = mmap (NULL, (empty?1024:m->len) ,
		m->rw?PROT_READ|PROT_WRITE:PROT_READ,
		MAP_SHARED, fd, (off_t)m->base);
	if (m->buf == MAP_FAILED) {
		free (m);
		m = NULL;
	}
	return m;
}
#elif __WINDOWS__
static RMmap *r_file_mmap_windows (RMmap *m, const char *file) {
	m->fh = CreateFile (file, GENERIC_READ | (m->rw?GENERIC_WRITE:0),
		FILE_SHARE_READ|(m->rw?FILE_SHARE_WRITE:0), NULL,
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (m->fh == INVALID_HANDLE_VALUE) {
		r_sys_perror ("r_file_mmap_windows: CreateFile");
		free (m);
		return NULL;
	}
	m->fm = CreateFileMapping (m->fh, NULL,
		PAGE_READONLY, 0, 0, NULL);
		//m->rw?PAGE_READWRITE:PAGE_READONLY, 0, 0, NULL);
	if (m->fm != INVALID_HANDLE_VALUE) {
		m->buf = MapViewOfFile (m->fm, 
			// m->rw?(FILE_MAP_READ|FILE_MAP_WRITE):FILE_MAP_READ,
			FILE_MAP_COPY,
			UT32_HI (m->base), UT32_LO (m->base), 0);
	} else {
		r_sys_perror ("r_file_mmap_windows: CreateFileMapping");
		CloseHandle (m->fh);
		free (m);
		m = NULL;
	}
	return m;
}
#else
static RMmap *r_file_mmap_other (RMmap *m) {
	ut8 empty = m->len == 0;
	m->buf = malloc ((empty?1024:m->len));
	if (!empty && m->buf) {
		lseek (m->fd, (off_t)0, SEEK_SET);
		read (m->fd, m->buf, m->len);
	} else {
		free (m);
		m = NULL;
	}
	return m;
}
#endif


// TODO: add rwx support?
R_API RMmap *r_file_mmap (const char *file, boolt rw, ut64 base) {
	RMmap *m = NULL;
	int fd = -1;
	if (!rw && !r_file_exists (file)) return m;
	fd = r_sandbox_open (file, rw? O_RDWR: O_RDONLY, 0644);
	if (fd == -1 && !rw) {
		eprintf ("r_file_mmap: file does not exis.\n");
		//m->buf = malloc (m->len);
		return m;
	}
	m = R_NEW (RMmap);
	if (!m) {
		if (fd != -1) close (fd);
		return NULL;
	}
	m->base = base;
	m->rw = rw;
	m->fd = fd;
	m->len = fd != -1? lseek (fd, (off_t)0, SEEK_END) : 0;

	if (m->fd == -1) {
		return m;
	}

	if (m->len == (off_t)-1) {
		close (fd);
		R_FREE (m);
		return NULL;
	}
#if __UNIX__
	return r_file_mmap_unix (m, fd);
#elif __WINDOWS__
	close (fd);
	m->fd = -1;
	return r_file_mmap_windows (m, file);
#else
	return r_file_mmap_other (m);
#endif
}

R_API void r_file_mmap_free (RMmap *m) {
	if (!m) return;
	if (m->fd == -1) {
		free (m);
		return;
	}
#if __UNIX__
	munmap (m->buf, m->len);
#elif __WINDOWS__
	CloseHandle (m->fm);
	CloseHandle (m->fh);
	UnmapViewOfFile (m->buf);
#endif
	close (m->fd);
	free (m);
}

R_API char *r_file_temp (const char *prefix) {
	int namesz;
	char *name;
	char *path = r_file_tmpdir ();
	namesz = strlen (prefix) + strlen (path) + 32;
	name = malloc (namesz);
	snprintf (name, namesz, "%s/%s.%"PFMT64x, path, prefix, r_sys_now ());
	free (path);
	return name;
}

R_API int r_file_mkstemp (const char *prefix, char **oname) {
	int h;
	char *path = r_file_tmpdir ();
	char name[1024];
#if __WINDOWS__
	if (GetTempFileName (path, prefix, 0, name))
		h = r_sandbox_open (name, O_RDWR|O_EXCL|O_BINARY, 0644);
	else h = -1;
#else
	mode_t mask;
	snprintf (name, sizeof (name), "%s/%sXXXXXX", path, prefix);
	mask = umask(S_IWGRP | S_IWOTH);
	h = mkstemp (name);
	umask(mask);
#endif
	if (oname) *oname = (h!=-1)? strdup (name): NULL;
	free (path);
	return h;
}

R_API char *r_file_tmpdir() {
#if __WINDOWS__
	char *path = r_sys_getenv ("TEMP");
	if (!path) path = strdup ("C:\\WINDOWS\\Temp\\");
#elif __ANDROID__
	char *path = strdup ("/data/data/org.radare.installer/radare2/tmp");
#else
	char *path = r_sys_getenv ("TMPDIR");
	if (path && !*path) {
		free (path);
		path = NULL;
	}
	if (!path) path = strdup ("/tmp");
#endif
	if (!r_file_is_directory (path)) {
		eprintf ("Cannot find temporary directory '%s'\n", path);
	}
	return path;
}

