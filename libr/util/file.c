/* radare - LGPL - Copyright 2007-2011 pancake<nopcode.org> */

#include "r_types.h"
#include "r_util.h"
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#if __UNIX__
#include <fcntl.h>
#include <sys/mman.h>
#endif

R_API const char *r_file_basename (const char *path) {
	const char *ptr = strrchr (path, '/');
	if (ptr) path = ptr + 1;
	return path;
}

R_API boolt r_file_exist(const char *str) {
	struct stat buf;
	if (stat (str, &buf)==-1)
		return R_FALSE;
	return (S_ISREG (buf.st_mode))?R_TRUE:R_FALSE;
}

R_API char *r_file_abspath(const char *file) {
#if __UNIX__
	if (file[0] != '/')
		return r_str_dup_printf ("%s/%s", r_sys_getcwd (), file);
#elif __WINDOWS__
	if (!strchr (file, ':'))
		return r_str_dup_printf ("%s/%s", r_sys_getcwd (), file);
#endif
	return strdup (file);
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
				ptr[0]='\0';
				snprintf (file, 1023, "%s/%s", str, bin);
				if (r_file_exist (file)) {
					free (path);
					return strdup (file);
				}
				str = ptr+1;
			}
		} while (ptr);
	} else return strdup (bin);
	free (path);
	return strdup (bin);
}

R_API char *r_file_slurp(const char *str, int *usz) {
	size_t rsz;
	char *ret;
	FILE *fd;
	long sz;
	if (!r_file_exist (str))
		return NULL;
	fd = fopen (str, "rb");
	if (fd == NULL)
		return NULL;
	fseek (fd, 0, SEEK_END);
	sz = ftell (fd);
	fseek (fd, 0, SEEK_SET);
	ret = (char *)malloc (sz+1);
	rsz = fread (ret, 1, sz, fd);
	if (rsz != sz)
		eprintf ("r_file_slurp: fread: error\n");
	fclose (fd);
	ret[rsz]='\0';
	if (usz)
		*usz = (ut32)sz;
	return ret;
}

R_API ut8 *r_file_slurp_hexpairs(const char *str, int *usz) {
	ut8 *ret;
	long sz;
	int c, bytes = 0;
	FILE *fd = fopen (str, "r");
	if (fd == NULL)
		return NULL;
	fseek (fd, 0, SEEK_END);
	sz = ftell (fd);
	fseek (fd, 0, SEEK_SET);
	ret = (ut8*)malloc ((sz>>1)+1);
	if (!ret)
		return NULL;
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
		return NULL;
	}

	ret[bytes] = '\0';
	fclose (fd);
	if (usz) *usz = bytes;
	return ret;
}

R_API char *r_file_slurp_range(const char *str, ut64 off, int sz, int *osz) {
	char *ret;
	FILE *fd = fopen (str, "rb");
	if (fd == NULL)
		return NULL;
	fseek (fd, off, SEEK_SET);
	ret = (char *)malloc (sz+1);
	if (ret != NULL) {
		if (osz)
			*osz = (int)(size_t)fread (ret, 1, sz, fd);
		else fread (ret, 1, sz, fd);
		ret[sz] = '\0';
	}
	fclose (fd);
	return ret;
}

R_API char *r_file_slurp_random_line(const char *file) {
	int i, lines = 0;
	struct timeval tv;
	int sz;
	char *ptr = NULL;
	char *str = r_file_slurp (file, &sz);
	if (str) {
		gettimeofday (&tv,NULL);
		srand (getpid()+tv.tv_usec);
		for(i=0; str[i]; i++)
			if (str[i]=='\n')
				lines++;
		lines = (rand()%lines);
		for(i=0; str[i]&&lines; i++)
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

R_API char *r_file_slurp_line(const char *file, int line, int context) {
	int i, lines = 0;
	int sz;
	char *ptr = NULL, *str = r_file_slurp (file, &sz);
	// TODO: Implement context
	if (str) {
		for (i=0;str[i];i++)
			if (str[i]=='\n')
				lines++;
		if (line > lines) {
			free (str);
			return NULL;
		}
		lines = line;
		for (i=0;str[i]&&lines;i++)
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

R_API boolt r_file_dump(const char *file, const ut8 *buf, int len) {
	int ret;
	FILE *fd = fopen(file, "wb");
	if (fd == NULL) {
		eprintf ("Cannot open '%s' for writing\n", file);
		return R_FALSE;
	}
	ret = fwrite (buf, 1, len, fd) == len;
	if (!ret)
		eprintf ("r_file_dump: fwrite: error\n");
	fclose (fd);
	return ret;
}

R_API boolt r_file_rm(const char *file) {
#if __WINDOWS__
	return (DeleteFile (file)==0)? R_TRUE:R_FALSE;
#else
	return (unlink (file)==0)? R_TRUE:R_FALSE;
#endif
}

// TODO: add rwx support?
R_API RMmap *r_file_mmap (const char *file, boolt rw) {
	RMmap *m = NULL;
#if __WINDOWS__
	int fd = open (file, 0);
#else
	int fd = open (file, rw?O_RDWR:O_RDONLY);
#endif
	if (fd != -1) {
		m = R_NEW (RMmap);
		if (!m) {
			close (fd);
			return NULL;
		}
		m->rw = rw;
		m->fd = fd;
		m->len = lseek (fd, (off_t)0, SEEK_END);
#if __UNIX__
		m->buf = mmap (NULL, m->len, rw?PROT_READ|PROT_WRITE:PROT_READ,
				MAP_SHARED, fd, (off_t)0);
		if (!m->buf) {
			free (m);
			m = NULL;
		}
#elif __WINDOWS__
		close (fd);
		m->fh = CreateFile (file, rw?GENERIC_WRITE:GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
		if (m->fh == NULL) {
			free (m);
			return NULL;
		}
		m->fm = CreateFileMapping (m->fh, NULL,
			rw?PAGE_READWRITE:PAGE_READONLY, 0, 0, NULL);
		if (m->fm == NULL) {
			CloseHandle (m->fh);
			free (m);
			return NULL;
		}
		if (m->fm != INVALID_HANDLE_VALUE) {
			m->buf = MapViewOfFile (m->fm, rw?FILE_MAP_READ|FILE_MAP_WRITE:FILE_MAP_READ, 0, 0, 0);
		} else {
			CloseHandle (m->fh);
			free (m);
			m = NULL;
		}
#else
		m->buf = malloc (m->len);
		if (m->buf) {
			lseek (fd, (off_t)0, SEEK_SET);
			read (fd, m->buf, m->len);
		} else {
			free (m);
			m = NULL;
		}
#endif
	}
	return m;
}

R_API void r_file_mmap_free (RMmap *m) {
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
