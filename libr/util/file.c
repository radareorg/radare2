/* radare - LGPL - Copyright 2007-2010 pancake<nopcode.org> */

#include "r_types.h"
#include "r_util.h"
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

R_API const char *r_file_basename (const char *path) {
	const char *ptr = strrchr (path, '/');
	if (ptr)
		path = ptr + 1;
	return path;
}

R_API int r_file_mkdir(const char *path) {
#if __WINDOWS__
	return mkdir(path);
#else
	return mkdir(path, 0755);
#endif
}

R_API int r_file_exist(const char *str) {
	struct stat buf;
	return (stat (str, &buf)==-1)?R_FALSE:R_TRUE;
}

R_API const char *r_file_abspath(const char *file) {
#if __UNIX__
	if (file[0] != '/')
		return r_str_dup_printf ("%s/%s", r_sys_getcwd (), file);
#elif __WINDOWS__
	if (!strchr (file, ':'))
		return r_str_dup_printf ("%s/%s", r_sys_getcwd (), file);
#endif
	return file;
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
        char *ret;
        long sz;
        FILE *fd = fopen (str, "rb");
        if (fd == NULL)
                return NULL;
        fseek (fd, 0,SEEK_END);
        sz = ftell (fd);
        fseek (fd, 0,SEEK_SET);
        ret = (char *)malloc (sz+1);
        fread (ret, sz, 1, fd); // TODO: handle return value :?
        ret[sz]='\0';
        fclose (fd);
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

	if (usz)
		*usz = bytes;
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
		*osz = (int)(size_t)fread (ret, 1, sz, fd);
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
	char *ptr, *str = r_file_slurp (file, &sz);
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

R_API int r_file_dump(const char *file, const ut8 *buf, int len) {
	FILE *fd = fopen(file, "wb");
	if (fd == NULL) {
		fprintf(stderr, "Cannot open '%s' for writing\n", file);
		return R_FALSE;
	}
	fwrite(buf, len, 1, fd);
	fclose(fd);
	return R_TRUE;
}

R_API int r_file_rm(const char *file) {
	// TODO: w32 unlink?
	return unlink(file);
}
