/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include "r_types.h"
#include "r_util.h"
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int r_file_mkdir(const char *path)
{
#if __WINDOWS__
	return mkdir(path);
#else
	return mkdir(path, 0755);
#endif
}

int r_file_exist(const char *str)
{
	struct stat buf;
	int ret = stat(str, &buf);
	if (ret == -1)
		return R_FALSE;
	return R_TRUE;
}

char *r_file_path(const char *bin)
{
	char file[1024];
	char *path_env = getenv("PATH");
	char *path = NULL;
	char *str, *ptr;

	if (path_env) {
		str = path = strdup(path_env);
		do {
			ptr = strchr(str, ':');
			if (ptr) {
				ptr[0]='\0';
				snprintf(file, 1023, "%s/%s", str, bin);
				if (r_file_exist(file)) {
					free(path);
					return strdup(file);
				}
				str = ptr+1;
			}
		} while(ptr);
	} else return strdup(bin);
	free(path);
	return strdup(bin);
}

char *r_file_slurp(const char *str, int *usz)
{
        char *ret;
        long sz;
        FILE *fd = fopen(str, "r");
        if (fd == NULL)
                return NULL;
        fseek(fd, 0,SEEK_END);
        sz = ftell(fd);
        fseek(fd, 0,SEEK_SET);
        ret = (char *)malloc(sz+1);
        fread(ret, sz, 1, fd);
        ret[sz]='\0';
        fclose(fd);
	if (usz)
		*usz = (u32)sz;
        return ret;
}

char *r_file_slurp_range(const char *str, u64 off, u64 sz)
{
        char *ret;
        FILE *fd = fopen(str, "r");
        if (fd == NULL)
                return NULL;
        fseek(fd, off,SEEK_SET);
        ret = (char *)malloc(sz+1);
        fread(ret, sz, 1, fd);
        ret[sz]='\0';
        fclose(fd);
        return ret;
}

char *r_file_slurp_random_line(const char *file)
{
	int i, lines = 0;
	struct timeval tv;
	int sz;
	char *ptr, *str = r_file_slurp(file, &sz);
	if (str) {
		gettimeofday(&tv,NULL);
		srand(getpid()+tv.tv_usec);
		for(i=0;str[i];i++)
			if (str[i]=='\n')
				lines++;
		lines = (rand()%lines);
		for(i=0;str[i]&&lines;i++)
			if (str[i]=='\n')
				lines--;
		ptr = str+i;
		for(i=0;ptr[i];i++) if (ptr[i]=='\n') { ptr[i]='\0'; break; }
		ptr = strdup(ptr);
		free(str);
	}
	return ptr;
}

int r_file_dump(const char *file, const u8 *buf, int len)
{
	FILE *fd = fopen(file, "wb");
	if (fd == NULL) {
		fprintf(stderr, "Cannot open '%s' for writing\n", file);
		return R_FALSE;
	}
	fwrite(buf, len, 1, fd);
	fclose(fd);
	return R_TRUE;
}

int r_file_rm(const char *file)
{
	return unlink(file);
}
