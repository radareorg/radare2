/*
 * Copyright (C) 2006, 2007, 2008
 *       pancake <youterm.com>
 *
 * radare is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * radare is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with radare; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "../../global.h"

//#define DATADIR "/usr/share/"
#define RSCDATADIR LIBDIR"/radare/bin"

static void rsc_help()
{
	printf("Usage: rsc [-l] [script] [-h]\n");
}

static void rsc_show_at(const char *dir)
{
	DIR *dh;
	struct dirent *de;

	if (dir == NULL)
		return;

	dh = opendir(dir);
	if (dh != NULL) {
		while((de = readdir(dh))) {
			if (de->d_name[0] != '.')
				printf("%s\n", de->d_name);
		}
		closedir(dh);
	}
}

static char gbuf[1024];

static const char *get_home_dir()
{
	const char *home = getenv("HOME");
	gbuf[0]='\0';
	if (home != NULL)
		snprintf(gbuf, 1023, "%s/.radare/rsc", home);
	return gbuf;
}

static void rsc_show()
{
	rsc_show_at(get_home_dir());
	rsc_show_at(RSCDATADIR);
}

static const char *get_path_for(const char *name)
{
	struct stat st;
	char path[1024];
	char pathfile[1024];

	sprintf(path, "%s", get_home_dir());
	sprintf(pathfile, "%s/%s", path, name);
	if (stat(pathfile, &st) == 0) {
		strcpy(gbuf,path);
		return gbuf;
	}

	sprintf(pathfile, RSCDATADIR"/%s", name);
	if (stat(pathfile, &st) == 0) {
		strcpy(gbuf, RSCDATADIR);
		return gbuf;
	}

	return NULL;
}

static int rsc_run(int argc, const char **argv)
{
	const char *path = get_path_for(argv[1]);
	char buf[4096]; // TODO: use strfoo functions
	int i;

	if (path == NULL) {
		fprintf(stderr, "rsc: Cannot find '%s'\n", argv[1]);
		return 1;
	}

	snprintf(buf, 4098, "\"%s/%s\" ", path, argv[1]);

	for(i=2;i<argc;i++) {
		strcat(buf, "\"");
		strcat(buf, argv[i]);
		strcat(buf, "\" ");
	}
	// printf("system('%s')\n", buf);
	return system(buf);
}

int main(int argc, const char **argv)
{
	if (argc<2) {
		rsc_help();
		return 1;
	}

	if (argv[1][0] == '-') {
		if (argv[1][1]=='l')
			rsc_show();
		else	rsc_help();
		return 0;
	}

	rsc_run(argc, argv);

	return 0;
}
