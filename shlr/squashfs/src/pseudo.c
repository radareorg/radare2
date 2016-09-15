/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2009, 2010
 * Phillip Lougher <phillip@lougher.demon.co.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * pseudo.c
 */

#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "pseudo.h"

#ifdef SQUASHFS_TRACE
#define TRACE(s, args...) \
		do { \
			printf("mksquashfs: "s, ## args); \
		} while(0)
#else
#define TRACE(s, args...)
#endif

#define ERROR(s, args...) \
		do { \
			fprintf(stderr, s, ## args); \
		} while(0)

#define EXIT_MKSQUASHFS() \
		do { \
			exit(1); \
		} while(0)

#define BAD_ERROR(s, args...) \
		do {\
			fprintf(stderr, "FATAL ERROR:" s, ##args);\
			EXIT_MKSQUASHFS();\
		} while(0);

#define TRUE 1
#define FALSE 0

struct pseudo_dev **pseudo_file = NULL;
int pseudo_count = 0;

static void dump_pseudo(struct pseudo *pseudo, char *string)
{
	int i;
	char path[1024];

	for(i = 0; i < pseudo->names; i++) {
		struct pseudo_entry *entry = &pseudo->name[i];
		if(string)
			strcat(strcat(strcpy(path, string), "/"), entry->name);
		else
			strcpy(path, entry->name);
		if(entry->pseudo == NULL)
			ERROR("%s %c %o %d %d %d %d\n", path, entry->dev->type,
				entry->dev->mode, entry->dev->uid,
				entry->dev->gid, entry->dev->major,
				entry->dev->minor);
		else
			dump_pseudo(entry->pseudo, path);
	}
}


static char *get_component(char *target, char *targname)
{
	while(*target == '/')
		target ++;

	while(*target != '/' && *target!= '\0')
		*targname ++ = *target ++;

	*targname = '\0';

	return target;
}


/*
 * Add pseudo device target to the set of pseudo devices.  Pseudo_dev
 * describes the pseudo device attributes.
 */
struct pseudo *add_pseudo(struct pseudo *pseudo, struct pseudo_dev *pseudo_dev,
	char *target, char *alltarget)
{
	char targname[1024];
	int i;

	target = get_component(target, targname);

	if(pseudo == NULL) {
		if((pseudo = malloc(sizeof(struct pseudo))) == NULL)
			BAD_ERROR("failed to allocate pseudo file\n");

		pseudo->names = 0;
		pseudo->count = 0;
		pseudo->name = NULL;
	}

	for(i = 0; i < pseudo->names; i++)
		if(strcmp(pseudo->name[i].name, targname) == 0)
			break;

	if(i == pseudo->names) {
		/* allocate new name entry */
		pseudo->names ++;
		pseudo->name = realloc(pseudo->name, (i + 1) *
			sizeof(struct pseudo_entry));
		if(pseudo->name == NULL)
			BAD_ERROR("failed to allocate pseudo file\n");
		pseudo->name[i].name = strdup(targname);

		if(target[0] == '\0') {
			/* at leaf pathname component */
			pseudo->name[i].pseudo = NULL;
			pseudo->name[i].pathname = strdup(alltarget);
			pseudo->name[i].dev = pseudo_dev;
		} else {
			/* recurse adding child components */
			pseudo->name[i].dev = NULL;
			pseudo->name[i].pseudo = add_pseudo(NULL, pseudo_dev,
				target, alltarget);
		}
	} else {
		/* existing matching entry */
		if(pseudo->name[i].pseudo == NULL) {
			/* No sub-directory which means this is the leaf
			 * component of a pre-existing pseudo file.
			 */
			if(target[0] != '\0') {
				/* entry must exist as a 'd' type pseudo file */
				if(pseudo->name[i].dev->type == 'd')
					/* recurse adding child components */
					pseudo->name[i].pseudo =
						add_pseudo(NULL, pseudo_dev,
						target, alltarget);
				else
					ERROR("%s already exists as a non "
						"directory.  Ignoring %s!\n",
						 targname, alltarget);
			} else if(memcmp(pseudo_dev, pseudo->name[i].dev,
					sizeof(struct pseudo_dev)) != 0)
				ERROR("%s already exists as a different pseudo "
					"definition.  Ignoring!\n", alltarget);
			else ERROR("%s already exists as an identical "
					"pseudo definition!\n", alltarget);
		} else {
			/* sub-directory exists which means this can only be a
			 * 'd' type pseudo file */
			if(target[0] == '\0') {
				if(pseudo->name[i].dev == NULL &&
						pseudo_dev->type == 'd') {
					pseudo->name[i].pathname =
						strdup(alltarget);
					pseudo->name[i].dev = pseudo_dev;
				} else
					ERROR("%s already exists as a "
						"directory.  Ignoring %s!\n",
						targname, alltarget);
			} else
				/* recurse adding child components */
				add_pseudo(pseudo->name[i].pseudo, pseudo_dev,
					target, alltarget);
		}
	}

	return pseudo;
}


/*
 * Find subdirectory in pseudo directory referenced by pseudo, matching
 * filename.  If filename doesn't exist or if filename is a leaf file
 * return NULL
 */
struct pseudo *pseudo_subdir(char *filename, struct pseudo *pseudo)
{
	int i;

	if(pseudo == NULL)
		return NULL;

	for(i = 0; i < pseudo->names; i++)
		if(strcmp(filename, pseudo->name[i].name) == 0)
			return pseudo->name[i].pseudo;

	return NULL;
}


struct pseudo_entry *pseudo_readdir(struct pseudo *pseudo)
{
	if(pseudo == NULL)
		return NULL;

	while(pseudo->count < pseudo->names) {
		if(pseudo->name[pseudo->count].dev != NULL)
			return &pseudo->name[pseudo->count++];
		else
			pseudo->count++;
	}

	return NULL;
}


int exec_file(char *command, struct pseudo_dev *dev)
{
	int child, res;
	static pid_t pid = -1;
	int pipefd[2];
#ifdef USE_TMP_FILE
	char filename[1024];
	int status;
	static int number = 0;
#endif

	if(pid == -1)
		pid = getpid();

#ifdef USE_TMP_FILE
	sprintf(filename, "/tmp/squashfs_pseudo_%d_%d", pid, number ++);
	pipefd[1] = open(filename, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU);
	if(pipefd[1] == -1) {
		printf("open failed\n");
		return -1;
	}
#else
	res = pipe(pipefd);
	if(res == -1) {
		printf("pipe failed\n");
		return -1;
	}
#endif

	child = fork();
	if(child == -1) {
		printf("fork failed\n");
		goto failed;
	}

	if(child == 0) {
		close(STDOUT_FILENO);
		res = dup(pipefd[1]);
		if(res == -1) {
			printf("dup failed\n");
			exit(EXIT_FAILURE);
		}
		execl("/bin/sh", "sh", "-c", command, (char *) NULL);
		printf("execl failed\n");
		exit(EXIT_FAILURE);
	}

#ifdef USE_TMP_FILE
	res = waitpid(child, &status, 0);
	close(pipefd[1]);
	if(res != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		dev->filename = strdup(filename);
		return 0;
	}
failed:
	unlink(filename);
	return -1;
#else
	close(pipefd[1]);
	dev->fd = pipefd[0];
	dev->child = child;
	return 0;
failed:
	return -1;
#endif
}


void add_pseudo_file(struct pseudo_dev *dev)
{
	pseudo_file = realloc(pseudo_file, (pseudo_count + 1) *
		sizeof(struct pseudo_dev *));
	if(pseudo_file == NULL)
		BAD_ERROR("Failed to realloc pseudo_file\n");

	dev->pseudo_id = pseudo_count;
	pseudo_file[pseudo_count ++] = dev;
}


void delete_pseudo_files()
{
#ifdef USE_TMP_FILE
	int i;

	for(i = 0; i < pseudo_count; i++)
		unlink(pseudo_file[i]->filename);
#endif
}


struct pseudo_dev *get_pseudo_file(int pseudo_id)
{
	return pseudo_file[pseudo_id];
}


int read_pseudo_def(struct pseudo **pseudo, char *def)
{
	int n, bytes;
	unsigned int major = 0, minor = 0, mode;
	char filename[2048], type, suid[100], sgid[100], *ptr;
	long long uid, gid;
	struct pseudo_dev *dev;

	n = sscanf(def, "%s %c %o %s %s %n", filename, &type, &mode, suid,
			sgid, &bytes);

	if(n < 5) {
		ERROR("Not enough or invalid arguments in pseudo file "
			"definition\n");
		goto error;
	}

	switch(type) {
	case 'b':
	case 'c':
		n = sscanf(def + bytes,  "%u %u", &major, &minor);

		if(n < 2) {
			ERROR("Not enough or invalid arguments in pseudo file "
				"definition\n");
			goto error;
		}	
		
		if(major > 0xfff) {
			ERROR("Major %d out of range\n", major);
			goto error;
		}

		if(minor > 0xfffff) {
			ERROR("Minor %d out of range\n", minor);
			goto error;
		}

	case 'f':
		if(def[bytes] == '\0') {
			ERROR("Not enough arguments in pseudo file "
				"definition\n");
			goto error;
		}	
		break;
	case 'd':
	case 'm':
		break;
	default:
		ERROR("Unsupported type %c\n", type);
		goto error;
	}


	if(mode > 07777) {
		ERROR("Mode %o out of range\n", mode);
		goto error;
	}

	uid = strtoll(suid, &ptr, 10);
	if(*ptr == '\0') {
		if(uid < 0 || uid > ((1LL << 32) - 1)) {
			ERROR("Uid %s out of range\n", suid);
			goto error;
		}
	} else {
		struct passwd *pwuid = getpwnam(suid);
		if(pwuid)
			uid = pwuid->pw_uid;
		else {
			ERROR("Uid %s invalid uid or unknown user\n", suid);
			goto error;
		}
	}
		
	gid = strtoll(sgid, &ptr, 10);
	if(*ptr == '\0') {
		if(gid < 0 || gid > ((1LL << 32) - 1)) {
			ERROR("Gid %s out of range\n", sgid);
			goto error;
		}
	} else {
		struct group *grgid = getgrnam(sgid);
		if(grgid)
			gid = grgid->gr_gid;
		else {
			ERROR("Gid %s invalid uid or unknown user\n", sgid);
			goto error;
		}
	}

	switch(type) {
	case 'b':
		mode |= S_IFBLK;
		break;
	case 'c':
		mode |= S_IFCHR;
		break;
	case 'd':
		mode |= S_IFDIR;
		break;
	case 'f':
		mode |= S_IFREG;
		break;
	}

	dev = malloc(sizeof(struct pseudo_dev));
	if(dev == NULL)
		BAD_ERROR("Failed to create pseudo_dev\n");

	dev->type = type;
	dev->mode = mode;
	dev->uid = uid;
	dev->gid = gid;
	dev->major = major;
	dev->minor = minor;

	if(type == 'f') {
		int res;

		printf("Executing dynamic pseudo file\n");
		printf("\t\"%s\"\n", def);
		res = exec_file(def + bytes, dev);
		if(res == -1) {
			ERROR("Failed to execute dynamic pseudo file definition"
				" \"%s\"\n", def);
			return FALSE;
		}
		add_pseudo_file(dev);
	}

	*pseudo = add_pseudo(*pseudo, dev, filename, filename);

	return TRUE;

error:
	ERROR("Bad pseudo file definition \"%s\"\n", def);
	return FALSE;
}
		


#define MAX_LINE 2048

int read_pseudo_file(struct pseudo **pseudo, char *filename)
{
	FILE *fd;
	char *line = NULL;
	int size = 0;
	int res = TRUE;

	fd = fopen(filename, "r");
	if(fd == NULL) {
		ERROR("Could not open pseudo device file \"%s\" because %s\n",
				filename, strerror(errno));
		return FALSE;
	}

	while(1) {
		int total = 0;

		while(1) {
			int n, err;

			if(total + MAX_LINE > size) {
				line = realloc(line, size += MAX_LINE);
				if(line == NULL) {
					ERROR("No space in read_pseudo_file\n");
					return FALSE;
				}
			}

			err = fscanf(fd, "%2047[^\n]%n\n", line + total, &n);
			if(err <= 0)
				goto done;

			if(line[total] == '#')
				continue;

			if(line[total + n - 1] != '\\')
				break;

			total += n - 1;
		}	

		res = read_pseudo_def(pseudo, line);
		if(res == FALSE)
			break;
	}

done:
	fclose(fd);
	free(line);
	return res;
}
