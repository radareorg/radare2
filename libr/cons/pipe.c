/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_cons.h>
#include <unistd.h>

//TODO: cons_pipe should be using a stack pipe_push, pipe_pop
/* this is the base fd.. more than one is supported :) */
static int backup_fd=999;

int r_cons_pipe_open(const char *file, int append)
{
	int fd = open(file, O_RDWR | O_CREAT | (append?O_APPEND:O_TRUNC), 0644);
	if (fd==-1) {
		fprintf(stderr, "Cannot open file '%s'\n", file);
		return -1;
	}
	dup2(1, backup_fd+fd);
	dup2(fd, 1);
	return fd;
}

void r_cons_pipe_close(int fd)
{
	if (fd == -1)
		return;
	close(fd);
	dup2(backup_fd+fd, 1);
}


/* --- trash --- */

void r_cons_stdout_close(int fd)
{
	if (fd != -1)
		close(fd);
	dup2(fd, 1);
}

void r_cons_stdout_close_file()
{
	close(r_cons_stdout_fd);
	dup2(r_cons_stdout_fd, 1);
}

void r_cons_stdout_open(const char *file, int append)
{
	int fd;
	if (r_cons_stdout_fd != 1) // XXX nested stdout dupping not supported
		return;

	fd = open(file, O_RDWR | O_CREAT | (append?O_APPEND:O_TRUNC), 0644);
	if (fd==-1)
		return;
	r_cons_stdout_fd = fd;
	dup2(1, r_cons_stdout_fd);
	//close(1);
	dup2(fd, 1);
}

int r_cons_stdout_set_fd(int fd)
{
	if (r_cons_stdout_fd == 0)
		return fd;
	return r_cons_stdout_fd = fd;
}
