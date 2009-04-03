/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

/* TODO: write li->fds setter/getter helpers */

#include "r_io.h"
#include "list.h"
#include <stdio.h>

int r_io_handle_init(struct r_io_t *io)
{
	INIT_LIST_HEAD(&io->io_list);
	/* load default IO plugins here */
	return 0;
}

int r_io_handle_add(struct r_io_t *io, struct r_io_handle_t *plugin)
{
	int i;
	struct r_io_list_t *li;
	li = MALLOC_STRUCT(struct r_io_list_t);
	if (li == NULL)
		return -1;
	li->plugin = plugin;
	for(i=0;i<R_IO_NFDS;i++)
		li->plugin->fds[i] = -1;
	list_add_tail(&(li->list), &(io->io_list));
	return 0;
}

struct r_io_handle_t *r_io_handle_resolve(struct r_io_t *io, const char *filename)
{
	struct list_head *pos;
	list_for_each_prev(pos, &io->io_list) {
		struct r_io_list_t *il = list_entry(pos, struct r_io_list_t, list);
		if (il->plugin->handle_open(io, filename))
			return il->plugin;
	}
	return NULL;
}

struct r_io_handle_t *r_io_handle_resolve_fd(struct r_io_t *io, int fd)
{
	int i;
	struct list_head *pos;
	list_for_each_prev(pos, &io->io_list) {
		struct r_io_list_t *il = list_entry(pos, struct r_io_list_t, list);
		for(i=0;i<R_IO_NFDS;i++) {
			if (il->plugin->fds[i] == fd)
				return il->plugin;
		}
	}
	return NULL;
}

int r_io_handle_generate(struct r_io_t *io)
{
	return (rand()%666)+1024;
}

int r_io_handle_open(struct r_io_t *io, int fd, struct r_io_handle_t *plugin)
{
	int i=0;
	struct list_head *pos;
	list_for_each_prev(pos, &io->io_list) {
		struct r_io_list_t *il = list_entry(pos, struct r_io_list_t, list);
		if (plugin == il->plugin) {
			for(i=0;i<R_IO_NFDS;i++) {
				if (il->plugin->fds[i] == -1) {
					il->plugin->fds[i] = fd;
					return 0;
				}
			}
			return -1;
		}
	}
	return -1;
}

int r_io_handle_close(struct r_io_t *io, int fd, struct r_io_handle_t *plugin)
{
	int i=0;
	struct list_head *pos;
	list_for_each_prev(pos, &io->io_list) {
		struct r_io_list_t *il = list_entry(pos, struct r_io_list_t, list);
		if (plugin == il->plugin) {
			for(i=0;i<R_IO_NFDS;i++) {
				if (il->plugin->fds[i] == fd) {
					il->plugin->fds[i] = -1;
					return 0;
				}
			}
			return -1;
		}
	}
	return -1;
}

int r_io_handle_list(struct r_io_t *io)
{
	int n = 0;
	struct list_head *pos;
	printf("IO handlers:\n");
	list_for_each_prev(pos, &io->io_list) {
		struct r_io_list_t *il = list_entry(pos, struct r_io_list_t, list);
		printf(" - %s\n", il->plugin->name);
		n++;
	}
	return n;
}
